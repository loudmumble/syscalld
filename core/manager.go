package core

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// SensorHealth is a point-in-time snapshot of a sensor's runtime statistics.
// It is safe to read after being returned — no pointers into internal state.
type SensorHealth struct {
	Name        string
	Mode        string
	Started     bool
	EventCount  uint64
	ErrorCount  uint64
	StartTime   time.Time
	LastEventAt time.Time
}

// Sensor is the interface that all sensor implementations must satisfy.
// It is defined here (in core) to avoid circular imports, since the manager
// needs to reference sensors but sensors reference core types.
type Sensor interface {
	// Name returns the sensor's identifier (e.g. "syscall", "process").
	Name() string
	// Start initializes the sensor with the given filter configuration.
	Start(filters *SensorFilter)
	// Stop cleans up resources and detaches probes.
	Stop()
	// Poll retrieves pending events from the sensor.
	Poll() []Event
	// Mode returns the current operating mode ("ebpf" or "fallback").
	Mode() string
	// Started returns whether the sensor has been started.
	Started() bool
	// Health returns a snapshot of the sensor's runtime statistics.
	Health() SensorHealth
}

// ChanSensor is an optional interface implemented by eBPF sensors that
// expose a direct Go channel path in addition to Poll().
type ChanSensor interface {
	Chan() <-chan Event
}

// SensorManager manages sensor lifecycle, compiles BPF programs, and runs the poll loop.
//
// Usage:
//
//	mgr := core.NewSensorManager(nil)
//	mgr.Add(sensors.NewSyscallSensor())
//	mgr.On("syscall", myHandler)
//	mgr.Start()
//	// ... sensors are now polling ...
//	mgr.Stop()
type SensorManager struct {
	Bus     *EventBus
	Filters *SensorFilter

	mu           sync.RWMutex
	sensors      []Sensor
	running      bool
	pollDone     chan struct{}
	pollInterval time.Duration
	merged       chan Event
	mergedDone   chan struct{}
	stopCh       chan struct{} // closed on Stop to signal goroutines
	droppedCount uint64       // atomic — events dropped due to full merged channel
}

// NewSensorManager creates a new SensorManager with optional filter configuration.
func NewSensorManager(filters *SensorFilter) *SensorManager {
	if filters == nil {
		filters = NewSensorFilter()
	}
	return &SensorManager{
		Bus:          NewEventBus(),
		Filters:      filters,
		pollInterval: 10 * time.Millisecond,
		merged:       make(chan Event, 4096),
	}
}

// Events returns a merged read-only channel that delivers every event emitted
// by all registered sensors. The channel is fed by the polling loop (fallback
// sensors) and directly by eBPF sensor channels (when available). It is closed
// when Stop() completes. Callers must re-call Events() after a Stop/Start
// cycle to get the new channel.
func (m *SensorManager) Events() <-chan Event {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.merged
}

// DroppedEvents returns the number of events that were dropped because the
// merged channel buffer was full. This is an atomic counter that can be
// called from any goroutine.
func (m *SensorManager) DroppedEvents() uint64 {
	return atomic.LoadUint64(&m.droppedCount)
}

// SetPollInterval configures the polling interval. Must be called before Start().
func (m *SensorManager) SetPollInterval(d time.Duration) {
	if d > 0 {
		m.pollInterval = d
	}
}

// Add registers a sensor to be managed.
func (m *SensorManager) Add(sensor Sensor) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sensors = append(m.sensors, sensor)
}

// On registers an event handler for a specific event type (delegates to EventBus).
func (m *SensorManager) On(eventType string, callback EventHandler) {
	m.Bus.On(eventType, callback)
}

// OnAny registers a catch-all event handler.
func (m *SensorManager) OnAny(callback EventHandler) {
	m.Bus.OnAny(callback)
}

// Start starts all sensors and begins the polling goroutine.
func (m *SensorManager) Start() {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.running = true
	m.merged = make(chan Event, 4096)
	m.stopCh = make(chan struct{})
	atomic.StoreUint64(&m.droppedCount, 0)
	sensors := make([]Sensor, len(m.sensors))
	copy(sensors, m.sensors)
	m.mu.Unlock()

	for _, sensor := range sensors {
		sensor.Start(m.Filters)
	}

	m.mu.Lock()
	m.pollDone = make(chan struct{})
	m.mergedDone = make(chan struct{})
	m.mu.Unlock()

	go m.pollLoop()
	go m.fanIn()
}

// Stop stops the polling goroutine and cleans up all sensors.
func (m *SensorManager) Stop() {
	m.mu.Lock()
	wasRunning := m.running
	m.running = false
	pollDone := m.pollDone
	mergedDone := m.mergedDone
	stopCh := m.stopCh
	m.mu.Unlock()

	// Signal goroutines to exit.
	if wasRunning && stopCh != nil {
		close(stopCh)
	}

	if wasRunning && pollDone != nil {
		<-pollDone
	}
	if wasRunning && mergedDone != nil {
		<-mergedDone
	}

	// Close the merged channel so consumers of Events() see an EOF.
	if wasRunning {
		close(m.merged)
	}

	m.mu.RLock()
	sensors := make([]Sensor, len(m.sensors))
	copy(sensors, m.sensors)
	m.mu.RUnlock()

	for _, sensor := range sensors {
		sensor.Stop()
	}
}

// emitToMerged sends an event to the merged channel, incrementing the drop
// counter if the buffer is full.
func (m *SensorManager) emitToMerged(evt Event) {
	select {
	case m.merged <- evt:
	default:
		dropped := atomic.AddUint64(&m.droppedCount, 1)
		// Log every 1000th drop to avoid flooding stderr.
		if dropped == 1 || dropped%1000 == 0 {
			fmt.Fprintf(os.Stderr, "[SensorManager] Event buffer full — %d events dropped total\n", dropped)
		}
	}
}

// fanIn reads from every ChanSensor's channel and forwards events to the
// merged channel and the EventBus. It exits when stopCh is closed.
// Sensors that do not implement ChanSensor are served by the poll loop.
func (m *SensorManager) fanIn() {
	defer close(m.mergedDone)

	m.mu.RLock()
	sensors := make([]Sensor, len(m.sensors))
	copy(sensors, m.sensors)
	stopCh := m.stopCh
	m.mu.RUnlock()

	var chans []<-chan Event
	for _, s := range sensors {
		cs, ok := s.(ChanSensor)
		if !ok {
			continue
		}
		ch := cs.Chan()
		if ch != nil {
			chans = append(chans, ch)
		}
	}

	// If no ChanSensors, just wait for stop signal and exit.
	if len(chans) == 0 {
		<-stopCh
		return
	}

	for {
		select {
		case <-stopCh:
			return
		default:
		}
		for _, ch := range chans {
			m.drainChan(ch)
		}
		// Brief sleep to yield CPU between drain cycles.
		time.Sleep(m.pollInterval)
	}
}

func (m *SensorManager) drainChan(ch <-chan Event) {
	for {
		select {
		case evt, ok := <-ch:
			if !ok {
				return
			}
			m.emitToMerged(evt)
			m.Bus.Emit(evt)
		default:
			return
		}
	}
}

func (m *SensorManager) pollLoop() {
	defer close(m.pollDone)

	m.mu.RLock()
	stopCh := m.stopCh
	m.mu.RUnlock()

	lastCanary := time.Now()
	const canaryInterval = 30 * time.Second

	for {
		select {
		case <-stopCh:
			return
		default:
		}

		m.mu.RLock()
		sensors := make([]Sensor, len(m.sensors))
		copy(sensors, m.sensors)
		m.mu.RUnlock()

		for _, sensor := range sensors {
			func() {
				defer func() {
					if r := recover(); r != nil {
						fmt.Fprintf(os.Stderr, "[SensorManager] Poll error in %s: %v\n",
							sensor.Name(), r)
					}
				}()
				events := sensor.Poll()
				for _, event := range events {
					m.Bus.Emit(event)
					m.emitToMerged(event)
				}
			}()
		}

		// Emit a periodic canary heartbeat to verify the pipeline is healthy.
		// Consumers can subscribe to "canary" events to detect sensor stalls.
		if time.Since(lastCanary) >= canaryInterval {
			canary := NewCanaryEvent()
			m.Bus.Emit(canary)
			m.emitToMerged(canary)
			lastCanary = time.Now()
		}

		time.Sleep(m.pollInterval)
	}
}

// SensorCount returns the number of registered sensors.
func (m *SensorManager) SensorCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sensors)
}

// Running returns whether the manager is actively polling.
func (m *SensorManager) Running() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// SensorNames returns the names of all registered sensors.
func (m *SensorManager) SensorNames() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	names := make([]string, len(m.sensors))
	for i, s := range m.sensors {
		names[i] = s.Name()
	}
	return names
}

// Healths returns a health snapshot for every registered sensor.
func (m *SensorManager) Healths() []SensorHealth {
	m.mu.RLock()
	sensors := make([]Sensor, len(m.sensors))
	copy(sensors, m.sensors)
	m.mu.RUnlock()

	out := make([]SensorHealth, len(sensors))
	for i, s := range sensors {
		out[i] = s.Health()
	}
	return out
}
