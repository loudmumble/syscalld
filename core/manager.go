package core

import (
	"fmt"
	"os"
	"sync"
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

	mu           sync.Mutex
	sensors      []Sensor
	running      bool
	pollDone     chan struct{}
	pollInterval time.Duration
	merged       chan Event
	mergedDone   chan struct{}
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
// sensors) and directly by eBPF sensor channels (when available). It remains
// open until Stop() returns.
func (m *SensorManager) Events() <-chan Event {
	return m.merged
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
	defer m.mu.Unlock()

	if m.running {
		return
	}
	m.running = true

	for _, sensor := range m.sensors {
		sensor.Start(m.Filters)
	}

	m.pollDone = make(chan struct{})
	m.mergedDone = make(chan struct{})
	go m.pollLoop()
	go m.fanIn()
}

// Stop stops the polling goroutine and cleans up all sensors.
func (m *SensorManager) Stop() {
	m.mu.Lock()
	wasRunning := m.running
	m.running = false
	m.mu.Unlock()

	if wasRunning && m.pollDone != nil {
		<-m.pollDone
	}
	if wasRunning && m.mergedDone != nil {
		<-m.mergedDone
	}

	m.mu.Lock()
	for _, sensor := range m.sensors {
		sensor.Stop()
	}
	m.mu.Unlock()
}

// fanIn reads from every ChanSensor's channel and forwards events to the
// merged channel and the EventBus. It exits when the manager stops running.
// Sensors that do not implement ChanSensor are served by the poll loop.
func (m *SensorManager) fanIn() {
	defer close(m.mergedDone)

	m.mu.Lock()
	sensors := make([]Sensor, len(m.sensors))
	copy(sensors, m.sensors)
	m.mu.Unlock()

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

	for {
		m.mu.Lock()
		running := m.running
		m.mu.Unlock()
		if !running {
			return
		}
		for _, ch := range chans {
			m.drainChan(ch)
		}
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
			select {
			case m.merged <- evt:
			default:
			}
			m.Bus.Emit(evt)
		default:
			return
		}
	}
}

func (m *SensorManager) pollLoop() {
	defer close(m.pollDone)

	lastCanary := time.Now()
	const canaryInterval = 30 * time.Second

	for {
		m.mu.Lock()
		if !m.running {
			m.mu.Unlock()
			return
		}
		sensors := make([]Sensor, len(m.sensors))
		copy(sensors, m.sensors)
		m.mu.Unlock()

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
					select {
					case m.merged <- event:
					default:
					}
				}
			}()
		}

		// Emit a periodic canary heartbeat to verify the pipeline is healthy.
		// Consumers can subscribe to "canary" events to detect sensor stalls.
		if time.Since(lastCanary) >= canaryInterval {
			canary := NewCanaryEvent()
			m.Bus.Emit(canary)
			select {
			case m.merged <- canary:
			default:
			}
			lastCanary = time.Now()
		}

		time.Sleep(m.pollInterval)
	}
}

// SensorCount returns the number of registered sensors.
func (m *SensorManager) SensorCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sensors)
}

// Running returns whether the manager is actively polling.
func (m *SensorManager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

// SensorNames returns the names of all registered sensors.
func (m *SensorManager) SensorNames() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, len(m.sensors))
	for i, s := range m.sensors {
		names[i] = s.Name()
	}
	return names
}

// Healths returns a health snapshot for every registered sensor.
func (m *SensorManager) Healths() []SensorHealth {
	m.mu.Lock()
	sensors := make([]Sensor, len(m.sensors))
	copy(sensors, m.sensors)
	m.mu.Unlock()

	out := make([]SensorHealth, len(sensors))
	for i, s := range sensors {
		out[i] = s.Health()
	}
	return out
}
