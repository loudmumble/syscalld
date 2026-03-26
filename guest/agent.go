package guest

import (
	"encoding/json"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/loudmumble/syscalld/core"
)

// AgentConfig holds the configuration for a GuestAgentRunner.
type AgentConfig struct {
	Output       io.Writer
	Sensors      []core.Sensor
	SensorFilter *core.SensorFilter
	Fallback     bool
}

// GuestAgentRunner manages the execution of sensors inside the VM.
type GuestAgentRunner struct {
	manager  *core.SensorManager
	output   io.Writer
	sensors  []core.Sensor
	fallback bool
	mu       sync.Mutex
	running  bool
	evtCount int64
}

// NewGuestAgentRunner creates a new agent runner with the given configuration.
func NewGuestAgentRunner(cfg AgentConfig) *GuestAgentRunner {
	if cfg.SensorFilter == nil {
		cfg.SensorFilter = core.NewSensorFilter()
	}
	return &GuestAgentRunner{
		manager:  core.NewSensorManager(cfg.SensorFilter),
		output:   cfg.Output,
		sensors:  cfg.Sensors,
		fallback: cfg.Fallback,
	}
}

// Start registers sensors, sets up the event handler, and starts the manager.
func (r *GuestAgentRunner) Start() {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return
	}
	r.running = true
	r.mu.Unlock()

	for _, s := range r.sensors {
		r.manager.Add(s)
	}
	r.manager.OnAny(r.handleEvent)
	r.manager.Start()
}

// Stop stops the sensor manager and marks the runner as not running.
func (r *GuestAgentRunner) Stop() {
	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return
	}
	r.running = false
	r.mu.Unlock()

	r.manager.Stop()
}

// Running returns whether the runner is currently active.
func (r *GuestAgentRunner) Running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running
}

// EventCount returns the number of events successfully written.
func (r *GuestAgentRunner) EventCount() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.evtCount
}

// Manager returns the underlying SensorManager.
func (r *GuestAgentRunner) Manager() *core.SensorManager {
	return r.manager
}

func (r *GuestAgentRunner) handleEvent(event core.Event) {
	line, err := SerializeEvent(event)
	if err != nil {
		return
	}

	_, err = r.output.Write([]byte(line + "\n"))
	if err != nil {
		return
	}

	r.mu.Lock()
	r.evtCount++
	r.mu.Unlock()
}

// GetStats returns current operational statistics.
func (r *GuestAgentRunner) GetStats() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()

	return map[string]any{
		"running":     r.running,
		"event_count": r.evtCount,
		"sensors":     r.manager.SensorNames(),
	}
}

// SerializeEvent converts an Event to a compact JSON string.
func SerializeEvent(evt core.Event) (string, error) {
	b, err := json.Marshal(evt)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// SetupSignalHandlers traps SIGINT/SIGTERM and stops the runner on signal.
func SetupSignalHandlers(runner *GuestAgentRunner) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		runner.Stop()
	}()
}
