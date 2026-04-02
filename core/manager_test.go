package core

import (
	"sync"
	"testing"
	"time"
)

// stubSensor implements Sensor for testing.
type stubSensor struct {
	name    string
	mode    string
	started bool
	stopped bool
	events  []Event
}

func newStubSensor(name string, events []Event) *stubSensor {
	return &stubSensor{name: name, mode: "fallback", events: events}
}

func (s *stubSensor) Name() string          { return s.name }
func (s *stubSensor) Mode() string          { return s.mode }
func (s *stubSensor) Started() bool         { return s.started }
func (s *stubSensor) Start(f *SensorFilter) { s.started = true; s.mode = "fallback" }
func (s *stubSensor) Stop()                 { s.stopped = true; s.started = false }
func (s *stubSensor) Health() SensorHealth  { return SensorHealth{Name: s.name, Mode: s.mode, Started: s.started} }
func (s *stubSensor) Poll() []Event {
	if !s.started {
		return nil
	}
	return s.events
}

func TestManagerDefaultInit(t *testing.T) {
	mgr := NewSensorManager(nil)
	if mgr.SensorCount() != 0 {
		t.Errorf("expected 0, got %d", mgr.SensorCount())
	}
	if mgr.Running() {
		t.Error("expected not running")
	}
	if mgr.Bus == nil {
		t.Error("expected non-nil bus")
	}
	if mgr.Filters == nil {
		t.Error("expected non-nil filters")
	}
}

func TestManagerCustomFilters(t *testing.T) {
	f := NewSensorFilter()
	f.TargetPIDs[42] = struct{}{}
	mgr := NewSensorManager(f)
	if mgr.Filters != f {
		t.Error("expected same filter")
	}
	if _, ok := mgr.Filters.TargetPIDs[42]; !ok {
		t.Error("expected PID 42 in filter")
	}
}

func TestManagerAddSensor(t *testing.T) {
	mgr := NewSensorManager(nil)
	mgr.Add(newStubSensor("stub", nil))
	if mgr.SensorCount() != 1 {
		t.Errorf("expected 1, got %d", mgr.SensorCount())
	}
}

func TestManagerAddMultiple(t *testing.T) {
	mgr := NewSensorManager(nil)
	mgr.Add(newStubSensor("a", nil))
	mgr.Add(newStubSensor("b", nil))
	mgr.Add(newStubSensor("c", nil))
	if mgr.SensorCount() != 3 {
		t.Errorf("expected 3, got %d", mgr.SensorCount())
	}
}

func TestManagerSensorNames(t *testing.T) {
	mgr := NewSensorManager(nil)
	mgr.Add(newStubSensor("sensor_a", nil))
	mgr.Add(newStubSensor("sensor_b", nil))
	names := mgr.SensorNames()
	if len(names) != 2 || names[0] != "sensor_a" || names[1] != "sensor_b" {
		t.Errorf("unexpected names: %v", names)
	}
}

func TestManagerOnDelegatesToBus(t *testing.T) {
	mgr := NewSensorManager(nil)
	mgr.On("syscall", func(e Event) {})
	if mgr.Bus.HandlerCount() != 1 {
		t.Errorf("expected 1, got %d", mgr.Bus.HandlerCount())
	}
}

func TestManagerOnAnyDelegatesToBus(t *testing.T) {
	mgr := NewSensorManager(nil)
	mgr.OnAny(func(e Event) {})
	if mgr.Bus.HandlerCount() != 1 {
		t.Errorf("expected 1, got %d", mgr.Bus.HandlerCount())
	}
}

func TestManagerStartStartsSensors(t *testing.T) {
	mgr := NewSensorManager(nil)
	s := newStubSensor("stub", nil)
	mgr.Add(s)
	mgr.Start()
	defer mgr.Stop()
	if !s.started {
		t.Error("expected started")
	}
	if !mgr.Running() {
		t.Error("expected running")
	}
}

func TestManagerStopStopsSensors(t *testing.T) {
	mgr := NewSensorManager(nil)
	s := newStubSensor("stub", nil)
	mgr.Add(s)
	mgr.Start()
	mgr.Stop()
	if !s.stopped {
		t.Error("expected stopped")
	}
	if mgr.Running() {
		t.Error("expected not running")
	}
}

func TestManagerDoubleStartIsNoop(t *testing.T) {
	mgr := NewSensorManager(nil)
	mgr.Add(newStubSensor("stub", nil))
	mgr.Start()
	mgr.Start() // Should not panic
	defer mgr.Stop()
	if !mgr.Running() {
		t.Error("expected running")
	}
}

func TestManagerPollThreadStops(t *testing.T) {
	mgr := NewSensorManager(nil)
	mgr.Add(newStubSensor("stub", nil))
	mgr.Start()
	mgr.Stop()
	if mgr.Running() {
		t.Error("expected not running after stop")
	}
}

func TestManagerEventsReachHandlers(t *testing.T) {
	evt := &SyscallEvent{
		KernelEvent: KernelEvent{PID: 1, EventType: "syscall"},
		SyscallNR:   59,
		Args:        []int{},
	}
	s := newStubSensor("stub", []Event{evt})
	mgr := NewSensorManager(nil)
	mgr.Add(s)

	var mu sync.Mutex
	var received []Event
	mgr.On("syscall", func(e Event) {
		mu.Lock()
		received = append(received, e)
		mu.Unlock()
	})
	mgr.Start()
	time.Sleep(100 * time.Millisecond)
	mgr.Stop()

	mu.Lock()
	defer mu.Unlock()
	if len(received) < 1 {
		t.Error("expected at least 1 event")
	}
	if received[0].(*SyscallEvent).PID != 1 {
		t.Error("expected PID 1")
	}
}

func TestManagerMultipleEventTypes(t *testing.T) {
	events := []Event{
		&SyscallEvent{KernelEvent: KernelEvent{PID: 1, EventType: "syscall"}, Args: []int{}},
		&ProcessEvent{KernelEvent: KernelEvent{PID: 2, EventType: "process"}, Action: "exec", Argv: []string{}},
	}
	s := newStubSensor("stub", events)
	mgr := NewSensorManager(nil)
	mgr.Add(s)

	var mu sync.Mutex
	var syscalls, processes []Event
	mgr.On("syscall", func(e Event) {
		mu.Lock()
		syscalls = append(syscalls, e)
		mu.Unlock()
	})
	mgr.On("process", func(e Event) {
		mu.Lock()
		processes = append(processes, e)
		mu.Unlock()
	})
	mgr.Start()
	time.Sleep(100 * time.Millisecond)
	mgr.Stop()

	mu.Lock()
	defer mu.Unlock()
	if len(syscalls) < 1 {
		t.Error("expected at least 1 syscall event")
	}
	if len(processes) < 1 {
		t.Error("expected at least 1 process event")
	}
}

func TestManagerErrorInPollDoesNotCrash(t *testing.T) {
	// Create a sensor that panics in Poll
	s := &panicSensor{}
	mgr := NewSensorManager(nil)
	mgr.Add(s)
	mgr.Start()
	time.Sleep(100 * time.Millisecond)
	mgr.Stop()
	if mgr.Running() {
		t.Error("expected not running")
	}
}

type panicSensor struct{}

func (s *panicSensor) Name() string           { return "error_sensor" }
func (s *panicSensor) Mode() string           { return "fallback" }
func (s *panicSensor) Started() bool          { return true }
func (s *panicSensor) Start(f *SensorFilter)  {}
func (s *panicSensor) Stop()                  {}
func (s *panicSensor) Health() SensorHealth   { return SensorHealth{Name: "error_sensor", Mode: "fallback", Started: true} }
func (s *panicSensor) Poll() []Event          { panic("poll failure") }
