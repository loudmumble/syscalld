package core

import (
	"bytes"
	"os"
	"sync"
	"testing"
)

func TestRegisterTypedHandler(t *testing.T) {
	bus := NewEventBus()
	bus.On("syscall", func(e Event) {})
	if bus.HandlerCount() != 1 {
		t.Errorf("expected 1, got %d", bus.HandlerCount())
	}
}

func TestRegisterMultipleTypedHandlers(t *testing.T) {
	bus := NewEventBus()
	bus.On("syscall", func(e Event) {})
	bus.On("syscall", func(e Event) {})
	bus.On("process", func(e Event) {})
	if bus.HandlerCount() != 3 {
		t.Errorf("expected 3, got %d", bus.HandlerCount())
	}
}

func TestRegisterAnyHandler(t *testing.T) {
	bus := NewEventBus()
	bus.OnAny(func(e Event) {})
	if bus.HandlerCount() != 1 {
		t.Errorf("expected 1, got %d", bus.HandlerCount())
	}
}

func TestRegisterMixedHandlers(t *testing.T) {
	bus := NewEventBus()
	bus.On("file", func(e Event) {})
	bus.OnAny(func(e Event) {})
	if bus.HandlerCount() != 2 {
		t.Errorf("expected 2, got %d", bus.HandlerCount())
	}
}

func TestClearRemovesAll(t *testing.T) {
	bus := NewEventBus()
	bus.On("syscall", func(e Event) {})
	bus.On("process", func(e Event) {})
	bus.OnAny(func(e Event) {})
	if bus.HandlerCount() != 3 {
		t.Errorf("expected 3, got %d", bus.HandlerCount())
	}
	bus.Clear()
	if bus.HandlerCount() != 0 {
		t.Errorf("expected 0, got %d", bus.HandlerCount())
	}
}

func TestEmitToTypedHandler(t *testing.T) {
	bus := NewEventBus()
	var received []Event
	bus.On("syscall", func(e Event) { received = append(received, e) })
	event := &SyscallEvent{KernelEvent: KernelEvent{PID: 1, EventType: "syscall"}, SyscallNR: 59, Args: []int{}}
	bus.Emit(event)
	if len(received) != 1 {
		t.Fatalf("expected 1, got %d", len(received))
	}
	if received[0] != event {
		t.Error("expected same event instance")
	}
}

func TestEmitDoesNotCrossTypes(t *testing.T) {
	bus := NewEventBus()
	var received []Event
	bus.On("process", func(e Event) { received = append(received, e) })
	bus.Emit(&SyscallEvent{KernelEvent: KernelEvent{PID: 1, EventType: "syscall"}, Args: []int{}})
	if len(received) != 0 {
		t.Errorf("expected 0, got %d", len(received))
	}
}

func TestEmitToAnyHandler(t *testing.T) {
	bus := NewEventBus()
	var received []Event
	bus.OnAny(func(e Event) { received = append(received, e) })
	bus.Emit(&SyscallEvent{KernelEvent: KernelEvent{PID: 1, EventType: "syscall"}, Args: []int{}})
	bus.Emit(&ProcessEvent{KernelEvent: KernelEvent{PID: 2, EventType: "process"}, Argv: []string{}})
	bus.Emit(&FileEvent{KernelEvent: KernelEvent{PID: 3, EventType: "file"}})
	if len(received) != 3 {
		t.Errorf("expected 3, got %d", len(received))
	}
}

func TestEmitToBothTypedAndAny(t *testing.T) {
	bus := NewEventBus()
	var typed, catchall []Event
	bus.On("syscall", func(e Event) { typed = append(typed, e) })
	bus.OnAny(func(e Event) { catchall = append(catchall, e) })
	event := &SyscallEvent{KernelEvent: KernelEvent{PID: 1, EventType: "syscall"}, Args: []int{}}
	bus.Emit(event)
	if len(typed) != 1 {
		t.Errorf("expected 1 typed, got %d", len(typed))
	}
	if len(catchall) != 1 {
		t.Errorf("expected 1 catchall, got %d", len(catchall))
	}
}

func TestTypedCalledBeforeAny(t *testing.T) {
	bus := NewEventBus()
	var order []string
	bus.On("syscall", func(e Event) { order = append(order, "typed") })
	bus.OnAny(func(e Event) { order = append(order, "any") })
	bus.Emit(&SyscallEvent{KernelEvent: KernelEvent{EventType: "syscall"}, Args: []int{}})
	if len(order) != 2 || order[0] != "typed" || order[1] != "any" {
		t.Errorf("expected [typed, any], got %v", order)
	}
}

func TestMultipleTypedAllCalled(t *testing.T) {
	bus := NewEventBus()
	counts := [2]int{}
	bus.On("network", func(e Event) { counts[0]++ })
	bus.On("network", func(e Event) { counts[1]++ })
	bus.Emit(&NetworkEvent{KernelEvent: KernelEvent{EventType: "network"}})
	if counts[0] != 1 || counts[1] != 1 {
		t.Errorf("expected [1, 1], got %v", counts)
	}
}

func TestEmitNoHandlersNoError(t *testing.T) {
	bus := NewEventBus()
	// Should not panic
	bus.Emit(&SyscallEvent{KernelEvent: KernelEvent{PID: 1, EventType: "syscall"}, Args: []int{}})
}

func TestEmitAllEventTypes(t *testing.T) {
	bus := NewEventBus()
	var received []string
	bus.OnAny(func(e Event) { received = append(received, e.GetEventType()) })
	events := []Event{
		&SyscallEvent{KernelEvent: KernelEvent{EventType: "syscall"}, Args: []int{}},
		&ProcessEvent{KernelEvent: KernelEvent{EventType: "process"}, Argv: []string{}},
		&FileEvent{KernelEvent: KernelEvent{EventType: "file"}},
		&NetworkEvent{KernelEvent: KernelEvent{EventType: "network"}},
		&MemoryEvent{KernelEvent: KernelEvent{EventType: "memory"}},
		&ModuleEvent{KernelEvent: KernelEvent{EventType: "module"}},
		&DnsEvent{KernelEvent: KernelEvent{EventType: "dns"}},
	}
	for _, e := range events {
		bus.Emit(e)
	}
	expected := []string{"syscall", "process", "file", "network", "memory", "module", "dns"}
	if len(received) != len(expected) {
		t.Fatalf("expected %d, got %d", len(expected), len(received))
	}
	for i, exp := range expected {
		if received[i] != exp {
			t.Errorf("at %d: expected %q, got %q", i, exp, received[i])
		}
	}
}

func TestHandlerExceptionDoesNotCrashBus(t *testing.T) {
	// Redirect stderr to capture output
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	bus := NewEventBus()
	var goodReceived []Event
	bus.On("syscall", func(e Event) { panic("test error") })
	bus.On("syscall", func(e Event) { goodReceived = append(goodReceived, e) })
	bus.Emit(&SyscallEvent{KernelEvent: KernelEvent{PID: 1, EventType: "syscall"}, Args: []int{}})

	w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)
	errOutput := buf.String()

	if len(goodReceived) != 1 {
		t.Errorf("expected 1, got %d", len(goodReceived))
	}
	if !bytes.Contains([]byte(errOutput), []byte("Handler error")) {
		t.Errorf("expected error message in stderr, got %q", errOutput)
	}
}

func TestAnyHandlerExceptionDoesNotCrashBus(t *testing.T) {
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	bus := NewEventBus()
	var received []Event
	bus.OnAny(func(e Event) { panic("any error") })
	bus.OnAny(func(e Event) { received = append(received, e) })
	bus.Emit(&SyscallEvent{KernelEvent: KernelEvent{EventType: "syscall"}, Args: []int{}})

	w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)
	errOutput := buf.String()

	if len(received) != 1 {
		t.Errorf("expected 1, got %d", len(received))
	}
	if !bytes.Contains([]byte(errOutput), []byte("Catch-all handler error")) {
		t.Errorf("expected error message in stderr, got %q", errOutput)
	}
}

func TestClearThenEmitNoCallbacks(t *testing.T) {
	bus := NewEventBus()
	var received []Event
	bus.On("syscall", func(e Event) { received = append(received, e) })
	bus.OnAny(func(e Event) { received = append(received, e) })
	bus.Clear()
	bus.Emit(&SyscallEvent{KernelEvent: KernelEvent{EventType: "syscall"}, Args: []int{}})
	if len(received) != 0 {
		t.Errorf("expected 0, got %d", len(received))
	}
}

func TestReregisterAfterClear(t *testing.T) {
	bus := NewEventBus()
	var received []Event
	bus.On("syscall", func(e Event) {})
	bus.Clear()
	bus.On("process", func(e Event) { received = append(received, e) })
	bus.Emit(&ProcessEvent{KernelEvent: KernelEvent{EventType: "process"}, Argv: []string{}})
	if len(received) != 1 {
		t.Errorf("expected 1, got %d", len(received))
	}
}

func TestEventBusConcurrency(t *testing.T) {
	bus := NewEventBus()
	var mu sync.Mutex
	count := 0
	bus.On("syscall", func(e Event) {
		mu.Lock()
		count++
		mu.Unlock()
	})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bus.Emit(&SyscallEvent{KernelEvent: KernelEvent{EventType: "syscall"}, Args: []int{}})
		}()
	}
	wg.Wait()

	mu.Lock()
	if count != 100 {
		t.Errorf("expected 100, got %d", count)
	}
	mu.Unlock()
}

func TestOnNilHandlerPanics(t *testing.T) {
	bus := NewEventBus()
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil callback in On()")
		}
	}()
	bus.On("syscall", nil)
}

func TestOnAnyNilHandlerPanics(t *testing.T) {
	bus := NewEventBus()
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil callback in OnAny()")
		}
	}()
	bus.OnAny(nil)
}
