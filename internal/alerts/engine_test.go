package alerts

import (
	"sync"
	"testing"

	"github.com/loudmumble/syscalld/internal/config"
)

func TestEngineNoRules(t *testing.T) {
	e := NewEngine(nil, nil)
	e.Observe("syscall") // should not panic
	if e.RuleCount() != 0 {
		t.Fatalf("expected 0 rules, got %d", e.RuleCount())
	}
}

func TestEngineFiresOnThreshold(t *testing.T) {
	var mu sync.Mutex
	var fired []Alert

	rules := []config.AlertRule{
		{Name: "test-rule", EventType: "syscall", ThresholdPerSecond: 5, Severity: "critical"},
	}
	e := NewEngine(rules, func(a Alert) {
		mu.Lock()
		fired = append(fired, a)
		mu.Unlock()
	})

	// Send 4 events — should not fire
	for i := 0; i < 4; i++ {
		e.Observe("syscall")
	}
	mu.Lock()
	if len(fired) != 0 {
		t.Fatalf("expected 0 alerts after 4 events, got %d", len(fired))
	}
	mu.Unlock()

	// 5th event should fire
	e.Observe("syscall")
	mu.Lock()
	if len(fired) != 1 {
		t.Fatalf("expected 1 alert after 5 events, got %d", len(fired))
	}
	if fired[0].Rule.Name != "test-rule" {
		t.Fatalf("expected rule name 'test-rule', got %q", fired[0].Rule.Name)
	}
	if fired[0].Rate != 5 {
		t.Fatalf("expected rate 5, got %d", fired[0].Rate)
	}
	mu.Unlock()
}

func TestEngineIgnoresWrongType(t *testing.T) {
	var fired int
	rules := []config.AlertRule{
		{Name: "net-rule", EventType: "network", ThresholdPerSecond: 1, Severity: "warning"},
	}
	e := NewEngine(rules, func(a Alert) { fired++ })

	for i := 0; i < 100; i++ {
		e.Observe("syscall") // wrong type — should never fire
	}
	if fired != 0 {
		t.Fatalf("expected 0 alerts for wrong event type, got %d", fired)
	}
}

func TestEngineCooldown(t *testing.T) {
	var fired int
	rules := []config.AlertRule{
		{Name: "cd-rule", EventType: "process", ThresholdPerSecond: 1, Severity: "info"},
	}
	e := NewEngine(rules, func(a Alert) { fired++ })

	// Fire 10 events rapidly — should only fire once due to cooldown
	for i := 0; i < 10; i++ {
		e.Observe("process")
	}
	if fired != 1 {
		t.Fatalf("expected 1 alert with cooldown, got %d", fired)
	}
}
