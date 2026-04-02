// Package alerts provides a lightweight threshold-based alerting engine.
//
// The engine counts events per type within a rolling 1-second window and
// fires an alert callback when the count exceeds a configured threshold.
package alerts

import (
	"sync"
	"time"

	"github.com/loudmumble/syscalld/internal/config"
)

// Alert is emitted when a threshold rule fires.
type Alert struct {
	Time    time.Time
	Rule    config.AlertRule
	Rate    int // observed events/sec when alert fired
	Message string
}

// AlertHandler is called when an alert fires.
type AlertHandler func(Alert)

// Engine evaluates alert rules against event rates.
type Engine struct {
	rules   []config.AlertRule
	handler AlertHandler

	mu       sync.Mutex
	counts   map[string]int       // event_type -> count in current window
	windowAt time.Time            // start of current 1-second window
	cooldown map[string]time.Time // rule name -> last fire time
}

// NewEngine creates an alert engine with the given rules and callback.
// If rules is empty, the engine is a no-op. Handler must not be nil if
// rules are provided.
func NewEngine(rules []config.AlertRule, handler AlertHandler) *Engine {
	return &Engine{
		rules:    rules,
		handler:  handler,
		counts:   make(map[string]int),
		windowAt: time.Now(),
		cooldown: make(map[string]time.Time),
	}
}

// Observe records an event of the given type and evaluates all matching
// rules. If a threshold is exceeded, the alert handler is called.
// Safe for concurrent use.
func (e *Engine) Observe(eventType string) {
	if len(e.rules) == 0 {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()

	// Roll the window if more than 1 second has passed.
	if now.Sub(e.windowAt) >= time.Second {
		e.counts = make(map[string]int)
		e.windowAt = now
	}

	e.counts[eventType]++
	count := e.counts[eventType]

	for _, rule := range e.rules {
		if rule.EventType != eventType {
			continue
		}
		if rule.ThresholdPerSecond <= 0 {
			continue
		}
		if count < rule.ThresholdPerSecond {
			continue
		}
		// Only fire once per 10-second cooldown per rule to avoid flooding.
		if last, ok := e.cooldown[rule.Name]; ok && now.Sub(last) < 10*time.Second {
			continue
		}
		e.cooldown[rule.Name] = now

		alert := Alert{
			Time:    now,
			Rule:    rule,
			Rate:    count,
			Message: rule.Name + ": " + eventType + " rate exceeded threshold",
		}
		if e.handler != nil {
			e.handler(alert)
		}
	}
}

// RuleCount returns the number of active rules.
func (e *Engine) RuleCount() int {
	return len(e.rules)
}
