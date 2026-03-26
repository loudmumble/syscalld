// Package alerting provides threshold-based alert evaluation and webhook delivery.
package alerting

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/loudmumble/syscalld/core"
	"github.com/loudmumble/syscalld/internal/config"
)

// Alert represents a triggered alert.
type Alert struct {
	Rule      string  `json:"rule"`
	EventType string  `json:"event_type"`
	Severity  string  `json:"severity"`
	Rate      float64 `json:"events_per_second"`
	Threshold int     `json:"threshold"`
	Timestamp float64 `json:"timestamp"`
}

// Monitor tracks event rates and fires alerts when thresholds are exceeded.
type Monitor struct {
	rules      []config.AlertRule
	webhookURL string
	onAlert    func(Alert)

	mu       sync.Mutex
	counters map[string]*rateCounter // keyed by event type
	cooldown map[string]time.Time    // prevent alert storms
}

type rateCounter struct {
	count int
	start time.Time
}

// NewMonitor creates an alert monitor from config.
func NewMonitor(rules []config.AlertRule, webhookURL string) *Monitor {
	return &Monitor{
		rules:      rules,
		webhookURL: webhookURL,
		counters:   make(map[string]*rateCounter),
		cooldown:   make(map[string]time.Time),
	}
}

// OnAlert sets a callback for triggered alerts (e.g., logging to stdout).
func (m *Monitor) OnAlert(fn func(Alert)) {
	m.onAlert = fn
}

// Check evaluates an event against all alert rules. Call this for every event.
func (m *Monitor) Check(e core.Event) {
	if len(m.rules) == 0 {
		return
	}

	eventType := e.GetEventType()
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	rc, ok := m.counters[eventType]
	if !ok || now.Sub(rc.start) >= time.Second {
		// Start a new 1-second window
		m.counters[eventType] = &rateCounter{count: 1, start: now}
		return
	}
	rc.count++

	elapsed := now.Sub(rc.start).Seconds()
	if elapsed <= 0 {
		return
	}
	rate := float64(rc.count) / elapsed

	for _, rule := range m.rules {
		if rule.EventType != eventType {
			continue
		}
		if rate < float64(rule.ThresholdPerSecond) {
			continue
		}
		// Check cooldown — don't fire the same rule more than once per 10 seconds
		if last, ok := m.cooldown[rule.Name]; ok && now.Sub(last) < 10*time.Second {
			continue
		}
		m.cooldown[rule.Name] = now

		alert := Alert{
			Rule:      rule.Name,
			EventType: eventType,
			Severity:  rule.Severity,
			Rate:      rate,
			Threshold: rule.ThresholdPerSecond,
			Timestamp: float64(now.UnixNano()) / 1e9,
		}

		if m.onAlert != nil {
			m.onAlert(alert)
		}
		if m.webhookURL != "" {
			go m.sendWebhook(alert)
		}
	}
}

func (m *Monitor) sendWebhook(alert Alert) {
	payload, err := json.Marshal(alert)
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", m.webhookURL, bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "syscalld-alerting/1.0")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}
