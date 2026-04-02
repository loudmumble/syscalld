// Package config provides YAML-based configuration for syscalld.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration for the syscalld daemon.
type Config struct {
	// Sensors lists which sensors to enable. If empty, all sensors are enabled.
	Sensors []string `yaml:"sensors"`

	// Filters contains per-sensor filter configuration.
	Filters FilterConfig `yaml:"filters"`

	// Output controls output format and destination.
	Output OutputConfig `yaml:"output"`

	// Alerts defines threshold-based alerting rules.
	Alerts []AlertRule `yaml:"alerts"`

	// Fallback enables proc-based fallback when eBPF is unavailable.
	Fallback bool `yaml:"fallback"`

	// PollInterval is the sensor polling interval in milliseconds.
	PollIntervalMS int `yaml:"poll_interval_ms"`
}

// FilterConfig contains per-sensor filter settings.
type FilterConfig struct {
	// TargetPIDs limits monitoring to specific PIDs (empty = all).
	TargetPIDs []int `yaml:"target_pids"`

	// ExcludePIDs excludes specific PIDs from monitoring.
	ExcludePIDs []int `yaml:"exclude_pids"`

	// TargetComms limits monitoring to processes with these comm names.
	TargetComms []string `yaml:"target_comms"`

	// ExcludeComms excludes processes with these comm names.
	ExcludeComms []string `yaml:"exclude_comms"`

	// MinSeverity filters events below this severity level (0 = all).
	MinSeverity int `yaml:"min_severity"`
}

// OutputConfig controls how events are emitted.
type OutputConfig struct {
	// Format: json, ndjson, text (default: text)
	Format string `yaml:"format"`

	// File path for output. Empty means stdout.
	File string `yaml:"file"`

	// WebhookURL sends alerts to this URL when set.
	WebhookURL string `yaml:"webhook_url"`
}

// AlertRule defines a threshold-based alert.
type AlertRule struct {
	// Name is a human-readable rule identifier.
	Name string `yaml:"name"`

	// EventType is the sensor event type to monitor (e.g. "network", "syscall").
	EventType string `yaml:"event_type"`

	// ThresholdPerSecond triggers an alert when events exceed this rate.
	ThresholdPerSecond int `yaml:"threshold_per_second"`

	// Severity label to apply: info, warning, critical.
	Severity string `yaml:"severity"`
}

// AllSensors is the default full sensor list.
var AllSensors = []string{"syscall", "process", "filesystem", "network", "memory", "module", "dns"}

// Default returns a sensible default configuration.
func Default() *Config {
	return &Config{
		Sensors:        AllSensors,
		Fallback:       true,
		PollIntervalMS: 10,
		Output:         OutputConfig{Format: "text"},
	}
}

// Load reads a YAML config file from disk, returning Default() if not found.
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Default(), nil
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if len(cfg.Sensors) == 0 {
		cfg.Sensors = AllSensors
	}
	if cfg.PollIntervalMS <= 0 {
		cfg.PollIntervalMS = 10
	}
	return cfg, nil
}

// Save writes a config to disk, creating parent directories as needed.
func Save(cfg *Config, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// DefaultPath returns the default config file path.
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join("/etc", "syscalld", "config.yaml")
	}
	return filepath.Join(home, ".syscalld", "config.yaml")
}

// Presets returns built-in named configuration presets.
func Presets() map[string]*Config {
	return map[string]*Config{
		"security-audit": {
			Sensors:        []string{"network", "syscall", "process"},
			Fallback:       true,
			PollIntervalMS: 10,
			Output:         OutputConfig{Format: "json"},
			Alerts: []AlertRule{
				{Name: "privilege-escalation", EventType: "syscall", ThresholdPerSecond: 5, Severity: "critical"},
				{Name: "mass-network", EventType: "network", ThresholdPerSecond: 100, Severity: "warning"},
			},
		},
		"threat-hunting": {
			Sensors:        AllSensors,
			Fallback:       true,
			PollIntervalMS: 5,
			Output:         OutputConfig{Format: "ndjson"},
			Alerts: []AlertRule{
				{Name: "dns-exfil", EventType: "dns", ThresholdPerSecond: 50, Severity: "warning"},
				{Name: "suspicious-exec", EventType: "process", ThresholdPerSecond: 10, Severity: "critical"},
			},
		},
		"performance-baseline": {
			Sensors:        []string{"memory", "filesystem", "network"},
			Fallback:       true,
			PollIntervalMS: 50,
			Output:         OutputConfig{Format: "text"},
		},
		"minimal": {
			Sensors:        []string{"process"},
			Fallback:       true,
			PollIntervalMS: 100,
			Output:         OutputConfig{Format: "text"},
		},
	}
}
