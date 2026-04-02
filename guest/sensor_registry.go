package guest

import (
	"fmt"
	"os"
	"sort"
	"sync"

	"github.com/loudmumble/syscalld/core"
	"github.com/loudmumble/syscalld/sensors"
)

// DefaultVirtioPath is the default virtio-serial device path for guest communication.
const DefaultVirtioPath = "/dev/vport0p1"

// Registry contains all known sensor constructors.
var Registry = map[string]func() core.Sensor{
	"syscall":    func() core.Sensor { return sensors.NewSyscallSensor() },
	"process":    func() core.Sensor { return GetProcessSensor() },
	"filesystem": func() core.Sensor { return sensors.NewFilesystemSensor() },
	"network":    func() core.Sensor { return sensors.NewNetworkSensor() },
	"memory":     func() core.Sensor { return sensors.NewMemorySensor() },
	"module":     func() core.Sensor { return sensors.NewModuleSensor() },
	"dns":        func() core.Sensor { return sensors.NewDnsSensor() },
}

// SensorRegistry is a package-level alias for Registry.
var SensorRegistry = Registry

// AllSensorNames returns the sorted names of all registered sensors.
func AllSensorNames() []string {
	names := make([]string, 0, len(Registry))
	for name := range Registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// GetProcessSensor returns either the eBPF version (if root and eBPF loads
// successfully) or the fallback /proc-based version. If eBPF initialization
// fails at Start() time, it automatically degrades to the fallback sensor.
func GetProcessSensor() core.Sensor {
	if os.Getuid() == 0 && os.Getenv("FORCE_FALLBACK") == "" {
		return &ebpfWithFallback{
			ebpf:     sensors.NewProcessSensorEBPF(),
			fallback: sensors.NewProcessSensor(),
		}
	}
	return sensors.NewProcessSensor()
}

// ebpfWithFallback wraps an eBPF sensor and a fallback sensor. If the eBPF
// sensor fails to start (Started() returns false after Start()), it
// transparently delegates all operations to the fallback.
type ebpfWithFallback struct {
	ebpf     core.Sensor
	fallback core.Sensor
	mu       sync.RWMutex
	active   core.Sensor
}

func (s *ebpfWithFallback) Name() string {
	s.mu.RLock()
	a := s.active
	s.mu.RUnlock()
	if a != nil {
		return a.Name()
	}
	return s.ebpf.Name()
}

func (s *ebpfWithFallback) Start(filters *core.SensorFilter) {
	s.ebpf.Start(filters)
	if s.ebpf.Started() {
		s.mu.Lock()
		s.active = s.ebpf
		s.mu.Unlock()
	} else {
		fmt.Fprintf(os.Stderr, "[sensor] eBPF %s failed to load, falling back to /proc\n", s.ebpf.Name())
		s.fallback.Start(filters)
		s.mu.Lock()
		s.active = s.fallback
		s.mu.Unlock()
	}
}

func (s *ebpfWithFallback) Stop() {
	s.mu.RLock()
	a := s.active
	s.mu.RUnlock()
	if a != nil {
		a.Stop()
	}
}

func (s *ebpfWithFallback) Poll() []core.Event {
	s.mu.RLock()
	a := s.active
	s.mu.RUnlock()
	if a != nil {
		return a.Poll()
	}
	return nil
}

func (s *ebpfWithFallback) Mode() string {
	s.mu.RLock()
	a := s.active
	s.mu.RUnlock()
	if a != nil {
		return a.Mode()
	}
	return "fallback"
}

func (s *ebpfWithFallback) Started() bool {
	s.mu.RLock()
	a := s.active
	s.mu.RUnlock()
	if a != nil {
		return a.Started()
	}
	return false
}

func (s *ebpfWithFallback) Health() core.SensorHealth {
	s.mu.RLock()
	a := s.active
	s.mu.RUnlock()
	if a != nil {
		return a.Health()
	}
	return core.SensorHealth{Name: s.ebpf.Name()}
}

// SelectSensors instantiates the sensors identified by name.
// A nil slice returns all registered sensors. "all" expands to all registered sensors.
func SelectSensors(names []string) ([]core.Sensor, error) {
	var active []core.Sensor

	if names == nil {
		for _, constructor := range Registry {
			active = append(active, constructor())
		}
		return active, nil
	}

	if len(names) == 1 && names[0] == "all" {
		for _, constructor := range Registry {
			active = append(active, constructor())
		}
		return active, nil
	}

	for _, name := range names {
		if constructor, ok := Registry[name]; ok {
			active = append(active, constructor())
		} else {
			return nil, fmt.Errorf("unknown sensor: %s", name)
		}
	}

	return active, nil
}
