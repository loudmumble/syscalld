package guest

import (
	"fmt"
	"os"
	"sort"

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

// GetProcessSensor returns either the eBPF version (if root) or the fallback version.
func GetProcessSensor() core.Sensor {
	if os.Getuid() == 0 && os.Getenv("FORCE_FALLBACK") == "" {
		return sensors.NewProcessSensorEBPF()
	}
	return sensors.NewProcessSensor()
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
