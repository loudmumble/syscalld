package sensors

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/loudmumble/syscalld/core"
)

// ModuleSensor traces kernel module load events.
// In fallback mode, reads /proc/modules and detects newly loaded modules.
type ModuleSensor struct {
	*BaseSensor
	knownModules map[string]struct{}
}

// NewModuleSensor creates a new ModuleSensor.
func NewModuleSensor() *ModuleSensor {
	s := &ModuleSensor{
		BaseSensor:   NewBaseSensor("module"),
		knownModules: make(map[string]struct{}),
	}
	s.BPFProgram = s.bpfProgram
	s.PollFallback = s.pollFallback
	s.OnStart = s.onStart
	return s
}

func (s *ModuleSensor) onStart(filters *core.SensorFilter) {
	s.knownModules = readModules()
}

func (s *ModuleSensor) bpfProgram(filters *core.SensorFilter) string {
	defines := filters.ToBPFDefines()
	outputMacro := PerfOutputMacro("events", 24)
	submitCode := SubmitEventCode("events", "ctx")

	return fmt.Sprintf(`%s
#include <uapi/linux/ptrace.h>
#include <linux/module.h>

struct mod_data_t {
    u64 timestamp;
    u32 pid;
    u32 tid;
    u32 uid;
    int operation;  // 1=load
    char comm[16];
    char module_name[64];
};

%s

int trace_do_init_module(struct pt_regs *ctx, struct module *mod) {
    struct mod_data_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    #ifdef FILTER_PID_ENABLED
      #ifdef FILTER_PID
        if (pid != FILTER_PID) return 0;
      #endif
    #endif

    data.timestamp = bpf_ktime_get_ns();
    data.pid = pid;
    data.tid = (u32)pid_tgid;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.operation = 1;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_str(&data.module_name, sizeof(data.module_name), mod->name);

    %s
    return 0;
}
`, defines, outputMacro, submitCode)
}

func (s *ModuleSensor) pollFallback() []core.Event {
	var events []core.Event
	now := float64(time.Now().UnixNano()) / 1e9

	currentModules := readModules()
	for mod := range currentModules {
		if _, known := s.knownModules[mod]; !known {
			evt := &core.ModuleEvent{
				KernelEvent: core.KernelEvent{
					Timestamp: now,
					EventType: "module",
				},
				Operation:  "load",
				ModuleName: mod,
			}
			events = append(events, evt)
		}
	}
	s.knownModules = currentModules

	return events
}

func readModules() map[string]struct{} {
	modules := make(map[string]struct{})
	f, err := os.Open("/proc/modules")
	if err != nil {
		return modules
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) > 0 {
			modules[parts[0]] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "[ModuleSensor] scanner error reading /proc/modules: %v\n", err)
	}
	return modules
}
