package sensors

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/loudmumble/syscalld/core"
)

// ProcessSensor traces process creation, execution, and termination.
// In fallback mode, scans /proc with diff-based new/exited process detection.
type ProcessSensor struct {
	*BaseSensor
	knownPIDs map[int]procInfo
}

type procInfo struct {
	PID     int
	PPID    int
	UID     int
	Comm    string
	Cmdline string
}

// NewProcessSensor creates a new ProcessSensor.
func NewProcessSensor() *ProcessSensor {
	s := &ProcessSensor{
		BaseSensor: NewBaseSensor("process"),
		knownPIDs:  make(map[int]procInfo),
	}
	s.BPFProgram = s.bpfProgram
	s.PollFallback = s.pollFallback
	s.OnStart = s.onStart
	return s
}

func (s *ProcessSensor) onStart(filters *core.SensorFilter) {
	s.knownPIDs = scanProc()
}

func (s *ProcessSensor) bpfProgram(filters *core.SensorFilter) string {
	defines := filters.ToBPFDefines()
	outputMacro := PerfOutputMacro("events", 24)
	submitCode := SubmitEventCode("events", "args")

	return fmt.Sprintf(`%s
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct proc_data_t {
    u64 timestamp;
    u32 pid;
    u32 tid;
    u32 uid;
    u32 ppid;
    int action;  // 1=exec, 2=fork, 3=exit
    int exit_code;
    char comm[16];
    char filename[256];
};

%s

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct proc_data_t data = {};
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
    data.ppid = args->old_pid;
    data.action = 1;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_str(&data.filename, sizeof(data.filename), args->filename);

    %s
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_fork) {
    struct proc_data_t data = {};

    data.timestamp = bpf_ktime_get_ns();
    data.pid = args->child_pid;
    data.ppid = args->parent_pid;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.action = 2;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    #ifdef FILTER_PID_ENABLED
      #ifdef FILTER_PID
        if (data.ppid != FILTER_PID && data.pid != FILTER_PID) return 0;
      #endif
    #endif

    %s
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    struct proc_data_t data = {};
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
    data.action = 3;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.exit_code = 0;

    %s
    return 0;
}
`, defines, outputMacro, submitCode, submitCode, submitCode)
}

func (s *ProcessSensor) pollFallback() []core.Event {
	currentPIDs := scanProc()
	var events []core.Event
	now := float64(time.Now().UnixNano()) / 1e9

	// Detect new processes
	for pid, info := range currentPIDs {
		if _, known := s.knownPIDs[pid]; !known {
			filename := ""
			var argv []string
			if info.Cmdline != "" {
				parts := strings.Fields(info.Cmdline)
				filename = parts[0]
				argv = parts
			}
			evt := &core.ProcessEvent{
				KernelEvent: core.KernelEvent{
					Timestamp: now,
					PID:       pid,
					UID:       info.UID,
					Comm:      info.Comm,
					EventType: "process",
				},
				Action:   "exec",
				PPID:     info.PPID,
				Filename: filename,
				Argv:     argv,
			}
			events = append(events, evt)
		}
	}

	// Detect exited processes
	for pid, info := range s.knownPIDs {
		if _, exists := currentPIDs[pid]; !exists {
			evt := &core.ProcessEvent{
				KernelEvent: core.KernelEvent{
					Timestamp: now,
					PID:       pid,
					UID:       info.UID,
					Comm:      info.Comm,
					EventType: "process",
				},
				Action: "exit",
				PPID:   info.PPID,
				Argv:   []string{},
			}
			events = append(events, evt)
		}
	}

	s.knownPIDs = currentPIDs
	return events
}

func scanProc() map[int]procInfo {
	pids := make(map[int]procInfo)
	matches, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		return pids
	}

	// Cap scanned processes to prevent unbounded memory allocation.
	limit := 500
	if len(matches) < limit {
		limit = len(matches)
	}

	for _, pidDir := range matches[:limit] {
		pid, err := strconv.Atoi(filepath.Base(pidDir))
		if err != nil {
			continue
		}

		info := procInfo{PID: pid}

		// Read status
		statusData, err := os.ReadFile(filepath.Join(pidDir, "status"))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(statusData), "\n") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := parts[0]
			val := strings.TrimSpace(parts[1])
			switch key {
			case "Name":
				info.Comm = val
			case "PPid":
				info.PPID, _ = strconv.Atoi(val)
			case "Uid":
				fields := strings.Fields(val)
				if len(fields) > 0 {
					info.UID, _ = strconv.Atoi(fields[0])
				}
			}
		}

		// Read cmdline
		if cmdlineData, err := os.ReadFile(filepath.Join(pidDir, "cmdline")); err == nil {
			info.Cmdline = strings.TrimSpace(strings.ReplaceAll(string(cmdlineData), "\x00", " "))
		}

		pids[pid] = info
	}

	return pids
}
