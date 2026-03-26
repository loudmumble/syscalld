package sensors

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/loudmumble/syscalld/core"
)

// SyscallSensor traces system calls using raw_syscalls/sys_enter and sys_exit tracepoints.
// In fallback mode, reads /proc/[pid]/syscall for a snapshot of current in-flight syscalls.
type SyscallSensor struct {
	*BaseSensor
}

// NewSyscallSensor creates a new SyscallSensor.
func NewSyscallSensor() *SyscallSensor {
	s := &SyscallSensor{
		BaseSensor: NewBaseSensor("syscall"),
	}
	s.BPFProgram = s.bpfProgram
	s.PollFallback = s.pollFallback
	return s
}

func (s *SyscallSensor) bpfProgram(filters *core.SensorFilter) string {
	defines := filters.ToBPFDefines()
	outputMacro := PerfOutputMacro("events", 24)
	submitEnter := SubmitEventCode("events", "args")
	submitExit := SubmitEventCode("events", "args")

	return fmt.Sprintf(`%s
#include <uapi/linux/ptrace.h>

struct syscall_data_t {
    u64 timestamp;
    u32 pid;
    u32 tid;
    u32 uid;
    u32 syscall_nr;
    u64 args[6];
    long ret;
    u8 phase;  // 0 = enter, 1 = exit
    char comm[16];
};

%s

// Map to store enter-phase data keyed by tid for matching with exit
BPF_HASH(active_syscalls, u64, u32);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    struct syscall_data_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    #ifdef FILTER_PID_ENABLED
      #ifdef FILTER_PID
        if (pid != FILTER_PID) return 0;
      #endif
    #endif

    data.timestamp = bpf_ktime_get_ns();
    data.pid = pid;
    data.tid = tid;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.syscall_nr = args->id;
    data.phase = 0;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    data.args[0] = args->args[0];
    data.args[1] = args->args[1];
    data.args[2] = args->args[2];
    data.args[3] = args->args[3];
    data.args[4] = args->args[4];
    data.args[5] = args->args[5];

    // Store syscall nr for exit matching
    u32 nr = args->id;
    active_syscalls.update(&pid_tgid, &nr);

    %s
    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    struct syscall_data_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    #ifdef FILTER_PID_ENABLED
      #ifdef FILTER_PID
        if (pid != FILTER_PID) return 0;
      #endif
    #endif

    // Look up what syscall this exit corresponds to
    u32 *nr_ptr = active_syscalls.lookup(&pid_tgid);
    if (!nr_ptr) return 0;

    data.timestamp = bpf_ktime_get_ns();
    data.pid = pid;
    data.tid = tid;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.syscall_nr = *nr_ptr;
    data.ret = args->ret;
    data.phase = 1;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    active_syscalls.delete(&pid_tgid);

    %s
    return 0;
}
`, defines, outputMacro, submitEnter, submitExit)
}

func (s *SyscallSensor) pollFallback() []core.Event {
	var events []core.Event
	now := float64(time.Now().UnixNano()) / 1e9

	matches, _ := filepath.Glob("/proc/[0-9]*")
	limit := 50
	if len(matches) < limit {
		limit = len(matches)
	}

	for _, pidDir := range matches[:limit] {
		pid, err := strconv.Atoi(filepath.Base(pidDir))
		if err != nil {
			continue
		}

		syscallPath := filepath.Join(pidDir, "syscall")
		f, err := os.Open(syscallPath)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(f)
		if !scanner.Scan() {
			f.Close()
			continue
		}
		content := strings.TrimSpace(scanner.Text())
		f.Close()

		parts := strings.Fields(content)
		if len(parts) == 0 || parts[0] == "running" {
			continue
		}

		nr, err := strconv.Atoi(parts[0])
		if err != nil || nr < 0 {
			continue
		}

		// Read comm
		comm := ""
		if commData, err := os.ReadFile(filepath.Join(pidDir, "comm")); err == nil {
			comm = strings.TrimSpace(string(commData))
			if len(comm) > 16 {
				comm = comm[:16]
			}
		}

		var intArgs []int
		for _, argStr := range parts[1:7] {
			v, err := strconv.ParseInt(argStr, 16, 64)
			if err != nil {
				break
			}
			intArgs = append(intArgs, int(v))
		}

		evt := &core.SyscallEvent{
			KernelEvent: core.KernelEvent{
				Timestamp: now,
				PID:       pid,
				Comm:      comm,
				EventType: "syscall",
			},
			SyscallNR:   nr,
			SyscallName: core.SecuritySyscalls[nr],
			Args:        intArgs,
			Phase:       "enter",
		}
		events = append(events, evt)
	}

	return events
}
