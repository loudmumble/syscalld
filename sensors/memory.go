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

// MemorySensor traces memory mapping and protection operations.
// In fallback mode, it scans /proc/[pid]/maps system-wide to detect newly
// appearing anonymous executable memory regions — a high-confidence indicator
// of process injection or fileless code execution.
//
// Two categories are tracked:
//   - "mmap_exec_anon":  executable mapping with no backing file (device 00:00,
//     inode 0, no name). Indicates injected shellcode or JIT-compiled code.
//   - "mmap_exec_memfd": executable mapping backed by a memfd (path starts with
//     "/memfd:"). This is the VoidLink fileless execution fingerprint —
//     memfd_create() → write payload → mmap(PROT_EXEC) → execveat(AT_EMPTY_PATH).
type MemorySensor struct {
	*BaseSensor
	knownRegions map[string]struct{} // key: "pid:0x<addr_start>"
}

// NewMemorySensor creates a new MemorySensor.
func NewMemorySensor() *MemorySensor {
	s := &MemorySensor{
		BaseSensor:   NewBaseSensor("memory"),
		knownRegions: make(map[string]struct{}),
	}
	s.BPFProgram = s.bpfProgram
	s.PollFallback = s.pollFallback
	return s
}

func (s *MemorySensor) bpfProgram(filters *core.SensorFilter) string {
	defines := filters.ToBPFDefines()
	outputMacro := PerfOutputMacro("events", 24)
	submitCode := SubmitEventCode("events", "ctx")

	return fmt.Sprintf(`%s
#include <uapi/linux/ptrace.h>
#include <linux/mm.h>

struct mem_data_t {
    u64 timestamp;
    u32 pid;
    u32 tid;
    u32 uid;
    int operation;  // 1=mmap, 2=mprotect, 3=memfd_create
    u64 addr;
    u64 length;
    u32 prot;
    u32 flags;
    int fd;
    char comm[16];
    char memfd_name[64];
};

%s

int trace_do_mmap(struct pt_regs *ctx) {
    struct mem_data_t data = {};
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

    data.addr = PT_REGS_PARM2(ctx);
    data.length = PT_REGS_PARM3(ctx);
    data.prot = (u32)PT_REGS_PARM4(ctx);
    data.flags = (u32)PT_REGS_PARM5(ctx);

    %s
    return 0;
}

int trace_do_mprotect(struct pt_regs *ctx) {
    struct mem_data_t data = {};
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
    data.operation = 2;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    data.addr = PT_REGS_PARM1(ctx);
    data.length = PT_REGS_PARM2(ctx);
    data.prot = (u32)PT_REGS_PARM3(ctx);

    %s
    return 0;
}

int trace_memfd_create(struct pt_regs *ctx) {
    struct mem_data_t data = {};
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
    data.operation = 3;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    const char *name = (const char *)PT_REGS_PARM1(ctx);
    bpf_probe_read_str(&data.memfd_name, sizeof(data.memfd_name), name);
    data.flags = (u32)PT_REGS_PARM2(ctx);

    %s
    return 0;
}
`, defines, outputMacro, submitCode, submitCode, submitCode)
}

// pollFallback scans /proc/[pid]/maps across up to 30 processes, looking for
// newly appearing anonymous or memfd-backed executable memory regions.
// New regions are emitted as MemoryEvents and tracked to avoid re-emission.
func (s *MemorySensor) pollFallback() []core.Event {
	var events []core.Event
	now := float64(time.Now().UnixNano()) / 1e9

	matches, _ := filepath.Glob("/proc/[0-9]*")
	scanned := 0
	maxScanned := 200

	current := make(map[string]struct{})
	for _, pidDir := range matches {
		if scanned >= maxScanned {
			break
		}

		pid, err := strconv.Atoi(filepath.Base(pidDir))
		if err != nil {
			continue
		}

		// Check readability before counting toward limit.
		if _, err := os.Stat(filepath.Join(pidDir, "maps")); err != nil {
			continue
		}
		scanned++

		s.scanPIDMaps(pidDir, pid, now, current, &events)
	}

	s.knownRegions = current
	return events
}

// scanPIDMaps reads /proc/[pid]/maps for a single process, extracting
// executable anonymous and memfd-backed regions into the current map
// and appending new events. File handle is closed via defer.
func (s *MemorySensor) scanPIDMaps(pidDir string, pid int, now float64, current map[string]struct{}, events *[]core.Event) {
	f, err := os.Open(filepath.Join(pidDir, "maps"))
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}

		perms := parts[1]
		if !strings.Contains(perms, "x") {
			continue
		}

		device := parts[3]
		inode := parts[4]
		var mapName string
		if len(parts) >= 6 {
			mapName = parts[5]
		}

		isAnon := device == "00:00" && inode == "0" && mapName == ""
		isMemFD := strings.HasPrefix(mapName, "/memfd:")

		isKernelAnon := mapName == "[vdso]" || mapName == "[vsyscall]" ||
			mapName == "[heap]" || mapName == "[stack]" ||
			strings.HasPrefix(mapName, "[anon:") ||
			strings.HasPrefix(mapName, "[stack:")

		if (!isAnon && !isMemFD) || isKernelAnon {
			continue
		}

		addrRange := strings.SplitN(parts[0], "-", 2)
		if len(addrRange) != 2 {
			continue
		}
		start, err := strconv.ParseUint(addrRange[0], 16, 64)
		if err != nil {
			continue
		}
		end, err := strconv.ParseUint(addrRange[1], 16, 64)
		if err != nil {
			continue
		}
		if end <= start {
			continue
		}

		key := fmt.Sprintf("%d:0x%x", pid, start)
		current[key] = struct{}{}

		if _, known := s.knownRegions[key]; !known {
			prot := 0
			if strings.Contains(perms, "r") {
				prot |= 1 // PROT_READ
			}
			if strings.Contains(perms, "w") {
				prot |= 2 // PROT_WRITE
			}
			if strings.Contains(perms, "x") {
				prot |= 4 // PROT_EXEC
			}

			operation := "mmap_exec_anon"
			if isMemFD {
				operation = "mmap_exec_memfd"
			}

			comm := readProcComm(pidDir)
			evt := &core.MemoryEvent{
				KernelEvent: core.KernelEvent{
					Timestamp: now,
					PID:       pid,
					Comm:      comm,
					EventType: "memory",
				},
				Operation: operation,
				Addr:      start,
				Length:    int(end - start),
				Prot:      prot,
				MemFDName: mapName,
			}
			*events = append(*events, evt)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "[MemorySensor] scanner error reading %s/maps: %v\n", pidDir, err)
	}
}
