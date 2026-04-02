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

// FilesystemSensor traces filesystem operations using kprobes on VFS functions.
// In fallback mode, it monitors file descriptor associations system-wide by
// diffing /proc/[pid]/fd across all processes, emitting a FileEvent for each
// newly observed open file path. This correctly captures cross-process activity
// rather than only the sensor process's own file descriptors.
type FilesystemSensor struct {
	*BaseSensor
	knownFiles map[string]struct{} // key: "pid:path"
}

// NewFilesystemSensor creates a new FilesystemSensor.
func NewFilesystemSensor() *FilesystemSensor {
	s := &FilesystemSensor{
		BaseSensor: NewBaseSensor("filesystem"),
		knownFiles: make(map[string]struct{}),
	}
	s.BPFProgram = s.bpfProgram
	s.PollFallback = s.pollFallback
	return s
}

func (s *FilesystemSensor) bpfProgram(filters *core.SensorFilter) string {
	defines := filters.ToBPFDefines()
	outputMacro := PerfOutputMacro("events", 24)
	submitCode := SubmitEventCode("events", "ctx")

	return fmt.Sprintf(`%s
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/dcache.h>

struct file_data_t {
    u64 timestamp;
    u32 pid;
    u32 tid;
    u32 uid;
    u32 flags;
    u32 mode;
    int operation;  // 1=open, 2=write, 3=unlink
    char comm[16];
    char path[256];
};

%s

static __always_inline int trace_file_op(struct pt_regs *ctx, int op) {
    struct file_data_t data = {};
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
    data.operation = op;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    %s
    return 0;
}

int trace_vfs_open(struct pt_regs *ctx) {
    return trace_file_op(ctx, 1);
}

int trace_vfs_write(struct pt_regs *ctx) {
    return trace_file_op(ctx, 2);
}

int trace_vfs_unlink(struct pt_regs *ctx) {
    return trace_file_op(ctx, 3);
}
`, defines, outputMacro, submitCode)
}

// pollFallback scans /proc/[pid]/fd for up to 30 processes, detecting newly
// opened files by diffing against the prior snapshot. A FileEvent is emitted
// for each fd symlink that was not seen in the previous poll cycle.
//
// Only regular filesystem paths are reported; sockets, pipes, /proc/, /dev/,
// and /sys/ entries are filtered to reduce noise.
func (s *FilesystemSensor) pollFallback() []core.Event {
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

		fdDir := filepath.Join(pidDir, "fd")
		entries, err := os.ReadDir(fdDir)
		if err != nil {
			// Process may have exited or we lack permissions — don't count toward limit.
			continue
		}

		scanned++ // Count only successfully read processes toward the limit.

		fdLimit := 20
		if len(entries) < fdLimit {
			fdLimit = len(entries)
		}

		for _, entry := range entries[:fdLimit] {
			link, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
			if err != nil {
				continue
			}

			// Skip non-filesystem paths (sockets, pipes, anon_inode:*, etc.)
			if !strings.HasPrefix(link, "/") ||
				strings.HasPrefix(link, "/proc/") ||
				strings.HasPrefix(link, "/dev/") ||
				strings.HasPrefix(link, "/sys/") {
				continue
			}

			key := fmt.Sprintf("%d:%s", pid, link)
			current[key] = struct{}{}

			if _, known := s.knownFiles[key]; !known {
				comm := readProcComm(pidDir)
				evt := &core.FileEvent{
					KernelEvent: core.KernelEvent{
						Timestamp: now,
						PID:       pid,
						Comm:      comm,
						EventType: "file",
					},
					Operation: "open",
					Path:      link,
				}
				events = append(events, evt)
			}
		}
	}

	s.knownFiles = current
	return events
}
