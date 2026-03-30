package core

import (
	"fmt"
	"strings"
)

// SensorFilter provides compile-time and runtime filter configuration for sensors.
// It generates C #define macros for BPF programs and provides runtime match methods
// for fallback/Python-side filtering.
type SensorFilter struct {
	// TargetPIDs filters to only trace these PIDs (empty = all).
	TargetPIDs map[int]struct{}
	// TargetPIDNS filters by PID namespace inode number. Nil means no filter.
	TargetPIDNS *int
	// TargetCgroup filters by cgroup v2 path. Empty means no filter.
	TargetCgroup string
	// SyscallWhitelist only captures these syscall numbers (empty = all).
	SyscallWhitelist map[int]struct{}
	// ExcludeComms skips events from these process names.
	ExcludeComms map[string]struct{}
}

// NewSensorFilter creates a SensorFilter with empty/nil defaults.
func NewSensorFilter() *SensorFilter {
	return &SensorFilter{
		TargetPIDs:       make(map[int]struct{}),
		SyscallWhitelist: make(map[int]struct{}),
		ExcludeComms:     make(map[string]struct{}),
	}
}

// ToBPFDefines generates C #define statements for BPF program filtering.
// Returns a string of C preprocessor directives to prepend to BPF source.
func (f *SensorFilter) ToBPFDefines() string {
	var lines []string

	if len(f.TargetPIDs) > 0 {
		lines = append(lines, "#define FILTER_PID_ENABLED 1")
		if len(f.TargetPIDs) == 1 {
			for pid := range f.TargetPIDs {
				lines = append(lines, fmt.Sprintf("#define FILTER_PID %d", pid))
			}
		} else {
			lines = append(lines, fmt.Sprintf("#define FILTER_PID_COUNT %d", len(f.TargetPIDs)))
		}
	}

	if f.TargetPIDNS != nil {
		lines = append(lines, "#define FILTER_PID_NS_ENABLED 1")
		lines = append(lines, fmt.Sprintf("#define FILTER_PID_NS %d", *f.TargetPIDNS))
	}

	if f.TargetCgroup != "" {
		lines = append(lines, "#define FILTER_CGROUP_ENABLED 1")
	}

	if len(f.SyscallWhitelist) > 0 {
		lines = append(lines, "#define FILTER_SYSCALL_ENABLED 1")
		lines = append(lines, fmt.Sprintf("#define FILTER_SYSCALL_COUNT %d", len(f.SyscallWhitelist)))
	}

	if len(f.ExcludeComms) > 0 {
		lines = append(lines, "#define FILTER_EXCLUDE_COMM_ENABLED 1")
		lines = append(lines, fmt.Sprintf("#define FILTER_EXCLUDE_COMM_COUNT %d", len(f.ExcludeComms)))
	}

	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

// MatchesPID checks if a PID passes the filter (for fallback/runtime filtering).
func (f *SensorFilter) MatchesPID(pid int) bool {
	if len(f.TargetPIDs) == 0 {
		return true
	}
	_, ok := f.TargetPIDs[pid]
	return ok
}

// MatchesComm checks if a comm name passes the filter (not in exclude list).
func (f *SensorFilter) MatchesComm(comm string) bool {
	if len(f.ExcludeComms) == 0 {
		return true
	}
	_, excluded := f.ExcludeComms[comm]
	return !excluded
}

// MatchesSyscall checks if a syscall number passes the whitelist filter.
func (f *SensorFilter) MatchesSyscall(syscallNR int) bool {
	if len(f.SyscallWhitelist) == 0 {
		return true
	}
	_, ok := f.SyscallWhitelist[syscallNR]
	return ok
}
