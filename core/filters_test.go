package core

import (
	"strings"
	"testing"
)

func TestEmptyFilter(t *testing.T) {
	f := NewSensorFilter()
	if len(f.TargetPIDs) != 0 {
		t.Error("expected empty TargetPIDs")
	}
	if f.TargetPIDNS != nil {
		t.Error("expected nil TargetPIDNS")
	}
	if f.TargetCgroup != "" {
		t.Error("expected empty TargetCgroup")
	}
	if len(f.SyscallWhitelist) != 0 {
		t.Error("expected empty SyscallWhitelist")
	}
	if len(f.ExcludeComms) != 0 {
		t.Error("expected empty ExcludeComms")
	}
}

func TestEmptyFilterProducesNoDefines(t *testing.T) {
	f := NewSensorFilter()
	if f.ToBPFDefines() != "" {
		t.Errorf("expected empty, got %q", f.ToBPFDefines())
	}
}

func TestSinglePID(t *testing.T) {
	f := NewSensorFilter()
	f.TargetPIDs[1234] = struct{}{}
	defines := f.ToBPFDefines()
	if !strings.Contains(defines, "#define FILTER_PID_ENABLED 1") {
		t.Error("missing FILTER_PID_ENABLED")
	}
	if !strings.Contains(defines, "#define FILTER_PID 1234") {
		t.Error("missing FILTER_PID 1234")
	}
}

func TestMultiplePIDs(t *testing.T) {
	f := NewSensorFilter()
	f.TargetPIDs[100] = struct{}{}
	f.TargetPIDs[200] = struct{}{}
	f.TargetPIDs[300] = struct{}{}
	defines := f.ToBPFDefines()
	if !strings.Contains(defines, "#define FILTER_PID_ENABLED 1") {
		t.Error("missing FILTER_PID_ENABLED")
	}
	if !strings.Contains(defines, "#define FILTER_PID_COUNT 3") {
		t.Error("missing FILTER_PID_COUNT 3")
	}
}

func TestMatchesPIDEmpty(t *testing.T) {
	f := NewSensorFilter()
	if !f.MatchesPID(100) {
		t.Error("expected true for 100")
	}
	if !f.MatchesPID(0) {
		t.Error("expected true for 0")
	}
}

func TestMatchesPIDSet(t *testing.T) {
	f := NewSensorFilter()
	f.TargetPIDs[100] = struct{}{}
	f.TargetPIDs[200] = struct{}{}
	if !f.MatchesPID(100) {
		t.Error("expected true for 100")
	}
	if !f.MatchesPID(200) {
		t.Error("expected true for 200")
	}
	if f.MatchesPID(300) {
		t.Error("expected false for 300")
	}
}

func TestPIDNSFilter(t *testing.T) {
	pidns := 4026531836
	f := NewSensorFilter()
	f.TargetPIDNS = &pidns
	defines := f.ToBPFDefines()
	if !strings.Contains(defines, "#define FILTER_PID_NS_ENABLED 1") {
		t.Error("missing FILTER_PID_NS_ENABLED")
	}
	if !strings.Contains(defines, "#define FILTER_PID_NS 4026531836") {
		t.Error("missing FILTER_PID_NS value")
	}
}

func TestNoPIDNS(t *testing.T) {
	f := NewSensorFilter()
	if strings.Contains(f.ToBPFDefines(), "FILTER_PID_NS") {
		t.Error("should not contain FILTER_PID_NS")
	}
}

func TestCgroupFilter(t *testing.T) {
	f := NewSensorFilter()
	f.TargetCgroup = "/sys/fs/cgroup/sandbox"
	defines := f.ToBPFDefines()
	if !strings.Contains(defines, "#define FILTER_CGROUP_ENABLED 1") {
		t.Error("missing FILTER_CGROUP_ENABLED")
	}
}

func TestNoCgroup(t *testing.T) {
	f := NewSensorFilter()
	if strings.Contains(f.ToBPFDefines(), "FILTER_CGROUP") {
		t.Error("should not contain FILTER_CGROUP")
	}
}

func TestSyscallWhitelist(t *testing.T) {
	f := NewSensorFilter()
	f.SyscallWhitelist[59] = struct{}{}
	f.SyscallWhitelist[42] = struct{}{}
	f.SyscallWhitelist[9] = struct{}{}
	defines := f.ToBPFDefines()
	if !strings.Contains(defines, "#define FILTER_SYSCALL_ENABLED 1") {
		t.Error("missing FILTER_SYSCALL_ENABLED")
	}
	if !strings.Contains(defines, "#define FILTER_SYSCALL_COUNT 3") {
		t.Error("missing FILTER_SYSCALL_COUNT 3")
	}
}

func TestMatchesSyscallEmpty(t *testing.T) {
	f := NewSensorFilter()
	if !f.MatchesSyscall(59) {
		t.Error("expected true for 59")
	}
	if !f.MatchesSyscall(0) {
		t.Error("expected true for 0")
	}
}

func TestMatchesSyscallWhitelist(t *testing.T) {
	f := NewSensorFilter()
	f.SyscallWhitelist[59] = struct{}{}
	f.SyscallWhitelist[42] = struct{}{}
	if !f.MatchesSyscall(59) {
		t.Error("expected true for 59")
	}
	if !f.MatchesSyscall(42) {
		t.Error("expected true for 42")
	}
	if f.MatchesSyscall(10) {
		t.Error("expected false for 10")
	}
}

func TestExcludeComms(t *testing.T) {
	f := NewSensorFilter()
	f.ExcludeComms["sshd"] = struct{}{}
	f.ExcludeComms["systemd"] = struct{}{}
	defines := f.ToBPFDefines()
	if !strings.Contains(defines, "#define FILTER_EXCLUDE_COMM_ENABLED 1") {
		t.Error("missing FILTER_EXCLUDE_COMM_ENABLED")
	}
	if !strings.Contains(defines, "#define FILTER_EXCLUDE_COMM_COUNT 2") {
		t.Error("missing FILTER_EXCLUDE_COMM_COUNT 2")
	}
}

func TestMatchesCommEmpty(t *testing.T) {
	f := NewSensorFilter()
	if !f.MatchesComm("anything") {
		t.Error("expected true")
	}
}

func TestMatchesCommExcluded(t *testing.T) {
	f := NewSensorFilter()
	f.ExcludeComms["sshd"] = struct{}{}
	f.ExcludeComms["systemd"] = struct{}{}
	if f.MatchesComm("sshd") {
		t.Error("expected false for sshd")
	}
	if f.MatchesComm("systemd") {
		t.Error("expected false for systemd")
	}
	if !f.MatchesComm("bash") {
		t.Error("expected true for bash")
	}
}

func TestAllFilters(t *testing.T) {
	pidns := 123456
	f := NewSensorFilter()
	f.TargetPIDs[100] = struct{}{}
	f.TargetPIDNS = &pidns
	f.TargetCgroup = "/cgroup"
	f.SyscallWhitelist[59] = struct{}{}
	f.ExcludeComms["sshd"] = struct{}{}
	defines := f.ToBPFDefines()
	if !strings.Contains(defines, "#define FILTER_PID_ENABLED 1") {
		t.Error("missing FILTER_PID_ENABLED")
	}
	if !strings.Contains(defines, "#define FILTER_PID_NS_ENABLED 1") {
		t.Error("missing FILTER_PID_NS_ENABLED")
	}
	if !strings.Contains(defines, "#define FILTER_CGROUP_ENABLED 1") {
		t.Error("missing FILTER_CGROUP_ENABLED")
	}
	if !strings.Contains(defines, "#define FILTER_SYSCALL_ENABLED 1") {
		t.Error("missing FILTER_SYSCALL_ENABLED")
	}
	if !strings.Contains(defines, "#define FILTER_EXCLUDE_COMM_ENABLED 1") {
		t.Error("missing FILTER_EXCLUDE_COMM_ENABLED")
	}
}

func TestDefinesEndWithNewline(t *testing.T) {
	f := NewSensorFilter()
	f.TargetPIDs[1] = struct{}{}
	defines := f.ToBPFDefines()
	if !strings.HasSuffix(defines, "\n") {
		t.Error("defines should end with newline")
	}
}

func TestIndependentInstances(t *testing.T) {
	f1 := NewSensorFilter()
	f2 := NewSensorFilter()
	f1.TargetPIDs[1] = struct{}{}
	if _, ok := f2.TargetPIDs[1]; ok {
		t.Error("f2 should not have PID 1")
	}
}
