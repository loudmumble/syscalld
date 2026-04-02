package core

import (
	"testing"
)

// ---------------------------------------------------------------------------
// KernelEvent base
// ---------------------------------------------------------------------------

func TestKernelEventDefaults(t *testing.T) {
	e := &KernelEvent{EventType: "base"}
	if e.Timestamp != 0.0 {
		t.Errorf("expected 0.0, got %f", e.Timestamp)
	}
	if e.PID != 0 {
		t.Errorf("expected 0, got %d", e.PID)
	}
	if e.TID != 0 {
		t.Errorf("expected 0, got %d", e.TID)
	}
	if e.UID != 0 {
		t.Errorf("expected 0, got %d", e.UID)
	}
	if e.Comm != "" {
		t.Errorf("expected empty, got %q", e.Comm)
	}
	if e.EventType != "base" {
		t.Errorf("expected base, got %q", e.EventType)
	}
}

func TestKernelEventCustomValues(t *testing.T) {
	e := &KernelEvent{Timestamp: 1.0, PID: 100, TID: 100, UID: 1000, Comm: "test", EventType: "custom"}
	if e.PID != 100 {
		t.Errorf("expected 100, got %d", e.PID)
	}
	if e.Comm != "test" {
		t.Errorf("expected test, got %q", e.Comm)
	}
	if e.EventType != "custom" {
		t.Errorf("expected custom, got %q", e.EventType)
	}
}

func TestKernelEventToSentinel(t *testing.T) {
	e := &KernelEvent{Timestamp: 1.5, PID: 42, Comm: "bash", EventType: "base"}
	d := e.ToSentinelEvent()
	if d["timestamp"] != 1.5 {
		t.Errorf("expected 1.5, got %v", d["timestamp"])
	}
	if d["type"] != "base" {
		t.Errorf("expected base, got %v", d["type"])
	}
	if d["pid"] != 42 {
		t.Errorf("expected 42, got %v", d["pid"])
	}
	if d["comm"] != "bash" {
		t.Errorf("expected bash, got %v", d["comm"])
	}
}

func TestKernelEventToMalscope(t *testing.T) {
	e := &KernelEvent{Timestamp: 2.0, PID: 99, EventType: "base"}
	d := e.ToMalscopeEvent()
	if d["timestamp"] != 2.0 {
		t.Errorf("expected 2.0, got %v", d["timestamp"])
	}
	if d["event_type"] != "base" {
		t.Errorf("expected base, got %v", d["event_type"])
	}
	if d["pid"] != 99 {
		t.Errorf("expected 99, got %v", d["pid"])
	}
	if _, ok := d["details"].(map[string]interface{}); !ok {
		t.Error("expected details to be map")
	}
}

func TestKernelEventComm16Chars(t *testing.T) {
	e := &KernelEvent{Comm: "aaaaaaaaaaaaaaaa"}
	if len(e.Comm) != 16 {
		t.Errorf("expected 16, got %d", len(e.Comm))
	}
}

// ---------------------------------------------------------------------------
// SyscallEvent
// ---------------------------------------------------------------------------

func TestSyscallEventDefaults(t *testing.T) {
	e := NewSyscallEvent()
	if e.GetEventType() != "syscall" {
		t.Errorf("expected syscall, got %q", e.GetEventType())
	}
	if len(e.Args) != 0 {
		t.Errorf("expected empty args, got %v", e.Args)
	}
	if e.Phase != "enter" {
		t.Errorf("expected enter, got %q", e.Phase)
	}
}

func TestSyscallEventInheritsKernelEvent(t *testing.T) {
	e := NewSyscallEvent()
	e.PID = 1
	e.Comm = "cat"
	var _ Event = e // compile-time check
}

func TestSyscallEventFields(t *testing.T) {
	e := &SyscallEvent{
		KernelEvent: KernelEvent{EventType: "syscall"},
		SyscallNR:   59,
		SyscallName: "execve",
		Args:        []int{1, 2, 3, 4, 5, 6},
		Ret:         0,
		Phase:       "enter",
	}
	if e.SyscallNR != 59 {
		t.Errorf("expected 59, got %d", e.SyscallNR)
	}
	if e.SyscallName != "execve" {
		t.Errorf("expected execve, got %q", e.SyscallName)
	}
	if len(e.Args) != 6 {
		t.Errorf("expected 6 args, got %d", len(e.Args))
	}
	if e.Ret != 0 {
		t.Errorf("expected 0, got %d", e.Ret)
	}
	if e.Phase != "enter" {
		t.Errorf("expected enter, got %q", e.Phase)
	}
}

func TestSyscallEventExitPhase(t *testing.T) {
	e := &SyscallEvent{
		KernelEvent: KernelEvent{EventType: "syscall"},
		Phase:       "exit",
		Ret:         -1,
		Args:        []int{},
	}
	if e.Phase != "exit" {
		t.Errorf("expected exit, got %q", e.Phase)
	}
	if e.Ret != -1 {
		t.Errorf("expected -1, got %d", e.Ret)
	}
}

func TestSyscallEventToSentinel(t *testing.T) {
	e := &SyscallEvent{
		KernelEvent: KernelEvent{Timestamp: 1.0, PID: 10, Comm: "ls", EventType: "syscall"},
		SyscallNR:   59,
		Args:        []int{1, 2, 3},
	}
	d := e.ToSentinelEvent()
	if d["type"] != "syscall" {
		t.Errorf("expected syscall, got %v", d["type"])
	}
	if d["syscall_nr"] != 59 {
		t.Errorf("expected 59, got %v", d["syscall_nr"])
	}
	if d["syscall_name"] != "execve" {
		t.Errorf("expected execve, got %v", d["syscall_name"])
	}
	if d["pid"] != 10 {
		t.Errorf("expected 10, got %v", d["pid"])
	}
	if d["comm"] != "ls" {
		t.Errorf("expected ls, got %v", d["comm"])
	}
}

func TestSyscallEventToSentinelWithName(t *testing.T) {
	e := &SyscallEvent{
		KernelEvent: KernelEvent{EventType: "syscall"},
		SyscallNR:   9,
		SyscallName: "mmap",
		Args:        []int{},
	}
	d := e.ToSentinelEvent()
	if d["syscall_name"] != "mmap" {
		t.Errorf("expected mmap, got %v", d["syscall_name"])
	}
}

func TestSyscallEventToSentinelUnknown(t *testing.T) {
	e := &SyscallEvent{
		KernelEvent: KernelEvent{EventType: "syscall"},
		SyscallNR:   999,
		Args:        []int{},
	}
	d := e.ToSentinelEvent()
	if d["syscall_name"] != "" {
		t.Errorf("expected empty, got %v", d["syscall_name"])
	}
}

func TestSyscallEventToMalscope(t *testing.T) {
	e := &SyscallEvent{
		KernelEvent: KernelEvent{Timestamp: 1.0, PID: 10, Comm: "curl", EventType: "syscall"},
		SyscallNR:   42,
		Ret:         0,
		Args:        []int{3, 4},
	}
	d := e.ToMalscopeEvent()
	if d["syscall_nr"] != 42 {
		t.Errorf("expected 42, got %v", d["syscall_nr"])
	}
	if d["syscall_name"] != "connect" {
		t.Errorf("expected connect, got %v", d["syscall_name"])
	}
	if d["return_value"] != "0" {
		t.Errorf("expected 0, got %v", d["return_value"])
	}
	if d["comm"] != "curl" {
		t.Errorf("expected curl, got %v", d["comm"])
	}
}

func TestSyscallEventDefaultArgsList(t *testing.T) {
	e1 := NewSyscallEvent()
	e2 := NewSyscallEvent()
	if len(e1.Args) != 0 || len(e2.Args) != 0 {
		t.Error("expected empty args")
	}
	// Ensure separate instances
	e1.Args = append(e1.Args, 1)
	if len(e2.Args) != 0 {
		t.Error("args should not be shared")
	}
}

// ---------------------------------------------------------------------------
// ProcessEvent
// ---------------------------------------------------------------------------

func TestProcessEventDefaults(t *testing.T) {
	e := NewProcessEvent()
	if e.GetEventType() != "process" {
		t.Errorf("expected process, got %q", e.GetEventType())
	}
}

func TestProcessEventExec(t *testing.T) {
	e := &ProcessEvent{
		KernelEvent: KernelEvent{PID: 100, UID: 1000, Comm: "python3", EventType: "process"},
		Action:      "exec",
		PPID:        1,
		Filename:    "/usr/bin/python3",
		Argv:        []string{"python3", "test.py"},
	}
	if e.Action != "exec" {
		t.Errorf("expected exec, got %q", e.Action)
	}
	if e.Filename != "/usr/bin/python3" {
		t.Errorf("expected /usr/bin/python3, got %q", e.Filename)
	}
}

func TestProcessEventFork(t *testing.T) {
	e := &ProcessEvent{
		KernelEvent: KernelEvent{PID: 200, EventType: "process"},
		Action:      "fork",
		PPID:        100,
		Argv:        []string{},
	}
	if e.Action != "fork" {
		t.Errorf("expected fork, got %q", e.Action)
	}
	if e.PPID != 100 {
		t.Errorf("expected 100, got %d", e.PPID)
	}
}

func TestProcessEventExit(t *testing.T) {
	exitCode := 0
	e := &ProcessEvent{
		KernelEvent: KernelEvent{PID: 100, EventType: "process"},
		Action:      "exit",
		ExitCode:    &exitCode,
		Argv:        []string{},
	}
	if *e.ExitCode != 0 {
		t.Errorf("expected 0, got %d", *e.ExitCode)
	}
}

func TestProcessEventExitCodeNilByDefault(t *testing.T) {
	e := NewProcessEvent()
	if e.ExitCode != nil {
		t.Error("expected nil exit code")
	}
}

func TestProcessEventToSentinel(t *testing.T) {
	e := &ProcessEvent{
		KernelEvent: KernelEvent{Timestamp: 1.0, PID: 50, UID: 0, Comm: "sh", EventType: "process"},
		Action:      "exec",
		PPID:        1,
		Filename:    "/bin/sh",
		Argv:        []string{"sh", "-c", "ls"},
	}
	d := e.ToSentinelEvent()
	if d["type"] != "process" {
		t.Errorf("expected process, got %v", d["type"])
	}
	if d["action"] != "exec" {
		t.Errorf("expected exec, got %v", d["action"])
	}
	if d["filename"] != "/bin/sh" {
		t.Errorf("expected /bin/sh, got %v", d["filename"])
	}
}

func TestProcessEventToSentinelExitCode(t *testing.T) {
	exitCode := 137
	e := &ProcessEvent{
		KernelEvent: KernelEvent{EventType: "process"},
		Action:      "exit",
		ExitCode:    &exitCode,
		Argv:        []string{},
	}
	d := e.ToSentinelEvent()
	if d["exit_code"] != 137 {
		t.Errorf("expected 137, got %v", d["exit_code"])
	}
}

func TestProcessEventToMalscope(t *testing.T) {
	e := &ProcessEvent{
		KernelEvent: KernelEvent{Timestamp: 1.0, PID: 50, EventType: "process"},
		Action:      "exec",
		PPID:        1,
		Filename:    "/bin/sh",
		Argv:        []string{"sh"},
	}
	d := e.ToMalscopeEvent()
	if d["event_type"] != "process" {
		t.Errorf("expected process, got %v", d["event_type"])
	}
	details := d["details"].(map[string]string)
	if details["action"] != "exec" {
		t.Errorf("expected exec, got %v", details["action"])
	}
	if details["filename"] != "/bin/sh" {
		t.Errorf("expected /bin/sh, got %v", details["filename"])
	}
	if details["ppid"] != "1" {
		t.Errorf("expected 1, got %v", details["ppid"])
	}
}

// ---------------------------------------------------------------------------
// FileEvent
// ---------------------------------------------------------------------------

func TestFileEventDefaults(t *testing.T) {
	e := NewFileEvent()
	if e.GetEventType() != "file" {
		t.Errorf("expected file, got %q", e.GetEventType())
	}
}

func TestFileEventOpen(t *testing.T) {
	e := &FileEvent{
		KernelEvent: KernelEvent{EventType: "file"},
		Operation:   "open",
		Path:        "/etc/passwd",
		Flags:       0,
		Mode:        0644,
	}
	if e.Operation != "open" {
		t.Errorf("expected open, got %q", e.Operation)
	}
	if e.Path != "/etc/passwd" {
		t.Errorf("expected /etc/passwd, got %q", e.Path)
	}
}

func TestFileEventToSentinel(t *testing.T) {
	e := &FileEvent{
		KernelEvent: KernelEvent{Timestamp: 1.0, PID: 10, UID: 0, EventType: "file"},
		Path:        "/tmp/x",
		Operation:   "write",
	}
	d := e.ToSentinelEvent()
	if d["type"] != "file" {
		t.Errorf("expected file, got %v", d["type"])
	}
	if d["path"] != "/tmp/x" {
		t.Errorf("expected /tmp/x, got %v", d["path"])
	}
	if d["operation"] != "write" {
		t.Errorf("expected write, got %v", d["operation"])
	}
}

func TestFileEventToMalscope(t *testing.T) {
	e := &FileEvent{
		KernelEvent: KernelEvent{EventType: "file"},
		Path:        "/etc/shadow",
		Operation:   "open",
		Flags:       2,
		Mode:        0600,
	}
	d := e.ToMalscopeEvent()
	details := d["details"].(map[string]string)
	if details["path"] != "/etc/shadow" {
		t.Errorf("expected /etc/shadow, got %v", details["path"])
	}
	if details["flags"] != "2" {
		t.Errorf("expected 2, got %v", details["flags"])
	}
	if details["mode"] != "384" {
		t.Errorf("expected 384, got %v", details["mode"])
	}
}

// ---------------------------------------------------------------------------
// NetworkEvent
// ---------------------------------------------------------------------------

func TestNetworkEventDefaults(t *testing.T) {
	e := NewNetworkEvent()
	if e.GetEventType() != "network" {
		t.Errorf("expected network, got %q", e.GetEventType())
	}
	if e.Protocol != "tcp" {
		t.Errorf("expected tcp, got %q", e.Protocol)
	}
}

func TestNetworkEventConnect(t *testing.T) {
	e := &NetworkEvent{
		KernelEvent: KernelEvent{EventType: "network"},
		Action:      "connect",
		SAddr:       "192.168.1.1",
		DAddr:       "10.0.0.1",
		SPort:       54321,
		DPort:       443,
		Protocol:    "tcp",
	}
	if e.Action != "connect" {
		t.Errorf("expected connect, got %q", e.Action)
	}
	if e.SAddr != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %q", e.SAddr)
	}
	if e.DAddr != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %q", e.DAddr)
	}
	if e.DPort != 443 {
		t.Errorf("expected 443, got %d", e.DPort)
	}
}

func TestNetworkEventSendBytes(t *testing.T) {
	e := &NetworkEvent{
		KernelEvent: KernelEvent{EventType: "network"},
		Action:      "send",
		BytesSent:   1024,
	}
	if e.BytesSent != 1024 {
		t.Errorf("expected 1024, got %d", e.BytesSent)
	}
}

func TestNetworkEventStateChange(t *testing.T) {
	e := &NetworkEvent{
		KernelEvent: KernelEvent{EventType: "network"},
		Action:      "state_change",
		NewState:    1,
	}
	if e.NewState != 1 {
		t.Errorf("expected 1, got %d", e.NewState)
	}
}

func TestNetworkEventToSentinel(t *testing.T) {
	e := &NetworkEvent{
		KernelEvent: KernelEvent{Timestamp: 1.0, PID: 10, Comm: "curl", EventType: "network"},
		SAddr:       "127.0.0.1",
		DAddr:       "93.184.216.34",
		SPort:       12345,
		DPort:       80,
		Protocol:    "tcp",
	}
	d := e.ToSentinelEvent()
	if d["type"] != "network" {
		t.Errorf("expected network, got %v", d["type"])
	}
	if d["saddr"] != "127.0.0.1" {
		t.Errorf("expected 127.0.0.1, got %v", d["saddr"])
	}
	if d["protocol"] != "tcp" {
		t.Errorf("expected tcp, got %v", d["protocol"])
	}
}

func TestNetworkEventToMalscope(t *testing.T) {
	e := &NetworkEvent{
		KernelEvent: KernelEvent{EventType: "network"},
		Action:      "connect",
		SAddr:       "10.0.0.1",
		DAddr:       "8.8.8.8",
		SPort:       55555,
		DPort:       53,
	}
	d := e.ToMalscopeEvent()
	details := d["details"].(map[string]string)
	if details["action"] != "connect" {
		t.Errorf("expected connect, got %v", details["action"])
	}
	if details["dport"] != "53" {
		t.Errorf("expected 53, got %v", details["dport"])
	}
}

// ---------------------------------------------------------------------------
// MemoryEvent
// ---------------------------------------------------------------------------

func TestMemoryEventDefaults(t *testing.T) {
	e := NewMemoryEvent()
	if e.GetEventType() != "memory" {
		t.Errorf("expected memory, got %q", e.GetEventType())
	}
	if e.FD != -1 {
		t.Errorf("expected -1, got %d", e.FD)
	}
}

func TestMemoryEventMmap(t *testing.T) {
	e := &MemoryEvent{
		KernelEvent: KernelEvent{EventType: "memory"},
		Operation:   "mmap",
		Addr:        0x7F0000000000,
		Length:      4096,
		Prot:        7,
		Flags:       0x22,
	}
	if e.Operation != "mmap" {
		t.Errorf("expected mmap, got %q", e.Operation)
	}
	if e.Addr != 0x7F0000000000 {
		t.Errorf("expected 0x7F0000000000, got %x", e.Addr)
	}
	if e.Prot != 7 {
		t.Errorf("expected 7, got %d", e.Prot)
	}
}

func TestMemoryEventMprotect(t *testing.T) {
	e := &MemoryEvent{
		KernelEvent: KernelEvent{EventType: "memory"},
		Operation:   "mprotect",
		Prot:        5,
	}
	if e.Prot != 5 {
		t.Errorf("expected 5, got %d", e.Prot)
	}
}

func TestMemoryEventMemfdCreate(t *testing.T) {
	e := &MemoryEvent{
		KernelEvent: KernelEvent{EventType: "memory"},
		Operation:   "memfd_create",
		MemFDName:   "jit-code",
		Flags:       1,
	}
	if e.MemFDName != "jit-code" {
		t.Errorf("expected jit-code, got %q", e.MemFDName)
	}
}

func TestMemoryEventToSentinel(t *testing.T) {
	e := &MemoryEvent{
		KernelEvent: KernelEvent{Timestamp: 1.0, PID: 10, EventType: "memory"},
		Operation:   "mmap",
		Addr:        0x1000,
		Length:      4096,
		Prot:        7,
	}
	d := e.ToSentinelEvent()
	if d["type"] != "memory" {
		t.Errorf("expected memory, got %v", d["type"])
	}
	if d["addr"] != uint64(0x1000) {
		t.Errorf("expected 0x1000, got %v", d["addr"])
	}
	if d["prot"] != 7 {
		t.Errorf("expected 7, got %v", d["prot"])
	}
}

func TestMemoryEventToMalscope(t *testing.T) {
	e := &MemoryEvent{
		KernelEvent: KernelEvent{EventType: "memory"},
		Operation:   "mmap",
		Addr:        0xDEAD,
		Length:      8192,
		Prot:        5,
	}
	d := e.ToMalscopeEvent()
	details := d["details"].(map[string]string)
	if details["addr"] != "0xdead" {
		t.Errorf("expected 0xdead, got %v", details["addr"])
	}
	if details["prot"] != "5" {
		t.Errorf("expected 5, got %v", details["prot"])
	}
}

func TestMemoryEventToMalscopeMemfdName(t *testing.T) {
	e := &MemoryEvent{
		KernelEvent: KernelEvent{EventType: "memory"},
		Operation:   "memfd_create",
		MemFDName:   "payload",
	}
	d := e.ToMalscopeEvent()
	details := d["details"].(map[string]string)
	if details["memfd_name"] != "payload" {
		t.Errorf("expected payload, got %v", details["memfd_name"])
	}
}

// ---------------------------------------------------------------------------
// ModuleEvent
// ---------------------------------------------------------------------------

func TestModuleEventDefaults(t *testing.T) {
	e := NewModuleEvent()
	if e.GetEventType() != "module" {
		t.Errorf("expected module, got %q", e.GetEventType())
	}
}

func TestModuleEventLoad(t *testing.T) {
	e := &ModuleEvent{
		KernelEvent: KernelEvent{EventType: "module"},
		Operation:   "load",
		ModuleName:  "evil_rootkit",
		Filename:    "/tmp/evil.ko",
	}
	if e.Operation != "load" {
		t.Errorf("expected load, got %q", e.Operation)
	}
	if e.ModuleName != "evil_rootkit" {
		t.Errorf("expected evil_rootkit, got %q", e.ModuleName)
	}
}

func TestModuleEventToSentinel(t *testing.T) {
	e := &ModuleEvent{
		KernelEvent: KernelEvent{Timestamp: 1.0, PID: 1, Comm: "insmod", EventType: "module"},
		Operation:   "load",
		ModuleName:  "test_mod",
	}
	d := e.ToSentinelEvent()
	if d["type"] != "module" {
		t.Errorf("expected module, got %v", d["type"])
	}
	if d["module_name"] != "test_mod" {
		t.Errorf("expected test_mod, got %v", d["module_name"])
	}
}

func TestModuleEventToMalscope(t *testing.T) {
	e := &ModuleEvent{
		KernelEvent: KernelEvent{EventType: "module"},
		Operation:   "load",
		ModuleName:  "nf_tables",
	}
	d := e.ToMalscopeEvent()
	details := d["details"].(map[string]string)
	if details["operation"] != "load" {
		t.Errorf("expected load, got %v", details["operation"])
	}
	if details["module_name"] != "nf_tables" {
		t.Errorf("expected nf_tables, got %v", details["module_name"])
	}
}

// ---------------------------------------------------------------------------
// DnsEvent
// ---------------------------------------------------------------------------

func TestDnsEventDefaults(t *testing.T) {
	e := NewDnsEvent()
	if e.GetEventType() != "dns" {
		t.Errorf("expected dns, got %q", e.GetEventType())
	}
	if e.DestPort != 53 {
		t.Errorf("expected 53, got %d", e.DestPort)
	}
}

func TestDnsEventQuery(t *testing.T) {
	e := &DnsEvent{
		KernelEvent: KernelEvent{EventType: "dns"},
		QueryName:   "evil.example.com",
		QueryType:   1,
		DestIP:      "8.8.8.8",
		DestPort:    53,
	}
	if e.QueryName != "evil.example.com" {
		t.Errorf("expected evil.example.com, got %q", e.QueryName)
	}
	if e.QueryType != 1 {
		t.Errorf("expected 1, got %d", e.QueryType)
	}
}

func TestDnsEventToSentinel(t *testing.T) {
	e := &DnsEvent{
		KernelEvent: KernelEvent{Timestamp: 1.0, PID: 10, Comm: "dig", EventType: "dns"},
		QueryName:   "test.com",
		QueryType:   1,
		DestIP:      "1.1.1.1",
		DestPort:    53,
	}
	d := e.ToSentinelEvent()
	if d["type"] != "dns" {
		t.Errorf("expected dns, got %v", d["type"])
	}
	if d["query_name"] != "test.com" {
		t.Errorf("expected test.com, got %v", d["query_name"])
	}
	if d["dest_ip"] != "1.1.1.1" {
		t.Errorf("expected 1.1.1.1, got %v", d["dest_ip"])
	}
}

func TestDnsEventToMalscope(t *testing.T) {
	e := &DnsEvent{
		KernelEvent: KernelEvent{EventType: "dns"},
		QueryName:   "c2.malware.io",
		DestIP:      "8.8.4.4",
		QueryType:   28,
		DestPort:    53,
	}
	d := e.ToMalscopeEvent()
	details := d["details"].(map[string]string)
	if details["query_name"] != "c2.malware.io" {
		t.Errorf("expected c2.malware.io, got %v", details["query_name"])
	}
	if details["query_type"] != "28" {
		t.Errorf("expected 28, got %v", details["query_type"])
	}
}

// ---------------------------------------------------------------------------
// SECURITY_SYSCALLS mapping
// ---------------------------------------------------------------------------

func TestSecuritySyscallsExecve(t *testing.T) {
	if SecuritySyscalls[59] != "execve" {
		t.Errorf("expected execve, got %q", SecuritySyscalls[59])
	}
}

func TestSecuritySyscallsConnect(t *testing.T) {
	if SecuritySyscalls[42] != "connect" {
		t.Errorf("expected connect, got %q", SecuritySyscalls[42])
	}
}

func TestSecuritySyscallsMmap(t *testing.T) {
	if SecuritySyscalls[9] != "mmap" {
		t.Errorf("expected mmap, got %q", SecuritySyscalls[9])
	}
}

func TestSecuritySyscallsMemfdCreate(t *testing.T) {
	if SecuritySyscalls[319] != "memfd_create" {
		t.Errorf("expected memfd_create, got %q", SecuritySyscalls[319])
	}
}

func TestSecuritySyscallsClone3(t *testing.T) {
	if SecuritySyscalls[435] != "clone3" {
		t.Errorf("expected clone3, got %q", SecuritySyscalls[435])
	}
}

func TestReverseMapping(t *testing.T) {
	if SyscallNameToNR["execve"] != 59 {
		t.Errorf("expected 59, got %d", SyscallNameToNR["execve"])
	}
	if SyscallNameToNR["connect"] != 42 {
		t.Errorf("expected 42, got %d", SyscallNameToNR["connect"])
	}
}

func TestAllEntriesHaveReverse(t *testing.T) {
	for nr, name := range SecuritySyscalls {
		if SyscallNameToNR[name] != nr {
			t.Errorf("reverse mapping mismatch for %s: expected %d, got %d", name, nr, SyscallNameToNR[name])
		}
	}
}

func TestMinimumEntries(t *testing.T) {
	if len(SecuritySyscalls) < 20 {
		t.Errorf("expected >= 20 entries, got %d", len(SecuritySyscalls))
	}
}

// ---------------------------------------------------------------------------
// EVENT_TYPES registry
// ---------------------------------------------------------------------------

func TestAllEventTypesRegistered(t *testing.T) {
	expected := map[string]bool{
		"base": true, "syscall": true, "process": true, "file": true,
		"network": true, "memory": true, "module": true, "dns": true,
		"canary": true,
	}
	for name := range expected {
		if _, ok := EventTypes[name]; !ok {
			t.Errorf("missing event type: %s", name)
		}
	}
	if len(EventTypes) != len(expected) {
		t.Errorf("expected %d types, got %d", len(expected), len(EventTypes))
	}
}

func TestAllTypesAreEventSubclasses(t *testing.T) {
	for name, ctor := range EventTypes {
		e := ctor()
		if e == nil {
			t.Errorf("%s constructor returned nil", name)
		}
		var _ Event = e // compile-time check
	}
}

func TestInstantiateAllTypes(t *testing.T) {
	for name, ctor := range EventTypes {
		e := ctor()
		if e.GetEventType() != name {
			t.Errorf("expected %q, got %q", name, e.GetEventType())
		}
	}
}
