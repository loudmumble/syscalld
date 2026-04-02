// Package core provides the foundational types for the syscalld sensor framework.
//
// It defines event types (ProcessEvent, NetworkEvent, FileEvent, etc.),
// the EventBus for routing events to consumers, SensorFilter for
// compile-time and runtime filtering, and SensorManager for lifecycle
// management.
package core

import (
	"fmt"
	"time"
)

// SecuritySyscalls maps x86_64 syscall numbers to their names.
// Includes security-relevant syscalls plus commonly observed ones
// for display quality in fallback mode polling.
var SecuritySyscalls = map[int]string{
	0:   "read",
	1:   "write",
	2:   "open",
	3:   "close",
	5:   "fstat",
	7:   "poll",
	8:   "lseek",
	9:   "mmap",
	10:  "mprotect",
	11:  "munmap",
	17:  "pread64",
	18:  "pwrite64",
	21:  "access",
	23:  "select",
	25:  "mremap",
	28:  "madvise",
	34:  "pause",
	35:  "nanosleep",
	41:  "socket",
	42:  "connect",
	43:  "accept",
	44:  "sendto",
	45:  "recvfrom",
	46:  "sendmsg",
	47:  "recvmsg",
	48:  "shutdown",
	49:  "bind",
	50:  "listen",
	56:  "clone",
	57:  "fork",
	58:  "vfork",
	59:  "execve",
	60:  "exit",
	61:  "wait4",
	62:  "kill",
	72:  "fcntl",
	78:  "getdents",
	80:  "chdir",
	82:  "rename",
	83:  "mkdir",
	84:  "rmdir",
	87:  "unlink",
	90:  "chmod",
	92:  "chown",
	101: "ptrace",
	155: "pivot_root",
	157: "prctl",
	165: "mount",
	175: "init_module",
	186: "gettid",
	202: "futex",
	217: "getdents64",
	228: "clock_gettime",
	230: "clock_nanosleep",
	231: "exit_group",
	232: "epoll_wait",
	257: "openat",
	263: "unlinkat",
	270: "pselect6",
	271: "ppoll",
	280: "timerfd_settime",
	281: "epoll_pwait",
	288: "accept4",
	302: "preadv",
	310: "process_vm_readv",
	313: "finit_module",
	319: "memfd_create",
	322: "execveat",
	435: "clone3",
	441: "epoll_pwait2",
}

// SyscallNameToNR is the reverse mapping: syscall name -> number.
var SyscallNameToNR map[string]int

func init() {
	SyscallNameToNR = make(map[string]int, len(SecuritySyscalls))
	for nr, name := range SecuritySyscalls {
		SyscallNameToNR[name] = nr
	}
}

// EventTypes maps event type discriminator strings to zero-value constructors.
var EventTypes = map[string]func() Event{
	"base":    func() Event { return &KernelEvent{EventType: "base"} },
	"syscall": func() Event { return NewSyscallEvent() },
	"process": func() Event { return NewProcessEvent() },
	"file":    func() Event { return NewFileEvent() },
	"network": func() Event { return NewNetworkEvent() },
	"memory":  func() Event { return NewMemoryEvent() },
	"module":  func() Event { return NewModuleEvent() },
	"dns":     func() Event { return NewDnsEvent() },
	"canary":  func() Event { return NewCanaryEvent() },
}

// Event is the interface all kernel events implement.
type Event interface {
	// GetEventType returns the event discriminator string.
	GetEventType() string
	// ToSentinelEvent maps the event to a probe-oriented event dict.
	ToSentinelEvent() map[string]interface{}
	// ToMalscopeEvent maps the event to a behavior-oriented event dict.
	ToMalscopeEvent() map[string]interface{}
}

// KernelEvent is the base event for all kernel sensor data.
// All events carry core process context (pid, tid, uid, comm) along
// with a high-resolution timestamp.
type KernelEvent struct {
	Timestamp float64  `json:"timestamp"`
	PID       int      `json:"pid"`
	TID       int      `json:"tid"`
	UID       int      `json:"uid"`
	Comm      string   `json:"comm"`
	EventType string   `json:"event_type"`
	MITRE     MITRETag `json:"mitre,omitempty"`
}

// GetEventType implements Event.
func (e *KernelEvent) GetEventType() string {
	return e.EventType
}

// ToSentinelEvent maps to the probe-oriented event format.
func (e *KernelEvent) ToSentinelEvent() map[string]interface{} {
	m := map[string]interface{}{
		"timestamp": e.Timestamp,
		"type":      e.EventType,
		"pid":       e.PID,
		"comm":      e.Comm,
	}
	if e.MITRE.TechniqueID != "" {
		m["mitre_technique_id"] = e.MITRE.TechniqueID
		m["mitre_tactic"] = e.MITRE.Tactic
		m["mitre_name"] = e.MITRE.Name
	}
	return m
}

// ToMalscopeEvent maps to the behavior-oriented event format.
func (e *KernelEvent) ToMalscopeEvent() map[string]interface{} {
	details := map[string]interface{}{}
	if e.MITRE.TechniqueID != "" {
		details["mitre_technique_id"] = e.MITRE.TechniqueID
		details["mitre_tactic"] = e.MITRE.Tactic
		details["mitre_name"] = e.MITRE.Name
	}
	return map[string]interface{}{
		"timestamp":  e.Timestamp,
		"event_type": e.EventType,
		"pid":        e.PID,
		"details":    details,
	}
}

// SyscallEvent represents a raw syscall enter/exit event.
type SyscallEvent struct {
	KernelEvent
	SyscallNR   int    `json:"syscall_nr"`
	SyscallName string `json:"syscall_name"`
	Args        []int  `json:"args"`
	Ret         int    `json:"ret"`
	Phase       string `json:"phase"`
}

// NewSyscallEvent creates a SyscallEvent with proper defaults.
func NewSyscallEvent() *SyscallEvent {
	return &SyscallEvent{
		KernelEvent: KernelEvent{EventType: "syscall"},
		Args:        []int{},
		Phase:       "enter",
	}
}

// GetEventType implements Event.
func (e *SyscallEvent) GetEventType() string {
	return "syscall"
}

// ToSentinelEvent maps to the probe-oriented SyscallEvent format.
func (e *SyscallEvent) ToSentinelEvent() map[string]interface{} {
	name := e.SyscallName
	if name == "" {
		name = SecuritySyscalls[e.SyscallNR]
	}
	m := map[string]interface{}{
		"timestamp":    e.Timestamp,
		"type":         "syscall",
		"pid":          e.PID,
		"comm":         e.Comm,
		"syscall_nr":   e.SyscallNR,
		"syscall_name": name,
		"args":         e.Args,
	}
	if e.MITRE.TechniqueID != "" {
		m["mitre_technique_id"] = e.MITRE.TechniqueID
		m["mitre_tactic"] = e.MITRE.Tactic
		m["mitre_name"] = e.MITRE.Name
	}
	return m
}

// ToMalscopeEvent maps to the behavior-oriented SyscallEvent format.
func (e *SyscallEvent) ToMalscopeEvent() map[string]interface{} {
	name := e.SyscallName
	if name == "" {
		name = SecuritySyscalls[e.SyscallNR]
	}
	strArgs := make([]string, len(e.Args))
	for i, a := range e.Args {
		strArgs[i] = fmt.Sprintf("%d", a)
	}
	m := map[string]interface{}{
		"timestamp":    e.Timestamp,
		"pid":          e.PID,
		"syscall_name": name,
		"syscall_nr":   e.SyscallNR,
		"args":         strArgs,
		"return_value": fmt.Sprintf("%d", e.Ret),
		"duration_us":  0.0,
		"comm":         e.Comm,
	}
	if e.MITRE.TechniqueID != "" {
		m["mitre_technique_id"] = e.MITRE.TechniqueID
		m["mitre_tactic"] = e.MITRE.Tactic
		m["mitre_name"] = e.MITRE.Name
	}
	return m
}

// ProcessEvent represents a process lifecycle event: fork, exec, exit.
type ProcessEvent struct {
	KernelEvent
	Action   string   `json:"action"`
	PPID     int      `json:"ppid"`
	Filename string   `json:"filename"`
	Argv     []string `json:"argv"`
	ExitCode *int     `json:"exit_code"`
}

// NewProcessEvent creates a ProcessEvent with proper defaults.
func NewProcessEvent() *ProcessEvent {
	return &ProcessEvent{
		KernelEvent: KernelEvent{EventType: "process"},
		Argv:        []string{},
	}
}

// GetEventType implements Event.
func (e *ProcessEvent) GetEventType() string {
	return "process"
}

// ToSentinelEvent maps to the probe-oriented ProcessEvent format.
func (e *ProcessEvent) ToSentinelEvent() map[string]interface{} {
	result := map[string]interface{}{
		"timestamp": e.Timestamp,
		"type":      "process",
		"action":    e.Action,
		"pid":       e.PID,
		"ppid":      e.PPID,
		"uid":       e.UID,
		"comm":      e.Comm,
		"filename":  e.Filename,
		"argv":      e.Argv,
	}
	if e.ExitCode != nil {
		result["exit_code"] = *e.ExitCode
	}
	if e.MITRE.TechniqueID != "" {
		result["mitre_technique_id"] = e.MITRE.TechniqueID
		result["mitre_tactic"] = e.MITRE.Tactic
		result["mitre_name"] = e.MITRE.Name
	}
	return result
}

// ToMalscopeEvent maps to the behavior-oriented event format.
func (e *ProcessEvent) ToMalscopeEvent() map[string]interface{} {
	details := map[string]string{
		"action":   e.Action,
		"filename": e.Filename,
		"ppid":     fmt.Sprintf("%d", e.PPID),
	}
	if len(e.Argv) > 0 {
		argv := ""
		for i, a := range e.Argv {
			if i > 0 {
				argv += " "
			}
			argv += a
		}
		details["argv"] = argv
	}
	if e.ExitCode != nil {
		details["exit_code"] = fmt.Sprintf("%d", *e.ExitCode)
	}
	if e.MITRE.TechniqueID != "" {
		details["mitre_technique_id"] = e.MITRE.TechniqueID
		details["mitre_tactic"] = e.MITRE.Tactic
		details["mitre_name"] = e.MITRE.Name
	}
	return map[string]interface{}{
		"timestamp":  e.Timestamp,
		"event_type": "process",
		"pid":        e.PID,
		"details":    details,
	}
}

// FileEvent represents a VFS file operation event.
type FileEvent struct {
	KernelEvent
	Operation string `json:"operation"`
	Path      string `json:"path"`
	Flags     int    `json:"flags"`
	Mode      int    `json:"mode"`
}

// NewFileEvent creates a FileEvent with proper defaults.
func NewFileEvent() *FileEvent {
	return &FileEvent{
		KernelEvent: KernelEvent{EventType: "file"},
	}
}

// GetEventType implements Event.
func (e *FileEvent) GetEventType() string {
	return "file"
}

// ToSentinelEvent maps to the probe-oriented FileEvent format.
func (e *FileEvent) ToSentinelEvent() map[string]interface{} {
	m := map[string]interface{}{
		"timestamp": e.Timestamp,
		"type":      "file",
		"path":      e.Path,
		"operation": e.Operation,
		"pid":       e.PID,
		"uid":       e.UID,
	}
	if e.MITRE.TechniqueID != "" {
		m["mitre_technique_id"] = e.MITRE.TechniqueID
		m["mitre_tactic"] = e.MITRE.Tactic
		m["mitre_name"] = e.MITRE.Name
	}
	return m
}

// ToMalscopeEvent maps to the behavior-oriented event format.
func (e *FileEvent) ToMalscopeEvent() map[string]interface{} {
	details := map[string]string{
		"operation": e.Operation,
		"path":      e.Path,
		"flags":     fmt.Sprintf("%d", e.Flags),
		"mode":      fmt.Sprintf("%d", e.Mode),
	}
	if e.MITRE.TechniqueID != "" {
		details["mitre_technique_id"] = e.MITRE.TechniqueID
		details["mitre_tactic"] = e.MITRE.Tactic
		details["mitre_name"] = e.MITRE.Name
	}
	return map[string]interface{}{
		"timestamp":  e.Timestamp,
		"event_type": "file",
		"pid":        e.PID,
		"details":    details,
	}
}

// NetworkEvent represents a TCP/UDP network activity event.
type NetworkEvent struct {
	KernelEvent
	Action    string `json:"action"`
	SAddr     string `json:"saddr"`
	DAddr     string `json:"daddr"`
	SPort     int    `json:"sport"`
	DPort     int    `json:"dport"`
	Protocol  string `json:"protocol"`
	BytesSent int    `json:"bytes_sent"`
	NewState  int    `json:"new_state"`
}

// NewNetworkEvent creates a NetworkEvent with proper defaults.
func NewNetworkEvent() *NetworkEvent {
	return &NetworkEvent{
		KernelEvent: KernelEvent{EventType: "network"},
		Protocol:    "tcp",
	}
}

// GetEventType implements Event.
func (e *NetworkEvent) GetEventType() string {
	return "network"
}

// ToSentinelEvent maps to the probe-oriented NetworkEvent format.
func (e *NetworkEvent) ToSentinelEvent() map[string]interface{} {
	m := map[string]interface{}{
		"timestamp": e.Timestamp,
		"type":      "network",
		"pid":       e.PID,
		"comm":      e.Comm,
		"saddr":     e.SAddr,
		"daddr":     e.DAddr,
		"sport":     e.SPort,
		"dport":     e.DPort,
		"protocol":  e.Protocol,
	}
	if e.MITRE.TechniqueID != "" {
		m["mitre_technique_id"] = e.MITRE.TechniqueID
		m["mitre_tactic"] = e.MITRE.Tactic
		m["mitre_name"] = e.MITRE.Name
	}
	return m
}

// ToMalscopeEvent maps to the behavior-oriented event format.
func (e *NetworkEvent) ToMalscopeEvent() map[string]interface{} {
	details := map[string]string{
		"action":     e.Action,
		"saddr":      e.SAddr,
		"daddr":      e.DAddr,
		"sport":      fmt.Sprintf("%d", e.SPort),
		"dport":      fmt.Sprintf("%d", e.DPort),
		"protocol":   e.Protocol,
		"bytes_sent": fmt.Sprintf("%d", e.BytesSent),
	}
	if e.MITRE.TechniqueID != "" {
		details["mitre_technique_id"] = e.MITRE.TechniqueID
		details["mitre_tactic"] = e.MITRE.Tactic
		details["mitre_name"] = e.MITRE.Name
	}
	return map[string]interface{}{
		"timestamp":  e.Timestamp,
		"event_type": "network",
		"pid":        e.PID,
		"details":    details,
	}
}

// MemoryEvent represents a memory mapping/protection change event.
type MemoryEvent struct {
	KernelEvent
	Operation string `json:"operation"`
	Addr      uint64 `json:"addr"`
	Length    int    `json:"length"`
	Prot      int    `json:"prot"`
	Flags     int    `json:"flags"`
	FD        int    `json:"fd"`
	MemFDName string `json:"memfd_name"`
}

// NewMemoryEvent creates a MemoryEvent with proper defaults.
func NewMemoryEvent() *MemoryEvent {
	return &MemoryEvent{
		KernelEvent: KernelEvent{EventType: "memory"},
		FD:          -1,
	}
}

// GetEventType implements Event.
func (e *MemoryEvent) GetEventType() string {
	return "memory"
}

// ToSentinelEvent maps to the probe-oriented event dict.
func (e *MemoryEvent) ToSentinelEvent() map[string]interface{} {
	m := map[string]interface{}{
		"timestamp": e.Timestamp,
		"type":      "memory",
		"pid":       e.PID,
		"comm":      e.Comm,
		"operation": e.Operation,
		"addr":      e.Addr,
		"length":    e.Length,
		"prot":      e.Prot,
		"flags":     e.Flags,
	}
	if e.MITRE.TechniqueID != "" {
		m["mitre_technique_id"] = e.MITRE.TechniqueID
		m["mitre_tactic"] = e.MITRE.Tactic
		m["mitre_name"] = e.MITRE.Name
	}
	return m
}

// ToMalscopeEvent maps to the behavior-oriented event format.
func (e *MemoryEvent) ToMalscopeEvent() map[string]interface{} {
	details := map[string]string{
		"operation": e.Operation,
		"addr":      fmt.Sprintf("0x%x", e.Addr),
		"length":    fmt.Sprintf("%d", e.Length),
		"prot":      fmt.Sprintf("%d", e.Prot),
		"flags":     fmt.Sprintf("%d", e.Flags),
	}
	if e.MemFDName != "" {
		details["memfd_name"] = e.MemFDName
	}
	if e.MITRE.TechniqueID != "" {
		details["mitre_technique_id"] = e.MITRE.TechniqueID
		details["mitre_tactic"] = e.MITRE.Tactic
		details["mitre_name"] = e.MITRE.Name
	}
	return map[string]interface{}{
		"timestamp":  e.Timestamp,
		"event_type": "memory",
		"pid":        e.PID,
		"details":    details,
	}
}

// ModuleEvent represents a kernel module load/unload event.
type ModuleEvent struct {
	KernelEvent
	Operation  string `json:"operation"`
	ModuleName string `json:"module_name"`
	Filename   string `json:"filename"`
}

// NewModuleEvent creates a ModuleEvent with proper defaults.
func NewModuleEvent() *ModuleEvent {
	return &ModuleEvent{
		KernelEvent: KernelEvent{EventType: "module"},
	}
}

// GetEventType implements Event.
func (e *ModuleEvent) GetEventType() string {
	return "module"
}

// ToSentinelEvent maps to the probe-oriented event dict.
func (e *ModuleEvent) ToSentinelEvent() map[string]interface{} {
	m := map[string]interface{}{
		"timestamp":   e.Timestamp,
		"type":        "module",
		"pid":         e.PID,
		"comm":        e.Comm,
		"operation":   e.Operation,
		"module_name": e.ModuleName,
		"filename":    e.Filename,
	}
	if e.MITRE.TechniqueID != "" {
		m["mitre_technique_id"] = e.MITRE.TechniqueID
		m["mitre_tactic"] = e.MITRE.Tactic
		m["mitre_name"] = e.MITRE.Name
	}
	return m
}

// ToMalscopeEvent maps to the behavior-oriented event format.
func (e *ModuleEvent) ToMalscopeEvent() map[string]interface{} {
	details := map[string]string{
		"operation":   e.Operation,
		"module_name": e.ModuleName,
		"filename":    e.Filename,
	}
	if e.MITRE.TechniqueID != "" {
		details["mitre_technique_id"] = e.MITRE.TechniqueID
		details["mitre_tactic"] = e.MITRE.Tactic
		details["mitre_name"] = e.MITRE.Name
	}
	return map[string]interface{}{
		"timestamp":  e.Timestamp,
		"event_type": "module",
		"pid":        e.PID,
		"details":    details,
	}
}

// DnsEvent represents a DNS query event captured from UDP port 53 traffic.
type DnsEvent struct {
	KernelEvent
	QueryName string `json:"query_name"`
	QueryType int    `json:"query_type"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
}

// NewDnsEvent creates a DnsEvent with proper defaults.
func NewDnsEvent() *DnsEvent {
	return &DnsEvent{
		KernelEvent: KernelEvent{EventType: "dns"},
		DestPort:    53,
	}
}

// GetEventType implements Event.
func (e *DnsEvent) GetEventType() string {
	return "dns"
}

// ToSentinelEvent maps to the probe-oriented event dict.
func (e *DnsEvent) ToSentinelEvent() map[string]interface{} {
	m := map[string]interface{}{
		"timestamp":  e.Timestamp,
		"type":       "dns",
		"pid":        e.PID,
		"comm":       e.Comm,
		"query_name": e.QueryName,
		"query_type": e.QueryType,
		"dest_ip":    e.DestIP,
		"dest_port":  e.DestPort,
	}
	if e.MITRE.TechniqueID != "" {
		m["mitre_technique_id"] = e.MITRE.TechniqueID
		m["mitre_tactic"] = e.MITRE.Tactic
		m["mitre_name"] = e.MITRE.Name
	}
	return m
}

// ToMalscopeEvent maps to the behavior-oriented event format.
func (e *DnsEvent) ToMalscopeEvent() map[string]interface{} {
	details := map[string]string{
		"query_name": e.QueryName,
		"query_type": fmt.Sprintf("%d", e.QueryType),
		"dest_ip":    e.DestIP,
		"dest_port":  fmt.Sprintf("%d", e.DestPort),
	}
	if e.MITRE.TechniqueID != "" {
		details["mitre_technique_id"] = e.MITRE.TechniqueID
		details["mitre_tactic"] = e.MITRE.Tactic
		details["mitre_name"] = e.MITRE.Name
	}
	return map[string]interface{}{
		"timestamp":  e.Timestamp,
		"event_type": "dns",
		"pid":        e.PID,
		"details":    details,
	}
}

// CanaryEvent is a synthetic health-check heartbeat emitted periodically by
// SensorManager to verify that the event pipeline is alive and flowing.
// Consumers can subscribe to "canary" events to detect sensor stalls or
// pipeline degradation without waiting for real activity.
type CanaryEvent struct {
	KernelEvent
	Healthy bool `json:"healthy"`
}

// NewCanaryEvent creates a CanaryEvent with healthy=true defaults.
func NewCanaryEvent() *CanaryEvent {
	return &CanaryEvent{
		KernelEvent: KernelEvent{
			EventType: "canary",
			Timestamp: float64(time.Now().UnixNano()) / 1e9,
		},
		Healthy: true,
	}
}

// GetEventType implements Event.
func (e *CanaryEvent) GetEventType() string { return "canary" }

// ToSentinelEvent maps to the probe-oriented event dict.
func (e *CanaryEvent) ToSentinelEvent() map[string]interface{} {
	return map[string]interface{}{
		"timestamp": e.Timestamp,
		"type":      "canary",
		"healthy":   e.Healthy,
	}
}

// ToMalscopeEvent maps to the behavior-oriented event format.
func (e *CanaryEvent) ToMalscopeEvent() map[string]interface{} {
	return map[string]interface{}{
		"timestamp":  e.Timestamp,
		"event_type": "canary",
		"details": map[string]interface{}{
			"healthy": e.Healthy,
		},
	}
}
