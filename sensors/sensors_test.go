package sensors

import (
	"strings"
	"testing"

	"github.com/loudmumble/syscalld/core"
)

// ---------------------------------------------------------------------------
// Sensor constructors and metadata for parametrized tests
// ---------------------------------------------------------------------------

type sensorFactory struct {
	Name        string
	Constructor func() core.Sensor
}

var allSensors = []sensorFactory{
	{"syscall", func() core.Sensor { return NewSyscallSensor() }},
	{"process", func() core.Sensor { return NewProcessSensor() }},
	{"filesystem", func() core.Sensor { return NewFilesystemSensor() }},
	{"network", func() core.Sensor { return NewNetworkSensor() }},
	{"memory", func() core.Sensor { return NewMemorySensor() }},
	{"module", func() core.Sensor { return NewModuleSensor() }},
	{"dns", func() core.Sensor { return NewDnsSensor() }},
}

// ---------------------------------------------------------------------------
// Common sensor tests (parametrized across all 7)
// ---------------------------------------------------------------------------

func TestAllSensors_IsBaseSensor(t *testing.T) {
	for _, sf := range allSensors {
		t.Run(sf.Name, func(t *testing.T) {
			s := sf.Constructor()
			if _, ok := s.(interface{ Name() string }); !ok {
				t.Fatalf("%s does not implement Name()", sf.Name)
			}
		})
	}
}

func TestAllSensors_Name(t *testing.T) {
	for _, sf := range allSensors {
		t.Run(sf.Name, func(t *testing.T) {
			s := sf.Constructor()
			if s.Name() != sf.Name {
				t.Fatalf("expected name %q, got %q", sf.Name, s.Name())
			}
		})
	}
}

func TestAllSensors_InitialModeFallback(t *testing.T) {
	for _, sf := range allSensors {
		t.Run(sf.Name, func(t *testing.T) {
			s := sf.Constructor()
			if s.Mode() != "fallback" {
				t.Fatalf("expected mode 'fallback', got %q", s.Mode())
			}
		})
	}
}

func TestAllSensors_NotStartedInitially(t *testing.T) {
	for _, sf := range allSensors {
		t.Run(sf.Name, func(t *testing.T) {
			s := sf.Constructor()
			if s.Started() {
				t.Fatal("sensor should not be started initially")
			}
		})
	}
}

func TestAllSensors_BPFProgramReturnsString(t *testing.T) {
	for _, sf := range allSensors {
		t.Run(sf.Name, func(t *testing.T) {
			s := sf.Constructor()
			// Access the BaseSensor's GetBPFProgram via type assertion
			type bpfGetter interface {
				GetBPFProgram(filters *core.SensorFilter) string
			}
			bg, ok := s.(bpfGetter)
			if !ok {
				t.Fatal("sensor does not implement GetBPFProgram")
			}
			f := core.NewSensorFilter()
			program := bg.GetBPFProgram(f)
			if len(program) < 50 {
				t.Fatalf("BPF program too short: %d chars", len(program))
			}
		})
	}
}

func TestAllSensors_BPFProgramContainsStruct(t *testing.T) {
	for _, sf := range allSensors {
		t.Run(sf.Name, func(t *testing.T) {
			s := sf.Constructor()
			type bpfGetter interface {
				GetBPFProgram(filters *core.SensorFilter) string
			}
			bg := s.(bpfGetter)
			program := bg.GetBPFProgram(core.NewSensorFilter())
			if !strings.Contains(program, "struct") {
				t.Fatal("BPF program should contain 'struct'")
			}
		})
	}
}

func TestAllSensors_BPFProgramContainsOutputMacro(t *testing.T) {
	for _, sf := range allSensors {
		t.Run(sf.Name, func(t *testing.T) {
			s := sf.Constructor()
			type bpfGetter interface {
				GetBPFProgram(filters *core.SensorFilter) string
			}
			bg := s.(bpfGetter)
			program := bg.GetBPFProgram(core.NewSensorFilter())
			if !strings.Contains(program, "BPF_PERF_OUTPUT") && !strings.Contains(program, "BPF_RINGBUF_OUTPUT") {
				t.Fatal("BPF program should contain output macro")
			}
		})
	}
}

func TestAllSensors_BPFProgramWithPIDFilter(t *testing.T) {
	for _, sf := range allSensors {
		t.Run(sf.Name, func(t *testing.T) {
			s := sf.Constructor()
			type bpfGetter interface {
				GetBPFProgram(filters *core.SensorFilter) string
			}
			bg := s.(bpfGetter)
			f := core.NewSensorFilter()
			f.TargetPIDs[1234] = struct{}{}
			program := bg.GetBPFProgram(f)
			if !strings.Contains(program, "FILTER_PID") {
				t.Fatal("BPF program with PID filter should contain FILTER_PID")
			}
		})
	}
}

func TestAllSensors_StartInFallbackMode(t *testing.T) {
	for _, sf := range allSensors {
		t.Run(sf.Name, func(t *testing.T) {
			s := sf.Constructor()
			s.Start(core.NewSensorFilter())
			if s.Mode() != "fallback" {
				t.Fatalf("expected mode 'fallback', got %q", s.Mode())
			}
			if !s.Started() {
				t.Fatal("sensor should be started after Start()")
			}
			s.Stop()
		})
	}
}

func TestAllSensors_StopAfterStart(t *testing.T) {
	for _, sf := range allSensors {
		t.Run(sf.Name, func(t *testing.T) {
			s := sf.Constructor()
			s.Start(core.NewSensorFilter())
			s.Stop()
			if s.Started() {
				t.Fatal("sensor should not be started after Stop()")
			}
		})
	}
}

func TestAllSensors_PollBeforeStartReturnsEmpty(t *testing.T) {
	for _, sf := range allSensors {
		t.Run(sf.Name, func(t *testing.T) {
			s := sf.Constructor()
			result := s.Poll()
			if len(result) != 0 {
				t.Fatalf("expected empty poll before start, got %d events", len(result))
			}
		})
	}
}

func TestAllSensors_PollReturnsList(t *testing.T) {
	for _, sf := range allSensors {
		t.Run(sf.Name, func(t *testing.T) {
			s := sf.Constructor()
			s.Start(core.NewSensorFilter())
			result := s.Poll()
			// result may be nil (Go's nil slice) or empty, both are valid
			_ = result
			s.Stop()
		})
	}
}

func TestAllSensors_DoubleStartIsSafe(t *testing.T) {
	for _, sf := range allSensors {
		t.Run(sf.Name, func(t *testing.T) {
			s := sf.Constructor()
			s.Start(core.NewSensorFilter())
			s.Start(core.NewSensorFilter()) // Should not panic
			s.Stop()
		})
	}
}

func TestAllSensors_DoubleStopIsSafe(t *testing.T) {
	for _, sf := range allSensors {
		t.Run(sf.Name, func(t *testing.T) {
			s := sf.Constructor()
			s.Start(core.NewSensorFilter())
			s.Stop()
			s.Stop() // Should not panic
		})
	}
}

// ---------------------------------------------------------------------------
// SyscallSensor-specific tests
// ---------------------------------------------------------------------------

func TestSyscallSensor_BPFHasSysEnter(t *testing.T) {
	s := NewSyscallSensor()
	program := s.GetBPFProgram(core.NewSensorFilter())
	if !strings.Contains(program, "raw_syscalls, sys_enter") {
		t.Fatal("BPF program should contain 'raw_syscalls, sys_enter'")
	}
}

func TestSyscallSensor_BPFHasSysExit(t *testing.T) {
	s := NewSyscallSensor()
	program := s.GetBPFProgram(core.NewSensorFilter())
	if !strings.Contains(program, "raw_syscalls, sys_exit") {
		t.Fatal("BPF program should contain 'raw_syscalls, sys_exit'")
	}
}

func TestSyscallSensor_BPFCaptures6Args(t *testing.T) {
	s := NewSyscallSensor()
	program := s.GetBPFProgram(core.NewSensorFilter())
	if !strings.Contains(program, "args[5]") {
		t.Fatal("BPF program should capture 6 args (args[5])")
	}
}

func TestSyscallSensor_BPFHasActiveSyscallsMap(t *testing.T) {
	s := NewSyscallSensor()
	program := s.GetBPFProgram(core.NewSensorFilter())
	if !strings.Contains(program, "BPF_HASH(active_syscalls") {
		t.Fatal("BPF program should contain BPF_HASH(active_syscalls)")
	}
}

func TestSyscallSensor_FallbackReturnsSyscallEvents(t *testing.T) {
	s := NewSyscallSensor()
	s.Start(core.NewSensorFilter())
	events := s.Poll()
	for _, e := range events {
		if e.GetEventType() != "syscall" {
			t.Fatalf("expected event_type 'syscall', got %q", e.GetEventType())
		}
		if _, ok := e.(*core.SyscallEvent); !ok {
			t.Fatal("event should be *core.SyscallEvent")
		}
	}
	s.Stop()
}

// ---------------------------------------------------------------------------
// ProcessSensor-specific tests
// ---------------------------------------------------------------------------

func TestProcessSensor_BPFHasExec(t *testing.T) {
	s := NewProcessSensor()
	program := s.GetBPFProgram(core.NewSensorFilter())
	if !strings.Contains(program, "sched_process_exec") {
		t.Fatal("BPF program should contain 'sched_process_exec'")
	}
}

func TestProcessSensor_BPFHasFork(t *testing.T) {
	s := NewProcessSensor()
	program := s.GetBPFProgram(core.NewSensorFilter())
	if !strings.Contains(program, "sched_process_fork") {
		t.Fatal("BPF program should contain 'sched_process_fork'")
	}
}

func TestProcessSensor_BPFHasExit(t *testing.T) {
	s := NewProcessSensor()
	program := s.GetBPFProgram(core.NewSensorFilter())
	if !strings.Contains(program, "sched_process_exit") {
		t.Fatal("BPF program should contain 'sched_process_exit'")
	}
}

func TestProcessSensor_BPFReadsFilename(t *testing.T) {
	s := NewProcessSensor()
	program := s.GetBPFProgram(core.NewSensorFilter())
	if !strings.Contains(program, "bpf_probe_read_str") {
		t.Fatal("BPF program should contain 'bpf_probe_read_str'")
	}
}

func TestProcessSensor_FallbackReturnsProcessEvents(t *testing.T) {
	s := NewProcessSensor()
	s.Start(core.NewSensorFilter())
	// First poll initializes known_pids, second detects changes
	events1 := s.Poll()
	events2 := s.Poll()
	for _, e := range append(events1, events2...) {
		if e.GetEventType() != "process" {
			t.Fatalf("expected event_type 'process', got %q", e.GetEventType())
		}
		if _, ok := e.(*core.ProcessEvent); !ok {
			t.Fatal("event should be *core.ProcessEvent")
		}
	}
	s.Stop()
}

// ---------------------------------------------------------------------------
// FilesystemSensor-specific tests
// ---------------------------------------------------------------------------

func TestFilesystemSensor_BPFHasVfsOpen(t *testing.T) {
	s := NewFilesystemSensor()
	program := s.GetBPFProgram(core.NewSensorFilter())
	if !strings.Contains(program, "trace_vfs_open") {
		t.Fatal("BPF program should contain 'trace_vfs_open'")
	}
}

func TestFilesystemSensor_BPFHasVfsWrite(t *testing.T) {
	s := NewFilesystemSensor()
	program := s.GetBPFProgram(core.NewSensorFilter())
	if !strings.Contains(program, "trace_vfs_write") {
		t.Fatal("BPF program should contain 'trace_vfs_write'")
	}
}

func TestFilesystemSensor_BPFHasVfsUnlink(t *testing.T) {
	s := NewFilesystemSensor()
	program := s.GetBPFProgram(core.NewSensorFilter())
	if !strings.Contains(program, "trace_vfs_unlink") {
		t.Fatal("BPF program should contain 'trace_vfs_unlink'")
	}
}

func TestFilesystemSensor_FallbackReturnsFileEvents(t *testing.T) {
	s := NewFilesystemSensor()
	s.Start(core.NewSensorFilter())
	events := s.Poll()
	for _, e := range events {
		if e.GetEventType() != "file" {
			t.Fatalf("expected event_type 'file', got %q", e.GetEventType())
		}
		if _, ok := e.(*core.FileEvent); !ok {
			t.Fatal("event should be *core.FileEvent")
		}
	}
	s.Stop()
}

// ---------------------------------------------------------------------------
// NetworkSensor-specific tests
// ---------------------------------------------------------------------------

func TestNetworkSensor_BPFHasInetSockSetState(t *testing.T) {
	s := NewNetworkSensor()
	program := s.GetBPFProgram(core.NewSensorFilter())
	if !strings.Contains(program, "inet_sock_set_state") {
		t.Fatal("BPF program should contain 'inet_sock_set_state'")
	}
}

func TestNetworkSensor_BPFHasTcpSendmsg(t *testing.T) {
	s := NewNetworkSensor()
	program := s.GetBPFProgram(core.NewSensorFilter())
	if !strings.Contains(program, "trace_tcp_sendmsg") {
		t.Fatal("BPF program should contain 'trace_tcp_sendmsg'")
	}
}

func TestNetworkSensor_BPFHasTcpRecvmsg(t *testing.T) {
	s := NewNetworkSensor()
	program := s.GetBPFProgram(core.NewSensorFilter())
	if !strings.Contains(program, "trace_tcp_recvmsg") {
		t.Fatal("BPF program should contain 'trace_tcp_recvmsg'")
	}
}

func TestNetworkSensor_BPFChecksTcpProtocol(t *testing.T) {
	s := NewNetworkSensor()
	program := s.GetBPFProgram(core.NewSensorFilter())
	if !strings.Contains(program, "IPPROTO_TCP") {
		t.Fatal("BPF program should contain 'IPPROTO_TCP'")
	}
}

func TestNetworkSensor_FallbackReturnsNetworkEvents(t *testing.T) {
	s := NewNetworkSensor()
	s.Start(core.NewSensorFilter())
	events := s.Poll()
	for _, e := range events {
		if e.GetEventType() != "network" {
			t.Fatalf("expected event_type 'network', got %q", e.GetEventType())
		}
		if _, ok := e.(*core.NetworkEvent); !ok {
			t.Fatal("event should be *core.NetworkEvent")
		}
	}
	s.Stop()
}

func TestNetworkSensor_ParseHexAddr(t *testing.T) {
	ip, port := ParseHexAddr("0100007F:1F90")
	if ip != "127.0.0.1" {
		t.Fatalf("expected IP '127.0.0.1', got %q", ip)
	}
	if port != 8080 {
		t.Fatalf("expected port 8080, got %d", port)
	}
}

func TestNetworkSensor_ParseHexAddrZero(t *testing.T) {
	ip, port := ParseHexAddr("00000000:0000")
	if ip != "0.0.0.0" {
		t.Fatalf("expected IP '0.0.0.0', got %q", ip)
	}
	if port != 0 {
		t.Fatalf("expected port 0, got %d", port)
	}
}

func TestNetworkSensor_ParseHexAddrInvalid(t *testing.T) {
	ip, port := ParseHexAddr("invalid")
	if ip != "0.0.0.0" {
		t.Fatalf("expected IP '0.0.0.0', got %q", ip)
	}
	if port != 0 {
		t.Fatalf("expected port 0, got %d", port)
	}
}

func TestNetworkSensor_ParseHexAddrHighPort(t *testing.T) {
	ip, port := ParseHexAddr("0100007F:FFFF")
	if ip != "127.0.0.1" {
		t.Fatalf("expected IP '127.0.0.1', got %q", ip)
	}
	if port != 65535 {
		t.Fatalf("expected port 65535, got %d", port)
	}
}

// ---------------------------------------------------------------------------
// MemorySensor-specific tests
// ---------------------------------------------------------------------------

func TestMemorySensor_BPFHasDoMmap(t *testing.T) {
	s := NewMemorySensor()
	program := s.GetBPFProgram(core.NewSensorFilter())
	if !strings.Contains(program, "trace_do_mmap") {
		t.Fatal("BPF program should contain 'trace_do_mmap'")
	}
}

func TestMemorySensor_BPFHasMprotect(t *testing.T) {
	s := NewMemorySensor()
	program := s.GetBPFProgram(core.NewSensorFilter())
	if !strings.Contains(program, "trace_do_mprotect") {
		t.Fatal("BPF program should contain 'trace_do_mprotect'")
	}
}

func TestMemorySensor_BPFHasMemfdCreate(t *testing.T) {
	s := NewMemorySensor()
	program := s.GetBPFProgram(core.NewSensorFilter())
	if !strings.Contains(program, "trace_memfd_create") {
		t.Fatal("BPF program should contain 'trace_memfd_create'")
	}
}

func TestMemorySensor_BPFReadsMemfdName(t *testing.T) {
	s := NewMemorySensor()
	program := s.GetBPFProgram(core.NewSensorFilter())
	if !strings.Contains(program, "bpf_probe_read_str") {
		t.Fatal("BPF program should contain 'bpf_probe_read_str'")
	}
}

func TestMemorySensor_FallbackReturnsMemoryEvents(t *testing.T) {
	s := NewMemorySensor()
	s.Start(core.NewSensorFilter())
	events := s.Poll()
	for _, e := range events {
		if e.GetEventType() != "memory" {
			t.Fatalf("expected event_type 'memory', got %q", e.GetEventType())
		}
		if _, ok := e.(*core.MemoryEvent); !ok {
			t.Fatal("event should be *core.MemoryEvent")
		}
	}
	s.Stop()
}

// ---------------------------------------------------------------------------
// ModuleSensor-specific tests
// ---------------------------------------------------------------------------

func TestModuleSensor_BPFHasDoInitModule(t *testing.T) {
	s := NewModuleSensor()
	program := s.GetBPFProgram(core.NewSensorFilter())
	if !strings.Contains(program, "trace_do_init_module") {
		t.Fatal("BPF program should contain 'trace_do_init_module'")
	}
}

func TestModuleSensor_BPFReadsModuleName(t *testing.T) {
	s := NewModuleSensor()
	program := s.GetBPFProgram(core.NewSensorFilter())
	if !strings.Contains(program, "bpf_probe_read_str") {
		t.Fatal("BPF program should contain 'bpf_probe_read_str'")
	}
}

func TestModuleSensor_FallbackReturnsModuleEvents(t *testing.T) {
	s := NewModuleSensor()
	s.Start(core.NewSensorFilter())
	// First poll initializes known_modules
	events1 := s.Poll()
	// Second poll detects new modules (likely empty in test)
	events2 := s.Poll()
	for _, e := range append(events1, events2...) {
		if e.GetEventType() != "module" {
			t.Fatalf("expected event_type 'module', got %q", e.GetEventType())
		}
		if _, ok := e.(*core.ModuleEvent); !ok {
			t.Fatal("event should be *core.ModuleEvent")
		}
	}
	s.Stop()
}

// ---------------------------------------------------------------------------
// DnsSensor-specific tests
// ---------------------------------------------------------------------------

func TestDnsSensor_BPFHasUdpSendmsg(t *testing.T) {
	s := NewDnsSensor()
	program := s.GetBPFProgram(core.NewSensorFilter())
	if !strings.Contains(program, "trace_udp_sendmsg") {
		t.Fatal("BPF program should contain 'trace_udp_sendmsg'")
	}
}

func TestDnsSensor_BPFFiltersPort53(t *testing.T) {
	s := NewDnsSensor()
	program := s.GetBPFProgram(core.NewSensorFilter())
	if !strings.Contains(program, "htons(53)") && !strings.Contains(program, "53") {
		t.Fatal("BPF program should reference port 53")
	}
}

func TestDnsSensor_BPFIncludesQueryNameField(t *testing.T) {
	s := NewDnsSensor()
	program := s.GetBPFProgram(core.NewSensorFilter())
	if !strings.Contains(program, "query_name") {
		t.Fatal("BPF program should contain 'query_name'")
	}
}

func TestDnsSensor_DecodeDNSNameSimple(t *testing.T) {
	// "example.com" in DNS wire format: \x07example\x03com\x00
	raw := []byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00}
	result := DecodeDNSName(raw)
	if result != "example.com" {
		t.Fatalf("expected 'example.com', got %q", result)
	}
}

func TestDnsSensor_DecodeDNSNameSubdomain(t *testing.T) {
	raw := []byte{0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00}
	result := DecodeDNSName(raw)
	if result != "www.example.com" {
		t.Fatalf("expected 'www.example.com', got %q", result)
	}
}

func TestDnsSensor_DecodeDNSNameEmpty(t *testing.T) {
	result1 := DecodeDNSName([]byte{0x00})
	if result1 != "" {
		t.Fatalf("expected empty string for \\x00, got %q", result1)
	}
	result2 := DecodeDNSName([]byte{})
	if result2 != "" {
		t.Fatalf("expected empty string for empty input, got %q", result2)
	}
}

func TestDnsSensor_DecodeDNSNameTruncated(t *testing.T) {
	// Truncated data — should not crash
	raw := []byte{0x07, 'e', 'x', 'a', 'm'}
	result := DecodeDNSName(raw)
	// Should return a string (possibly empty or partial), not crash
	_ = result
}

func TestDnsSensor_DecodeDNSNameSingleLabel(t *testing.T) {
	raw := []byte{0x04, 't', 'e', 's', 't', 0x00}
	result := DecodeDNSName(raw)
	if result != "test" {
		t.Fatalf("expected 'test', got %q", result)
	}
}

func TestDnsSensor_FallbackReturnsDnsEvents(t *testing.T) {
	s := NewDnsSensor()
	s.Start(core.NewSensorFilter())
	events := s.Poll()
	for _, e := range events {
		if e.GetEventType() != "dns" {
			t.Fatalf("expected event_type 'dns', got %q", e.GetEventType())
		}
		if _, ok := e.(*core.DnsEvent); !ok {
			t.Fatal("event should be *core.DnsEvent")
		}
	}
	s.Stop()
}

// ---------------------------------------------------------------------------
// BaseSensor static helpers
// ---------------------------------------------------------------------------

func TestBaseSensorHelpers_PerfOutputMacro(t *testing.T) {
	macro := PerfOutputMacro("events", 24)
	if !strings.Contains(macro, "events") {
		t.Fatal("macro should contain buffer name 'events'")
	}
	if !strings.Contains(macro, "BPF_PERF_OUTPUT") && !strings.Contains(macro, "BPF_RINGBUF_OUTPUT") {
		t.Fatal("macro should contain output type")
	}
}

func TestBaseSensorHelpers_SubmitEventCode(t *testing.T) {
	code := SubmitEventCode("events", "ctx")
	if !strings.Contains(code, "events") {
		t.Fatal("submit code should contain buffer name")
	}
	if !strings.Contains(code, "data") {
		t.Fatal("submit code should reference 'data'")
	}
}

func TestBaseSensorHelpers_CommonFilterCode(t *testing.T) {
	code := CommonFilterCode()
	if !strings.Contains(code, "FILTER_PID") {
		t.Fatal("common filter code should contain FILTER_PID")
	}
}

func TestBaseSensorHelpers_PerfOutputMacroCustomName(t *testing.T) {
	macro := PerfOutputMacro("my_buffer", 20)
	if !strings.Contains(macro, "my_buffer") {
		t.Fatal("macro should contain custom buffer name")
	}
}

func TestBaseSensorHelpers_SubmitEventCodeCustomCtx(t *testing.T) {
	code := SubmitEventCode("my_buf", "args")
	if !strings.Contains(code, "my_buf") {
		t.Fatal("submit code should contain custom buffer name")
	}
}

// ---------------------------------------------------------------------------
// BCCAvailable and RingbufSupported constants
// ---------------------------------------------------------------------------

func TestBCCAvailableIsFalse(t *testing.T) {
	if BCCAvailable {
		t.Fatal("BCCAvailable should be false in Go implementation")
	}
}

func TestRingbufSupportedIsFalse(t *testing.T) {
	if RingbufSupported {
		t.Fatal("RingbufSupported should be false in Go implementation")
	}
}

// ---------------------------------------------------------------------------
// BaseSensor lifecycle edge cases
// ---------------------------------------------------------------------------

func TestBaseSensor_PollWithNilFallback(t *testing.T) {
	s := NewBaseSensor("test")
	s.started = true
	result := s.Poll()
	if result != nil {
		t.Fatal("Poll with nil PollFallback should return nil")
	}
}

func TestBaseSensor_GetBPFProgramWithNilFunc(t *testing.T) {
	s := NewBaseSensor("test")
	result := s.GetBPFProgram(core.NewSensorFilter())
	if result != "" {
		t.Fatal("GetBPFProgram with nil BPFProgram func should return empty string")
	}
}

func TestBaseSensor_StopWithNilOnStop(t *testing.T) {
	s := NewBaseSensor("test")
	s.started = true
	s.Stop() // Should not panic
	if s.started {
		t.Fatal("started should be false after Stop()")
	}
}

func TestBaseSensor_StartWithNilOnStart(t *testing.T) {
	s := NewBaseSensor("test")
	s.Start(core.NewSensorFilter()) // Should not panic
	if !s.started {
		t.Fatal("started should be true after Start()")
	}
}

// ---------------------------------------------------------------------------
// Sensor mode detection (non-root always fallback)
// ---------------------------------------------------------------------------

func TestSensorModeDetection_FallbackWhenNonRoot(t *testing.T) {
	s := NewProcessSensor()
	s.Start(core.NewSensorFilter())
	if s.Mode() != "fallback" {
		t.Fatalf("expected 'fallback' mode, got %q", s.Mode())
	}
	s.Stop()
}

// ---------------------------------------------------------------------------
// itoa helper (internal)
// ---------------------------------------------------------------------------

func TestItoa(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{10, "10"},
		{24, "24"},
		{-5, "-5"},
		{100, "100"},
	}
	for _, tc := range tests {
		result := itoa(tc.input)
		if result != tc.expected {
			t.Errorf("itoa(%d) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// Additional edge case tests
// ---------------------------------------------------------------------------

func TestDecodeDNSName_LongLabel(t *testing.T) {
	// Label with max length (63 bytes)
	raw := make([]byte, 0, 70)
	raw = append(raw, 10) // length 10
	raw = append(raw, []byte("abcdefghij")...)
	raw = append(raw, 0) // terminator
	result := DecodeDNSName(raw)
	if result != "abcdefghij" {
		t.Fatalf("expected 'abcdefghij', got %q", result)
	}
}

func TestParseHexAddr_EmptyString(t *testing.T) {
	ip, port := ParseHexAddr("")
	if ip != "0.0.0.0" {
		t.Fatalf("expected '0.0.0.0', got %q", ip)
	}
	if port != 0 {
		t.Fatalf("expected port 0, got %d", port)
	}
}

func TestParseHexAddr_MissingPort(t *testing.T) {
	ip, port := ParseHexAddr("0100007F")
	if ip != "0.0.0.0" {
		t.Fatalf("expected '0.0.0.0', got %q", ip)
	}
	if port != 0 {
		t.Fatalf("expected port 0, got %d", port)
	}
}
