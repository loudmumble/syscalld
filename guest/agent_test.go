package guest

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/loudmumble/syscalld/core"
	"github.com/loudmumble/syscalld/sensors"
)

// ---------------------------------------------------------------------------
// Module import / registry
// ---------------------------------------------------------------------------

func TestSensorRegistryHasAllSeven(t *testing.T) {
	if len(SensorRegistry) != 7 {
		t.Fatalf("expected 7 sensors in registry, got %d", len(SensorRegistry))
	}
	expected := []string{"syscall", "process", "filesystem", "network", "memory", "module", "dns"}
	for _, name := range expected {
		if _, ok := SensorRegistry[name]; !ok {
			t.Fatalf("sensor %q missing from registry", name)
		}
	}
}

func TestAllSensorNamesMatchesRegistry(t *testing.T) {
	names := AllSensorNames()
	nameSet := make(map[string]struct{})
	for _, n := range names {
		nameSet[n] = struct{}{}
	}
	regSet := make(map[string]struct{})
	for k := range SensorRegistry {
		regSet[k] = struct{}{}
	}
	if len(nameSet) != len(regSet) {
		t.Fatalf("AllSensorNames (%d) != SensorRegistry (%d)", len(nameSet), len(regSet))
	}
	for k := range regSet {
		if _, ok := nameSet[k]; !ok {
			t.Fatalf("registry key %q not in AllSensorNames", k)
		}
	}
}

func TestAllSensorNamesCount(t *testing.T) {
	names := AllSensorNames()
	if len(names) != 7 {
		t.Fatalf("expected 7 sensor names, got %d", len(names))
	}
}

func TestDefaultVirtioPath(t *testing.T) {
	if DefaultVirtioPath == "" {
		t.Fatal("DefaultVirtioPath should not be empty")
	}
	if !strings.HasPrefix(DefaultVirtioPath, "/dev/") {
		t.Fatalf("DefaultVirtioPath should start with /dev/, got %q", DefaultVirtioPath)
	}
}

// ---------------------------------------------------------------------------
// Event serialization
// ---------------------------------------------------------------------------

func TestSerializeEvent_BaseEvent(t *testing.T) {
	event := &core.KernelEvent{Timestamp: 1.5, PID: 42, Comm: "bash", EventType: "base"}
	line, err := SerializeEvent(event)
	if err != nil {
		t.Fatalf("SerializeEvent failed: %v", err)
	}
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(line), &data); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if data["event_type"] != "base" {
		t.Fatalf("expected event_type 'base', got %v", data["event_type"])
	}
	if int(data["pid"].(float64)) != 42 {
		t.Fatalf("expected pid 42, got %v", data["pid"])
	}
	if data["comm"] != "bash" {
		t.Fatalf("expected comm 'bash', got %v", data["comm"])
	}
}

func TestSerializeEvent_SyscallEvent(t *testing.T) {
	event := &core.SyscallEvent{
		KernelEvent: core.KernelEvent{Timestamp: 2.0, PID: 100, Comm: "cat", EventType: "syscall"},
		SyscallNR:   59,
		SyscallName: "execve",
		Args:        []int{1, 2, 3},
		Ret:         0,
		Phase:       "enter",
	}
	line, err := SerializeEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]interface{}
	json.Unmarshal([]byte(line), &data)
	if data["event_type"] != "syscall" {
		t.Fatalf("expected 'syscall', got %v", data["event_type"])
	}
	if int(data["syscall_nr"].(float64)) != 59 {
		t.Fatalf("expected syscall_nr 59, got %v", data["syscall_nr"])
	}
	if data["syscall_name"] != "execve" {
		t.Fatalf("expected 'execve', got %v", data["syscall_name"])
	}
	if data["phase"] != "enter" {
		t.Fatalf("expected phase 'enter', got %v", data["phase"])
	}
}

func TestSerializeEvent_ProcessEvent(t *testing.T) {
	event := &core.ProcessEvent{
		KernelEvent: core.KernelEvent{Timestamp: 3.0, PID: 200, EventType: "process"},
		Action:      "exec",
		PPID:        1,
		Filename:    "/bin/ls",
		Argv:        []string{"ls", "-la"},
	}
	line, err := SerializeEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]interface{}
	json.Unmarshal([]byte(line), &data)
	if data["event_type"] != "process" {
		t.Fatalf("expected 'process', got %v", data["event_type"])
	}
	if data["action"] != "exec" {
		t.Fatalf("expected action 'exec', got %v", data["action"])
	}
	if data["filename"] != "/bin/ls" {
		t.Fatalf("expected filename '/bin/ls', got %v", data["filename"])
	}
}

func TestSerializeEvent_NetworkEvent(t *testing.T) {
	event := &core.NetworkEvent{
		KernelEvent: core.KernelEvent{Timestamp: 4.0, PID: 300, EventType: "network"},
		SAddr:       "10.0.0.1",
		DAddr:       "1.2.3.4",
		SPort:       12345,
		DPort:       443,
	}
	line, err := SerializeEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]interface{}
	json.Unmarshal([]byte(line), &data)
	if data["event_type"] != "network" {
		t.Fatalf("expected 'network', got %v", data["event_type"])
	}
	if int(data["dport"].(float64)) != 443 {
		t.Fatalf("expected dport 443, got %v", data["dport"])
	}
	if data["saddr"] != "10.0.0.1" {
		t.Fatalf("expected saddr '10.0.0.1', got %v", data["saddr"])
	}
}

func TestSerializeEvent_FileEvent(t *testing.T) {
	event := &core.FileEvent{
		KernelEvent: core.KernelEvent{Timestamp: 5.0, PID: 400, EventType: "file"},
		Operation:   "open",
		Path:        "/etc/passwd",
		Flags:       0,
		Mode:        0o644,
	}
	line, err := SerializeEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]interface{}
	json.Unmarshal([]byte(line), &data)
	if data["event_type"] != "file" {
		t.Fatalf("expected 'file', got %v", data["event_type"])
	}
	if data["path"] != "/etc/passwd" {
		t.Fatalf("expected path '/etc/passwd', got %v", data["path"])
	}
}

func TestSerializeEvent_MemoryEvent(t *testing.T) {
	event := &core.MemoryEvent{
		KernelEvent: core.KernelEvent{Timestamp: 6.0, PID: 500, EventType: "memory"},
		Operation:   "mmap",
		Addr:        0x7FFF0000,
		Length:      4096,
	}
	line, err := SerializeEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]interface{}
	json.Unmarshal([]byte(line), &data)
	if data["event_type"] != "memory" {
		t.Fatalf("expected 'memory', got %v", data["event_type"])
	}
	if uint64(data["addr"].(float64)) != 0x7FFF0000 {
		t.Fatalf("expected addr 0x7FFF0000, got %v", data["addr"])
	}
}

func TestSerializeEvent_ModuleEvent(t *testing.T) {
	event := &core.ModuleEvent{
		KernelEvent: core.KernelEvent{Timestamp: 7.0, PID: 600, EventType: "module"},
		Operation:   "load",
		ModuleName:  "evil_mod",
	}
	line, err := SerializeEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]interface{}
	json.Unmarshal([]byte(line), &data)
	if data["event_type"] != "module" {
		t.Fatalf("expected 'module', got %v", data["event_type"])
	}
	if data["module_name"] != "evil_mod" {
		t.Fatalf("expected module_name 'evil_mod', got %v", data["module_name"])
	}
}

func TestSerializeEvent_DnsEvent(t *testing.T) {
	event := &core.DnsEvent{
		KernelEvent: core.KernelEvent{Timestamp: 8.0, PID: 700, EventType: "dns"},
		QueryName:   "evil.com",
		QueryType:   1,
		DestIP:      "8.8.8.8",
	}
	line, err := SerializeEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]interface{}
	json.Unmarshal([]byte(line), &data)
	if data["event_type"] != "dns" {
		t.Fatalf("expected 'dns', got %v", data["event_type"])
	}
	if data["query_name"] != "evil.com" {
		t.Fatalf("expected query_name 'evil.com', got %v", data["query_name"])
	}
}

func TestSerializeEvent_CompactJSON(t *testing.T) {
	event := &core.KernelEvent{PID: 1, EventType: "base"}
	line, err := SerializeEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(line, "\n") {
		t.Fatal("serialized event should not contain newlines")
	}
	// Compact JSON should be parseable
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(line), &data); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
}

func TestSerializeEvent_NDJSONFormat(t *testing.T) {
	events := []core.Event{
		&core.SyscallEvent{
			KernelEvent: core.KernelEvent{PID: 1, EventType: "syscall"},
			SyscallNR:   59,
		},
		&core.ProcessEvent{
			KernelEvent: core.KernelEvent{PID: 2, EventType: "process"},
			Action:      "fork",
		},
	}
	var lines []string
	for _, e := range events {
		line, err := SerializeEvent(e)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, line+"\n")
	}
	for _, line := range lines {
		if !strings.HasSuffix(line, "\n") {
			t.Fatal("NDJSON line should end with newline")
		}
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &data); err != nil {
			t.Fatalf("invalid JSON in NDJSON: %v", err)
		}
		if _, ok := data["event_type"]; !ok {
			t.Fatal("NDJSON line should contain event_type")
		}
	}
}

// ---------------------------------------------------------------------------
// Sensor selection
// ---------------------------------------------------------------------------

func TestSelectSensors_AllDefault(t *testing.T) {
	sensorList, err := SelectSensors(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sensorList) != 7 {
		t.Fatalf("expected 7 sensors, got %d", len(sensorList))
	}
	names := make(map[string]struct{})
	for _, s := range sensorList {
		names[s.Name()] = struct{}{}
	}
	for _, expected := range AllSensorNames() {
		if _, ok := names[expected]; !ok {
			t.Fatalf("missing sensor %q", expected)
		}
	}
}

func TestSelectSensors_Subset(t *testing.T) {
	sensorList, err := SelectSensors([]string{"syscall", "network"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sensorList) != 2 {
		t.Fatalf("expected 2 sensors, got %d", len(sensorList))
	}
	names := make(map[string]struct{})
	for _, s := range sensorList {
		names[s.Name()] = struct{}{}
	}
	if _, ok := names["syscall"]; !ok {
		t.Fatal("missing 'syscall'")
	}
	if _, ok := names["network"]; !ok {
		t.Fatal("missing 'network'")
	}
}

func TestSelectSensors_Single(t *testing.T) {
	sensorList, err := SelectSensors([]string{"dns"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sensorList) != 1 {
		t.Fatalf("expected 1 sensor, got %d", len(sensorList))
	}
	if sensorList[0].Name() != "dns" {
		t.Fatalf("expected 'dns', got %q", sensorList[0].Name())
	}
}

func TestSelectSensors_UnknownRaises(t *testing.T) {
	_, err := SelectSensors([]string{"nonexistent"})
	if err == nil {
		t.Fatal("expected error for unknown sensor")
	}
	if !strings.Contains(err.Error(), "unknown sensor") {
		t.Fatalf("error should mention 'unknown sensor', got: %v", err)
	}
}

func TestSelectSensors_AllAreBaseSensor(t *testing.T) {
	sensorList, err := SelectSensors(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sensorList {
		if _, ok := s.(interface{ Name() string }); !ok {
			t.Fatalf("sensor %q does not implement Name()", s.Name())
		}
	}
}

func TestSelectSensors_EmptyList(t *testing.T) {
	sensorList, err := SelectSensors([]string{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sensorList) != 0 {
		t.Fatalf("expected 0 sensors for empty list, got %d", len(sensorList))
	}
}

func TestSelectSensors_DuplicateNames(t *testing.T) {
	sensorList, err := SelectSensors([]string{"dns", "dns"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sensorList) != 2 {
		t.Fatalf("expected 2 sensors (duplicates allowed), got %d", len(sensorList))
	}
}

// ---------------------------------------------------------------------------
// GuestAgentRunner lifecycle
// ---------------------------------------------------------------------------

func TestGuestAgentRunner_StartStop(t *testing.T) {
	var buf bytes.Buffer
	sensorList, _ := SelectSensors([]string{"syscall"})
	runner := NewGuestAgentRunner(AgentConfig{
		Output:       &buf,
		Sensors:      sensorList,
		SensorFilter: core.NewSensorFilter(),
		Fallback:     true,
	})
	runner.Start()
	if !runner.Running() {
		t.Fatal("runner should be running after Start()")
	}
	if runner.EventCount() != 0 {
		t.Fatalf("expected 0 events initially, got %d", runner.EventCount())
	}
	runner.Stop()
	if runner.Running() {
		t.Fatal("runner should not be running after Stop()")
	}
}

func TestGuestAgentRunner_DoubleStartSafe(t *testing.T) {
	var buf bytes.Buffer
	runner := NewGuestAgentRunner(AgentConfig{
		Output:       &buf,
		Sensors:      mustSelectSensors([]string{"syscall"}),
		SensorFilter: core.NewSensorFilter(),
		Fallback:     true,
	})
	runner.Start()
	runner.Start() // Should not panic
	if !runner.Running() {
		t.Fatal("runner should be running")
	}
	runner.Stop()
}

func TestGuestAgentRunner_DoubleStopSafe(t *testing.T) {
	var buf bytes.Buffer
	runner := NewGuestAgentRunner(AgentConfig{
		Output:       &buf,
		Sensors:      mustSelectSensors([]string{"syscall"}),
		SensorFilter: core.NewSensorFilter(),
		Fallback:     true,
	})
	runner.Start()
	runner.Stop()
	runner.Stop() // Should not panic
	if runner.Running() {
		t.Fatal("runner should not be running")
	}
}

func TestGuestAgentRunner_HandleEventIncrementsCount(t *testing.T) {
	var buf bytes.Buffer
	runner := NewGuestAgentRunner(AgentConfig{
		Output:       &buf,
		Sensors:      mustSelectSensors([]string{"syscall"}),
		SensorFilter: core.NewSensorFilter(),
		Fallback:     true,
	})
	runner.Start()
	event := &core.SyscallEvent{
		KernelEvent: core.KernelEvent{PID: 42, EventType: "syscall"},
		SyscallNR:   59,
	}
	runner.handleEvent(event)
	if runner.EventCount() != 1 {
		t.Fatalf("expected event count 1, got %d", runner.EventCount())
	}
	content := buf.String()
	if !strings.HasSuffix(content, "\n") {
		t.Fatal("output should end with newline")
	}
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(content)), &data); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if int(data["pid"].(float64)) != 42 {
		t.Fatalf("expected pid 42, got %v", data["pid"])
	}
	runner.Stop()
}

func TestGuestAgentRunner_HandleEventWriteErrorLogged(t *testing.T) {
	// Use a writer that always fails
	runner := NewGuestAgentRunner(AgentConfig{
		Output:       &failWriter{},
		Sensors:      mustSelectSensors([]string{"syscall"}),
		SensorFilter: core.NewSensorFilter(),
		Fallback:     true,
	})
	runner.Start()
	// Should not panic, just log error
	runner.handleEvent(&core.SyscallEvent{
		KernelEvent: core.KernelEvent{PID: 1, EventType: "syscall"},
	})
	if runner.EventCount() != 0 {
		t.Fatalf("expected 0 events on write error, got %d", runner.EventCount())
	}
	runner.Stop()
}

func TestGuestAgentRunner_PIDFilterPassedToManager(t *testing.T) {
	var buf bytes.Buffer
	filt := core.NewSensorFilter()
	filt.TargetPIDs[999] = struct{}{}
	runner := NewGuestAgentRunner(AgentConfig{
		Output:       &buf,
		Sensors:      mustSelectSensors([]string{"syscall"}),
		SensorFilter: filt,
		Fallback:     true,
	})
	if _, ok := runner.Manager().Filters.TargetPIDs[999]; !ok {
		t.Fatal("PID 999 should be in manager's filter")
	}
}

func TestGuestAgentRunner_ManagerProperty(t *testing.T) {
	var buf bytes.Buffer
	runner := NewGuestAgentRunner(AgentConfig{
		Output:       &buf,
		Sensors:      mustSelectSensors([]string{"syscall"}),
		SensorFilter: core.NewSensorFilter(),
		Fallback:     true,
	})
	if runner.Manager() == nil {
		t.Fatal("Manager() should not be nil")
	}
}

func TestGuestAgentRunner_FallbackFlagActivates(t *testing.T) {
	var buf bytes.Buffer
	sensorList := mustSelectSensors([]string{"syscall"})
	runner := NewGuestAgentRunner(AgentConfig{
		Output:       &buf,
		Sensors:      sensorList,
		SensorFilter: core.NewSensorFilter(),
		Fallback:     true,
	})
	runner.Start()
	if !runner.Running() {
		t.Fatal("runner should be running")
	}
	for _, s := range sensorList {
		if s.Mode() != "fallback" {
			t.Fatalf("sensor %q should be in fallback mode, got %q", s.Name(), s.Mode())
		}
	}
	runner.Stop()
}

func TestGuestAgentRunner_FallbackWritesEvents(t *testing.T) {
	var buf bytes.Buffer
	sensorList := mustSelectSensors([]string{"process"})
	runner := NewGuestAgentRunner(AgentConfig{
		Output:       &buf,
		Sensors:      sensorList,
		SensorFilter: core.NewSensorFilter(),
		Fallback:     true,
	})
	runner.Start()
	// Run one manual poll cycle
	for _, s := range sensorList {
		events := s.Poll()
		for _, event := range events {
			runner.handleEvent(event)
		}
	}
	runner.Stop()
	// Output should be parseable NDJSON (may be empty if no /proc changes)
	content := buf.String()
	for _, line := range strings.Split(strings.TrimSpace(content), "\n") {
		if line == "" {
			continue
		}
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(line), &data); err != nil {
			t.Fatalf("invalid NDJSON line: %v", err)
		}
		if _, ok := data["event_type"]; !ok {
			t.Fatal("NDJSON line should contain event_type")
		}
	}
}

// ---------------------------------------------------------------------------
// Signal handling
// ---------------------------------------------------------------------------

func TestSetupSignalHandlers_DoesNotPanic(t *testing.T) {
	var buf bytes.Buffer
	runner := NewGuestAgentRunner(AgentConfig{
		Output:       &buf,
		Sensors:      mustSelectSensors([]string{"syscall"}),
		SensorFilter: core.NewSensorFilter(),
		Fallback:     true,
	})
	runner.Start()
	// SetupSignalHandlers should not panic
	SetupSignalHandlers(runner)
	runner.Stop()
}

// ---------------------------------------------------------------------------
// Multiple sensors in runner
// ---------------------------------------------------------------------------

func TestGuestAgentRunner_MultipleSensors(t *testing.T) {
	var buf bytes.Buffer
	sensorList := mustSelectSensors([]string{"syscall", "process", "dns"})
	runner := NewGuestAgentRunner(AgentConfig{
		Output:       &buf,
		Sensors:      sensorList,
		SensorFilter: core.NewSensorFilter(),
		Fallback:     true,
	})
	runner.Start()
	if !runner.Running() {
		t.Fatal("runner should be running")
	}
	if runner.Manager().SensorCount() != 3 {
		t.Fatalf("expected 3 sensors in manager, got %d", runner.Manager().SensorCount())
	}
	runner.Stop()
}

func TestGuestAgentRunner_AllSensors(t *testing.T) {
	var buf bytes.Buffer
	sensorList := mustSelectSensors(nil)
	runner := NewGuestAgentRunner(AgentConfig{
		Output:       &buf,
		Sensors:      sensorList,
		SensorFilter: core.NewSensorFilter(),
		Fallback:     true,
	})
	runner.Start()
	if runner.Manager().SensorCount() != 7 {
		t.Fatalf("expected 7 sensors in manager, got %d", runner.Manager().SensorCount())
	}
	runner.Stop()
}

// ---------------------------------------------------------------------------
// Sensor constructors from registry produce correct types
// ---------------------------------------------------------------------------

func TestSensorRegistryConstructors(t *testing.T) {
	expectedTypes := map[string]string{
		"syscall":    "*sensors.SyscallSensor",
		"process":    "*sensors.ProcessSensor",
		"filesystem": "*sensors.FilesystemSensor",
		"network":    "*sensors.NetworkSensor",
		"memory":     "*sensors.MemorySensor",
		"module":     "*sensors.ModuleSensor",
		"dns":        "*sensors.DnsSensor",
	}
	for name, ctor := range SensorRegistry {
		s := ctor()
		if s.Name() != name {
			t.Errorf("sensor from registry[%q] has name %q", name, s.Name())
		}
		_ = expectedTypes[name]
	}
}

func TestSensorRegistryConstructors_ImplementSensor(t *testing.T) {
	for name, ctor := range SensorRegistry {
		s := ctor()
		// Verify it implements core.Sensor
		var _ core.Sensor = s
		if s.Name() != name {
			t.Errorf("sensor %q has wrong name %q", name, s.Name())
		}
	}
}

// ---------------------------------------------------------------------------
// BaseSensor type assertion from registry
// ---------------------------------------------------------------------------

func TestRegistrySensorsAreBaseSensor(t *testing.T) {
	for name, ctor := range SensorRegistry {
		s := ctor()
		// All sensors should have Mode() returning "fallback" initially
		if s.Mode() != "fallback" {
			t.Errorf("sensor %q initial mode should be 'fallback', got %q", name, s.Mode())
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// mustSelectSensors wraps SelectSensors and panics on error (for test setup).
func mustSelectSensors(names []string) []core.Sensor {
	s, err := SelectSensors(names)
	if err != nil {
		panic(err)
	}
	return s
}

// failWriter is an io.Writer that always returns an error.
type failWriter struct{}

func (w *failWriter) Write(p []byte) (int, error) {
	return 0, &writeError{}
}

type writeError struct{}

func (e *writeError) Error() string { return "write failed" }

// Ensure sensors package is used (avoid unused import)
var _ = sensors.NewSyscallSensor
