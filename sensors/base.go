// Package sensors provides the sensor implementations for the eBPF framework.
//
// Each sensor monitors a specific category of kernel activity (syscalls,
// processes, filesystem, network, memory, modules, DNS). In this Go
// implementation, eBPF interaction is simulated — the sensors provide a
// clean interface that in production would use cilium/ebpf, but here they
// use /proc-based fallback polling.
package sensors

import (
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/loudmumble/syscalld/core"
)

// BCCAvailable indicates whether BCC is available for eBPF program loading.
// In the Go implementation, this is always false (fallback mode only).
const BCCAvailable = false

// RingbufSupported indicates whether BPF ring buffer is supported.
// In the Go implementation, this is always false (perf output path).
const RingbufSupported = false

// KernelCapabilities reports dynamic eBPF capability detection results.
type KernelCapabilities struct {
	RingbufSupported bool
	KernelVersion    string
	Major            int
	Minor            int
}

// DetectKernelCapabilities probes the running kernel version via uname(2)
// and returns capability flags. Ringbuf requires kernel >= 5.8.
func DetectKernelCapabilities() KernelCapabilities {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return KernelCapabilities{}
	}

	release := utsnameReleaseToString(uts.Release[:])
	major, minor := parseKernelVersion(release)

	return KernelCapabilities{
		RingbufSupported: major > 5 || (major == 5 && minor >= 8),
		KernelVersion:    release,
		Major:            major,
		Minor:            minor,
	}
}

// utsnameReleaseToString converts the Utsname.Release array to a string.
// The element type varies by arch (int8 on amd64, byte on arm64); we cast
// through byte to handle both.
func utsnameReleaseToString[T byte | int8](s []T) string {
	b := make([]byte, 0, len(s))
	for _, v := range s {
		if v == 0 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}

func parseKernelVersion(release string) (major, minor int) {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return 0, 0
	}
	for _, c := range parts[0] {
		if c >= '0' && c <= '9' {
			major = major*10 + int(c-'0')
		} else {
			break
		}
	}
	for _, c := range parts[1] {
		if c >= '0' && c <= '9' {
			minor = minor*10 + int(c-'0')
		} else {
			break
		}
	}
	return
}

// BaseSensor provides common functionality for all sensor implementations.
// Concrete sensors embed this and assign the BPFProgram, PollFallback,
// OnStart, and OnStop function fields during construction.
//
// Thread safety: stateMu protects started, mode, filter, and startTime.
// healthMu protects lastEventAt. eventCount and errorCount use atomics.
type BaseSensor struct {
	name string

	// stateMu protects started, mode, filter, startTime against concurrent
	// access from Start/Stop (caller goroutine) and Poll/Health (poll loop).
	stateMu   sync.RWMutex
	mode      string
	started   bool
	filter    *core.SensorFilter
	startTime time.Time

	// Health metrics — eventCount and errorCount are accessed atomically.
	eventCount  uint64
	errorCount  uint64
	healthMu    sync.Mutex
	lastEventAt time.Time

	// PollFallback is called each poll cycle in fallback mode.
	// Concrete sensors set this during construction.
	PollFallback func() []core.Event

	// BPFProgram generates the BPF C source code for this sensor.
	BPFProgram func(filters *core.SensorFilter) string

	// OnStart is called during Start for sensor-specific initialization.
	OnStart func(filters *core.SensorFilter)

	// OnStop is called during Stop for sensor-specific cleanup.
	OnStop func()
}

// NewBaseSensor creates a new BaseSensor with the given name.
func NewBaseSensor(name string) *BaseSensor {
	return &BaseSensor{
		name: name,
		mode: "fallback",
	}
}

// Name returns the sensor's identifier.
func (s *BaseSensor) Name() string {
	return s.name
}

// Mode returns the current operating mode ("fallback" or "ebpf").
func (s *BaseSensor) Mode() string {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.mode
}

// Started returns whether the sensor has been started.
func (s *BaseSensor) Started() bool {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.started
}

// Start initializes the sensor. Since BCC is not available in Go,
// it always uses fallback mode (reading /proc).
func (s *BaseSensor) Start(filters *core.SensorFilter) {
	s.stateMu.Lock()
	if s.started {
		s.stateMu.Unlock()
		return
	}
	s.started = true
	s.startTime = time.Now()
	s.filter = filters
	s.mode = "fallback"
	s.stateMu.Unlock()

	if s.OnStart != nil {
		s.OnStart(filters)
	}
}

// Stop cleans up the sensor and resets the started flag.
func (s *BaseSensor) Stop() {
	s.stateMu.Lock()
	s.started = false
	s.stateMu.Unlock()

	if s.OnStop != nil {
		s.OnStop()
	}
}

// Poll retrieves pending events from the sensor. Events are filtered through
// the SensorFilter before being returned. It increments the event counter and
// records the last-event timestamp for health tracking.
func (s *BaseSensor) Poll() []core.Event {
	s.stateMu.RLock()
	started := s.started
	filter := s.filter
	s.stateMu.RUnlock()
	if !started {
		return nil
	}
	if s.PollFallback == nil {
		return nil
	}
	events := s.PollFallback()
	events = filterEvents(events, filter)
	if len(events) > 0 {
		atomic.AddUint64(&s.eventCount, uint64(len(events)))
		s.healthMu.Lock()
		s.lastEventAt = time.Now()
		s.healthMu.Unlock()
	}
	return events
}

// filterEvents applies PID, comm, and syscall filters to a slice of events.
// Events that don't match the filter criteria are dropped.
func filterEvents(events []core.Event, filter *core.SensorFilter) []core.Event {
	if filter == nil || len(events) == 0 {
		return events
	}
	hasPIDFilter := len(filter.TargetPIDs) > 0
	hasCommFilter := len(filter.ExcludeComms) > 0
	hasSyscallFilter := len(filter.SyscallWhitelist) > 0
	if !hasPIDFilter && !hasCommFilter && !hasSyscallFilter {
		return events
	}

	filtered := make([]core.Event, 0, len(events))
	for _, evt := range events {
		pid, comm, syscallNR := extractEventContext(evt)
		if hasPIDFilter && !filter.MatchesPID(pid) {
			continue
		}
		if hasCommFilter && !filter.MatchesComm(comm) {
			continue
		}
		if hasSyscallFilter && syscallNR >= 0 && !filter.MatchesSyscall(syscallNR) {
			continue
		}
		filtered = append(filtered, evt)
	}
	return filtered
}

// extractEventContext pulls PID, comm, and syscall NR from any event type.
// Returns syscallNR=-1 for non-syscall events.
func extractEventContext(evt core.Event) (pid int, comm string, syscallNR int) {
	syscallNR = -1
	switch e := evt.(type) {
	case *core.SyscallEvent:
		return e.PID, e.Comm, e.SyscallNR
	case *core.ProcessEvent:
		return e.PID, e.Comm, -1
	case *core.FileEvent:
		return e.PID, e.Comm, -1
	case *core.NetworkEvent:
		return e.PID, e.Comm, -1
	case *core.MemoryEvent:
		return e.PID, e.Comm, -1
	case *core.ModuleEvent:
		return e.PID, e.Comm, -1
	case *core.DnsEvent:
		return e.PID, e.Comm, -1
	case *core.CanaryEvent:
		return e.PID, e.Comm, -1
	case *core.KernelEvent:
		return e.PID, e.Comm, -1
	default:
		return 0, "", -1
	}
}

// IncrErrorCount records a recoverable error in the sensor's health stats.
// Call this from PollFallback or BPF callbacks on non-fatal errors.
func (s *BaseSensor) IncrErrorCount() {
	atomic.AddUint64(&s.errorCount, 1)
}

// Health returns a snapshot of this sensor's runtime statistics.
// The snapshot is safe to read after return — no pointers into internal state.
func (s *BaseSensor) Health() core.SensorHealth {
	s.healthMu.Lock()
	lastEvt := s.lastEventAt
	s.healthMu.Unlock()

	s.stateMu.RLock()
	mode := s.mode
	started := s.started
	startTime := s.startTime
	s.stateMu.RUnlock()

	return core.SensorHealth{
		Name:        s.name,
		Mode:        mode,
		Started:     started,
		EventCount:  atomic.LoadUint64(&s.eventCount),
		ErrorCount:  atomic.LoadUint64(&s.errorCount),
		StartTime:   startTime,
		LastEventAt: lastEvt,
	}
}

// Chan returns a nil channel for BaseSensor; eBPF sensor variants override this.
func (s *BaseSensor) Chan() <-chan core.Event {
	return nil
}

// GetBPFProgram returns the BPF C program text for the given filters.
func (s *BaseSensor) GetBPFProgram(filters *core.SensorFilter) string {
	if s.BPFProgram != nil {
		return s.BPFProgram(filters)
	}
	return ""
}

// PerfOutputMacro generates the appropriate output buffer declaration macro.
func PerfOutputMacro(name string, sizeShift int) string {
	if RingbufSupported {
		return "BPF_RINGBUF_OUTPUT(" + name + ", 1 << " + strconv.Itoa(sizeShift) + ");"
	}
	return "BPF_PERF_OUTPUT(" + name + ");"
}

// SubmitEventCode generates the C code to submit an event to the output buffer.
func SubmitEventCode(bufName string, ctx string) string {
	if RingbufSupported {
		return bufName + ".ringbuf_output(&data, sizeof(data), 0);"
	}
	return bufName + ".perf_submit(" + ctx + ", &data, sizeof(data));"
}

// CommonFilterCode generates common C filter code using #defines from SensorFilter.
func CommonFilterCode() string {
	return `
    // PID filtering
    #ifdef FILTER_PID_ENABLED
      #ifdef FILTER_PID
        if (pid != FILTER_PID) return 0;
      #endif
    #endif

    // Comm exclusion filtering
    #ifdef FILTER_EXCLUDE_COMM_ENABLED
    {
        struct comm_key_t __ck = {};
        bpf_get_current_comm(&__ck.comm, sizeof(__ck.comm));
        u8 *__excluded = excluded_comms.lookup(&__ck);
        if (__excluded) return 0;
    }
    #endif
`
}

