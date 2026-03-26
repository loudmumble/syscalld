// Package sensors provides the sensor implementations for the eBPF framework.
//
// Each sensor monitors a specific category of kernel activity (syscalls,
// processes, filesystem, network, memory, modules, DNS). In this Go
// implementation, eBPF interaction is simulated — the sensors provide a
// clean interface that in production would use cilium/ebpf, but here they
// use /proc-based fallback polling.
package sensors

import (
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
type BaseSensor struct {
	name    string
	mode    string
	started bool
	filter  *core.SensorFilter

	// Health metrics — eventCount and errorCount are accessed atomically.
	eventCount  uint64
	errorCount  uint64
	startTime   time.Time
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
	return s.mode
}

// Started returns whether the sensor has been started.
func (s *BaseSensor) Started() bool {
	return s.started
}

// Start initializes the sensor. Since BCC is not available in Go,
// it always uses fallback mode (reading /proc).
func (s *BaseSensor) Start(filters *core.SensorFilter) {
	if s.started {
		return
	}
	s.started = true
	s.startTime = time.Now()
	s.filter = filters
	s.mode = "fallback"
	if s.OnStart != nil {
		s.OnStart(filters)
	}
}

// Stop cleans up the sensor and resets the started flag.
func (s *BaseSensor) Stop() {
	s.started = false
	if s.OnStop != nil {
		s.OnStop()
	}
}

// Poll retrieves pending events from the sensor. It increments the event
// counter and records the last-event timestamp for health tracking.
func (s *BaseSensor) Poll() []core.Event {
	if !s.started {
		return nil
	}
	if s.PollFallback == nil {
		return nil
	}
	events := s.PollFallback()
	if len(events) > 0 {
		atomic.AddUint64(&s.eventCount, uint64(len(events)))
		s.healthMu.Lock()
		s.lastEventAt = time.Now()
		s.healthMu.Unlock()
	}
	return events
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
	return core.SensorHealth{
		Name:        s.name,
		Mode:        s.mode,
		Started:     s.started,
		EventCount:  atomic.LoadUint64(&s.eventCount),
		ErrorCount:  atomic.LoadUint64(&s.errorCount),
		StartTime:   s.startTime,
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
		return "BPF_RINGBUF_OUTPUT(" + name + ", 1 << " + itoa(sizeShift) + ");"
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

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	if neg {
		s = "-" + s
	}
	return s
}
