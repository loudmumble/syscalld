package sensors

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/loudmumble/syscalld/core"
)

// DnsSensor captures DNS queries by hooking UDP sends to port 53.
// In fallback mode, it scans /proc/net/udp for sockets with a remote port of 53,
// emitting a DnsEvent for each newly observed resolver connection. Process
// attribution is performed via socket inode → /proc/[pid]/fd lookup.
type DnsSensor struct {
	*BaseSensor
	knownConns map[string]struct{} // key: "localAddr-remoteAddr" (raw hex from /proc/net/udp)
}

// NewDnsSensor creates a new DnsSensor.
func NewDnsSensor() *DnsSensor {
	s := &DnsSensor{
		BaseSensor: NewBaseSensor("dns"),
		knownConns: make(map[string]struct{}),
	}
	s.BPFProgram = s.bpfProgram
	s.PollFallback = s.pollFallback
	return s
}

func (s *DnsSensor) bpfProgram(filters *core.SensorFilter) string {
	defines := filters.ToBPFDefines()
	outputMacro := PerfOutputMacro("events", 24)
	submitCode := SubmitEventCode("events", "ctx")

	return fmt.Sprintf(`%s
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/udp.h>

struct dns_data_t {
    u64 timestamp;
    u32 pid;
    u32 tid;
    u32 uid;
    u32 daddr;
    u16 dport;
    u16 query_type;
    char comm[16];
    char query_name[128];
};

%s

int trace_udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len) {
    u16 dport = sk->__sk_common.skc_dport;
    if (dport != __constant_htons(53))
        return 0;

    struct dns_data_t data = {};
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
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    data.daddr = sk->__sk_common.skc_daddr;
    data.dport = 53;

    struct iov_iter *iter = &msg->msg_iter;
    if (iter->count > 12) {
        const struct iovec *iov = NULL;
        bpf_probe_read(&iov, sizeof(iov), &iter->iov);
        if (iov) {
            void *base = NULL;
            bpf_probe_read(&base, sizeof(base), &iov->iov_base);
            if (base) {
                bpf_probe_read_user(data.query_name, sizeof(data.query_name) - 1, base + 12);
            }
        }
    }

    %s
    return 0;
}
`, defines, outputMacro, submitCode)
}

// pollFallback scans /proc/net/udp for UDP sockets with remote port 53, emitting
// a DnsEvent for each newly observed resolver connection. Uses inode→PID lookup
// to attribute the DNS query to its owning process.
func (s *DnsSensor) pollFallback() []core.Event {
	var events []core.Event
	now := float64(time.Now().UnixNano()) / 1e9

	// Build socket inode → PID map once per poll for process attribution.
	inodePID := buildInodePIDMap()

	f, err := os.Open("/proc/net/udp")
	if err != nil {
		return events
	}
	defer f.Close()

	current := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	scanner.Scan() // Skip the header line.

	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		// /proc/net/udp columns: sl local_address rem_address st tx_rx_queue
		//   tr:tm->when retrnsmt uid timeout inode
		if len(parts) < 10 {
			continue
		}

		remAddr := parts[2]
		_, dport := ParseHexAddr(remAddr)
		if dport != 53 {
			continue
		}

		localAddr := parts[1]
		dstIP, _ := ParseHexAddr(remAddr)

		key := localAddr + "-" + remAddr
		current[key] = struct{}{}

		if _, known := s.knownConns[key]; !known {
			inode := parts[9]
			pid := inodePID[inode]

			comm := ""
			if pid > 0 {
				comm = readProcComm(fmt.Sprintf("/proc/%d", pid))
			}

			evt := &core.DnsEvent{
				KernelEvent: core.KernelEvent{
					Timestamp: now,
					PID:       pid,
					Comm:      comm,
					EventType: "dns",
				},
				DestIP:   dstIP,
				DestPort: 53,
			}
			events = append(events, evt)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "[DnsSensor] scanner error reading /proc/net/udp: %v\n", err)
	}

	s.knownConns = current
	return events
}

// DecodeDNSName decodes a DNS wire-format name (length-prefixed labels).
func DecodeDNSName(raw []byte) string {
	var labels []string
	i := 0
	for i < len(raw) {
		length := int(raw[i])
		if length == 0 {
			break
		}
		i++
		if i+length > len(raw) {
			break
		}
		label := raw[i : i+length]
		valid := true
		for _, b := range label {
			if b > 127 {
				valid = false
				break
			}
		}
		if !valid {
			break
		}
		labels = append(labels, string(label))
		i += length
	}
	if len(labels) == 0 {
		return ""
	}
	return strings.Join(labels, ".")
}
