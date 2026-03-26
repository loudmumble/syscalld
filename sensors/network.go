package sensors

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/loudmumble/syscalld/core"
)

// NetworkSensor traces TCP/UDP network activity.
// In fallback mode, reads /proc/net/tcp for established connections and attributes
// each to its owning process via socket inode lookup.
type NetworkSensor struct {
	*BaseSensor
	knownConns map[string]struct{}
}

// NewNetworkSensor creates a new NetworkSensor.
func NewNetworkSensor() *NetworkSensor {
	s := &NetworkSensor{
		BaseSensor: NewBaseSensor("network"),
		knownConns: make(map[string]struct{}),
	}
	s.BPFProgram = s.bpfProgram
	s.PollFallback = s.pollFallback
	return s
}

func (s *NetworkSensor) bpfProgram(filters *core.SensorFilter) string {
	defines := filters.ToBPFDefines()
	outputMacro := PerfOutputMacro("events", 24)
	submitTP := SubmitEventCode("events", "args")
	submitKP := SubmitEventCode("events", "ctx")

	return fmt.Sprintf(`%s
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct net_data_t {
    u64 timestamp;
    u32 pid;
    u32 tid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    int action;  // 1=state_change, 2=send, 3=recv
    u32 bytes;
    int new_state;
    char comm[16];
};

%s

TRACEPOINT_PROBE(sock, inet_sock_set_state) {
    if (args->protocol != IPPROTO_TCP)
        return 0;

    struct net_data_t data = {};
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
    data.saddr = args->saddr;
    data.daddr = args->daddr;
    data.sport = args->sport;
    data.dport = args->dport;
    data.action = 1;
    data.new_state = args->newstate;

    %s
    return 0;
}

int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    struct net_data_t data = {};
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

    data.saddr = sk->__sk_common.skc_rcv_saddr;
    data.daddr = sk->__sk_common.skc_daddr;
    data.sport = sk->__sk_common.skc_num;
    data.dport = sk->__sk_common.skc_dport;
    data.action = 2;
    data.bytes = (u32)size;

    %s
    return 0;
}

int trace_tcp_recvmsg(struct pt_regs *ctx, struct sock *sk) {
    struct net_data_t data = {};
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

    data.saddr = sk->__sk_common.skc_rcv_saddr;
    data.daddr = sk->__sk_common.skc_daddr;
    data.sport = sk->__sk_common.skc_num;
    data.dport = sk->__sk_common.skc_dport;
    data.action = 3;

    %s
    return 0;
}
`, defines, outputMacro, submitTP, submitKP, submitKP)
}

// pollFallback reads /proc/net/tcp for ESTABLISHED connections, emitting a
// NetworkEvent for each newly observed connection. Process attribution is
// performed via the socket inode field (column 9 in /proc/net/tcp) matched
// against /proc/[pid]/fd symbolic links.
func (s *NetworkSensor) pollFallback() []core.Event {
	var events []core.Event
	now := float64(time.Now().UnixNano()) / 1e9

	// Build inode→PID map once per poll for process attribution.
	inodePID := buildInodePIDMap()

	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		return events
	}
	defer f.Close()

	currentConns := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	scanner.Scan() // Skip header line.

	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		// /proc/net/tcp columns (0-indexed):
		//   0=sl 1=local_address 2=rem_address 3=st 4=tx_rx_queue
		//   5=tr:tm->when 6=retrnsmt 7=uid 8=timeout 9=inode
		if len(parts) < 10 {
			continue
		}

		localAddr := parts[1]
		remAddr := parts[2]
		state := parts[3]

		// 01 = TCP_ESTABLISHED
		if state != "01" {
			continue
		}

		connID := localAddr + "-" + remAddr
		currentConns[connID] = struct{}{}

		if _, known := s.knownConns[connID]; !known {
			lIP, lPort := ParseHexAddr(localAddr)
			rIP, rPort := ParseHexAddr(remAddr)

			// Attribute connection to its owning process.
			inode := parts[9]
			pid := inodePID[inode]
			comm := ""
			if pid > 0 {
				comm = readProcComm(fmt.Sprintf("/proc/%d", pid))
			}

			evt := &core.NetworkEvent{
				KernelEvent: core.KernelEvent{
					Timestamp: now,
					PID:       pid,
					Comm:      comm,
					EventType: "network",
				},
				Action:   "connect",
				SAddr:    lIP,
				DAddr:    rIP,
				SPort:    lPort,
				DPort:    rPort,
				Protocol: "tcp",
			}
			events = append(events, evt)
		}
	}
	s.knownConns = currentConns

	return events
}

// ParseHexAddr parses a /proc/net/tcp hex address:port into IP string and port int.
// The address is stored little-endian on x86_64.
func ParseHexAddr(hexAddr string) (string, int) {
	parts := strings.SplitN(hexAddr, ":", 2)
	if len(parts) != 2 {
		return "0.0.0.0", 0
	}

	port64, err := strconv.ParseUint(parts[1], 16, 32)
	if err != nil {
		return "0.0.0.0", 0
	}
	port := int(port64)

	ipHex, err := strconv.ParseUint(parts[0], 16, 32)
	if err != nil {
		return "0.0.0.0", port
	}

	// /proc/net/tcp stores IP in little-endian on x86_64.
	var ipBytes [4]byte
	ipBytes[0] = byte(ipHex)
	ipBytes[1] = byte(ipHex >> 8)
	ipBytes[2] = byte(ipHex >> 16)
	ipBytes[3] = byte(ipHex >> 24)
	ip := net.IP(ipBytes[:]).String()

	return ip, port
}
