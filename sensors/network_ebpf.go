package sensors

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/loudmumble/syscalld/bpf"
	"github.com/loudmumble/syscalld/core"
)

type NetworkSensorEBPF struct {
	*BaseSensor
	objs      bpf.BpfObjects
	links     []link.Link
	reader    *ringbuf.Reader
	events    chan core.Event
	done      chan struct{}
	closeOnce sync.Once
}

func NewNetworkSensorEBPF() *NetworkSensorEBPF {
	s := &NetworkSensorEBPF{
		BaseSensor: NewBaseSensor("network"),
		events:     make(chan core.Event, 1000),
		done:       make(chan struct{}),
	}
	s.mode = "ebpf"
	return s
}

func (s *NetworkSensorEBPF) Start(filters *core.SensorFilter) {
	if s.started {
		return
	}

	if err := bpf.LoadBpfObjects(&s.objs, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load bpf objects (network): %v\n", err)
		return
	}

	kp4, err := link.Kprobe("tcp_v4_connect", s.objs.TraceTcpV4Connect, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach kprobe tcp_v4_connect: %v\n", err)
		s.objs.Close()
		return
	}
	s.links = append(s.links, kp4)

	kp6, err := link.Kprobe("tcp_v6_connect", s.objs.TraceTcpV6Connect, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach kprobe tcp_v6_connect: %v\n", err)
	} else {
		s.links = append(s.links, kp6)
	}

	rd, err := ringbuf.NewReader(s.objs.NetEvents)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create ringbuf reader (network): %v\n", err)
		for _, l := range s.links {
			l.Close()
		}
		s.objs.Close()
		return
	}
	s.reader = rd
	s.started = true

	go s.readLoop()
}

func uint32ToIP(n uint32) string {
	ip := make(net.IP, 4)
	ip[0] = byte(n >> 24)
	ip[1] = byte(n >> 16)
	ip[2] = byte(n >> 8)
	ip[3] = byte(n)
	return ip.String()
}

func (s *NetworkSensorEBPF) readLoop() {
	var event bpf.BpfNetDataT

	for {
		select {
		case <-s.done:
			return
		default:
		}

		record, err := s.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			continue
		}

		now := float64(time.Now().UnixNano()) / 1e9

		evt := &core.NetworkEvent{
			KernelEvent: core.KernelEvent{
				Timestamp: now,
				PID:       int(event.Pid),
				TID:       int(event.Tid),
				UID:       int(event.Uid),
				Comm:      int8ToStr(event.Comm[:]),
				EventType: "network",
				MITRE:     core.HookMITREMap["tcp_v4_connect"],
			},
			Action:   "connect",
			SAddr:    uint32ToIP(event.Saddr),
			DAddr:    uint32ToIP(event.Daddr),
			SPort:    int(event.Sport),
			DPort:    int(event.Dport),
			Protocol: "tcp",
		}

		select {
		case s.events <- evt:
		default:
		}
	}
}

func (s *NetworkSensorEBPF) Stop() {
	s.stateMu.Lock()
	if !s.started {
		s.stateMu.Unlock()
		return
	}
	s.started = false
	s.stateMu.Unlock()

	s.closeOnce.Do(func() { close(s.done) })
	if s.reader != nil {
		s.reader.Close()
	}
	for _, l := range s.links {
		l.Close()
	}
	s.objs.Close()
}

func (s *NetworkSensorEBPF) Poll() []core.Event {
	var events []core.Event
	for {
		select {
		case evt := <-s.events:
			events = append(events, evt)
		default:
			return events
		}
	}
}

func (s *NetworkSensorEBPF) Chan() <-chan core.Event {
	return s.events
}
