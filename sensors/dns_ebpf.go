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

type DnsSensorEBPF struct {
	*BaseSensor
	objs      bpf.BpfObjects
	links     []link.Link
	reader    *ringbuf.Reader
	events    chan core.Event
	done      chan struct{}
	closeOnce sync.Once
}

func NewDnsSensorEBPF() *DnsSensorEBPF {
	s := &DnsSensorEBPF{
		BaseSensor: NewBaseSensor("dns"),
		events:     make(chan core.Event, 1000),
		done:       make(chan struct{}),
	}
	s.mode = "ebpf"
	return s
}

func (s *DnsSensorEBPF) Start(filters *core.SensorFilter) {
	if s.started {
		return
	}

	if err := bpf.LoadBpfObjects(&s.objs, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load bpf objects (dns): %v\n", err)
		return
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_sendto", s.objs.TraceDnsendto, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach tracepoint sys_enter_sendto: %v\n", err)
		s.objs.Close()
		return
	}
	s.links = append(s.links, tp)

	rd, err := ringbuf.NewReader(s.objs.DnsEvents)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create ringbuf reader (dns): %v\n", err)
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

func uint32ToIPBE(n uint32) string {
	ip := make(net.IP, 4)
	ip[0] = byte(n >> 24)
	ip[1] = byte(n >> 16)
	ip[2] = byte(n >> 8)
	ip[3] = byte(n)
	return ip.String()
}

func (s *DnsSensorEBPF) readLoop() {
	var event bpf.BpfDnsDataT

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

		// DNS query raw bytes — decode label-encoded name from the captured payload.
		queryBytes := make([]byte, len(event.Query))
		for i, v := range event.Query {
			queryBytes[i] = byte(v)
		}
		queryName := DecodeDNSName(queryBytes)

		evt := &core.DnsEvent{
			KernelEvent: core.KernelEvent{
				Timestamp: now,
				PID:       int(event.Pid),
				TID:       int(event.Tid),
				UID:       int(event.Uid),
				Comm:      int8ToStr(event.Comm[:]),
				EventType: "dns",
				MITRE:     core.HookMITREMap["dns_query"],
			},
			QueryName: queryName,
			QueryType: 1,
			DestIP:    uint32ToIPBE(event.Daddr),
			DestPort:  int(event.Dport),
		}

		select {
		case s.events <- evt:
		default:
		}
	}
}

func (s *DnsSensorEBPF) Stop() {
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

func (s *DnsSensorEBPF) Poll() []core.Event {
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

func (s *DnsSensorEBPF) Chan() <-chan core.Event {
	return s.events
}
