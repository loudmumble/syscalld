package sensors

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/loudmumble/syscalld/bpf"
	"github.com/loudmumble/syscalld/core"
)

type MemorySensorEBPF struct {
	*BaseSensor
	objs   bpf.BpfObjects
	links  []link.Link
	reader *ringbuf.Reader
	events chan core.Event
	done   chan struct{}
}

func NewMemorySensorEBPF() *MemorySensorEBPF {
	s := &MemorySensorEBPF{
		BaseSensor: NewBaseSensor("memory"),
		events:     make(chan core.Event, 1000),
		done:       make(chan struct{}),
	}
	s.mode = "ebpf"
	return s
}

func (s *MemorySensorEBPF) Start(filters *core.SensorFilter) {
	if s.started {
		return
	}

	if err := bpf.LoadBpfObjects(&s.objs, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load bpf objects (memory): %v\n", err)
		return
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_mmap", s.objs.TraceMemMmap, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach tracepoint sys_enter_mmap: %v\n", err)
		s.objs.Close()
		return
	}
	s.links = append(s.links, tp)

	rd, err := ringbuf.NewReader(s.objs.MemEvents)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create ringbuf reader (memory): %v\n", err)
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

func (s *MemorySensorEBPF) readLoop() {
	var event bpf.BpfMemDataT

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

		evt := &core.MemoryEvent{
			KernelEvent: core.KernelEvent{
				Timestamp: now,
				PID:       int(event.Pid),
				TID:       int(event.Tid),
				UID:       int(event.Uid),
				Comm:      int8ToStr(event.Comm[:]),
				EventType: "memory",
				MITRE:     core.HookMITREMap["mmap"],
			},
			Operation: "mmap",
			Addr:      event.Addr,
			Length:    int(event.Len),
			Prot:      int(event.Prot),
			Flags:     int(event.Flags),
			FD:        -1,
		}

		select {
		case s.events <- evt:
		default:
		}
	}
}

func (s *MemorySensorEBPF) Stop() {
	if !s.started {
		return
	}
	s.started = false
	close(s.done)
	if s.reader != nil {
		s.reader.Close()
	}
	for _, l := range s.links {
		l.Close()
	}
	s.objs.Close()
}

func (s *MemorySensorEBPF) Poll() []core.Event {
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

func (s *MemorySensorEBPF) Chan() <-chan core.Event {
	return s.events
}
