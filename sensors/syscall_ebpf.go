package sensors

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/loudmumble/syscalld/bpf"
	"github.com/loudmumble/syscalld/core"
)

type SyscallSensorEBPF struct {
	*BaseSensor
	objs     bpf.BpfObjects
	links    []link.Link
	reader   *ringbuf.Reader
	events   chan core.Event
	done     chan struct{}
	closeOnce sync.Once
}

func NewSyscallSensorEBPF() *SyscallSensorEBPF {
	s := &SyscallSensorEBPF{
		BaseSensor: NewBaseSensor("syscall"),
		events:     make(chan core.Event, 1000),
		done:       make(chan struct{}),
	}
	s.mode = "ebpf"
	return s
}

func (s *SyscallSensorEBPF) Start(filters *core.SensorFilter) {
	if s.started {
		return
	}

	if err := bpf.LoadBpfObjects(&s.objs, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load bpf objects (syscall): %v\n", err)
		return
	}

	tp, err := link.Tracepoint("raw_syscalls", "sys_enter", s.objs.TraceSysEnter, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach tracepoint raw_syscalls/sys_enter: %v\n", err)
		s.objs.Close()
		return
	}
	s.links = append(s.links, tp)

	rd, err := ringbuf.NewReader(s.objs.SyscallEvents)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create ringbuf reader (syscall): %v\n", err)
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

func (s *SyscallSensorEBPF) readLoop() {
	var event bpf.BpfSyscallDataT

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
		nr := int(event.Nr)
		name := core.SecuritySyscalls[nr]

		evt := &core.SyscallEvent{
			KernelEvent: core.KernelEvent{
				Timestamp: now,
				PID:       int(event.Pid),
				TID:       int(event.Tid),
				UID:       int(event.Uid),
				Comm:      int8ToStr(event.Comm[:]),
				EventType: "syscall",
				MITRE:     core.HookMITREMap["sys_enter"],
			},
			SyscallNR:   nr,
			SyscallName: name,
			Args:        []int{int(event.Args[0]), int(event.Args[1]), int(event.Args[2])},
			Phase:       "enter",
		}

		select {
		case s.events <- evt:
		default:
		}
	}
}

func (s *SyscallSensorEBPF) Stop() {
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

func (s *SyscallSensorEBPF) Poll() []core.Event {
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

func (s *SyscallSensorEBPF) Chan() <-chan core.Event {
	return s.events
}
