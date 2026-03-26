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

type ModuleSensorEBPF struct {
	*BaseSensor
	objs   bpf.BpfObjects
	links  []link.Link
	reader *ringbuf.Reader
	events chan core.Event
	done   chan struct{}
}

func NewModuleSensorEBPF() *ModuleSensorEBPF {
	s := &ModuleSensorEBPF{
		BaseSensor: NewBaseSensor("module"),
		events:     make(chan core.Event, 1000),
		done:       make(chan struct{}),
	}
	s.mode = "ebpf"
	return s
}

func (s *ModuleSensorEBPF) Start(filters *core.SensorFilter) {
	if s.started {
		return
	}

	if err := bpf.LoadBpfObjects(&s.objs, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load bpf objects (module): %v\n", err)
		return
	}

	kp, err := link.Kprobe("do_init_module", s.objs.TraceDoInitModule, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach kprobe do_init_module: %v\n", err)
		s.objs.Close()
		return
	}
	s.links = append(s.links, kp)

	rd, err := ringbuf.NewReader(s.objs.ModEvents)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create ringbuf reader (module): %v\n", err)
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

func (s *ModuleSensorEBPF) readLoop() {
	var event bpf.BpfModDataT

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

		evt := &core.ModuleEvent{
			KernelEvent: core.KernelEvent{
				Timestamp: now,
				PID:       int(event.Pid),
				TID:       int(event.Tid),
				UID:       int(event.Uid),
				Comm:      int8ToStr(event.Comm[:]),
				EventType: "module",
				MITRE:     core.HookMITREMap["do_init_module"],
			},
			Operation:  "load",
			ModuleName: int8ToStr(event.ModName[:]),
		}

		select {
		case s.events <- evt:
		default:
		}
	}
}

func (s *ModuleSensorEBPF) Stop() {
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

func (s *ModuleSensorEBPF) Poll() []core.Event {
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

func (s *ModuleSensorEBPF) Chan() <-chan core.Event {
	return s.events
}
