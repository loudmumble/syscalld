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

type FilesystemSensorEBPF struct {
	*BaseSensor
	objs   bpf.BpfObjects
	links  []link.Link
	reader *ringbuf.Reader
	events chan core.Event
	done   chan struct{}
}

func NewFilesystemSensorEBPF() *FilesystemSensorEBPF {
	s := &FilesystemSensorEBPF{
		BaseSensor: NewBaseSensor("filesystem"),
		events:     make(chan core.Event, 1000),
		done:       make(chan struct{}),
	}
	s.mode = "ebpf"
	return s
}

func (s *FilesystemSensorEBPF) Start(filters *core.SensorFilter) {
	if s.started {
		return
	}

	if err := bpf.LoadBpfObjects(&s.objs, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load bpf objects (filesystem): %v\n", err)
		return
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_openat", s.objs.TraceFsOpenat, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach tracepoint sys_enter_openat: %v\n", err)
		s.objs.Close()
		return
	}
	s.links = append(s.links, tp)

	rd, err := ringbuf.NewReader(s.objs.FsEvents)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create ringbuf reader (filesystem): %v\n", err)
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

func (s *FilesystemSensorEBPF) readLoop() {
	var event bpf.BpfFsDataT

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

		evt := &core.FileEvent{
			KernelEvent: core.KernelEvent{
				Timestamp: now,
				PID:       int(event.Pid),
				TID:       int(event.Tid),
				UID:       int(event.Uid),
				Comm:      int8ToStr(event.Comm[:]),
				EventType: "file",
				MITRE:     core.HookMITREMap["openat"],
			},
			Operation: "open",
			Path:      int8ToStr(event.Filename[:]),
			Flags:     int(event.Flags),
		}

		select {
		case s.events <- evt:
		default:
		}
	}
}

func (s *FilesystemSensorEBPF) Stop() {
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

func (s *FilesystemSensorEBPF) Poll() []core.Event {
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

func (s *FilesystemSensorEBPF) Chan() <-chan core.Event {
	return s.events
}
