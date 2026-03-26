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

type ProcessSensorEBPF struct {
	*BaseSensor
	objs   bpf.BpfObjects
	links  []link.Link
	reader *ringbuf.Reader
	events chan core.Event
	done   chan struct{}
}

func NewProcessSensorEBPF() *ProcessSensorEBPF {
	s := &ProcessSensorEBPF{
		BaseSensor: NewBaseSensor("process"),
		events:     make(chan core.Event, 1000),
		done:       make(chan struct{}),
	}
	s.mode = "ebpf"
	return s
}

func (s *ProcessSensorEBPF) Start(filters *core.SensorFilter) {
	if s.started {
		return
	}

	if err := bpf.LoadBpfObjects(&s.objs, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load objects: %v\n", err)
		return
	}

	tp, err := link.Tracepoint("sched", "sched_process_exec", s.objs.TraceProcessExec, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach tracepoint sched_process_exec: %v\n", err)
		s.objs.Close()
		return
	}
	s.links = append(s.links, tp)

	tpExit, err := link.Tracepoint("sched", "sched_process_exit", s.objs.TraceProcessExit, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach tracepoint sched_process_exit: %v\n", err)
	} else {
		s.links = append(s.links, tpExit)
	}

	rd, err := ringbuf.NewReader(s.objs.ProcEvents)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create ringbuf reader: %v\n", err)
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

func int8ToStr(arr []int8) string {
	b := make([]byte, len(arr))
	for i, v := range arr {
		if v == 0 {
			b = b[:i]
			break
		}
		b[i] = byte(v)
	}
	return string(b)
}

func (s *ProcessSensorEBPF) readLoop() {
	var event bpf.BpfProcDataT

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

		action := "exec"
		hookName := "sched_process_exec"
		if event.Action == 2 {
			action = "exit"
			hookName = "sched_process_exit"
		}

		evt := &core.ProcessEvent{
			KernelEvent: core.KernelEvent{
				Timestamp: now,
				PID:       int(event.Pid),
				TID:       int(event.Tid),
				UID:       int(event.Uid),
				Comm:      int8ToStr(event.Comm[:]),
				EventType: "process",
				MITRE:     core.HookMITREMap[hookName],
			},
			Action:   action,
			PPID:     int(event.Ppid),
			Filename: int8ToStr(event.Filename[:]),
			Argv:     []string{},
		}

		select {
		case s.events <- evt:
		default:
		}
	}
}

func (s *ProcessSensorEBPF) Stop() {
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

func (s *ProcessSensorEBPF) Poll() []core.Event {
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

func (s *ProcessSensorEBPF) Chan() <-chan core.Event {
	return s.events
}
