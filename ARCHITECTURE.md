# Architecture

## Overview

syscalld is a Go library that provides a unified interface for kernel event monitoring via eBPF. It is designed as a dependency for security tools (Sentinel, Agora, Aegis) and also ships a standalone CLI binary (`cmd/syscalld/`) with a Bubbletea TUI.

## Package Dependency Graph

```
guest/
  └── core/
  └── sensors/
        └── core/
```

- `core` has zero internal dependencies (only stdlib)
- `sensors` depends on `core` for event types and filter definitions
- `guest` depends on both `core` and `sensors`

## Core Package

### Event Type Hierarchy

```
Event (interface)
  └── KernelEvent (base struct)
        ├── SyscallEvent
        ├── ProcessEvent
        ├── FileEvent
        ├── NetworkEvent
        ├── MemoryEvent
        ├── ModuleEvent
        └── DnsEvent
```

All events implement `GetEventType()`, `ToSentinelEvent()`, and `ToMalscopeEvent()` for downstream consumer compatibility.

### EventBus

Thread-safe pub/sub dispatcher. Handlers register for specific event types or catch-all (`OnAny`). Panic recovery prevents one handler from crashing the bus.

### SensorFilter

Generates C `#define` macros for BPF program compile-time filtering and provides runtime `Matches*()` methods for fallback mode. Supports:
- PID filtering (single or set)
- PID namespace filtering
- Cgroup v2 filtering
- Syscall whitelisting
- Comm exclusion

### SensorManager

Manages sensor lifecycle: `Add()` -> `Start()` -> poll loop -> `Stop()`. Runs a goroutine that polls all sensors and emits events through the EventBus.

## Sensors Package

### BaseSensor

Embedded by all 7 concrete sensors. Provides:
- `Start()`/`Stop()` lifecycle with idempotent guards
- `Poll()` delegation to `PollFallback` function
- `GetBPFProgram()` delegation to `BPFProgram` function
- Static helpers: `PerfOutputMacro()`, `SubmitEventCode()`, `CommonFilterCode()`

### Sensor Implementations

Each sensor provides:
1. **BPF program text** -- Complete C source for eBPF attachment (tracepoints/kprobes)
2. **Fallback polling** -- `/proc` filesystem reading for unprivileged operation
3. **Event construction** -- Properly typed `core.Event` instances

### Operating Modes

| Mode | Trigger | Mechanism |
|------|---------|-----------|
| `ebpf` | Root + BCC available | Loads BPF C program via BCC |
| `fallback` | Non-root or no BCC | Reads `/proc` filesystem |

The Go implementation always uses fallback mode. The BPF program text is preserved for future integration with [cilium/ebpf](https://github.com/cilium/ebpf).

## Guest Package

Orchestrates sensor collection inside QEMU/KVM guest VMs:
- `SensorRegistry` -- Maps names to constructors
- `SelectSensors()` -- Instantiates sensors by name
- `SerializeEvent()` -- Compact JSON serialization
- `GuestAgentRunner` -- Start/stop lifecycle, fallback poll loop, NDJSON output over virtio-serial
- `SetupSignalHandlers()` -- SIGTERM/SIGINT graceful shutdown

## Thread Safety

- `EventBus`: Mutex-protected handler maps
- `SensorManager`: Mutex-protected sensor list and running state
- `GuestAgentRunner`: Mutex-protected running state and event count

## Data Flow

```
Kernel Event
  -> Sensor.Poll() returns []core.Event
  -> SensorManager.pollLoop() calls Bus.Emit()
  -> EventBus routes to typed + any handlers
  -> GuestAgentRunner.handleEvent() serializes to NDJSON
  -> io.Writer (virtio-serial / stdout)
```
