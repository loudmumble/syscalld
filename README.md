# syscalld

Unified eBPF kernel sensor framework for Linux security monitoring. A pure Go library (CGO_ENABLED=0) that reads `/proc` to trace syscalls, processes, filesystem operations, network activity, memory mappings, kernel modules, and DNS queries.

> **Note:** The Go implementation always operates in fallback mode (reading `/proc`). eBPF program loading is not active — `BCCAvailable` is hardcoded to `false`. The eBPF hook interface is designed for future activation via [cilium/ebpf](https://github.com/cilium/ebpf) but is currently dead code.

Consumed by **Sentinel**, **Agora**, and **Aegis**.

## Packages

| Package | Description |
|---------|-------------|
| `core` | Event types, EventBus, SensorFilter, SensorManager, Sensor interface |
| `sensors` | 7 sensor implementations: syscall, process, filesystem, network, memory, module, dns |
| `guest` | Guest VM agent runner, sensor registry, event serialization (NDJSON over virtio-serial) |

## Sensors

| Sensor | eBPF Hooks (designed, not active) | Active Fallback Source |
|--------|-----------|-----------------|
| **Syscall** | `raw_syscalls/sys_enter`, `sys_exit` | `/proc/[pid]/syscall` |
| **Process** | `sched/sched_process_exec`, `fork`, `exit` | `/proc` diff scan |
| **Filesystem** | `kprobe:vfs_open`, `vfs_write`, `vfs_unlink` | `/proc/[pid]/fd` (multi-PID diff) |
| **Network** | `sock/inet_sock_set_state`, `kprobe:tcp_sendmsg`, `tcp_recvmsg` | `/proc/net/tcp` + inode→PID map |
| **Memory** | `kprobe:do_mmap`, `do_mprotect`, `memfd_create` | `/proc/[pid]/maps` (multi-PID, VoidLink detection) |
| **Module** | `kprobe:do_init_module` | `/proc/modules` diff |
| **DNS** | `kprobe:udp_sendmsg` (port 53) | `/proc/net/udp` (port-53 sockets) |

## Usage

```go
import (
    "github.com/loudmumble/syscalld/core"
    "github.com/loudmumble/syscalld/sensors"
)

// Create manager with optional filters
filter := core.NewSensorFilter()
filter.TargetPIDs[1234] = struct{}{}
mgr := core.NewSensorManager(filter)

// Add sensors
mgr.Add(sensors.NewProcessSensor())
mgr.Add(sensors.NewNetworkSensor())

// Register event handlers
mgr.On("process", func(e core.Event) {
    pe := e.(*core.ProcessEvent)
    fmt.Printf("Process %s (pid=%d) action=%s\n", pe.Comm, pe.PID, pe.Action)
})

mgr.Start()
defer mgr.Stop()
```

## Guest Agent

```go
import "github.com/loudmumble/syscalld/guest"

sensorList, _ := guest.SelectSensors(nil) // all 7
runner := guest.NewGuestAgentRunner(guest.AgentConfig{
    Output:       os.Stdout,
    Sensors:      sensorList,
    SensorFilter: core.NewSensorFilter(),
    Fallback:     true,
})
runner.Start()
defer runner.Stop()
// runner is now streaming events to Output
```

## Operating Modes

- **eBPF mode** (not active): Would attach BPF programs to kernel tracepoints/kprobes (requires root + BCC). `BCCAvailable` is hardcoded `false` — this code path is never reached.
- **Fallback mode**: Reads `/proc` filesystem for equivalent data (no root required)

**The Go implementation always uses fallback mode.** `BCCAvailable = false` and `RingbufSupported = false` are hardcoded constants in `sensors/base.go`. All 7 sensors call `PollFallback`, which reads `/proc`. To activate real eBPF program loading in the future, swap in [cilium/ebpf](https://github.com/cilium/ebpf) and set `BCCAvailable = true`.

## Testing

```bash
make test        # Run all tests
make test-race   # Run with race detector
make vet         # Run go vet
make lint        # Run staticcheck + vet
make check       # All of the above
```

326 tests across 4 packages (core, sensors, guest, alerts) covering all event types, sensor lifecycle, BPF program validation, fallback polling, runtime filter application, event serialization, alert engine, and guest agent orchestration.

## Requirements

- Go 1.24.2+
- No CGO dependencies (`CGO_ENABLED=0`)

## Dependencies

- [cobra](https://github.com/spf13/cobra) — CLI framework
- [bubbletea](https://github.com/charmbracelet/bubbletea) — TUI dashboard
- [lipgloss](https://github.com/charmbracelet/lipgloss) — TUI styling
- [cilium/ebpf](https://github.com/cilium/ebpf) — eBPF types (future activation)
- [yaml.v3](https://gopkg.in/yaml.v3) — config parsing

## Project Structure

```
core/           Event types, bus, filters, manager
sensors/        7 sensor implementations + BaseSensor
guest/          Guest VM agent runner
cmd/syscalld/   CLI binary (Cobra + Bubbletea TUI)
internal/       YAML config system + TUI model
bpf/            Generated eBPF bindings (not active)
```

## Used By

- **Aegis** -- Behavioral IDS for agentic AI attacks
- **Sentinel** -- eBPF-based security monitoring toolkit
- **Agora** -- AI-powered malware analysis sandbox

## License

MIT

## CLI Binary (`cmd/syscalld/`)

A standalone command-line interface for using syscalld directly without integrating the library.

```bash
# Build
CGO_ENABLED=0 go build -o syscalld ./cmd/syscalld

# Stream events in text format
sudo ./syscalld run --sensors syscall,process,network

# Use a built-in preset
sudo ./syscalld run --preset security-audit
sudo ./syscalld run --preset threat-hunting      # NDJSON output
sudo ./syscalld run --preset performance-baseline
sudo ./syscalld run --preset minimal

# Note: --fallback flag exists but is redundant — fallback is always active
sudo ./syscalld run --fallback --sensors process

# Stream in JSON format
sudo ./syscalld run --format json --sensors network,dns

# Interactive live TUI
sudo ./syscalld tui

# Manage YAML configuration
./syscalld config show
./syscalld config init      # Write default config to ~/.syscalld/config.yaml
./syscalld config presets   # List available presets
```

### Configuration (`~/.syscalld/config.yaml`)

```yaml
sensors: [syscall, process, filesystem, network, memory, module, dns]
fallback: true   # Always active — eBPF mode is not implemented in the Go library
output:
  format: text   # text | json | ndjson
  file: ""       # empty = stdout
filters:
  target_pids: []
  exclude_pids: []       # Removes PIDs from target_pids (SensorFilter has no ExcludePIDs field)
  target_comms: []       # Parsed but not applied (SensorFilter has no TargetComms field)
  exclude_comms: []
  min_severity: 0
```

### Presets

| Preset | Sensors | Output | Use Case |
|--------|---------|--------|----------|
| `security-audit` | network, syscall, process | json | SOC monitoring |
| `threat-hunting` | all | ndjson | SIEM ingestion |
| `performance-baseline` | memory, filesystem, network | text | Performance analysis |
| `minimal` | process | text | Low-overhead tracing |

## Sprint History

| Sprint | Changes |
|--------|---------|
| 1 | Core library: 7 sensors, EventBus, SensorManager, SensorFilter, guest VM runner |
| 2 | CLI binary (`cmd/syscalld/`), YAML config system with presets, bubbletea live event TUI |
| 3 | Config init/show/presets management, fallback mode forcing, NDJSON streaming output |
