# syscalld

Unified kernel sensor framework for Linux security monitoring. A pure Go library (`CGO_ENABLED=0`) that reads `/proc` to trace syscalls, processes, filesystem operations, network activity, memory mappings, kernel modules, and DNS queries.

## Overview

syscalld provides 7 specialized sensors that monitor Linux kernel activity through the `/proc` filesystem. It ships as both a Go library for embedding into security tools and a standalone CLI with a live TUI dashboard.

> **Note:** The current implementation operates in fallback mode, reading `/proc` for all sensor data. The eBPF hook interface is designed for future activation via [cilium/ebpf](https://github.com/cilium/ebpf) but is not currently active.

## Features

- **7 kernel sensors** covering syscalls, processes, filesystem, network, memory, kernel modules, and DNS
- **Zero CGO dependencies** — builds with `CGO_ENABLED=0`
- **Configurable filtering** — target/exclude PIDs, syscall whitelisting, comm exclusion
- **Multiple output formats** — text, JSON, NDJSON
- **Built-in presets** — security-audit, threat-hunting, performance-baseline, minimal
- **Live TUI dashboard** — real-time event stream with [Bubbletea](https://github.com/charmbracelet/bubbletea)
- **Guest VM agent** — NDJSON event streaming over virtio-serial for QEMU/KVM guests
- **Health monitoring** — canary heartbeats, per-sensor event/error counters
- **MITRE ATT&CK mapping** — event types mapped to technique IDs

## Installation

### From source

```bash
CGO_ENABLED=0 go install github.com/loudmumble/syscalld/cmd/syscalld@latest
```

### As a library

```bash
go get github.com/loudmumble/syscalld
```

## Quick Start

### CLI

```bash
# Stream events in human-readable format
sudo syscalld run --sensors syscall,process,network

# Use a built-in preset
sudo syscalld run --preset security-audit

# JSON output for pipeline ingestion
sudo syscalld run --format json --sensors network,dns

# NDJSON for SIEM ingestion
sudo syscalld run --preset threat-hunting

# Interactive live TUI
sudo syscalld tui

# Configuration management
syscalld config show
syscalld config init
syscalld config presets
```

### Library

```go
import (
    "fmt"
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

### Guest VM Agent

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
```

## Sensors

| Sensor | eBPF Hooks (designed, not active) | Fallback Source |
|--------|-----------------------------------|-----------------|
| **Syscall** | `raw_syscalls/sys_enter`, `sys_exit` | `/proc/[pid]/syscall` |
| **Process** | `sched/sched_process_exec`, `fork`, `exit` | `/proc` diff scan |
| **Filesystem** | `kprobe:vfs_open`, `vfs_write`, `vfs_unlink` | `/proc/[pid]/fd` (multi-PID diff) |
| **Network** | `sock/inet_sock_set_state`, `kprobe:tcp_sendmsg` | `/proc/net/tcp` + inode-to-PID map |
| **Memory** | `kprobe:do_mmap`, `do_mprotect`, `memfd_create` | `/proc/[pid]/maps` (multi-PID, anonymous exec detection) |
| **Module** | `kprobe:do_init_module` | `/proc/modules` diff |
| **DNS** | `kprobe:udp_sendmsg` (port 53) | `/proc/net/udp` (port-53 sockets) |

## Configuration

Default config path: `~/.syscalld/config.yaml`

```yaml
sensors: [syscall, process, filesystem, network, memory, module, dns]
fallback: true
output:
  format: text    # text | json | ndjson
  file: ""        # empty = stdout
filters:
  target_pids: []
  exclude_pids: []
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

## Project Structure

```
core/           Event types, EventBus, filters, SensorManager
sensors/        7 sensor implementations + BaseSensor
guest/          Guest VM agent runner + sensor registry
cmd/syscalld/   CLI binary (Cobra + Bubbletea TUI)
internal/       YAML config system, alert engine, TUI model
bpf/            Generated eBPF bindings (future activation)
headers/        BPF helper headers + vmlinux.h
```

## Testing

```bash
make test        # Run all tests
make test-race   # Run with race detector
make vet         # Run go vet
make lint        # Run staticcheck + vet
make check       # All of the above
```

## Requirements

- Go 1.24.2+
- Linux (reads `/proc` filesystem)
- No CGO dependencies

## Dependencies

- [cobra](https://github.com/spf13/cobra) — CLI framework
- [bubbletea](https://github.com/charmbracelet/bubbletea) — TUI dashboard
- [lipgloss](https://github.com/charmbracelet/lipgloss) — TUI styling
- [cilium/ebpf](https://github.com/cilium/ebpf) — eBPF type definitions
- [yaml.v3](https://gopkg.in/yaml.v3) — config parsing

## License

MIT
