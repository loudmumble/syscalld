package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/loudmumble/syscalld/core"
	"github.com/loudmumble/syscalld/guest"
	"github.com/loudmumble/syscalld/internal/alerts"
	"github.com/loudmumble/syscalld/internal/config"
	"github.com/spf13/cobra"
)

var (
	runSensors  []string
	runPreset   string
	runFormat   string
	runFallback bool
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Start the sensor daemon and stream events",
	Long: `Start the syscalld sensor daemon and stream events to stdout (or file).

Reads configuration from --config (default: ~/.syscalld/config.yaml).
Flag values override config file settings.

PRESETS
  --preset security-audit       Network + syscall + process, JSON, alert rules
  --preset threat-hunting       All sensors, NDJSON, DNS exfil + exec alerts
  --preset performance-baseline Memory + filesystem + network, text output
  --preset minimal              Process sensor only, lowest overhead

OUTPUT FORMATS
  text    Human-readable with timestamps (default)
  json    Single JSON object per event
  ndjson  Newline-delimited JSON (for log pipelines)

EXAMPLES
  sudo syscalld run                                  All sensors, text to stdout
  sudo syscalld run --sensors process,network        Only process and network
  sudo syscalld run --preset threat-hunting           Full threat-hunting profile
  sudo syscalld run --format ndjson | tee events.log  Pipe NDJSON to file
  sudo syscalld run --fallback --sensors syscall      Force /proc, syscall only`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(configPath)
		if err != nil {
			return err
		}

		// Apply preset if specified
		if runPreset != "" {
			presets := config.Presets()
			p, ok := presets[runPreset]
			if !ok {
				return fmt.Errorf("unknown preset %q. Available: %s",
					runPreset, strings.Join(presetsKeys(), ", "))
			}
			cfg = p
		}

		// Flag overrides
		if len(runSensors) > 0 {
			cfg.Sensors = runSensors
		}
		if runFormat != "" {
			cfg.Output.Format = runFormat
		}
		if runFallback {
			cfg.Fallback = true
		}

		// Build sensor list
		sensorList, err := guest.SelectSensors(cfg.Sensors)
		if err != nil {
			return err
		}

		// Build filter
		filter := buildFilter(cfg)

		// Build manager
		mgr := core.NewSensorManager(filter)
		mgr.SetPollInterval(time.Duration(cfg.PollIntervalMS) * time.Millisecond)
		for _, s := range sensorList {
			mgr.Add(s)
		}

		// Warn about unimplemented config fields
		if cfg.Output.WebhookURL != "" {
			fmt.Fprintln(os.Stderr, "Warning: webhook_url is not yet implemented; alerts will only appear in output")
		}
		if cfg.Filters.MinSeverity > 0 {
			fmt.Fprintln(os.Stderr, "Warning: min_severity filter is not yet implemented; all events will be emitted")
		}

		// Open output
		out := os.Stdout
		if cfg.Output.File != "" {
			f, err := os.OpenFile(cfg.Output.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
			if err != nil {
				return fmt.Errorf("open output file: %w", err)
			}
			defer f.Close()
			out = f
		}

		// Alert engine
		var alertMu sync.Mutex
		var alertCount int
		alertEngine := alerts.NewEngine(cfg.Alerts, func(a alerts.Alert) {
			alertMu.Lock()
			alertCount++
			alertMu.Unlock()
			fmt.Fprintf(os.Stderr, "  [ALERT] [%s] %s (rate: %d/s, severity: %s)\n",
				a.Time.Format("15:04:05"), a.Message, a.Rate, a.Rule.Severity)
		})

		// Register event handler
		mgr.OnAny(func(e core.Event) {
			alertEngine.Observe(e.GetEventType())
			switch cfg.Output.Format {
			case "json", "ndjson":
				data, err := json.Marshal(e)
				if err != nil {
					fmt.Fprintf(os.Stderr, "marshal error: %v\n", err)
					return
				}
				fmt.Fprintln(out, string(data))
			default:
				fmt.Fprintln(out, formatEventText(e))
			}
		})

		mgr.Start()

		sensorNames := mgr.SensorNames()
		mode := "fallback (/proc)"
		if !cfg.Fallback {
			mode = "auto (eBPF with /proc fallback)"
		}
		fmt.Fprintf(os.Stderr, "\n  syscalld v%s\n", Version)
		fmt.Fprintf(os.Stderr, "  Mode:    %s\n", mode)
		fmt.Fprintf(os.Stderr, "  Sensors: %s\n", strings.Join(sensorNames, ", "))
		fmt.Fprintf(os.Stderr, "  Format:  %s\n", cfg.Output.Format)
		if cfg.Output.File != "" {
			fmt.Fprintf(os.Stderr, "  Output:  %s\n", cfg.Output.File)
		} else {
			fmt.Fprintf(os.Stderr, "  Output:  stdout\n")
		}
		if alertEngine.RuleCount() > 0 {
			fmt.Fprintf(os.Stderr, "  Alerts:  %d rules active\n", alertEngine.RuleCount())
		}
		fmt.Fprintf(os.Stderr, "  Press Ctrl+C to stop.\n\n")

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig

		fmt.Fprintf(os.Stderr, "\n  Stopping %d sensors... ", len(sensorNames))
		mgr.Stop()
		dropped := mgr.DroppedEvents()
		alertMu.Lock()
		ac := alertCount
		alertMu.Unlock()
		parts := []string{"done"}
		if dropped > 0 {
			parts = append(parts, fmt.Sprintf("%d dropped", dropped))
		}
		if ac > 0 {
			parts = append(parts, fmt.Sprintf("%d alerts fired", ac))
		}
		fmt.Fprintf(os.Stderr, "%s.\n", strings.Join(parts, ", "))
		return nil
	},
}

func init() {
	runCmd.Flags().StringSliceVar(&runSensors, "sensors", nil,
		"Sensors to enable (comma-separated: syscall,process,filesystem,network,memory,module,dns)")
	runCmd.Flags().StringVar(&runPreset, "preset", "",
		"Built-in config preset: security-audit, threat-hunting, performance-baseline, minimal")
	runCmd.Flags().StringVar(&runFormat, "format", "",
		"Output format: text, json, ndjson")
	runCmd.Flags().BoolVar(&runFallback, "fallback", false,
		"Force fallback mode (use /proc instead of eBPF)")
	rootCmd.AddCommand(runCmd)
}

func formatEventText(e core.Event) string {
	ts := ""
	switch ev := e.(type) {
	case *core.SyscallEvent:
		ts = time.Unix(0, int64(ev.Timestamp*1e9)).Format("15:04:05.000")
		name := ev.SyscallName
		if name == "" {
			name = fmt.Sprintf("nr=%d", ev.SyscallNR)
		}
		return fmt.Sprintf("%s [syscall]  pid=%-6d comm=%-16s %s", ts, ev.PID, ev.Comm, name)
	case *core.ProcessEvent:
		ts = time.Unix(0, int64(ev.Timestamp*1e9)).Format("15:04:05.000")
		detail := ev.Filename
		if ev.Action == "exit" && ev.ExitCode != nil {
			detail = fmt.Sprintf("exit_code=%d", *ev.ExitCode)
		}
		return fmt.Sprintf("%s [process]  pid=%-6d comm=%-16s %s %s", ts, ev.PID, ev.Comm, ev.Action, detail)
	case *core.FileEvent:
		ts = time.Unix(0, int64(ev.Timestamp*1e9)).Format("15:04:05.000")
		return fmt.Sprintf("%s [file]     pid=%-6d comm=%-16s %s %s", ts, ev.PID, ev.Comm, ev.Operation, ev.Path)
	case *core.NetworkEvent:
		ts = time.Unix(0, int64(ev.Timestamp*1e9)).Format("15:04:05.000")
		return fmt.Sprintf("%s [network]  pid=%-6d comm=%-16s %s %s:%d → %s:%d %s",
			ts, ev.PID, ev.Comm, ev.Action, ev.SAddr, ev.SPort, ev.DAddr, ev.DPort, ev.Protocol)
	case *core.MemoryEvent:
		ts = time.Unix(0, int64(ev.Timestamp*1e9)).Format("15:04:05.000")
		return fmt.Sprintf("%s [memory]   pid=%-6d comm=%-16s %s addr=0x%x len=%d prot=%d",
			ts, ev.PID, ev.Comm, ev.Operation, ev.Addr, ev.Length, ev.Prot)
	case *core.ModuleEvent:
		ts = time.Unix(0, int64(ev.Timestamp*1e9)).Format("15:04:05.000")
		return fmt.Sprintf("%s [module]   %s %s", ts, ev.Operation, ev.ModuleName)
	case *core.DnsEvent:
		ts = time.Unix(0, int64(ev.Timestamp*1e9)).Format("15:04:05.000")
		query := ev.QueryName
		if query == "" {
			query = "(unresolved)"
		}
		return fmt.Sprintf("%s [dns]      pid=%-6d comm=%-16s → %s:%d %s",
			ts, ev.PID, ev.Comm, ev.DestIP, ev.DestPort, query)
	case *core.CanaryEvent:
		ts = time.Unix(0, int64(ev.Timestamp*1e9)).Format("15:04:05.000")
		return fmt.Sprintf("%s [canary]   heartbeat healthy=%v", ts, ev.Healthy)
	default:
		return fmt.Sprintf("[%s] %+v", e.GetEventType(), e)
	}
}

func presetsKeys() []string {
	presets := config.Presets()
	keys := make([]string, 0, len(presets))
	for k := range presets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
