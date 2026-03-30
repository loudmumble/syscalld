package cmd

import (
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/loudmumble/syscalld/core"
	"github.com/loudmumble/syscalld/guest"
	"github.com/loudmumble/syscalld/internal/alerts"
	"github.com/loudmumble/syscalld/internal/config"
	tuipkg "github.com/loudmumble/syscalld/internal/tui"
	"github.com/spf13/cobra"
)

var tuiSensors []string
var tuiPreset string
var tuiFallback bool

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Launch interactive terminal dashboard",
	Long: `Launch the syscalld interactive terminal dashboard.

Displays a live event stream from all active sensors with four tabs:

  1 Stream  Real-time color-coded event feed, auto-scrolling
  2 Stats   Event counts per sensor type with proportional bar chart
  3 Config  Active sensors with mode, health, event/error counts
  4 Alerts  Threshold-based alert notifications

KEYBOARD
  Tab / Shift+Tab    Cycle through tabs
  1-4                Jump to tab directly
  Up/Down            Scroll event stream
  h/l or Left/Right  Previous/next tab
  q / Ctrl+C         Quit

EXAMPLES
  sudo syscalld tui                          All sensors, default config
  sudo syscalld tui --preset threat-hunting  Full threat-hunting profile
  sudo syscalld tui --sensors process,dns    Only process and DNS`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(configPath)
		if err != nil {
			return err
		}
		if tuiPreset != "" {
			presets := config.Presets()
			p, ok := presets[tuiPreset]
			if !ok {
				return fmt.Errorf("unknown preset: %q", tuiPreset)
			}
			cfg = p
		}
		if len(tuiSensors) > 0 {
			cfg.Sensors = tuiSensors
		}
		if tuiFallback {
			cfg.Fallback = true
		}

		sensorList, err := guest.SelectSensors(cfg.Sensors)
		if err != nil {
			return err
		}

		filter := buildFilter(cfg)

		mgr := core.NewSensorManager(filter)
		mgr.SetPollInterval(time.Duration(cfg.PollIntervalMS) * time.Millisecond)
		for _, s := range sensorList {
			mgr.Add(s)
		}

		// Wire alert engine into TUI model
		model := tuipkg.NewModel(mgr)
		alertEngine := alerts.NewEngine(cfg.Alerts, func(a alerts.Alert) {
			model.AddAlert(a.Time, a.Message, a.Rule.Severity)
		})
		mgr.OnAny(func(e core.Event) {
			alertEngine.Observe(e.GetEventType())
		})

		mgr.Start()
		defer mgr.Stop()

		p := tea.NewProgram(model, tea.WithAltScreen())
		_, err = p.Run()
		return err
	},
}

func init() {
	tuiCmd.Flags().StringSliceVar(&tuiSensors, "sensors", nil,
		"Sensors to enable (default: all)")
	tuiCmd.Flags().StringVar(&tuiPreset, "preset", "",
		"Use a built-in preset: security-audit, threat-hunting, performance-baseline, minimal")
	tuiCmd.Flags().BoolVar(&tuiFallback, "fallback", false,
		"Force fallback mode (use /proc instead of eBPF)")
	rootCmd.AddCommand(tuiCmd)
}
