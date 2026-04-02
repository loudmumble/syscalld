package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/loudmumble/syscalld/internal/config"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage sensor configuration",
	Long: `View, create, and manage syscalld configuration files.

Configuration lives at ~/.syscalld/config.yaml by default.
Override with the global --config flag.

SUBCOMMANDS
  show      Print the active configuration as YAML
  init      Generate a default config file
  preset    Apply a named preset and save to disk
  presets   List all available presets with descriptions`,
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Print the active configuration as YAML",
	Long: `Print the active configuration to stdout in YAML format.

Reads from --config path or ~/.syscalld/config.yaml. If no config file
exists, prints the built-in defaults.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(configPath)
		if err != nil {
			return err
		}
		data, err2 := yaml.Marshal(cfg)
		if err2 != nil {
			return fmt.Errorf("marshal config: %w", err2)
		}
		fmt.Print(string(data))
		return nil
	},
}

var configInitForce bool

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate a default config file",
	Long: `Generate a default configuration file at ~/.syscalld/config.yaml.

The generated config enables all 7 sensors in fallback mode with text
output to stdout. Edit the file to customize sensors, filters, output
format, and alert rules.

Use --force to overwrite an existing config file.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		path := configPath
		if path == "" {
			path = config.DefaultPath()
		}
		if _, err := os.Stat(path); err == nil && !configInitForce {
			fmt.Printf("Config already exists: %s\nUse --force to overwrite.\n", path)
			return nil
		}
		if err := config.Save(config.Default(), path); err != nil {
			return err
		}
		fmt.Printf("Config written to: %s\n", path)
		return nil
	},
}

var configPresetCmd = &cobra.Command{
	Use:   "preset [name]",
	Short: "Apply a built-in configuration preset",
	Long: `Apply a built-in configuration preset and save it as the active config.

Available presets:
  security-audit      Network + syscall + process, JSON output, alert thresholds
  threat-hunting      All sensors, NDJSON output, DNS exfil + suspicious exec alerts
  performance-baseline Memory + filesystem + network, text output
  minimal             Process sensor only`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		presets := config.Presets()
		p, ok := presets[args[0]]
		if !ok {
			keys := make([]string, 0, len(presets))
			for k := range presets {
				keys = append(keys, k)
			}
			return fmt.Errorf("unknown preset %q. Available: %s", args[0], strings.Join(keys, ", "))
		}
		path := configPath
		if path == "" {
			path = config.DefaultPath()
		}
		if err := config.Save(p, path); err != nil {
			return err
		}
		fmt.Printf("Preset %q applied and saved to %s\n", args[0], path)
		return nil
	},
}

var configListPresetsCmd = &cobra.Command{
	Use:   "presets",
	Short: "List available built-in presets",
	Long: `List all built-in configuration presets with descriptions.

Apply a preset with: syscalld config preset <name>
Or use at runtime with: syscalld run --preset <name>`,
	Run: func(cmd *cobra.Command, args []string) {
		type presetInfo struct {
			name string
			desc string
		}
		infos := []presetInfo{
			{"minimal", "Process sensor only — lowest overhead"},
			{"performance-baseline", "Memory + filesystem + network for baseline profiling"},
			{"security-audit", "Network + syscall + process with JSON output and alert rules"},
			{"threat-hunting", "All sensors, NDJSON output, DNS exfil + exec anomaly alerts"},
		}
		// Verify all presets in the list actually exist
		presets := config.Presets()
		fmt.Println("\nAvailable presets:")
		for _, info := range infos {
			if _, ok := presets[info.name]; ok {
				fmt.Printf("  %-24s %s\n", info.name, info.desc)
			}
		}
		// Show any presets that exist but aren't in our static list
		known := map[string]bool{"minimal": true, "performance-baseline": true, "security-audit": true, "threat-hunting": true}
		var extra []string
		for name := range presets {
			if !known[name] {
				extra = append(extra, name)
			}
		}
		sort.Strings(extra)
		for _, name := range extra {
			fmt.Printf("  %-24s (no description)\n", name)
		}
		fmt.Println("\nApply with: syscalld config preset <name>")
	},
}

func init() {
	configInitCmd.Flags().BoolVar(&configInitForce, "force", false, "Overwrite existing config file")
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configInitCmd)
	configCmd.AddCommand(configPresetCmd)
	configCmd.AddCommand(configListPresetsCmd)
	rootCmd.AddCommand(configCmd)
}
