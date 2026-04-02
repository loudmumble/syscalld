// Package cmd implements the syscalld CLI.
package cmd

import (
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"
)

// Build-time variables set via ldflags.
var (
	Version   = "2.0.0"
	Commit    = "dev"
	BuildDate = "unknown"
)

var configPath string

var rootCmd = &cobra.Command{
	Use:   "syscalld",
	Short: "Linux kernel sensor daemon — monitor syscalls, processes, network, and more",
	Long: `
  ╔═══════════════════════════════════════════════════════════╗
  ║                     syscalld v` + Version + `                      ║
  ║         Linux Kernel Sensor Monitoring Daemon             ║
  ╚═══════════════════════════════════════════════════════════╝

  Real-time kernel event monitoring via eBPF probes with automatic
  fallback to /proc when eBPF is unavailable (CGO_ENABLED=0).

  SENSORS
    syscall      Trace system calls across all processes
    process      Monitor process execution, fork, and exit
    filesystem   Detect file descriptor activity and access
    network      Track TCP/UDP connections and socket state
    memory       Detect anonymous executable memory regions (RWX, memfd)
    module       Monitor kernel module load/unload events
    dns          Capture DNS query traffic via UDP port 53

  QUICK START
    sudo syscalld run                         Run all sensors, text output
    sudo syscalld run --preset security-audit Use a built-in preset
    sudo syscalld run --format ndjson         NDJSON for log pipelines
    sudo syscalld tui                         Interactive terminal dashboard
    syscalld config init                      Generate default config

  CONFIGURATION
    Config file: ~/.syscalld/config.yaml (created with 'config init')
    Override with --config <path> or use --preset for one-off profiles.

  For more details on each command, use: syscalld <command> --help`,
	Version: Version,
}

// Execute runs the root command.
func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}
	return nil
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "",
		"Config file path (default: ~/.syscalld/config.yaml)")

	rootCmd.SetVersionTemplate(fmt.Sprintf(
		"syscalld %s (commit: %s, built: %s, go: %s, os/arch: %s/%s)\n",
		Version, Commit, BuildDate, runtime.Version(), runtime.GOOS, runtime.GOARCH,
	))
}
