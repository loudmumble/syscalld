package cmd

import (
	"fmt"
	"os"

	"github.com/loudmumble/syscalld/core"
	"github.com/loudmumble/syscalld/internal/config"
)

// buildFilter constructs a SensorFilter from the CLI config, applying
// target_pids, exclude_pids, and exclude_comms. Warns on unsupported fields.
func buildFilter(cfg *config.Config) *core.SensorFilter {
	filter := core.NewSensorFilter()
	for _, pid := range cfg.Filters.TargetPIDs {
		filter.TargetPIDs[pid] = struct{}{}
	}
	for _, pid := range cfg.Filters.ExcludePIDs {
		filter.ExcludePIDs[pid] = struct{}{}
	}
	if len(cfg.Filters.TargetComms) > 0 {
		fmt.Fprintln(os.Stderr, "Warning: target_comms is not supported; use exclude_comms instead")
	}
	for _, comm := range cfg.Filters.ExcludeComms {
		filter.ExcludeComms[comm] = struct{}{}
	}
	return filter
}
