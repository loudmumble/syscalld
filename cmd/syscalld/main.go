// Command syscalld is the CLI daemon for the syscalld framework.
package main

import (
	"os"

	"github.com/loudmumble/syscalld/cmd/syscalld/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
