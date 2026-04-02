package sensors

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// readProcComm reads the process name from /proc/[pid]/comm.
// Returns an empty string if the file is unreadable (process exited,
// permission denied, or /proc not mounted).
func readProcComm(pidDir string) string {
	data, err := os.ReadFile(filepath.Join(pidDir, "comm"))
	if err != nil {
		return ""
	}
	comm := strings.TrimSpace(string(data))
	if len(comm) > 16 {
		comm = comm[:16]
	}
	return comm
}

// buildInodePIDMap constructs a socket-inode → PID map by scanning
// /proc/[pid]/fd for symbolic links of the form "socket:[inode]".
//
// This allows network and DNS sensors to attribute connections to their
// owning process by cross-referencing the inode field from /proc/net/tcp
// and /proc/net/udp with the file descriptors held by each process.
func buildInodePIDMap() map[string]int {
	result := make(map[string]int)

	fdDirs, err := filepath.Glob("/proc/[0-9]*/fd")
	if err != nil {
		return result
	}

	for _, fdDir := range fdDirs {
		pidStr := filepath.Base(filepath.Dir(fdDir))
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}

		entries, err := os.ReadDir(fdDir)
		if err != nil {
			// Process may have exited between glob and ReadDir — skip silently.
			continue
		}

		// Cap per-process FD scan to prevent DoS from processes with huge fd tables.
		fdLimit := 256
		if len(entries) < fdLimit {
			fdLimit = len(entries)
		}

		for _, entry := range entries[:fdLimit] {
			link, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
			if err != nil {
				continue
			}
			// Socket symlinks have the form: "socket:[12345]"
			if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
				inode := link[8 : len(link)-1]
				result[inode] = pid
			}
		}
	}

	return result
}
