package scanner

import (
	"os"
	"strings"
)

// hostProcNetDev returns the path to /proc/1/net/dev on the host.
// With hostPID: true, PID 1 is the host's init process, so /proc/1/net/dev
// shows the host's real network interfaces (not the pod's).
//
// Note: /sys/class/net/ does NOT work for this purpose — it's filtered by
// the reader's network namespace, so even a host-mounted sysfs only shows
// pod interfaces.
func hostProcNetDev() string {
	if root := os.Getenv("HOST_ROOT"); root != "" {
		return root + "/proc/1/net/dev"
	}
	return ""
}

// collectHostInterfaces reads network interface names from /proc/1/net/dev.
// Returns nil if the file doesn't exist or can't be read.
//
// Format of /proc/net/dev:
//
//	Inter-|   Receive                                                |  Transmit
//	 face |bytes    packets errs drop fifo frame compressed multicast|bytes    ...
//	  eth0: 452698464934 709126800 ...
//	  cni0: 783649833831 194887922 ...
func collectHostInterfaces(procNetDevPath string) []InterfaceInfo {
	data, err := os.ReadFile(procNetDevPath)
	if err != nil {
		return nil
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) < 3 {
		return nil // Need at least header + 1 interface
	}

	var interfaces []InterfaceInfo
	// Skip first 2 lines (headers)
	for _, line := range lines[2:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Format: "  iface_name: rx_bytes rx_packets ..."
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		name := strings.TrimSpace(parts[0])
		if name == "" {
			continue
		}

		interfaces = append(interfaces, InterfaceInfo{
			Name: name,
		})
	}

	return interfaces
}
