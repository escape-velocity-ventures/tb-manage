package scanner

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// hostSysfsRoot returns the sysfs root for the host's network interfaces.
// When running inside a container with /host/sys mounted, HOST_ROOT should
// be set to "/host" so we read /host/sys/class/net/ instead of the pod's
// /sys/class/net/ (which only shows container interfaces).
func hostSysfsRoot() string {
	if root := os.Getenv("HOST_ROOT"); root != "" {
		return root + "/sys/class/net"
	}
	return ""
}

// collectHostInterfaces enumerates network interfaces from sysfs.
// Returns nil if the sysfs path doesn't exist or can't be read.
func collectHostInterfaces(sysfsNetPath string) []InterfaceInfo {
	entries, err := os.ReadDir(sysfsNetPath)
	if err != nil {
		return nil
	}

	var interfaces []InterfaceInfo
	for _, entry := range entries {
		name := entry.Name()
		iface := InterfaceInfo{
			Name: name,
		}

		base := filepath.Join(sysfsNetPath, name)

		if mac, err := readSysfsFile(filepath.Join(base, "address")); err == nil {
			iface.MAC = mac
		}

		if mtuStr, err := readSysfsFile(filepath.Join(base, "mtu")); err == nil {
			if mtu, err := strconv.Atoi(mtuStr); err == nil {
				iface.MTU = mtu
			}
		}

		if state, err := readSysfsFile(filepath.Join(base, "operstate")); err == nil {
			iface.State = strings.ToLower(state)
		}

		interfaces = append(interfaces, iface)
	}

	return interfaces
}

// readSysfsFile reads a single-line sysfs file and trims whitespace.
func readSysfsFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
