package scanner

import (
	"context"
	"strconv"
	"strings"
)

func collectHostInfo(ctx context.Context, runner CommandRunner, info *HostInfo) error {
	// OS version from /etc/os-release
	if out, err := runner.Run(ctx, `grep -E "^(PRETTY_NAME|VERSION_ID)=" /etc/os-release 2>/dev/null`); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				info.System.OSVersion = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
			}
		}
	}

	// CPU model from /proc/cpuinfo
	if out, err := runner.Run(ctx, `grep -m1 "model name" /proc/cpuinfo 2>/dev/null`); err == nil {
		parts := strings.SplitN(string(out), ":", 2)
		if len(parts) == 2 {
			info.System.CPUModel = strings.TrimSpace(parts[1])
		}
	}

	// CPU cores (physical)
	if out, err := runner.Run(ctx, `grep -c "^processor" /proc/cpuinfo 2>/dev/null`); err == nil {
		if cores, err := strconv.Atoi(strings.TrimSpace(string(out))); err == nil {
			info.System.CPUCores = cores
		}
	}

	// Memory from /proc/meminfo (MemTotal in kB)
	if out, err := runner.Run(ctx, `grep MemTotal /proc/meminfo 2>/dev/null`); err == nil {
		fields := strings.Fields(string(out))
		if len(fields) >= 2 {
			if kb, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				info.System.MemoryGB = float64(kb) / (1024 * 1024)
			}
		}
	}

	// Serial number from DMI/SMBIOS (requires root or readable sysfs)
	if out, err := runner.Run(ctx, `cat /sys/class/dmi/id/product_serial 2>/dev/null`); err == nil {
		serial := strings.TrimSpace(string(out))
		if !IsJunkSerial(serial) {
			info.System.SerialNumber = serial
		}
	}

	// Machine ID (always readable, unique per OS install)
	if out, err := runner.Run(ctx, `cat /etc/machine-id 2>/dev/null`); err == nil {
		info.System.MachineID = strings.TrimSpace(string(out))
	}

	return nil
}
