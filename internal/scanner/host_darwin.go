package scanner

import (
	"context"
	"strconv"
	"strings"
)

// extractIORegValue parses ioreg output like: "Key" = "Value"
func extractIORegValue(line string) string {
	parts := strings.SplitN(line, "= ", 2)
	if len(parts) < 2 {
		return ""
	}
	return strings.Trim(strings.TrimSpace(parts[1]), `"`)
}

func collectHostInfo(ctx context.Context, runner CommandRunner, info *HostInfo) error {
	// OS version from sw_vers
	if out, err := runner.Run(ctx, "sw_vers -productVersion"); err == nil {
		info.System.OSVersion = strings.TrimSpace(string(out))
	}

	// CPU model
	if out, err := runner.Run(ctx, "sysctl -n machdep.cpu.brand_string"); err == nil {
		info.System.CPUModel = strings.TrimSpace(string(out))
	}

	// CPU cores (physical)
	if out, err := runner.Run(ctx, "sysctl -n hw.physicalcpu"); err == nil {
		if cores, err := strconv.Atoi(strings.TrimSpace(string(out))); err == nil {
			info.System.CPUCores = cores
		}
	}

	// Memory in GB
	if out, err := runner.Run(ctx, "sysctl -n hw.memsize"); err == nil {
		if bytes, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64); err == nil {
			info.System.MemoryGB = float64(bytes) / (1024 * 1024 * 1024)
		}
	}

	// Serial number from IOKit
	// Output format: "IOPlatformSerialNumber" = "C02XXXXXXXXX"
	if out, err := runner.Run(ctx, `ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformSerialNumber`); err == nil {
		if serial := extractIORegValue(string(out)); !IsJunkSerial(serial) {
			info.System.SerialNumber = serial
		}
	}

	// Machine ID (Hardware UUID)
	// Output format: "IOPlatformUUID" = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
	if out, err := runner.Run(ctx, `ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID`); err == nil {
		if uuid := extractIORegValue(string(out)); uuid != "" {
			info.System.MachineID = uuid
		}
	}

	return nil
}
