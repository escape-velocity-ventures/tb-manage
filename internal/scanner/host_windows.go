//go:build windows

package scanner

import (
	"context"
	"strconv"
	"strings"
)

func collectHostInfo(ctx context.Context, runner CommandRunner, info *HostInfo) error {
	// OS version
	if out, err := runner.Run(ctx, "(Get-CimInstance Win32_OperatingSystem).Caption"); err == nil {
		info.System.OSVersion = strings.TrimSpace(string(out))
	}

	// CPU model
	if out, err := runner.Run(ctx, "(Get-CimInstance Win32_Processor).Name"); err == nil {
		info.System.CPUModel = strings.TrimSpace(string(out))
	}

	// CPU cores
	if out, err := runner.Run(ctx, "(Get-CimInstance Win32_Processor).NumberOfLogicalProcessors"); err == nil {
		if cores, e := strconv.Atoi(strings.TrimSpace(string(out))); e == nil {
			info.System.CPUCores = cores
		}
	}

	// Memory in GB
	if out, err := runner.Run(ctx, "[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)"); err == nil {
		if mem, e := strconv.ParseFloat(strings.TrimSpace(string(out)), 64); e == nil {
			info.System.MemoryGB = mem
		}
	}

	// Serial number
	if out, err := runner.Run(ctx, "(Get-CimInstance Win32_BIOS).SerialNumber"); err == nil {
		serial := strings.TrimSpace(string(out))
		if !IsJunkSerial(serial) {
			info.System.SerialNumber = serial
		}
	}

	// Machine ID (from MachineGuid in registry)
	if out, err := runner.Run(ctx, "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography').MachineGuid"); err == nil {
		info.System.MachineID = strings.TrimSpace(string(out))
	}

	return nil
}
