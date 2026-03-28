//go:build windows

package scanner

import "context"

func collectComplianceInfo(_ context.Context, _ CommandRunner) *ComplianceInfo {
	skip := ComplianceCheck{Status: "skip", Detail: "not applicable on Windows"}
	return &ComplianceInfo{
		LUKSEncrypted:      skip,
		UnattendedUpgrades: skip,
		SSHCAConfigured:    skip,
		RootLoginDisabled:  skip,
		FirewallActive:     skip,
		K3sVersion:         skip,
		OpenSCAPInstalled:  skip,
		USBGuardActive:     skip,
	}
}
