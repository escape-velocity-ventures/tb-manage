//go:build windows

package scanner

import "context"

func collectPatchInfo(_ context.Context, _ CommandRunner) PatchInfo {
	return PatchInfo{}
}

// parsePendingPackages — Windows stub for cross-platform test compilation.
func parsePendingPackages(output string) (total, security int, pkgs []PendingPkg) {
	return 0, 0, nil
}

// parseLastAptUpdate — Windows stub for cross-platform test compilation.
func parseLastAptUpdate(log string) string {
	return ""
}

// parseLastAutoUpdate — Windows stub for cross-platform test compilation.
func parseLastAutoUpdate(log string) string {
	return ""
}
