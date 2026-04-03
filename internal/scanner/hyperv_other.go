//go:build !windows && !darwin

package scanner

// platformVMScanners returns VM discovery scanners for the current platform.
func platformVMScanners() []Scanner {
	return []Scanner{NewQEMUScanner(), NewLimaScanner()}
}
