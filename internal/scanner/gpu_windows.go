//go:build windows

package scanner

import "context"

func collectGPUInfo(_ context.Context, _ CommandRunner) GPUInfo {
	return GPUInfo{}
}
