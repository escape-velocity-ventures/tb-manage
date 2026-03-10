//go:build windows

package scanner

import (
	"context"
)

func collectNetworkInfo(_ context.Context, _ CommandRunner, _ *NetworkInfo) error {
	// TODO: implement Windows network discovery via Get-NetAdapter / Get-NetIPAddress
	return nil
}
