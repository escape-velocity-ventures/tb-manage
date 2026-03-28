//go:build windows

package scanner

import (
	"context"
)

func collectStorageInfo(_ context.Context, _ CommandRunner, _ *StorageInfo) error {
	// TODO: implement Windows storage discovery via Get-Disk / Get-Volume
	return nil
}
