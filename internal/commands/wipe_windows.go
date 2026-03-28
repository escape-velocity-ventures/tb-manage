//go:build windows

package commands

import (
	"context"
	"log/slog"
	"time"
)

func platformWipe(_ context.Context, delay time.Duration) (*WipeResult, error) {
	slog.Info("wipe: not yet implemented on windows", "delay", delay)
	return &WipeResult{
		Method:          "no-op (windows)",
		PartitionWiped:  false,
		RebootScheduled: false,
	}, nil
}
