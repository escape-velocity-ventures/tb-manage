package terminal

import (
	"context"
	"log/slog"
	"time"
)

// StartGCLoop runs the session garbage collector on a timer. It blocks until
// ctx is cancelled. excludeFn is called on each tick to get the current list
// of managed service session IDs that should not be reaped for staleness.
func StartGCLoop(ctx context.Context, config GCConfig, excludeFn func() []string) {
	if config.Interval <= 0 {
		config.Interval = 60 * time.Second
	}

	slog.Info("session gc loop started",
		"interval", config.Interval,
		"stale_timeout", config.StaleTimeout,
		"dead_reap_delay", config.DeadReapDelay,
	)

	ticker := time.NewTicker(config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("session gc loop stopped")
			return
		case <-ticker.C:
			exclude := excludeFn()
			result, err := RunGC(config, exclude)
			if err != nil {
				slog.Warn("session gc error", "error", err)
				continue
			}
			if len(result.Reaped) > 0 {
				slog.Info("session gc cycle complete", "reaped", len(result.Reaped))
			}
		}
	}
}
