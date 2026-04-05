package supervisor

import (
	"context"
	"log/slog"
	"time"
)

// HealthChecker periodically checks agent sessions and restarts dead ones.
type HealthChecker struct {
	tmux     *TmuxManager
	registry *Registry
	interval time.Duration
	log      *slog.Logger

	// restartFn is called when a dead session needs restarting.
	// Exposed for testing; defaults to startAgentSession.
	restartFn func(name string) error
}

// NewHealthChecker creates a health checker that runs every interval.
func NewHealthChecker(tmux *TmuxManager, registry *Registry, interval time.Duration, logger *slog.Logger) *HealthChecker {
	h := &HealthChecker{
		tmux:     tmux,
		registry: registry,
		interval: interval,
		log:      logger,
	}
	h.restartFn = h.defaultRestart
	return h
}

// CheckOnce runs one health check pass. Returns names of sessions restarted.
func (h *HealthChecker) CheckOnce() []string {
	var restarted []string
	sessions := h.tmux.ListSessions()
	alive := make(map[string]bool)
	for _, s := range sessions {
		alive[s.Name] = true
	}

	for _, name := range h.registry.Names() {
		if !alive[name] {
			h.log.Warn("agent session dead, restarting", "agent", name)
			if err := h.restartFn(name); err != nil {
				h.log.Error("failed to restart agent", "agent", name, "error", err)
			} else {
				restarted = append(restarted, name)
			}
		}
	}
	return restarted
}

// Run starts the health check loop, blocking until ctx is cancelled.
func (h *HealthChecker) Run(ctx context.Context) {
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.CheckOnce()
		}
	}
}

func (h *HealthChecker) defaultRestart(name string) error {
	cmd, err := h.registry.BuildFullCommand(name)
	if err != nil {
		return err
	}
	return h.tmux.StartSession(name, cmd)
}
