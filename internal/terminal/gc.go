package terminal

import (
	"fmt"
	"log/slog"
	"time"
)

// GCConfig controls session garbage collection behavior.
type GCConfig struct {
	// StaleTimeout is how long a session can be inactive before it's considered
	// stale. Set to 0 to disable stale-based reaping. Default: 30m.
	StaleTimeout time.Duration

	// DeadReapDelay is how long to wait after a process dies before reaping
	// the session. Allows time to read final output. Default: 5s.
	DeadReapDelay time.Duration

	// Interval is how often the GC loop runs. Default: 60s.
	Interval time.Duration
}

// DefaultGCConfig returns the default GC configuration.
func DefaultGCConfig() GCConfig {
	return GCConfig{
		StaleTimeout:  30 * time.Minute,
		DeadReapDelay: 5 * time.Second,
		Interval:      60 * time.Second,
	}
}

// GCResult describes what the GC did.
type GCResult struct {
	Reaped  []string          // session IDs that were destroyed
	Reasons map[string]string // sessionID -> reason
}

// RunGC inspects all sessions and reaps dead/stale ones. Sessions in the
// exclude list are protected from stale-based reaping (but still reaped
// if their process is dead).
func RunGC(config GCConfig, exclude []string) (*GCResult, error) {
	sessions, err := InspectAllSessions()
	if err != nil {
		return nil, fmt.Errorf("gc inspect: %w", err)
	}

	now := time.Now()
	result := evaluateGC(sessions, config, exclude, now)

	// Actually destroy the sessions
	for _, id := range result.Reaped {
		if err := DestroyTmuxSession(id); err != nil {
			slog.Warn("gc: failed to destroy session", "id", id, "error", err)
		} else {
			slog.Info("gc: reaped session", "id", id, "reason", result.Reasons[id])
		}
	}

	return result, nil
}

// EvaluateGCPublic is the exported version of evaluateGC for use by the CLI
// dry-run command. It does not perform any side effects.
func EvaluateGCPublic(sessions []SessionInfo, config GCConfig, exclude []string, now time.Time) *GCResult {
	return evaluateGC(sessions, config, exclude, now)
}

// evaluateGC is the pure logic for determining which sessions to reap.
// It does not perform any side effects — separated for testability.
func evaluateGC(sessions []SessionInfo, config GCConfig, exclude []string, now time.Time) *GCResult {
	result := &GCResult{
		Reasons: make(map[string]string),
	}

	excludeSet := make(map[string]bool, len(exclude))
	for _, id := range exclude {
		excludeSet[id] = true
	}

	for _, s := range sessions {
		// Rule 1: Dead process — reap after DeadReapDelay
		if !s.HasProcess {
			deadTime := s.LastActivity // fallback if DeadSince not set
			if s.DeadSince != nil {
				deadTime = *s.DeadSince
			}
			if now.Sub(deadTime) >= config.DeadReapDelay {
				result.Reaped = append(result.Reaped, s.ID)
				result.Reasons[s.ID] = "dead process"
				continue
			}
		}

		// Rule 2: Stale session — skip if in exclude list or StaleTimeout is 0
		if config.StaleTimeout > 0 && !excludeSet[s.ID] && s.HasProcess {
			idle := now.Sub(s.LastActivity)
			if idle >= config.StaleTimeout {
				result.Reaped = append(result.Reaped, s.ID)
				result.Reasons[s.ID] = fmt.Sprintf("stale (no activity for %s)", idle)
				continue
			}
		}
	}

	return result
}
