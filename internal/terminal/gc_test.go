package terminal

import (
	"testing"
	"time"
)

func TestGCReapsDeadProcess(t *testing.T) {
	now := time.Now()
	sessions := []SessionInfo{
		{
			ID:           "dead-1",
			Name:         "tb-dead-1",
			Created:      now.Add(-10 * time.Minute),
			LastActivity: now.Add(-5 * time.Minute),
			HasProcess:   false,
			DeadSince:    ptrTime(now.Add(-30 * time.Second)),
			WindowCount:  1,
		},
	}

	cfg := GCConfig{
		StaleTimeout:  30 * time.Minute,
		DeadReapDelay: 5 * time.Second,
	}

	result := evaluateGC(sessions, cfg, nil, now)

	if len(result.Reaped) != 1 || result.Reaped[0] != "dead-1" {
		t.Errorf("expected dead-1 to be reaped, got %v", result.Reaped)
	}
	if result.Reasons["dead-1"] != "dead process" {
		t.Errorf("expected reason 'dead process', got %q", result.Reasons["dead-1"])
	}
}

func TestGCDoesNotReapRecentlyDeadProcess(t *testing.T) {
	now := time.Now()
	sessions := []SessionInfo{
		{
			ID:           "dead-recent",
			Name:         "tb-dead-recent",
			Created:      now.Add(-10 * time.Minute),
			LastActivity: now.Add(-1 * time.Second),
			HasProcess:   false,
			DeadSince:    ptrTime(now.Add(-1 * time.Second)),
			WindowCount:  1,
		},
	}

	cfg := GCConfig{
		StaleTimeout:  30 * time.Minute,
		DeadReapDelay: 5 * time.Second,
	}

	result := evaluateGC(sessions, cfg, nil, now)

	if len(result.Reaped) != 0 {
		t.Errorf("expected no reaps for recently dead process, got %v", result.Reaped)
	}
}

func TestGCReapsStaleSessions(t *testing.T) {
	now := time.Now()
	sessions := []SessionInfo{
		{
			ID:           "stale-1",
			Name:         "tb-stale-1",
			Created:      now.Add(-2 * time.Hour),
			LastActivity: now.Add(-45 * time.Minute),
			HasProcess:   true,
			WindowCount:  1,
		},
	}

	cfg := GCConfig{
		StaleTimeout:  30 * time.Minute,
		DeadReapDelay: 5 * time.Second,
	}

	result := evaluateGC(sessions, cfg, nil, now)

	if len(result.Reaped) != 1 || result.Reaped[0] != "stale-1" {
		t.Errorf("expected stale-1 to be reaped, got %v", result.Reaped)
	}
	if result.Reasons["stale-1"] != "stale (no activity for 45m0s)" {
		t.Errorf("unexpected reason: %q", result.Reasons["stale-1"])
	}
}

func TestGCDoesNotReapActiveSessions(t *testing.T) {
	now := time.Now()
	sessions := []SessionInfo{
		{
			ID:           "active-1",
			Name:         "tb-active-1",
			Created:      now.Add(-10 * time.Minute),
			LastActivity: now.Add(-5 * time.Minute),
			HasProcess:   true,
			WindowCount:  1,
		},
	}

	cfg := GCConfig{
		StaleTimeout:  30 * time.Minute,
		DeadReapDelay: 5 * time.Second,
	}

	result := evaluateGC(sessions, cfg, nil, now)

	if len(result.Reaped) != 0 {
		t.Errorf("expected no reaps for active session, got %v", result.Reaped)
	}
}

func TestGCExcludeListPreventsStaleReap(t *testing.T) {
	now := time.Now()
	sessions := []SessionInfo{
		{
			ID:           "svc-redis",
			Name:         "tb-svc-redis",
			Created:      now.Add(-24 * time.Hour),
			LastActivity: now.Add(-2 * time.Hour),
			HasProcess:   true,
			WindowCount:  1,
		},
	}

	cfg := GCConfig{
		StaleTimeout:  30 * time.Minute,
		DeadReapDelay: 5 * time.Second,
	}

	exclude := []string{"svc-redis"}

	result := evaluateGC(sessions, cfg, exclude, now)

	if len(result.Reaped) != 0 {
		t.Errorf("expected excluded service session not to be reaped for staleness, got %v", result.Reaped)
	}
}

func TestGCExcludedSessionStillReapedIfDead(t *testing.T) {
	now := time.Now()
	sessions := []SessionInfo{
		{
			ID:           "svc-redis",
			Name:         "tb-svc-redis",
			Created:      now.Add(-24 * time.Hour),
			LastActivity: now.Add(-2 * time.Hour),
			HasProcess:   false,
			DeadSince:    ptrTime(now.Add(-30 * time.Second)),
			WindowCount:  1,
		},
	}

	cfg := GCConfig{
		StaleTimeout:  30 * time.Minute,
		DeadReapDelay: 5 * time.Second,
	}

	exclude := []string{"svc-redis"}

	result := evaluateGC(sessions, cfg, exclude, now)

	if len(result.Reaped) != 1 || result.Reaped[0] != "svc-redis" {
		t.Errorf("expected dead excluded session to still be reaped, got %v", result.Reaped)
	}
	if result.Reasons["svc-redis"] != "dead process" {
		t.Errorf("unexpected reason: %q", result.Reasons["svc-redis"])
	}
}

func TestGCMultipleSessionsMixedResults(t *testing.T) {
	now := time.Now()
	sessions := []SessionInfo{
		{
			ID: "active", Name: "tb-active",
			Created: now.Add(-10 * time.Minute), LastActivity: now.Add(-1 * time.Minute),
			HasProcess: true, WindowCount: 1,
		},
		{
			ID: "dead", Name: "tb-dead",
			Created: now.Add(-10 * time.Minute), LastActivity: now.Add(-5 * time.Minute),
			HasProcess: false, DeadSince: ptrTime(now.Add(-30 * time.Second)), WindowCount: 1,
		},
		{
			ID: "stale", Name: "tb-stale",
			Created: now.Add(-2 * time.Hour), LastActivity: now.Add(-1 * time.Hour),
			HasProcess: true, WindowCount: 1,
		},
		{
			ID: "svc-protected", Name: "tb-svc-protected",
			Created: now.Add(-24 * time.Hour), LastActivity: now.Add(-12 * time.Hour),
			HasProcess: true, WindowCount: 1,
		},
	}

	cfg := GCConfig{
		StaleTimeout:  30 * time.Minute,
		DeadReapDelay: 5 * time.Second,
	}

	exclude := []string{"svc-protected"}

	result := evaluateGC(sessions, cfg, exclude, now)

	if len(result.Reaped) != 2 {
		t.Fatalf("expected 2 reaped sessions, got %d: %v", len(result.Reaped), result.Reaped)
	}

	reaped := map[string]bool{}
	for _, id := range result.Reaped {
		reaped[id] = true
	}

	if !reaped["dead"] {
		t.Error("expected 'dead' to be reaped")
	}
	if !reaped["stale"] {
		t.Error("expected 'stale' to be reaped")
	}
	if reaped["active"] {
		t.Error("expected 'active' NOT to be reaped")
	}
	if reaped["svc-protected"] {
		t.Error("expected 'svc-protected' NOT to be reaped (excluded)")
	}
}

func TestGCZeroStaleTimeoutDisablesStaleReap(t *testing.T) {
	now := time.Now()
	sessions := []SessionInfo{
		{
			ID: "old", Name: "tb-old",
			Created: now.Add(-24 * time.Hour), LastActivity: now.Add(-12 * time.Hour),
			HasProcess: true, WindowCount: 1,
		},
	}

	cfg := GCConfig{
		StaleTimeout:  0, // disabled
		DeadReapDelay: 5 * time.Second,
	}

	result := evaluateGC(sessions, cfg, nil, now)

	if len(result.Reaped) != 0 {
		t.Errorf("expected no reaps with zero StaleTimeout, got %v", result.Reaped)
	}
}

func TestGCEmptySessions(t *testing.T) {
	cfg := GCConfig{
		StaleTimeout:  30 * time.Minute,
		DeadReapDelay: 5 * time.Second,
	}

	result := evaluateGC(nil, cfg, nil, time.Now())

	if len(result.Reaped) != 0 {
		t.Errorf("expected no reaps for empty sessions, got %v", result.Reaped)
	}
}

func TestGCDeadProcessWithoutDeadSinceUsesLastActivity(t *testing.T) {
	now := time.Now()
	sessions := []SessionInfo{
		{
			ID: "dead-no-ts", Name: "tb-dead-no-ts",
			Created: now.Add(-10 * time.Minute), LastActivity: now.Add(-1 * time.Minute),
			HasProcess: false, DeadSince: nil, // tmux didn't report dead_since
			WindowCount: 1,
		},
	}

	cfg := GCConfig{
		StaleTimeout:  30 * time.Minute,
		DeadReapDelay: 5 * time.Second,
	}

	result := evaluateGC(sessions, cfg, nil, now)

	// LastActivity was 1 min ago, DeadReapDelay is 5s, so it should be reaped
	if len(result.Reaped) != 1 {
		t.Errorf("expected dead session without DeadSince to be reaped using LastActivity, got %v", result.Reaped)
	}
}

func TestGCDeadReapDelayRespected(t *testing.T) {
	now := time.Now()
	sessions := []SessionInfo{
		{
			ID: "dead-wait", Name: "tb-dead-wait",
			Created: now.Add(-10 * time.Minute), LastActivity: now.Add(-1 * time.Minute),
			HasProcess: false, DeadSince: ptrTime(now.Add(-2 * time.Second)), // dead for 2s
			WindowCount: 1,
		},
	}

	cfg := GCConfig{
		StaleTimeout:  30 * time.Minute,
		DeadReapDelay: 10 * time.Second, // require 10s dead
	}

	result := evaluateGC(sessions, cfg, nil, now)

	if len(result.Reaped) != 0 {
		t.Errorf("expected no reaps when dead for less than DeadReapDelay, got %v", result.Reaped)
	}
}

func TestDefaultGCConfig(t *testing.T) {
	cfg := DefaultGCConfig()
	if cfg.StaleTimeout != 30*time.Minute {
		t.Errorf("expected default StaleTimeout 30m, got %v", cfg.StaleTimeout)
	}
	if cfg.DeadReapDelay != 5*time.Second {
		t.Errorf("expected default DeadReapDelay 5s, got %v", cfg.DeadReapDelay)
	}
	if cfg.Interval != 60*time.Second {
		t.Errorf("expected default Interval 60s, got %v", cfg.Interval)
	}
}

// helper
func ptrTime(t time.Time) *time.Time {
	return &t
}
