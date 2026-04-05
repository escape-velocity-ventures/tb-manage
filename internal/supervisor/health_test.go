package supervisor

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestHealthCheck_AllAlive(t *testing.T) {
	mc := newMockCommander()
	// list-sessions returns all 4 agents
	output := "tinkerbelle\t1712000000\t1712001000\ncybill\t1712000100\t1712001100\naurelia\t1712000200\t1712001200\nblades\t1712000300\t1712001300\n"
	mc.On("tmux", []string{"list-sessions", "-F", "#{session_name}\t#{session_created}\t#{session_activity}"}, []byte(output), nil)

	tm := NewTmuxManager(mc)
	r := DefaultRegistry()
	h := NewHealthChecker(tm, r, 30*time.Second, testLogger())

	restarted := h.CheckOnce()
	if len(restarted) != 0 {
		t.Errorf("expected no restarts, got %v", restarted)
	}
}

func TestHealthCheck_OneDown(t *testing.T) {
	mc := newMockCommander()
	// list-sessions missing cybill
	output := "tinkerbelle\t1712000000\t1712001000\naurelia\t1712000200\t1712001200\nblades\t1712000300\t1712001300\n"
	mc.On("tmux", []string{"list-sessions", "-F", "#{session_name}\t#{session_created}\t#{session_activity}"}, []byte(output), nil)

	tm := NewTmuxManager(mc)
	r := DefaultRegistry()
	h := NewHealthChecker(tm, r, 30*time.Second, testLogger())

	restartCalled := false
	h.restartFn = func(name string) error {
		if name == "cybill" {
			restartCalled = true
		}
		return nil
	}

	restarted := h.CheckOnce()
	if !restartCalled {
		t.Error("expected restart for cybill")
	}
	if len(restarted) != 1 {
		t.Errorf("expected 1 restart, got %d", len(restarted))
	}
}

func TestHealthCheck_RestartFails(t *testing.T) {
	mc := newMockCommander()
	// list-sessions returns none
	mc.On("tmux", []string{"list-sessions", "-F", "#{session_name}\t#{session_created}\t#{session_activity}"}, nil, fmt.Errorf("no server"))

	tm := NewTmuxManager(mc)

	// Registry with just one agent for simplicity
	r := &Registry{agents: map[string]AgentConfig{
		"test": {Skill: "test", Channel: "test-ch"},
	}}
	h := NewHealthChecker(tm, r, 30*time.Second, testLogger())

	h.restartFn = func(name string) error {
		return fmt.Errorf("tmux not available")
	}

	restarted := h.CheckOnce()
	if len(restarted) != 0 {
		t.Errorf("expected no successful restarts, got %v", restarted)
	}
}

func TestHealthCheck_RunCancel(t *testing.T) {
	mc := newMockCommander()
	output := "tinkerbelle\t1712000000\t1712001000\n"
	mc.On("tmux", []string{"list-sessions", "-F", "#{session_name}\t#{session_created}\t#{session_activity}"}, []byte(output), nil)

	tm := NewTmuxManager(mc)
	r := &Registry{agents: map[string]AgentConfig{
		"tinkerbelle": {Skill: "oncall", Channel: "oncall-slack"},
	}}
	h := NewHealthChecker(tm, r, 10*time.Millisecond, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		h.Run(ctx)
		close(done)
	}()

	// Let it run briefly, then cancel
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// good
	case <-time.After(2 * time.Second):
		t.Fatal("health checker did not stop after context cancel")
	}
}
