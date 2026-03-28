package terminal

import (
	"strings"
	"testing"
)

func TestTmuxSessionName(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"abc-123", "tb-abc-123"},
		{"", "tb-"},
		{"session-with-dashes", "tb-session-with-dashes"},
	}
	for _, tt := range tests {
		got := tmuxSessionName(tt.id)
		if got != tt.want {
			t.Errorf("tmuxSessionName(%q) = %q, want %q", tt.id, got, tt.want)
		}
	}
}

func TestTmuxAvailable(t *testing.T) {
	// Should not panic regardless of whether tmux is installed.
	_ = TmuxAvailable()
}

func TestNewTmuxCommandArgs(t *testing.T) {
	cmd := NewTmuxCommand("sess-1", 120, 40, []string{"/bin/bash"})
	args := strings.Join(cmd.Args, " ")

	for _, want := range []string{
		"-L tb-manage",
		"new-session",
		"-s tb-sess-1",
		"-x 120",
		"-y 40",
		"-- /bin/bash",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("NewTmuxCommand args missing %q; got: %s", want, args)
		}
	}
}

func TestNewTmuxCommandNoShell(t *testing.T) {
	cmd := NewTmuxCommand("sess-2", 80, 24, nil)
	args := strings.Join(cmd.Args, " ")

	if strings.Contains(args, "--") {
		t.Errorf("NewTmuxCommand with no shell should not contain '--'; got: %s", args)
	}
}

func TestAttachTmuxCommandArgs(t *testing.T) {
	cmd := AttachTmuxCommand("sess-1")
	args := strings.Join(cmd.Args, " ")

	for _, want := range []string{"-L tb-manage", "attach-session", "-t tb-sess-1"} {
		if !strings.Contains(args, want) {
			t.Errorf("AttachTmuxCommand args missing %q; got: %s", want, args)
		}
	}
}

func TestItoa(t *testing.T) {
	tests := []struct {
		n    int
		want string
	}{
		{0, "0"},
		{1, "1"},
		{80, "80"},
		{120, "120"},
		{256, "256"},
	}
	for _, tt := range tests {
		got := itoa(tt.n)
		if got != tt.want {
			t.Errorf("itoa(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

// Integration test: only runs if tmux is available.
func TestTmuxIntegration(t *testing.T) {
	if !TmuxAvailable() {
		t.Skip("tmux not installed")
	}

	id := "test-integration"

	// Ensure clean state
	_ = DestroyTmuxSession(id)

	if TmuxSessionExists(id) {
		t.Fatal("session should not exist before creation")
	}

	// Create a detached session for testing (we don't need a PTY here)
	createCmd := NewTmuxCommand(id, 80, 24, []string{"/bin/sh"})
	// Override: add -d flag for test (we can't attach without a real PTY)
	createCmd.Args = append(createCmd.Args[:0],
		"tmux", "-L", TmuxSocket, "new-session", "-d", "-s", tmuxSessionName(id), "-x", "80", "-y", "24", "--", "/bin/sh",
	)
	if err := createCmd.Run(); err != nil {
		t.Fatalf("failed to create tmux session: %v", err)
	}

	if !TmuxSessionExists(id) {
		t.Fatal("session should exist after creation")
	}

	sessions := ListTmuxSessions()
	found := false
	for _, s := range sessions {
		if s == id {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ListTmuxSessions() should include %q; got %v", id, sessions)
	}

	if err := DestroyTmuxSession(id); err != nil {
		t.Fatalf("DestroyTmuxSession failed: %v", err)
	}

	if TmuxSessionExists(id) {
		t.Fatal("session should not exist after destroy")
	}
}
