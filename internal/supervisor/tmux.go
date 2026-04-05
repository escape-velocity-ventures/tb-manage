// Package supervisor manages Claude Code agent sessions in tmux.
package supervisor

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// SessionInfo describes a running tmux session.
type SessionInfo struct {
	Name     string
	Created  time.Time
	Activity time.Time
}

// Commander abstracts exec.Command for testing.
type Commander interface {
	// Run executes a command and returns combined output and error.
	Run(name string, args ...string) ([]byte, error)
}

// ExecCommander uses real exec.Command.
type ExecCommander struct{}

func (e *ExecCommander) Run(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// TmuxManager manages tmux sessions for Claude Code agents.
type TmuxManager struct {
	cmd Commander
}

// NewTmuxManager creates a TmuxManager with the given commander.
func NewTmuxManager(cmd Commander) *TmuxManager {
	return &TmuxManager{cmd: cmd}
}

// StartSession launches a new tmux session with the given name and command.
// Name must match ^[a-zA-Z0-9][a-zA-Z0-9_-]*$ to prevent tmux interpretation issues.
func (t *TmuxManager) StartSession(name, command string) error {
	if name == "" {
		return fmt.Errorf("session name is required")
	}
	if !safeIdentifier.MatchString(name) {
		return fmt.Errorf("session name %q contains unsafe characters (must match %s)", name, safeIdentifier.String())
	}
	if command == "" {
		return fmt.Errorf("command is required")
	}
	if t.HasSession(name) {
		return fmt.Errorf("session %q already exists", name)
	}
	// Wrap in sh -c to ensure shell interpretation of env vars and pipes.
	// tmux does invoke via shell internally, but being explicit prevents
	// ambiguity across tmux versions.
	_, err := t.cmd.Run("tmux", "new-session", "-d", "-s", name, "sh", "-c", command)
	if err != nil {
		return fmt.Errorf("start session %q: %w", name, err)
	}
	return nil
}

// StopSession kills a tmux session by name.
func (t *TmuxManager) StopSession(name string) error {
	if name == "" {
		return fmt.Errorf("session name is required")
	}
	if !t.HasSession(name) {
		return fmt.Errorf("session %q not found", name)
	}
	_, err := t.cmd.Run("tmux", "kill-session", "-t", name)
	if err != nil {
		return fmt.Errorf("stop session %q: %w", name, err)
	}
	return nil
}

// HasSession checks if a tmux session exists.
func (t *TmuxManager) HasSession(name string) bool {
	_, err := t.cmd.Run("tmux", "has-session", "-t", name)
	return err == nil
}

// ListSessions returns all running tmux sessions.
func (t *TmuxManager) ListSessions() []SessionInfo {
	out, err := t.cmd.Run("tmux", "list-sessions", "-F", "#{session_name}\t#{session_created}\t#{session_activity}")
	if err != nil {
		return nil
	}

	var sessions []SessionInfo
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) < 3 {
			continue
		}
		info := SessionInfo{Name: parts[0]}
		// Parse Unix timestamps
		if ts, err := parseUnixTimestamp(parts[1]); err == nil {
			info.Created = ts
		}
		if ts, err := parseUnixTimestamp(parts[2]); err == nil {
			info.Activity = ts
		}
		sessions = append(sessions, info)
	}
	return sessions
}

// CaptureLogs captures the last N lines from a tmux session's pane.
func (t *TmuxManager) CaptureLogs(name string, lines int) string {
	if lines <= 0 {
		lines = 100
	}
	out, err := t.cmd.Run("tmux", "capture-pane", "-t", name, "-p", "-S", fmt.Sprintf("-%d", lines))
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(out), "\n")
}

func parseUnixTimestamp(s string) (time.Time, error) {
	var ts int64
	_, err := fmt.Sscanf(s, "%d", &ts)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(ts, 0), nil
}
