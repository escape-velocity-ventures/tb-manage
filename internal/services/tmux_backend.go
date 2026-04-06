package services

import (
	"fmt"
	"os/exec"
	"strings"
)

// RealTmuxBackend implements TmuxBackend using real tmux commands.
// It uses the tb-manage socket (-L tb-manage) to isolate from user tmux.
type RealTmuxBackend struct {
	socket string
}

// NewRealTmuxBackend creates a TmuxBackend that uses the tb-manage tmux socket.
func NewRealTmuxBackend() *RealTmuxBackend {
	return &RealTmuxBackend{socket: "tb-manage"}
}

func (r *RealTmuxBackend) HasSession(name string) bool {
	cmd := exec.Command("tmux", "-L", r.socket, "has-session", "-t", name)
	return cmd.Run() == nil
}

func (r *RealTmuxBackend) StartSession(name, command string) error {
	cmd := exec.Command("tmux", "-L", r.socket, "new-session", "-d", "-s", name, "sh", "-c", command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tmux new-session: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (r *RealTmuxBackend) StopSession(name string) error {
	cmd := exec.Command("tmux", "-L", r.socket, "kill-session", "-t", name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tmux kill-session: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (r *RealTmuxBackend) ListSessions() []string {
	cmd := exec.Command("tmux", "-L", r.socket, "list-sessions", "-F", "#{session_name}")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var sessions []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			sessions = append(sessions, line)
		}
	}
	return sessions
}
