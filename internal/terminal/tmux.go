package terminal

import (
	"os/exec"
	"strings"
)

const (
	// TmuxSocket is the dedicated tmux socket name, isolating tb-manage
	// sessions from the user's personal tmux.
	TmuxSocket = "tb-manage"

	// TmuxPrefix is prepended to session IDs for tmux session names.
	TmuxPrefix = "tb-"
)

// TmuxAvailable reports whether tmux is installed and on PATH.
func TmuxAvailable() bool {
	_, err := exec.LookPath("tmux")
	return err == nil
}

// TmuxSessionExists checks whether a tmux session for the given ID exists.
func TmuxSessionExists(sessionID string) bool {
	cmd := exec.Command("tmux", "-L", TmuxSocket, "has-session", "-t", tmuxSessionName(sessionID))
	return cmd.Run() == nil
}

// ListTmuxSessions returns the IDs (without prefix) of all tb-manage tmux sessions.
func ListTmuxSessions() []string {
	cmd := exec.Command("tmux", "-L", TmuxSocket, "list-sessions", "-F", "#{session_name}")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var sessions []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, TmuxPrefix) {
			sessions = append(sessions, strings.TrimPrefix(line, TmuxPrefix))
		}
	}
	return sessions
}

// NewTmuxCommand returns an exec.Cmd that creates a new tmux session.
// The tmux client runs in the foreground (attached mode) so it can serve
// as the PTY process. When the PTY is killed, tmux detaches automatically.
func NewTmuxCommand(sessionID string, cols, rows int, shell []string) *exec.Cmd {
	args := []string{
		"-L", TmuxSocket,
		"new-session",
		"-s", tmuxSessionName(sessionID),
		"-x", itoa(cols),
		"-y", itoa(rows),
	}
	if len(shell) > 0 {
		args = append(args, "--")
		args = append(args, shell...)
	}
	return exec.Command("tmux", args...)
}

// AttachTmuxCommand returns an exec.Cmd that attaches to an existing tmux session.
func AttachTmuxCommand(sessionID string) *exec.Cmd {
	return exec.Command("tmux", "-L", TmuxSocket, "attach-session", "-t", tmuxSessionName(sessionID))
}

// DestroyTmuxSession kills a tmux session by ID.
func DestroyTmuxSession(sessionID string) error {
	return exec.Command("tmux", "-L", TmuxSocket, "kill-session", "-t", tmuxSessionName(sessionID)).Run()
}

func tmuxSessionName(sessionID string) string {
	return TmuxPrefix + sessionID
}

// itoa converts an int to its decimal string representation without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-" + itoa(-n)
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
