package terminal

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// SessionInfo holds metadata about a tmux session.
type SessionInfo struct {
	ID           string     // session name without tb- prefix
	Name         string     // full tmux session name (tb-xxx)
	Created      time.Time  // when session was created
	LastActivity time.Time  // last input/output activity
	HasProcess   bool       // whether the shell process is still alive
	DeadSince    *time.Time // when the process died (nil if alive or unknown)
	WindowCount  int        // number of tmux windows
}

// InspectSession returns metadata for a single tmux session.
func InspectSession(sessionID string) (*SessionInfo, error) {
	name := tmuxSessionName(sessionID)

	// Get session metadata: created, activity, windows
	cmd := exec.Command("tmux", "-L", TmuxSocket, "display-message",
		"-t", name, "-p", "#{session_created} #{session_activity} #{session_windows}")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("inspect session %s: %w", sessionID, err)
	}

	parts := strings.Fields(strings.TrimSpace(string(out)))
	if len(parts) < 3 {
		return nil, fmt.Errorf("unexpected tmux output for session %s: %q", sessionID, string(out))
	}

	created, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse session_created for %s: %w", sessionID, err)
	}

	activity, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse session_activity for %s: %w", sessionID, err)
	}

	windows, err := strconv.Atoi(parts[2])
	if err != nil {
		return nil, fmt.Errorf("parse session_windows for %s: %w", sessionID, err)
	}

	// Check if process is alive
	hasProcess, deadSince := checkPaneProcess(name)

	return &SessionInfo{
		ID:           sessionID,
		Name:         name,
		Created:      time.Unix(created, 0),
		LastActivity: time.Unix(activity, 0),
		HasProcess:   hasProcess,
		DeadSince:    deadSince,
		WindowCount:  windows,
	}, nil
}

// InspectAllSessions returns metadata for all tb-manage tmux sessions.
func InspectAllSessions() ([]SessionInfo, error) {
	ids := ListTmuxSessions()
	if len(ids) == 0 {
		return nil, nil
	}

	var sessions []SessionInfo
	for _, id := range ids {
		info, err := InspectSession(id)
		if err != nil {
			// Session may have disappeared between list and inspect; skip it
			continue
		}
		sessions = append(sessions, *info)
	}
	return sessions, nil
}

// checkPaneProcess checks whether the main pane process is alive.
// Returns (alive, deadSince). If the pane is dead but we can't determine when,
// deadSince is nil.
func checkPaneProcess(sessionName string) (bool, *time.Time) {
	cmd := exec.Command("tmux", "-L", TmuxSocket, "list-panes",
		"-t", sessionName, "-F", "#{pane_pid} #{pane_dead}")
	out, err := cmd.Output()
	if err != nil {
		// Can't determine — assume alive to be safe
		return true, nil
	}

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "1" {
			// pane_dead == 1 means the process exited
			return false, nil
		}
	}
	return true, nil
}
