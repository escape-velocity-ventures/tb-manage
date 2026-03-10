package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// Scanner is implemented by each discovery phase.
type Scanner interface {
	// Name returns a unique identifier for this scanner (e.g., "host", "network").
	Name() string
	// Scan collects data using the provided CommandRunner.
	Scan(ctx context.Context, runner CommandRunner) (json.RawMessage, error)
	// Platforms returns the OS platforms this scanner supports.
	// Empty slice means all platforms.
	Platforms() []string
}

// CommandRunner abstracts command execution for local vs SSH.
type CommandRunner interface {
	Run(ctx context.Context, cmd string) ([]byte, error)
}

// LocalRunner executes commands on the local host.
type LocalRunner struct{}

// Run executes a command locally via the platform shell.
func (r LocalRunner) Run(ctx context.Context, command string) ([]byte, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", command)
	} else {
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", command)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("command %q failed: %w (output: %s)", command, err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// Profile controls the scan depth.
type Profile int

const (
	ProfileMinimal  Profile = iota // OS, CPU, RAM
	ProfileStandard                // + network, storage
	ProfileFull                    // + containers, services, k8s
)

// ParseProfile converts a string to a Profile.
func ParseProfile(s string) (Profile, error) {
	switch strings.ToLower(s) {
	case "minimal":
		return ProfileMinimal, nil
	case "standard", "":
		return ProfileStandard, nil
	case "full":
		return ProfileFull, nil
	default:
		return 0, fmt.Errorf("unknown profile %q (valid: minimal, standard, full)", s)
	}
}

// String returns the profile name.
func (p Profile) String() string {
	switch p {
	case ProfileMinimal:
		return "minimal"
	case ProfileStandard:
		return "standard"
	case ProfileFull:
		return "full"
	default:
		return "unknown"
	}
}

// SupportsCurrentPlatform checks if a scanner supports the current OS.
func SupportsCurrentPlatform(s Scanner) bool {
	platforms := s.Platforms()
	if len(platforms) == 0 {
		return true
	}
	for _, p := range platforms {
		if p == runtime.GOOS {
			return true
		}
	}
	return false
}
