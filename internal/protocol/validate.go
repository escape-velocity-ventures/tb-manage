package protocol

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
)

// Allowed target types.
var allowedTargetTypes = map[string]bool{
	"host": true, "lima": true, "docker": true, "k8s-pod": true, "ssh": true,
}

// Allowed shells (exact paths).
var allowedShells = map[string]bool{
	"/bin/bash": true, "/bin/sh": true, "/bin/zsh": true, "": true,
	// Windows shells
	"powershell.exe": true, "pwsh.exe": true, "cmd.exe": true,
	`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`: true,
}

// Allowed docker runtimes.
var allowedRuntimes = map[string]bool{
	"docker": true, "podman": true, "": true,
}

// containerNameRe matches valid container/pod/VM names.
var containerNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

const maxNameLen = 253

// ValidateTerminalTarget checks that all fields contain safe, expected values.
func ValidateTerminalTarget(t *TerminalTarget) error {
	if t == nil {
		return nil
	}

	if !allowedTargetTypes[t.Type] {
		return fmt.Errorf("invalid target type: %q", t.Type)
	}

	if !allowedShells[t.Shell] {
		return fmt.Errorf("invalid shell: %q", t.Shell)
	}

	if !allowedRuntimes[t.Runtime] {
		return fmt.Errorf("invalid runtime: %q", t.Runtime)
	}

	// SSH target validation
	if t.Type == "ssh" {
		if err := validateSSHTarget(t); err != nil {
			return err
		}
	}

	for field, val := range map[string]string{
		"container": t.Container,
		"pod":       t.Pod,
		"namespace": t.Namespace,
		"name":      t.Name,
	} {
		if val == "" {
			continue
		}
		if len(val) > maxNameLen {
			return fmt.Errorf("%s name too long (%d chars, max %d)", field, len(val), maxNameLen)
		}
		if !containerNameRe.MatchString(val) {
			return fmt.Errorf("invalid %s name: %q", field, val)
		}
	}

	return nil
}

// sshUserRe matches valid SSH usernames (alphanumeric, dashes, underscores, dots).
var sshUserRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// validateSSHTarget validates SSH-specific fields.
func validateSSHTarget(t *TerminalTarget) error {
	if t.Host == "" {
		return fmt.Errorf("ssh target requires a host")
	}

	// Host must be an IP address or valid hostname (no shell metacharacters)
	host := t.Host
	if ip := net.ParseIP(host); ip == nil {
		// Not a raw IP — check it's a valid hostname
		if !containerNameRe.MatchString(host) {
			return fmt.Errorf("invalid ssh host: %q", host)
		}
	}

	// Validate user if provided
	if t.User != "" {
		if len(t.User) > 64 {
			return fmt.Errorf("ssh user too long (%d chars, max 64)", len(t.User))
		}
		if !sshUserRe.MatchString(t.User) {
			return fmt.Errorf("invalid ssh user: %q", t.User)
		}
	}

	// Validate port if provided
	if t.Port != 0 {
		if t.Port < 1 || t.Port > 65535 {
			return fmt.Errorf("invalid ssh port: %s", strconv.Itoa(t.Port))
		}
	}

	return nil
}
