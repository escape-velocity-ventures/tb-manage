package ssh

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Runner implements scanner.CommandRunner over SSH.
// It reuses a single SSH connection for multiple commands.
type Runner struct {
	client *ssh.Client
	mu     sync.Mutex
}

// Target represents an SSH target parsed from user@host[:port] format.
type Target struct {
	User string
	Host string
	Port string
}

// ParseTarget parses a string like "user@host" or "user@host:2222".
func ParseTarget(s string) (Target, error) {
	t := Target{Port: "22"}

	parts := strings.SplitN(s, "@", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return t, fmt.Errorf("invalid SSH target %q (expected user@host[:port])", s)
	}

	t.User = parts[0]
	hostPort := parts[1]

	// Check for port
	if h, p, err := net.SplitHostPort(hostPort); err == nil {
		t.Host = h
		t.Port = p
	} else {
		t.Host = hostPort
	}

	return t, nil
}

// ParseTargets splits a comma-separated list of SSH targets.
func ParseTargets(s string) ([]Target, error) {
	var targets []Target
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		t, err := ParseTarget(part)
		if err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no SSH targets specified")
	}
	return targets, nil
}

// Addr returns the host:port for dialing.
func (t Target) Addr() string {
	return net.JoinHostPort(t.Host, t.Port)
}

func (t Target) String() string {
	if t.Port == "22" {
		return t.User + "@" + t.Host
	}
	return fmt.Sprintf("%s@%s:%s", t.User, t.Host, t.Port)
}

// NewRunner establishes an SSH connection and returns a Runner.
func NewRunner(target Target) (*Runner, error) {
	config, err := buildSSHConfig(target.User)
	if err != nil {
		return nil, fmt.Errorf("ssh config: %w", err)
	}

	client, err := ssh.Dial("tcp", target.Addr(), config)
	if err != nil {
		return nil, fmt.Errorf("ssh dial %s: %w", target.Addr(), err)
	}

	return &Runner{client: client}, nil
}

// Run executes a command on the remote host.
// Commands are validated against the allowlist before execution.
func (r *Runner) Run(ctx context.Context, cmd string) ([]byte, error) {
	if !IsCommandAllowed(cmd) {
		return nil, fmt.Errorf("command not allowed: %q", cmd)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	session, err := r.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("ssh session: %w", err)
	}
	defer session.Close()

	// Support context cancellation
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			session.Signal(ssh.SIGTERM)
			session.Close()
		case <-done:
		}
	}()

	out, err := session.CombinedOutput(cmd)
	close(done)

	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if err != nil {
		return out, fmt.Errorf("command %q failed: %w (output: %s)", cmd, err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// Close closes the SSH connection.
func (r *Runner) Close() error {
	return r.client.Close()
}

// buildSSHConfig creates an SSH client config with key auth and agent forwarding.
func buildSSHConfig(user string) (*ssh.ClientConfig, error) {
	var signers []ssh.Signer

	// Try SSH agent first
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		conn, err := net.Dial("unix", sock)
		if err == nil {
			agentClient := agent.NewClient(conn)
			agentSigners, err := agentClient.Signers()
			if err == nil {
				signers = append(signers, agentSigners...)
			}
		}
	}

	// Fall back to default key files
	home, _ := os.UserHomeDir()
	keyFiles := []string{
		filepath.Join(home, ".ssh", "id_ed25519"),
		filepath.Join(home, ".ssh", "id_rsa"),
		filepath.Join(home, ".ssh", "id_ecdsa"),
	}

	for _, keyFile := range keyFiles {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			continue
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			continue
		}
		signers = append(signers, signer)
	}

	if len(signers) == 0 {
		return nil, fmt.Errorf("no SSH keys available (no agent and no key files found)")
	}

	// Host key verification — refuse to connect without known_hosts
	knownHostsFile := filepath.Join(home, ".ssh", "known_hosts")
	hostKeyCallback, err := knownhosts.New(knownHostsFile)
	if err != nil {
		return nil, fmt.Errorf("cannot verify host key: %s not found or unreadable (%w). "+
			"Connect manually first to populate known_hosts, "+
			"or run: ssh-keyscan <host> >> %s", knownHostsFile, err, knownHostsFile)
	}

	return &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback: hostKeyCallback,
	}, nil
}
