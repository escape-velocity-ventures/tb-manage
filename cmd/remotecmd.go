package cmd

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/tinkerbelle-io/tb-manage/internal/logging"
	"github.com/tinkerbelle-io/tb-manage/internal/tunnel"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

var (
	flagRemotePort   int
	flagRemoteUser   string
	flagRemoteKey    string
	flagRemoteNoOpen bool
	flagRemoteSSHPort string
)

var rdpCmd = &cobra.Command{
	Use:   "rdp <host>",
	Short: "Open an SSH tunnel to a host's RDP service and launch the client",
	Long: `Create an SSH tunnel forwarding a local port to the remote host's RDP port
(default 3389), then launch Microsoft Remote Desktop on macOS.

The tunnel stays open until interrupted with Ctrl-C.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRemote(args[0], "rdp", 3389)
	},
}

var vncCmd = &cobra.Command{
	Use:   "vnc <host>",
	Short: "Open an SSH tunnel to a host's VNC service and launch the client",
	Long: `Create an SSH tunnel forwarding a local port to the remote host's VNC port
(default 5900), then launch Screen Sharing on macOS.

The tunnel stays open until interrupted with Ctrl-C.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRemote(args[0], "vnc", 5900)
	},
}

func init() {
	for _, c := range []*cobra.Command{rdpCmd, vncCmd} {
		c.Flags().IntVar(&flagRemotePort, "port", 0, "Override remote service port")
		c.Flags().StringVar(&flagRemoteUser, "user", "ubuntu", "SSH username")
		c.Flags().StringVar(&flagRemoteKey, "key", "", "SSH private key path (default: ~/.ssh/id_ed25519)")
		c.Flags().BoolVar(&flagRemoteNoOpen, "no-open", false, "Print connection string but don't launch client")
		c.Flags().StringVar(&flagRemoteSSHPort, "ssh-port", "22", "SSH port on the target host")
		rootCmd.AddCommand(c)
	}
}

func runRemote(host, protocol string, defaultPort int) error {
	logging.Setup(flagLogLevel)

	remotePort := defaultPort
	if flagRemotePort > 0 {
		remotePort = flagRemotePort
	}

	sshAddr := net.JoinHostPort(host, flagRemoteSSHPort)
	remoteAddr := fmt.Sprintf("127.0.0.1:%d", remotePort)

	slog.Info("connecting", "host", host, "protocol", protocol, "remote_port", remotePort, "ssh_user", flagRemoteUser)

	config, err := buildRemoteSSHConfig(flagRemoteUser, flagRemoteKey)
	if err != nil {
		return fmt.Errorf("ssh config: %w", err)
	}

	tun, err := tunnel.Open(sshAddr, config, 0, remoteAddr)
	if err != nil {
		return fmt.Errorf("open tunnel: %w", err)
	}
	defer tun.Close()

	protocolUpper := "RDP"
	if protocol == "vnc" {
		protocolUpper = "VNC"
	}

	fmt.Printf("Tunnel open: %s -> %s:%d (%s)\n", tun.LocalAddr, host, remotePort, protocolUpper)

	// Build and print the client URL
	clientURL := buildClientURL(protocol, tun.LocalAddr)
	fmt.Printf("Client URL:  %s\n", clientURL)

	if !flagRemoteNoOpen && runtime.GOOS == "darwin" {
		slog.Info("launching client", "url", clientURL)
		if err := exec.Command("open", clientURL).Start(); err != nil {
			slog.Warn("failed to launch client", "error", err)
			fmt.Println("Launch failed — connect manually using the URL above.")
		}
	} else if !flagRemoteNoOpen && runtime.GOOS != "darwin" {
		fmt.Println("Auto-launch not supported on this OS — connect manually using the URL above.")
	}

	fmt.Println("\nPress Ctrl-C to close the tunnel.")

	// Wait for interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nClosing tunnel.")
	return nil
}

// buildClientURL returns the protocol URL for the local tunnel endpoint.
func buildClientURL(protocol, localAddr string) string {
	_, port, _ := net.SplitHostPort(localAddr)
	switch protocol {
	case "rdp":
		// Microsoft Remote Desktop URL scheme
		return fmt.Sprintf("rdp://full%%20address=s:localhost:%s", port)
	case "vnc":
		return fmt.Sprintf("vnc://localhost:%s", port)
	default:
		return fmt.Sprintf("localhost:%s", port)
	}
}

// buildRemoteSSHConfig creates an SSH client config for tunnel use.
// If keyPath is empty, it tries the SSH agent then default key files.
func buildRemoteSSHConfig(user, keyPath string) (*ssh.ClientConfig, error) {
	var signers []ssh.Signer

	// If explicit key specified, use only that
	if keyPath != "" {
		data, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("read key %s: %w", keyPath, err)
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse key %s: %w", keyPath, err)
		}
		signers = append(signers, signer)
	} else {
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
		for _, kf := range keyFiles {
			data, err := os.ReadFile(kf)
			if err != nil {
				continue
			}
			signer, err := ssh.ParsePrivateKey(data)
			if err != nil {
				continue
			}
			signers = append(signers, signer)
		}
	}

	if len(signers) == 0 {
		return nil, fmt.Errorf("no SSH keys available (no agent, no key files found)")
	}

	// Host key verification
	home, _ := os.UserHomeDir()
	var hostKeyCallback ssh.HostKeyCallback
	knownHostsFile := filepath.Join(home, ".ssh", "known_hosts")
	if cb, err := knownhosts.New(knownHostsFile); err == nil {
		hostKeyCallback = cb
	} else {
		hostKeyCallback = ssh.InsecureIgnoreHostKey()
	}

	return &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback: hostKeyCallback,
	}, nil
}
