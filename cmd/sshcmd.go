package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tinkerbelle-io/tb-manage/internal/sshca"
)

var (
	flagSSHPrincipal string
	flagSSHTTL       string
	flagSSHUser      string
	flagSSHPort      string
)

var sshCmd = &cobra.Command{
	Use:   "ssh <node>",
	Short: "SSH into a node using ephemeral CA-signed certificates",
	Long: `Generate an ephemeral SSH keypair, request a signed certificate from
the TinkerBelle SaaS SSH CA, and open an SSH session to the target node.
The keypair and certificate are deleted on disconnect.

Requires: ~/.tb-manage/identity.yaml or TB_SAAS_URL + TB_USER env vars.
Auth token: TB_AUTH_TOKEN env var (Supabase JWT).`,
	Args: cobra.ExactArgs(1),
	RunE: runSSHCmd,
}

func init() {
	sshCmd.Flags().StringVar(&flagSSHPrincipal, "principal", "operator", "SSH principal to request (readonly, operator, deltav, emergency-ops)")
	sshCmd.Flags().StringVar(&flagSSHTTL, "ttl", "", "Certificate TTL (e.g., 8h, 30m). Defaults to server default for the principal.")
	sshCmd.Flags().StringVar(&flagSSHUser, "user", "", "SSH username on the target (default: principal name, e.g., 'operator')")
	sshCmd.Flags().StringVar(&flagSSHPort, "port", "22", "SSH port on the target")
	rootCmd.AddCommand(sshCmd)
}

func runSSHCmd(_ *cobra.Command, args []string) error {
	node := args[0]

	// Load identity
	id, err := sshca.LoadIdentity("")
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}
	if err := id.Validate(); err != nil {
		return err
	}

	authToken := os.Getenv("TB_AUTH_TOKEN")
	if authToken == "" {
		return fmt.Errorf("TB_AUTH_TOKEN is required (Supabase user JWT)")
	}

	// Parse TTL
	var ttlSeconds int
	if flagSSHTTL != "" {
		dur, err := time.ParseDuration(flagSSHTTL)
		if err != nil {
			return fmt.Errorf("invalid --ttl %q: %w", flagSSHTTL, err)
		}
		ttlSeconds = int(dur.Seconds())
	}

	// Determine SSH user
	sshUser := flagSSHUser
	if sshUser == "" {
		sshUser = flagSSHPrincipal
	}

	slog.Info("generating ephemeral keypair")

	// Generate ephemeral keypair
	kp, err := sshca.GenerateEphemeralKeypair()
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}
	defer kp.Cleanup()

	// Request signed certificate
	client := sshca.NewClient(id.SaaSURL, id.AnonKey, authToken)
	signReq := &sshca.SignRequest{
		PublicKey:       strings.TrimSpace(kp.PublicKeyString),
		Principals:      []string{flagSSHPrincipal},
		ValiditySeconds: ttlSeconds,
		OrgID:           id.OrgID,
	}

	slog.Info("requesting certificate", "principal", flagSSHPrincipal, "node", node)

	signResp, err := client.RequestCert(signReq)
	if err != nil {
		return fmt.Errorf("request certificate: %w", err)
	}

	// Write certificate
	if err := kp.WriteCert(signResp.Certificate); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}

	slog.Info("certificate issued",
		"identity", signResp.KeyIdentity,
		"principals", signResp.Principals,
		"expires", signResp.ExpiresAt,
	)

	// Build SSH command
	sshArgs := []string{
		"-o", "CertificateFile=" + kp.CertPath,
		"-i", kp.PrivateKeyPath,
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		"-p", flagSSHPort,
		fmt.Sprintf("%s@%s", sshUser, node),
	}

	slog.Info("connecting", "node", node, "user", sshUser)

	// Execute SSH (replaces this process)
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("ssh not found in PATH: %w", err)
	}

	// Use Cmd instead of syscall.Exec for cross-platform compatibility
	// and to ensure cleanup runs after SSH exits
	cmd := exec.Command(sshBin, sshArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		// SSH returns non-zero on connection errors — surface it
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("ssh exited with code %d", exitErr.ExitCode())
		}
		return fmt.Errorf("ssh failed: %w", err)
	}

	slog.Info("session ended", "node", node)
	return nil
}
