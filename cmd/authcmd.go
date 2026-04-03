package cmd

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tinkerbelle-io/tb-manage/internal/sshca"
)

var (
	flagAuthAgent   string
	flagAuthTTL     string
	flagAuthBead    string
	flagAuthSource  string
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Request an SSH CA certificate for agent or programmatic use",
	Long: `Request a signed SSH certificate and store it in ~/.tb-manage/certs/.
Used for agent authentication (oncall bots, sprint agents, etc.).

The certificate is stored locally and can be used for multiple SSH sessions
until it expires.

Requires:
  TB_AUTH_TOKEN  - Supabase JWT of the parent operator (or agent JWT)
  TB_JWT_SECRET  - (for agent mode) HMAC secret to sign the agent JWT`,
	RunE: runAuthCmd,
}

func init() {
	authCmd.Flags().StringVar(&flagAuthAgent, "agent", "", "Agent name (e.g., oncall-bot, sprint-agent-3)")
	authCmd.Flags().StringVar(&flagAuthTTL, "ttl", "1h", "Certificate TTL (e.g., 30m, 1h, 4h)")
	authCmd.Flags().StringVar(&flagAuthBead, "bead", "", "Bead ID for context attribution (e.g., PM-055)")
	authCmd.Flags().StringVar(&flagAuthSource, "source-address", "10.0.0.0/8", "Source address CIDR for the certificate")
	authCmd.MarkFlagRequired("agent")
	rootCmd.AddCommand(authCmd)
}

var validAgentName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func runAuthCmd(_ *cobra.Command, _ []string) error {
	// Validate agent name — used in filenames and JWT subjects
	if !validAgentName.MatchString(flagAuthAgent) {
		return fmt.Errorf("invalid --agent %q: must match [a-zA-Z0-9_-]+", flagAuthAgent)
	}

	// Load identity
	id, err := sshca.LoadIdentity("")
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}
	if err := id.Validate(); err != nil {
		return err
	}

	// Ensure cert storage directory exists
	if err := sshca.EnsureIdentityDir(); err != nil {
		return err
	}

	// Parse TTL
	dur, err := time.ParseDuration(flagAuthTTL)
	if err != nil {
		return fmt.Errorf("invalid --ttl %q: %w", flagAuthTTL, err)
	}
	ttlSeconds := int(dur.Seconds())

	// Determine auth token
	// For agent mode, we build an agent JWT signed with TB_JWT_SECRET
	// For human mode, we use TB_AUTH_TOKEN directly
	var authToken string

	jwtSecret := os.Getenv("TB_JWT_SECRET")
	if jwtSecret != "" {
		// Agent mode: mint an agent JWT
		slog.Info("minting agent JWT", "agent", flagAuthAgent, "parent", id.User)
		agentJWT, err := mintAgentJWT(flagAuthAgent, id.User, flagAuthBead, jwtSecret)
		if err != nil {
			return fmt.Errorf("mint agent JWT: %w", err)
		}
		authToken = agentJWT
	} else {
		// Human mode: use the operator's token
		authToken = os.Getenv("TB_AUTH_TOKEN")
		if authToken == "" {
			return fmt.Errorf("TB_AUTH_TOKEN or TB_JWT_SECRET is required")
		}
	}

	// Generate ephemeral keypair
	slog.Info("generating keypair for agent", "agent", flagAuthAgent)
	kp, err := sshca.GenerateEphemeralKeypair()
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}
	// Don't cleanup kp here — we're storing the keys

	// Build sign request
	principals := []string{fmt.Sprintf("agent:%s", flagAuthAgent)}
	client := sshca.NewClient(id.SaaSURL, id.AnonKey, authToken)
	signReq := &sshca.SignRequest{
		PublicKey:       strings.TrimSpace(kp.PublicKeyString),
		Principals:      principals,
		ValiditySeconds: ttlSeconds,
		SourceAddress:   flagAuthSource,
		OrgID:           id.OrgID,
	}

	slog.Info("requesting agent certificate",
		"agent", flagAuthAgent,
		"ttl", flagAuthTTL,
		"source", flagAuthSource,
	)

	signResp, err := client.RequestCert(signReq)
	if err != nil {
		kp.Cleanup()
		return fmt.Errorf("request certificate: %w", err)
	}

	// Store cert + keys in ~/.tb-manage/certs/
	certPath, err := sshca.StoreCert(flagAuthAgent, kp, signResp.Certificate)
	if err != nil {
		kp.Cleanup()
		return fmt.Errorf("store certificate: %w", err)
	}

	// Clean up the temp dir (keys are now copied to certs dir)
	kp.Cleanup()

	// Clean expired certs while we're at it
	if removed, err := sshca.CleanExpiredCerts(); err == nil && removed > 0 {
		slog.Info("cleaned expired certs", "removed", removed)
	}

	fmt.Printf("Certificate issued for agent:%s\n", flagAuthAgent)
	fmt.Printf("  Identity:  %s\n", signResp.KeyIdentity)
	fmt.Printf("  Expires:   %s\n", signResp.ExpiresAt)
	fmt.Printf("  Cert path: %s\n", certPath)

	// Derive the private key path from cert path for convenience
	privKeyPath := strings.TrimSuffix(certPath, "-cert.pub")
	fmt.Printf("  Key path:  %s\n", privKeyPath)
	fmt.Printf("\nUsage:\n")
	fmt.Printf("  ssh -o CertificateFile=%s -i %s -o IdentitiesOnly=yes agent:%s@<node>\n",
		certPath, privKeyPath, flagAuthAgent)

	return nil
}

// mintAgentJWT creates a minimal HMAC-SHA256 JWT for agent authentication.
// This JWT is verified by the ssh-sign edge function.
func mintAgentJWT(agentName, parent, context, secret string) (string, error) {
	// Fixed header — deterministic byte output, no map ordering ambiguity
	headerJSON := []byte(`{"alg":"HS256","typ":"JWT"}`)

	now := time.Now().Unix()
	// Build payload with deterministic key order via json.Marshal on a struct
	type jwtPayload struct {
		Sub     string `json:"sub"`
		Parent  string `json:"parent"`
		Iat     int64  `json:"iat"`
		Exp     int64  `json:"exp"`
		Context string `json:"context,omitempty"`
	}
	p := jwtPayload{
		Sub:     "agent:" + agentName,
		Parent:  parent,
		Iat:     now,
		Exp:     now + 300, // 5 min validity
		Context: context,
	}
	payloadJSON, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("marshal JWT payload: %w", err)
	}

	// Base64url encode
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Sign
	sigInput := headerB64 + "." + payloadB64
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(sigInput))
	sig := mac.Sum(nil)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return sigInput + "." + sigB64, nil
}
