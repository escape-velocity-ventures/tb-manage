package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tinkerbelle-io/tb-manage/internal/auth"
	"github.com/tinkerbelle-io/tb-manage/internal/logging"
)

var flagJWT string

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register this host's SSH key with TinkerBelle SaaS",
	Long: `Register this host's SSH host key with TinkerBelle SaaS for authentication.

This is used for brownfield instances — existing servers that weren't provisioned
through TinkerBelle. After registration, tb-manage can authenticate to the SaaS
using the host's SSH key (no token needed).

The JWT can be obtained from the TinkerBelle SaaS dashboard under Settings → API Keys.`,
	RunE: runRegister,
}

func init() {
	registerCmd.Flags().StringVar(&flagJWT, "jwt", "", "User JWT for authentication (env: TB_JWT)")
	rootCmd.AddCommand(registerCmd)
}

type registerRequest struct {
	Name               string `json:"name"`
	HostKeyFingerprint string `json:"host_key_fingerprint"`
	HostKeyPublic      string `json:"host_key_public"`
	Provider           string `json:"provider"`
	InstanceID         string `json:"instance_id"`
}

type registerResponse struct {
	Success            bool   `json:"success"`
	NodeID             string `json:"node_id"`
	Name               string `json:"name"`
	HostKeyFingerprint string `json:"host_key_fingerprint"`
	Error              string `json:"error,omitempty"`
}

func resolveJWT() string {
	if flagJWT != "" {
		return flagJWT
	}
	return os.Getenv("TB_JWT")
}

func runRegister(cmd *cobra.Command, args []string) error {
	logging.Setup(flagLogLevel)

	url := resolveURL()
	if url == "" {
		return fmt.Errorf("--url or TB_URL is required")
	}

	jwt := resolveJWT()
	if jwt == "" {
		return fmt.Errorf("--jwt or TB_JWT is required (get this from the TinkerBelle dashboard)")
	}

	// Load host key
	identity, err := auth.LoadHostKey("")
	if err != nil {
		return fmt.Errorf("load host key: %w", err)
	}

	hostname, _ := os.Hostname()

	fmt.Println("Registering host with TinkerBelle SaaS...")
	fmt.Printf("  Host:        %s\n", hostname)
	fmt.Printf("  Fingerprint: %s\n", identity.Fingerprint)
	fmt.Printf("  SaaS URL:    %s\n", url)
	fmt.Println()

	// Build registration request
	reqBody := registerRequest{
		Name:               hostname,
		HostKeyFingerprint: identity.Fingerprint,
		HostKeyPublic:      strings.TrimSpace(identity.PublicKeySSH),
		Provider:           "baremetal", // brownfield — we don't know the provider
		InstanceID:         hostname,    // use hostname as instance ID for brownfield
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	// POST to register-node
	endpoint := fmt.Sprintf("%s/functions/v1/register-node", strings.TrimRight(url, "/"))
	httpReq, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+jwt)

	// Also set apikey header if we have an anon key (needed for Supabase relay)
	if anonKey := resolveAnonKey(); anonKey != "" {
		httpReq.Header.Set("apikey", anonKey)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("registration request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		var errResp registerResponse
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("registration failed (HTTP %d): %s", resp.StatusCode, errResp.Error)
		}
		return fmt.Errorf("registration failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var result registerResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	fmt.Printf("✓ Registered successfully\n")
	fmt.Printf("  Node ID: %s\n", result.NodeID)
	fmt.Printf("  Name:    %s\n", result.Name)
	fmt.Println()
	fmt.Println("This host can now authenticate to TinkerBelle SaaS using its SSH host key.")
	fmt.Println("Run 'tb-manage scan --upload --identity ssh-host-key' to send data.")

	return nil
}
