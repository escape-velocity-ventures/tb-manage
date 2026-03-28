package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tinkerbelle-io/tb-manage/internal/agent"
	"github.com/tinkerbelle-io/tb-manage/internal/auth"
	"github.com/tinkerbelle-io/tb-manage/internal/casync"
	"github.com/tinkerbelle-io/tb-manage/internal/config"
	"github.com/tinkerbelle-io/tb-manage/internal/logging"
	"github.com/tinkerbelle-io/tb-manage/internal/upload"
)

var (
	flagClusterID           string
	flagIdleTimeout         time.Duration
	flagScanInterval        time.Duration
	flagDaemonProfile       string
	flagGatewayURL          string
	flagSaaSURL             string
	flagPermissions         []string
	flagMaxSessions         int
	flagExcludeNamespaces   []string
	flagMaxRemediations     int
	flagRemediationCooldown time.Duration
	flagDryRun              bool
	flagSkipUpload          bool
	flagShellCommand        string
	flagAuditLog            string
	flagPublicKey           string
	flagNoTmux              bool
	flagCAKeySync           bool
	flagCAKeyPath           string
	flagCAStatePath         string
	flagCAOverlapWindow     time.Duration
	flagCASyncInterval      time.Duration
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Run as a persistent agent with scanning and terminal support",
	Long: `Run tb-manage as a daemon that continuously scans infrastructure,
reports to TinkerBelle SaaS, and serves terminal sessions via WebSocket.

The daemon runs two concurrent loops:
  1. Scan loop: periodic infrastructure scan + upload to edge-ingest
  2. WebSocket loop: terminal session multiplexing via gateway

Use --url for the SaaS base URL (Supabase, for upload).
Use --gateway for the WebSocket gateway URL (for terminal sessions).
Either or both can be specified.`,
	RunE: runDaemon,
}

func init() {
	daemonCmd.Flags().StringVar(&flagClusterID, "cluster-id", "", "Cluster identifier")
	daemonCmd.Flags().DurationVar(&flagIdleTimeout, "idle-timeout", 30*time.Minute, "Terminal session idle timeout")
	daemonCmd.Flags().DurationVar(&flagScanInterval, "scan-interval", 5*time.Minute, "Scan interval (e.g., 5m, 30s)")
	daemonCmd.Flags().StringVar(&flagDaemonProfile, "profile", "standard", "Scan profile: minimal, standard, full")
	daemonCmd.Flags().StringVar(&flagGatewayURL, "gateway", "", "Gateway WebSocket URL for terminal sessions (env: TB_GATEWAY_URL)")
	daemonCmd.Flags().StringVar(&flagSaaSURL, "saas-url", "", "SaaS base URL for upload (env: TB_URL, defaults to --url)")
	daemonCmd.Flags().StringSliceVar(&flagPermissions, "permissions", []string{"scan"}, "Agent permissions: scan, terminal")
	daemonCmd.Flags().IntVar(&flagMaxSessions, "max-sessions", 10, "Maximum concurrent terminal sessions")
	daemonCmd.Flags().StringSliceVar(&flagExcludeNamespaces, "exclude-namespaces", nil, "Comma-separated namespaces to exclude from k8s scanning (env: EXCLUDE_NAMESPACES)")
	daemonCmd.Flags().IntVar(&flagMaxRemediations, "max-remediations-per-hour", 10, "Circuit breaker: max auto-remediations per hour")
	daemonCmd.Flags().DurationVar(&flagRemediationCooldown, "remediation-cooldown", 30*time.Minute, "Per-resource cooldown between remediations")
	daemonCmd.Flags().BoolVar(&flagDryRun, "dry-run", false, "Remediation dry-run mode (log actions without executing)")
	daemonCmd.Flags().BoolVar(&flagSkipUpload, "skip-upload", false, "Skip host scan upload (controller mode — DaemonSet handles host reporting)")
	daemonCmd.Flags().StringVar(&flagAuditLog, "audit-log", "", "Custom audit log path (default: ~/.tb-manage/audit.log on macOS, /var/log/tb-manage/audit.log on Linux)")
	daemonCmd.Flags().StringVar(&flagPublicKey, "public-key", "", "Ed25519 public key for command signature verification (hex or base64, env: TB_PUBLIC_KEY)")
	daemonCmd.Flags().StringVar(&flagShellCommand, "shell-command", "", "Custom shell command for PTY sessions (e.g., 'nsenter -t 1 -m -u -i -n -- /bin/bash')")
	daemonCmd.Flags().BoolVar(&flagNoTmux, "no-tmux", false, "Disable persistent terminal sessions (no tmux)")
	daemonCmd.Flags().BoolVar(&flagCAKeySync, "ca-key-sync", false, "Enable SSH CA public key synchronization (env: TB_CA_KEY_SYNC)")
	daemonCmd.Flags().StringVar(&flagCAKeyPath, "ca-key-path", "/etc/ssh/tb_ca.pub", "Path for SSH CA public key file")
	daemonCmd.Flags().StringVar(&flagCAStatePath, "ca-state-path", "/var/lib/tb-manage/ca-rotation.json", "Path for CA rotation state file")
	daemonCmd.Flags().DurationVar(&flagCAOverlapWindow, "ca-overlap-window", 24*time.Hour, "Overlap window for CA key rotation")
	daemonCmd.Flags().DurationVar(&flagCASyncInterval, "ca-sync-interval", 6*time.Hour, "How often to sync CA public key from SaaS")
	rootCmd.AddCommand(daemonCmd)
}

func runDaemon(cmd *cobra.Command, args []string) error {
	logging.Setup(flagLogLevel)

	// Load config file for defaults (permissions, etc.)
	cfg, _ := config.Load(flagConfig)

	// Resolve values: flag > env > config file > default
	token := resolveToken()
	if token == "" && cfg != nil && cfg.Token != "" {
		token = cfg.Token
	}

	saasURL := resolveSaaSURL()
	if saasURL == "" && cfg != nil && cfg.URL != "" {
		saasURL = cfg.URL
	}

	gatewayURL := resolveGatewayURL()
	if gatewayURL == "" && cfg != nil && cfg.Gateway != "" {
		gatewayURL = cfg.Gateway
	}

	identity := resolveIdentity()
	// resolveIdentity returns "token" as default — if neither flag nor env
	// was set, fall back to config file
	if !cmd.Flags().Changed("identity") && resolveEnv("TB_IDENTITY") == "" && cfg != nil && cfg.Identity != "" {
		identity = cfg.Identity
	}

	// Need at least one mode of operation: token, multi-upstream, or host-key identity
	if token == "" && resolveUpstreams() == "" && identity != "ssh-host-key" {
		return cmd.Help()
	}

	// Merge permissions: flag overrides config file
	permissions := flagPermissions
	if !cmd.Flags().Changed("permissions") && cfg != nil && len(cfg.Permissions) > 0 {
		permissions = cfg.Permissions
	}

	// Resolve namespace exclusions: flag > config > defaults
	excludeNS := flagExcludeNamespaces
	if !cmd.Flags().Changed("exclude-namespaces") && cfg != nil && len(cfg.ExcludeNamespaces) > 0 {
		excludeNS = cfg.ExcludeNamespaces
	}

	// Build scan loop config
	var scanCfg *agent.ScanLoopConfig

	// Multi-upstream via TB_UPSTREAMS takes priority
	if upstreamsJSON := resolveUpstreams(); upstreamsJSON != "" {
		upstreams, err := upload.ParseUpstreams(upstreamsJSON)
		if err != nil {
			return fmt.Errorf("parse TB_UPSTREAMS: %w", err)
		}

		// Safety: at most 1 upstream may have "remediate" permission (prevents split-brain)
		remediateCount := 0
		for _, u := range upstreams {
			for _, p := range u.Permissions {
				if p == "remediate" {
					remediateCount++
				}
			}
		}
		if remediateCount > 1 {
			return fmt.Errorf("at most 1 upstream may have 'remediate' permission (found %d) — prevents split-brain remediation", remediateCount)
		}

		scanCfg = &agent.ScanLoopConfig{
			Profile:                flagDaemonProfile,
			Interval:               flagScanInterval,
			Upstreams:              upstreams,
			Version:                rootCmd.Version,
			ExcludeNamespaces:      excludeNS,
			SkipUpload:             flagSkipUpload,
			MaxRemediationsPerHour: flagMaxRemediations,
			RemediationCooldown:    flagRemediationCooldown,
			DryRun:                 flagDryRun,
		}
	} else if saasURL != "" {
		anonKey := resolveAnonKey()
		if anonKey == "" && cfg != nil && cfg.AnonKey != "" {
			anonKey = cfg.AnonKey
		}
		scanCfg = &agent.ScanLoopConfig{
			Profile:                flagDaemonProfile,
			Interval:               flagScanInterval,
			UploadURL:              saasURL,
			Token:                  token,
			AnonKey:                anonKey,
			IdentityMode:           identity,
			Version:                rootCmd.Version,
			ExcludeNamespaces:      excludeNS,
			SkipUpload:             flagSkipUpload,
			MaxRemediationsPerHour: flagMaxRemediations,
			RemediationCooldown:    flagRemediationCooldown,
			DryRun:                 flagDryRun,
		}
	}

	// Parse shell command if provided
	var shellCmd []string
	if flagShellCommand != "" {
		shellCmd = strings.Fields(flagShellCommand)
	}

	// Load SSH host key if identity mode is ssh-host-key
	var hostIdentity *auth.HostIdentity
	if identity == "ssh-host-key" {
		hi, err := auth.LoadHostKey("")
		if err != nil {
			return fmt.Errorf("load host key for gateway auth: %w", err)
		}
		hostIdentity = hi
		slog.Info("loaded SSH host key for gateway auth", "fingerprint", hi.Fingerprint)
	}

	// Build CA sync config if enabled
	var caSyncCfg *casync.Config
	caKeySync := flagCAKeySync || resolveEnv("TB_CA_KEY_SYNC") == "true"
	if caKeySync && saasURL != "" {
		caSyncCfg = &casync.Config{
			SaaSURL:       saasURL,
			Token:         token,
			AnonKey:       resolveAnonKey(),
			CAKeyPath:     flagCAKeyPath,
			StatePath:     flagCAStatePath,
			OverlapWindow: flagCAOverlapWindow,
			SyncInterval:  flagCASyncInterval,
			RestartSSHD:   true,
		}
		slog.Info("CA key sync enabled",
			"key_path", flagCAKeyPath,
			"sync_interval", flagCASyncInterval,
			"overlap_window", flagCAOverlapWindow,
		)
	}

	a := agent.New(agent.Config{
		WSURL:        gatewayURL,
		Token:        token,
		ClusterID:    flagClusterID,
		IdleTimeout:  flagIdleTimeout,
		ScanConfig:   scanCfg,
		Permissions:  permissions,
		MaxSessions:  flagMaxSessions,
		ShellCommand:       shellCmd,
		TokenInURLFallback: cfg.TokenInURLFallback,
		AuditLogPath:       flagAuditLog,
		PublicKey:          resolvePublicKey(),
		IdentityMode:       identity,
		HostIdentity:       hostIdentity,
		DisableTmux:        flagNoTmux,
		CASyncConfig:       caSyncCfg,
	})

	return a.Run(context.Background())
}

// resolveSaaSURL returns the SaaS URL for uploading scan results.
func resolveSaaSURL() string {
	if flagSaaSURL != "" {
		return flagSaaSURL
	}
	// Fall back to --url / TB_URL
	return resolveURL()
}

// resolveGatewayURL returns the gateway WebSocket URL.
func resolveGatewayURL() string {
	if flagGatewayURL != "" {
		return flagGatewayURL
	}
	return resolveEnv("TB_GATEWAY_URL")
}

func resolveEnv(key string) string {
	if v, ok := lookupEnv(key); ok {
		return v
	}
	return ""
}

// validateGatewayURL checks the gateway URL scheme.
// Returns an error if the URL is insecure and --allow-insecure is not set.
func validateGatewayURL(gatewayURL string, allowInsecure bool) error {
	if gatewayURL == "" {
		return nil
	}
	if strings.HasPrefix(gatewayURL, "ws://") {
		if !allowInsecure {
			return fmt.Errorf("insecure ws:// gateway URL rejected; use wss:// or pass --allow-insecure for local development")
		}
		slog.Warn("SECURITY: ws:// is insecure. Use wss:// for production.", "url", gatewayURL)
		return nil
	}
	if !strings.HasPrefix(gatewayURL, "wss://") {
		return fmt.Errorf("gateway URL must use wss:// (or ws:// with --allow-insecure); got: %s", gatewayURL)
	}
	return nil
}

// resolvePublicKey returns the Ed25519 public key from flag or env.
func resolvePublicKey() string {
	if flagPublicKey != "" {
		return flagPublicKey
	}
	return resolveEnv("TB_PUBLIC_KEY")
}
