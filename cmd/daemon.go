package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/tinkerbelle-io/tb-discover/internal/agent"
	"github.com/tinkerbelle-io/tb-discover/internal/config"
	"github.com/tinkerbelle-io/tb-discover/internal/logging"
	"github.com/tinkerbelle-io/tb-discover/internal/upload"
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
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Run as a persistent agent with scanning and terminal support",
	Long: `Run tb-discover as a daemon that continuously scans infrastructure,
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
	rootCmd.AddCommand(daemonCmd)
}

func runDaemon(cmd *cobra.Command, args []string) error {
	logging.Setup(flagLogLevel)

	// Load config file for defaults (permissions, etc.)
	cfg, _ := config.Load(flagConfig)

	token := resolveToken()
	saasURL := resolveSaaSURL()
	gatewayURL := resolveGatewayURL()

	// Need at least one mode of operation: root token OR multi-upstream config
	if token == "" && resolveUpstreams() == "" {
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
			MaxRemediationsPerHour: flagMaxRemediations,
			RemediationCooldown:    flagRemediationCooldown,
			DryRun:                 flagDryRun,
		}
	} else if saasURL != "" {
		scanCfg = &agent.ScanLoopConfig{
			Profile:                flagDaemonProfile,
			Interval:               flagScanInterval,
			UploadURL:              saasURL,
			Token:                  token,
			AnonKey:                resolveAnonKey(),
			Version:                rootCmd.Version,
			ExcludeNamespaces:      excludeNS,
			MaxRemediationsPerHour: flagMaxRemediations,
			RemediationCooldown:    flagRemediationCooldown,
			DryRun:                 flagDryRun,
		}
	}

	a := agent.New(agent.Config{
		WSURL:       gatewayURL,
		Token:       token,
		ClusterID:   flagClusterID,
		IdleTimeout: flagIdleTimeout,
		ScanConfig:  scanCfg,
		Permissions: permissions,
		MaxSessions: flagMaxSessions,
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
