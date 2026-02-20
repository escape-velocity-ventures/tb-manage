package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/tinkerbelle-io/tb-discover/internal/logging"
	"github.com/tinkerbelle-io/tb-discover/internal/scanner"
	"github.com/tinkerbelle-io/tb-discover/internal/ssh"
	"github.com/tinkerbelle-io/tb-discover/internal/upload"
)

var (
	flagProfile string
	flagJSON    bool
	flagSSH     []string
	flagUpload  bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run a one-shot infrastructure scan",
	Long: `Scan the local host (or remote hosts via --ssh) for infrastructure details.
Profiles control scan depth: minimal (OS/CPU/RAM), standard (+ network/storage),
full (+ containers/services/k8s).

SSH mode executes read-only commands on remote hosts via SSH key auth.
Multi-host: --ssh user@host1,user@host2 or --ssh user@host1 --ssh user@host2`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVar(&flagProfile, "profile", "standard", "Scan profile: minimal, standard, full")
	scanCmd.Flags().BoolVar(&flagJSON, "json", false, "Output as JSON")
	scanCmd.Flags().StringSliceVar(&flagSSH, "ssh", nil, "Remote hosts to scan via SSH (user@host[:port])")
	scanCmd.Flags().BoolVar(&flagUpload, "upload", false, "Upload results to TinkerBelle SaaS (requires --token and --url)")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	logging.Setup(flagLogLevel)

	profile, err := scanner.ParseProfile(flagProfile)
	if err != nil {
		return err
	}

	reg := scanner.NewRegistry()
	scanners := reg.ForProfile(profile)

	if len(scanners) == 0 {
		return fmt.Errorf("no scanners available for profile %q", flagProfile)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// SSH mode: scan remote hosts
	if len(flagSSH) > 0 {
		return runSSHScan(ctx, scanners, profile)
	}

	// Local mode
	return runLocalScan(ctx, scanners, profile)
}

func runLocalScan(ctx context.Context, scanners []scanner.Scanner, profile scanner.Profile) error {
	start := time.Now()
	result := scanner.NewResult()
	runner := scanner.LocalRunner{}

	for _, s := range scanners {
		data, scanErr := s.Scan(ctx, runner)
		if scanErr != nil {
			slog.Warn("scanner failed", "scanner", s.Name(), "error", scanErr)
			continue
		}
		result.Set(s.Name(), data)
	}

	scanner.ApplyTopology(result)

	result.Meta.Version = rootCmd.Version
	result.Meta.DurationMS = int(time.Since(start).Milliseconds())
	result.Meta.Profile = profile.String()

	hostname, _ := os.Hostname()
	result.Meta.SourceHost = hostname

	if flagUpload {
		if err := uploadResult(ctx, result); err != nil {
			return err
		}
	}

	return outputResult(result)
}

func runSSHScan(ctx context.Context, scanners []scanner.Scanner, profile scanner.Profile) error {
	// Parse all targets from all --ssh flags
	var targets []ssh.Target
	for _, s := range flagSSH {
		parsed, err := ssh.ParseTargets(s)
		if err != nil {
			return err
		}
		targets = append(targets, parsed...)
	}

	// Results for multi-host output
	type hostResult struct {
		Target string          `json:"target"`
		Result *scanner.Result `json:"result"`
		Error  string          `json:"error,omitempty"`
	}
	var results []hostResult

	for _, target := range targets {
		slog.Info("scanning remote host", "target", target.String())

		start := time.Now()
		result := scanner.NewResult()

		runner, err := ssh.NewRunner(target)
		if err != nil {
			slog.Error("ssh connect failed", "target", target.String(), "error", err)
			results = append(results, hostResult{Target: target.String(), Error: err.Error()})
			continue
		}

		for _, s := range scanners {
			// Skip K8s scanner for SSH mode (uses client-go, not commands)
			if s.Name() == "cluster" {
				continue
			}
			data, scanErr := s.Scan(ctx, runner)
			if scanErr != nil {
				slog.Warn("scanner failed", "target", target.String(), "scanner", s.Name(), "error", scanErr)
				continue
			}
			result.Set(s.Name(), data)
		}

		runner.Close()

		scanner.ApplyTopology(result)

		result.Meta.Version = rootCmd.Version
		result.Meta.DurationMS = int(time.Since(start).Milliseconds())
		result.Meta.Profile = profile.String()
		result.Meta.SourceHost = target.Host

		if flagUpload {
			if err := uploadResult(ctx, result); err != nil {
				slog.Error("upload failed", "target", target.String(), "error", err)
			}
		}

		results = append(results, hostResult{Target: target.String(), Result: result})
		slog.Info("scan complete", "target", target.String(), "duration_ms", result.Meta.DurationMS)
	}

	// Output
	if len(targets) == 1 && results[0].Error == "" {
		// Single host: output just the result
		return outputResult(results[0].Result)
	}

	// Multi-host: output array
	if flagJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}

	for _, hr := range results {
		fmt.Printf("\n=== %s ===\n", hr.Target)
		if hr.Error != "" {
			fmt.Printf("Error: %s\n", hr.Error)
			continue
		}
		fmt.Printf("Scan complete (%dms, profile: %s)\n", hr.Result.Meta.DurationMS, profile)
		for name, data := range hr.Result.Phases {
			fmt.Printf("\n--- %s ---\n", name)
			pretty, _ := json.MarshalIndent(data, "", "  ")
			fmt.Println(string(pretty))
		}
	}
	return nil
}

func uploadResult(ctx context.Context, result *scanner.Result) error {
	token := resolveToken()
	url := resolveURL()
	anonKey := resolveAnonKey()
	if token == "" || url == "" {
		return fmt.Errorf("--token/TB_TOKEN and --url/TB_URL required for upload")
	}

	req := upload.BuildRequest(result)
	req.AgentToken = token
	client := upload.NewClient(url, token, anonKey)
	resp, err := client.Upload(ctx, req)
	if err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}
	slog.Info("uploaded", "session_id", resp.SessionID, "cluster_id", resp.ClusterID, "resources", resp.ResourceCount)
	return nil
}

func outputResult(result *scanner.Result) error {
	if flagJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	fmt.Printf("Scan complete (%dms, profile: %s)\n", result.Meta.DurationMS, result.Meta.Profile)
	for name, data := range result.Phases {
		fmt.Printf("\n=== %s ===\n", name)
		pretty, _ := json.MarshalIndent(data, "", "  ")
		fmt.Println(string(pretty))
	}
	return nil
}
