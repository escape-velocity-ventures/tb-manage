package agent

import (
	"context"
	"log/slog"
	"time"

	"github.com/tinkerbelle-io/tb-discover/internal/commands"
	"github.com/tinkerbelle-io/tb-discover/internal/insights"
	"github.com/tinkerbelle-io/tb-discover/internal/remediation"
	"github.com/tinkerbelle-io/tb-discover/internal/scanner"
	"github.com/tinkerbelle-io/tb-discover/internal/upload"
	"k8s.io/client-go/kubernetes"
)

// ScanLoopConfig configures the periodic scan loop.
type ScanLoopConfig struct {
	Profile           string
	Interval          time.Duration
	UploadURL         string            // Supabase base URL for edge-ingest (single mode)
	Token             string            // agent_token (single mode)
	AnonKey           string            // Supabase anon key (single mode)
	Upstreams         []upload.Upstream // Multi-upstream mode
	Version           string            // binary version
	ExcludeNamespaces []string          // namespaces to skip during k8s scan

	// Controller mode: skip host scan upload (DaemonSet handles that)
	SkipUpload bool

	// Remediation
	MaxRemediationsPerHour int
	RemediationCooldown    time.Duration
	DryRun                 bool
}

// ScanLoop runs periodic infrastructure scans and uploads results.
type ScanLoop struct {
	cfg      ScanLoopConfig
	log      *slog.Logger
	uploader upload.Uploader

	// Insights
	insightsEngine   *insights.Engine
	insightReporters []*insights.Reporter

	// Remediation
	remediator  *remediation.Remediator
	remReporter *remediation.Reporter

	// Commands
	cmdPollers    []*commands.Poller
	cmdExecutor   *commands.Executor
	cmdCompleters []*commands.Completer

	// Shared k8s client (nil until first use, lazy-initialized)
	k8sClient kubernetes.Interface
}

// NewScanLoop creates a new scan loop.
func NewScanLoop(cfg ScanLoopConfig, logger *slog.Logger) *ScanLoop {
	sl := &ScanLoop{
		cfg: cfg,
		log: logger.With("component", "scanloop"),
	}

	if len(cfg.Upstreams) > 0 {
		sl.uploader = upload.NewMultiClient(cfg.Upstreams)
	} else if cfg.UploadURL != "" && cfg.Token != "" {
		sl.uploader = upload.NewClient(cfg.UploadURL, cfg.Token, cfg.AnonKey)
	}

	// Initialize insights engine
	sl.insightsEngine = insights.NewEngine(cfg.ExcludeNamespaces)

	// Set up per-upstream reporters and command infrastructure
	for _, u := range cfg.Upstreams {
		perms := permissionSet(u.Permissions)

		// Insight reporters for upstreams with "report" permission
		if perms["report"] || perms["scan"] {
			sl.insightReporters = append(sl.insightReporters,
				insights.NewReporter(u.URL, u.Token, u.AnonKey))
		}

		// Remediation for upstream with "remediate" or "remediate_dry_run" permission
		if perms["remediate"] || perms["remediate_dry_run"] {
			if sl.remReporter == nil {
				sl.remReporter = remediation.NewReporter(u.URL, u.Token, u.AnonKey)
			}
		}

		// Commands for upstreams with "execute_commands" permission
		if perms["execute_commands"] {
			sl.cmdPollers = append(sl.cmdPollers, commands.NewPoller(u.URL, u.Token, u.AnonKey))
			sl.cmdCompleters = append(sl.cmdCompleters, commands.NewCompleter(u.URL, u.Token, u.AnonKey))
		}
	}

	// Single-upstream fallback: use the single URL/token for all features
	if len(cfg.Upstreams) == 0 && cfg.UploadURL != "" && cfg.Token != "" {
		sl.insightReporters = append(sl.insightReporters,
			insights.NewReporter(cfg.UploadURL, cfg.Token, cfg.AnonKey))
	}

	return sl
}

// Run starts the scan loop. It runs an initial scan immediately, then
// scans at the configured interval until the context is cancelled.
func (sl *ScanLoop) Run(ctx context.Context) {
	sl.log.Info("scan loop starting",
		"profile", sl.cfg.Profile,
		"interval", sl.cfg.Interval,
		"upload", sl.uploader != nil,
	)

	// Initial scan immediately
	sl.runScan(ctx)

	ticker := time.NewTicker(sl.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			sl.log.Info("scan loop stopped")
			return
		case <-ticker.C:
			sl.runScan(ctx)
		}
	}
}

// runScan executes a single scan cycle:
// scan → upload → analyze → remediate → report insights → report remediations → poll commands → execute → report commands
func (sl *ScanLoop) runScan(ctx context.Context) {
	profile, err := scanner.ParseProfile(sl.cfg.Profile)
	if err != nil {
		sl.log.Error("invalid scan profile", "profile", sl.cfg.Profile, "error", err)
		return
	}

	reg := scanner.NewRegistryWithOptions(scanner.RegistryOptions{
		ExcludeNamespaces: sl.cfg.ExcludeNamespaces,
	})
	scanners := reg.ForProfile(profile)

	if len(scanners) == 0 {
		sl.log.Warn("no scanners for profile", "profile", sl.cfg.Profile)
		return
	}

	start := time.Now()
	result := scanner.NewResult()
	runner := scanner.LocalRunner{}

	sl.log.Debug("scan starting", "profile", sl.cfg.Profile, "scanners", len(scanners))

	for _, s := range scanners {
		if ctx.Err() != nil {
			sl.log.Info("scan interrupted by shutdown")
			return
		}

		data, scanErr := s.Scan(ctx, runner)
		if scanErr != nil {
			sl.log.Warn("scanner failed", "scanner", s.Name(), "error", scanErr)
			continue
		}
		result.Set(s.Name(), data)
	}

	// Apply topology inference
	scanner.ApplyTopology(result)

	hostname := nodeHostname()
	result.Meta.Version = sl.cfg.Version
	result.Meta.DurationMS = int(time.Since(start).Milliseconds())
	result.Meta.Profile = sl.cfg.Profile
	result.Meta.SourceHost = hostname

	// Override host name — HostScanner runs `hostname` inside the pod which
	// returns the pod name (e.g., tb-discover-xxxx), not the real node name.
	scanner.OverrideHostName(result, hostname)

	sl.log.Info("scan complete",
		"duration_ms", result.Meta.DurationMS,
		"phases", result.Meta.Phases,
		"inferred_role", result.Meta.InferredRole,
	)

	// Upload if configured (controller mode skips this — DaemonSet handles host uploads)
	if sl.uploader != nil && !sl.cfg.SkipUpload {
		sl.uploadResult(ctx, result)
	}

	// Insights + Remediation + Commands require k8s client
	clientset := sl.getK8sClient()
	if clientset == nil {
		sl.log.Debug("no k8s client available, skipping insights/remediation/commands")
		return
	}

	// Analyze
	allInsights := sl.insightsEngine.Analyze(ctx, clientset)
	if len(allInsights) > 0 {
		sl.log.Info("insights detected", "count", len(allInsights))
	}

	// Report insights
	for _, reporter := range sl.insightReporters {
		if _, err := reporter.Report(ctx, allInsights); err != nil {
			sl.log.Warn("insight report failed", "error", err)
		}
	}

	// Remediate
	if sl.remediator != nil {
		results := sl.remediator.Remediate(ctx, allInsights)
		if sl.remReporter != nil && len(results) > 0 {
			if err := sl.remReporter.Report(ctx, results); err != nil {
				sl.log.Warn("remediation report failed", "error", err)
			}
		}
	}

	// Poll and execute commands
	for i, poller := range sl.cmdPollers {
		cmds, err := poller.Poll(ctx)
		if err != nil {
			sl.log.Warn("command poll failed", "error", err)
			continue
		}
		if len(cmds) == 0 {
			continue
		}

		executor := sl.getCommandExecutor(clientset)
		for _, cmd := range cmds {
			result := executor.Execute(ctx, cmd)
			if i < len(sl.cmdCompleters) {
				if err := sl.cmdCompleters[i].Complete(ctx, cmd.ID, result); err != nil {
					sl.log.Warn("command completion report failed", "id", cmd.ID, "error", err)
				}
			}
		}
	}
}

// uploadResult sends scan results to edge-ingest.
func (sl *ScanLoop) uploadResult(ctx context.Context, result *scanner.Result) {
	req := upload.BuildRequest(result)

	resp, err := sl.uploader.Upload(ctx, req)
	if err != nil {
		sl.log.Error("upload failed", "error", err)
		return
	}

	sl.log.Info("upload complete",
		"session_id", resp.SessionID,
		"cluster_id", resp.ClusterID,
		"resources", resp.ResourceCount,
	)
}

// getK8sClient lazily creates a shared k8s clientset.
func (sl *ScanLoop) getK8sClient() kubernetes.Interface {
	if sl.k8sClient != nil {
		return sl.k8sClient
	}

	config, err := scanner.GetK8sConfig()
	if err != nil {
		sl.log.Debug("k8s config not available", "error", err)
		return nil
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		sl.log.Warn("failed to create k8s clientset", "error", err)
		return nil
	}

	sl.k8sClient = clientset

	// Now that we have a clientset, initialize the remediator if configured
	sl.initRemediator(clientset)

	return clientset
}

// initRemediator creates the remediator once we have a k8s client.
func (sl *ScanLoop) initRemediator(clientset kubernetes.Interface) {
	if sl.remediator != nil {
		return
	}

	// Check if any upstream has remediation permissions
	hasRemediate := false
	dryRun := sl.cfg.DryRun

	for _, u := range sl.cfg.Upstreams {
		perms := permissionSet(u.Permissions)
		if perms["remediate"] {
			hasRemediate = true
		}
		if perms["remediate_dry_run"] {
			hasRemediate = true
			dryRun = true
		}
	}

	if !hasRemediate {
		return
	}

	maxPerHour := sl.cfg.MaxRemediationsPerHour
	if maxPerHour <= 0 {
		maxPerHour = 10
	}
	cooldown := sl.cfg.RemediationCooldown
	if cooldown == 0 {
		cooldown = 30 * time.Minute
	}

	cb := remediation.NewCircuitBreaker(maxPerHour, cooldown)
	sl.remediator = remediation.NewRemediator(clientset, cb, dryRun)

	sl.log.Info("auto-remediation initialized",
		"dry_run", dryRun, "max_per_hour", maxPerHour, "cooldown", cooldown)
}

// getCommandExecutor returns or creates the command executor.
func (sl *ScanLoop) getCommandExecutor(clientset kubernetes.Interface) *commands.Executor {
	if sl.cmdExecutor != nil {
		return sl.cmdExecutor
	}
	sl.cmdExecutor = commands.NewExecutor(clientset)
	return sl.cmdExecutor
}

func permissionSet(perms []string) map[string]bool {
	m := make(map[string]bool, len(perms))
	for _, p := range perms {
		m[p] = true
	}
	return m
}
