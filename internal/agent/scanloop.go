package agent

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/tinkerbelle-io/tb-discover/internal/scanner"
	"github.com/tinkerbelle-io/tb-discover/internal/upload"
)

// ScanLoopConfig configures the periodic scan loop.
type ScanLoopConfig struct {
	Profile   string
	Interval  time.Duration
	UploadURL string // Supabase base URL for edge-ingest
	Token     string // agent_token
	AnonKey   string // Supabase anon key
	Version   string // binary version
}

// ScanLoop runs periodic infrastructure scans and uploads results.
type ScanLoop struct {
	cfg    ScanLoopConfig
	log    *slog.Logger
	client *upload.Client
}

// NewScanLoop creates a new scan loop.
func NewScanLoop(cfg ScanLoopConfig, logger *slog.Logger) *ScanLoop {
	sl := &ScanLoop{
		cfg: cfg,
		log: logger.With("component", "scanloop"),
	}

	if cfg.UploadURL != "" && cfg.Token != "" {
		sl.client = upload.NewClient(cfg.UploadURL, cfg.Token, cfg.AnonKey)
	}

	return sl
}

// Run starts the scan loop. It runs an initial scan immediately, then
// scans at the configured interval until the context is cancelled.
func (sl *ScanLoop) Run(ctx context.Context) {
	sl.log.Info("scan loop starting",
		"profile", sl.cfg.Profile,
		"interval", sl.cfg.Interval,
		"upload", sl.client != nil,
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

// runScan executes a single scan cycle.
func (sl *ScanLoop) runScan(ctx context.Context) {
	profile, err := scanner.ParseProfile(sl.cfg.Profile)
	if err != nil {
		sl.log.Error("invalid scan profile", "profile", sl.cfg.Profile, "error", err)
		return
	}

	reg := scanner.NewRegistry()
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

	hostname, _ := os.Hostname()
	result.Meta.Version = sl.cfg.Version
	result.Meta.DurationMS = int(time.Since(start).Milliseconds())
	result.Meta.Profile = sl.cfg.Profile
	result.Meta.SourceHost = hostname

	sl.log.Info("scan complete",
		"duration_ms", result.Meta.DurationMS,
		"phases", result.Meta.Phases,
		"inferred_role", result.Meta.InferredRole,
	)

	// Upload if configured
	if sl.client != nil {
		sl.uploadResult(ctx, result)
	}
}

// uploadResult sends scan results to edge-ingest.
func (sl *ScanLoop) uploadResult(ctx context.Context, result *scanner.Result) {
	req := upload.BuildRequest(result)
	req.AgentToken = sl.cfg.Token

	resp, err := sl.client.Upload(ctx, req)
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
