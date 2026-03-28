// Package casync provides SSH CA public key synchronization for tb-manage.
//
// It periodically fetches the SSH CA public key from the TinkerBelle SaaS,
// writes it to the node's sshd trusted CA keys file, and handles zero-downtime
// key rotation with an overlap window where both old and new keys are trusted.
package casync

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Action describes what happened when Apply was called.
type Action string

const (
	ActionInstalled       Action = "installed"
	ActionUnchanged       Action = "unchanged"
	ActionRotationStarted Action = "rotation_started"
)

// CAKeyResponse is the API response from the SaaS.
type CAKeyResponse struct {
	PublicKey   string `json:"publicKey"`
	Fingerprint string `json:"fingerprint"`
	Version    int    `json:"version"`
}

// --- Fetcher: retrieves CA key from SaaS API ---

// Fetcher retrieves the SSH CA public key from the SaaS API.
type Fetcher struct {
	baseURL string
	token   string
	anonKey string
	client  *http.Client
}

// NewFetcher creates a new CA key fetcher.
func NewFetcher(baseURL, token, anonKey string) *Fetcher {
	return &Fetcher{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		anonKey: anonKey,
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

// Fetch retrieves the current CA public key from the SaaS.
func (f *Fetcher) Fetch(ctx context.Context) (*CAKeyResponse, error) {
	url := f.baseURL + "/api/v1/ssh/ca-public-key"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+f.token)
	if f.anonKey != "" {
		req.Header.Set("apikey", f.anonKey)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch CA key: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CA key API returned %d: %s", resp.StatusCode, string(body))
	}

	var result CAKeyResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse CA key response: %w", err)
	}

	if strings.TrimSpace(result.PublicKey) == "" {
		return nil, fmt.Errorf("CA key API returned empty public key")
	}

	return &result, nil
}

// --- Writer: manages the CA key file on disk ---

// Writer manages the SSH CA public key file on disk.
type Writer struct {
	keyPath string
	log     *slog.Logger
}

// NewWriter creates a new CA key file writer.
func NewWriter(keyPath string, log *slog.Logger) *Writer {
	return &Writer{
		keyPath: keyPath,
		log:     log,
	}
}

// Apply writes the CA key to disk, handling first-time setup and rotation.
// Returns the action taken.
func (w *Writer) Apply(newKey, fingerprint string) (Action, error) {
	newKey = strings.TrimSpace(newKey)

	// Read current file
	existing, err := os.ReadFile(w.keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			// First-time setup
			return w.writeKey(newKey, ActionInstalled)
		}
		return "", fmt.Errorf("read existing key file: %w", err)
	}

	// Parse existing keys
	currentKeys := nonEmptyLines(string(existing))

	// Check if new key is already present
	for _, k := range currentKeys {
		if k == newKey {
			return ActionUnchanged, nil
		}
	}

	// New key not present — start rotation with overlap
	// Write old key(s) + new key
	var lines []string
	lines = append(lines, currentKeys...)
	lines = append(lines, newKey)

	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(w.keyPath, []byte(content), 0644); err != nil {
		return "", fmt.Errorf("write overlap key file: %w", err)
	}

	w.log.Info("CA key rotation started — overlap file written",
		"keys_in_file", len(lines),
		"fingerprint", fingerprint,
	)

	return ActionRotationStarted, nil
}

// FinalizeRotation removes all keys except the given key from the file.
// Returns true if finalization happened, false if already finalized.
func (w *Writer) FinalizeRotation(currentKey string) (bool, error) {
	currentKey = strings.TrimSpace(currentKey)

	existing, err := os.ReadFile(w.keyPath)
	if err != nil {
		return false, fmt.Errorf("read key file for finalization: %w", err)
	}

	keys := nonEmptyLines(string(existing))
	if len(keys) <= 1 {
		// Already finalized or single key
		return false, nil
	}

	// Write only the current key
	return true, w.writeKeyRaw(currentKey)
}

func (w *Writer) writeKey(key string, action Action) (Action, error) {
	if err := w.writeKeyRaw(key); err != nil {
		return "", err
	}
	return action, nil
}

func (w *Writer) writeKeyRaw(key string) error {
	content := key + "\n"
	if err := os.WriteFile(w.keyPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write CA key file: %w", err)
	}
	return nil
}

// --- RotationState: tracks pending rotations across restarts ---

// RotationState tracks the state of a pending key rotation.
type RotationState struct {
	path string

	Pending        bool      `json:"pending"`
	OldFingerprint string    `json:"old_fingerprint,omitempty"`
	NewFingerprint string    `json:"new_fingerprint,omitempty"`
	NewPublicKey   string    `json:"new_public_key,omitempty"`
	StartedAt      time.Time `json:"started_at,omitempty"`
}

// NewRotationState creates a rotation state tracker.
func NewRotationState(path string) *RotationState {
	return &RotationState{path: path}
}

// Load reads the rotation state from disk.
func (rs *RotationState) Load() error {
	data, err := os.ReadFile(rs.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No state file = no pending rotation
		}
		return fmt.Errorf("read rotation state: %w", err)
	}
	return json.Unmarshal(data, rs)
}

// Save writes the rotation state to disk.
func (rs *RotationState) Save() error {
	data, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal rotation state: %w", err)
	}
	return os.WriteFile(rs.path, data, 0644)
}

// HasPending returns true if there's a pending rotation.
func (rs *RotationState) HasPending() bool {
	return rs.Pending
}

// Start marks a rotation as started.
func (rs *RotationState) Start(oldFP, newFP string) {
	rs.Pending = true
	rs.OldFingerprint = oldFP
	rs.NewFingerprint = newFP
	rs.StartedAt = time.Now()
}

// Complete clears the pending rotation.
func (rs *RotationState) Complete() {
	rs.Pending = false
	rs.OldFingerprint = ""
	rs.NewFingerprint = ""
	rs.NewPublicKey = ""
	rs.StartedAt = time.Time{}
}

// ReadyToFinalize returns true if the overlap window has elapsed.
func (rs *RotationState) ReadyToFinalize(overlapWindow time.Duration) bool {
	if !rs.Pending {
		return false
	}
	return time.Since(rs.StartedAt) >= overlapWindow
}

// --- Config ---

// Config holds the CA sync configuration.
type Config struct {
	SaaSURL       string        // Base URL of the SaaS API
	Token         string        // Auth token
	AnonKey       string        // Supabase anon key
	CAKeyPath     string        // Path to write the CA public key (default: /etc/ssh/tb_ca.pub)
	StatePath     string        // Path for rotation state file (default: /var/lib/tb-manage/ca-rotation.json)
	OverlapWindow time.Duration // How long to keep both keys during rotation (default: 24h)
	SyncInterval  time.Duration // How often to check for key updates (default: 6h)
	RestartSSHD   bool          // Whether to restart sshd after key changes (default: true in prod)
}

// DefaultConfig returns sensible defaults for CA sync.
func DefaultConfig() Config {
	return Config{
		CAKeyPath:     "/etc/ssh/tb_ca.pub",
		StatePath:     "/var/lib/tb-manage/ca-rotation.json",
		OverlapWindow: 24 * time.Hour,
		SyncInterval:  6 * time.Hour,
		RestartSSHD:   true,
	}
}

// --- Syncer: orchestrates the fetch/compare/write/finalize cycle ---

// Syncer orchestrates periodic CA key synchronization.
type Syncer struct {
	cfg     Config
	fetcher *Fetcher
	writer  *Writer
	state   *RotationState
	log     *slog.Logger
	mu      sync.Mutex
}

// NewSyncer creates a new CA key syncer.
func NewSyncer(cfg Config, log *slog.Logger) *Syncer {
	return &Syncer{
		cfg:     cfg,
		fetcher: NewFetcher(cfg.SaaSURL, cfg.Token, cfg.AnonKey),
		writer:  NewWriter(cfg.CAKeyPath, log),
		state:   NewRotationState(cfg.StatePath),
		log:     log.With("component", "casync"),
	}
}

// Run starts the periodic CA key sync loop.
func (s *Syncer) Run(ctx context.Context) {
	s.log.Info("CA key sync starting",
		"interval", s.cfg.SyncInterval,
		"key_path", s.cfg.CAKeyPath,
		"overlap_window", s.cfg.OverlapWindow,
	)

	// Load any existing rotation state
	if err := s.state.Load(); err != nil {
		s.log.Warn("failed to load rotation state", "error", err)
	}

	// Initial sync immediately
	if err := s.SyncOnce(ctx); err != nil {
		s.log.Error("initial CA key sync failed", "error", err)
	}

	ticker := time.NewTicker(s.cfg.SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.log.Info("CA key sync stopped")
			return
		case <-ticker.C:
			if err := s.SyncOnce(ctx); err != nil {
				s.log.Error("CA key sync failed", "error", err)
			}
		}
	}
}

// SyncOnce performs a single sync cycle: fetch, compare, write/rotate, finalize if needed.
func (s *Syncer) SyncOnce(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Load rotation state from disk (may have been written by a previous run)
	if err := s.state.Load(); err != nil {
		s.log.Warn("failed to load rotation state", "error", err)
	}

	// Step 1: Check if a pending rotation needs finalization
	if s.state.HasPending() && s.state.ReadyToFinalize(s.cfg.OverlapWindow) {
		s.log.Info("overlap window elapsed — finalizing rotation",
			"old_fingerprint", s.state.OldFingerprint,
			"new_fingerprint", s.state.NewFingerprint,
		)

		finalized, err := s.writer.FinalizeRotation(s.state.NewPublicKey)
		if err != nil {
			return fmt.Errorf("finalize rotation: %w", err)
		}
		if finalized {
			s.restartSSHD("rotation finalized")
		}

		s.state.Complete()
		if err := s.state.Save(); err != nil {
			s.log.Warn("failed to save rotation state", "error", err)
		}

		s.log.Info("CA key rotation complete",
			"fingerprint", s.state.NewFingerprint,
		)
	}

	// Step 2: Fetch current key from SaaS
	resp, err := s.fetcher.Fetch(ctx)
	if err != nil {
		return fmt.Errorf("fetch CA key: %w", err)
	}

	// Step 3: Apply key (first-time, unchanged, or start rotation)
	action, err := s.writer.Apply(resp.PublicKey, resp.Fingerprint)
	if err != nil {
		return fmt.Errorf("apply CA key: %w", err)
	}

	switch action {
	case ActionInstalled:
		s.log.Info("CA key installed (first-time setup)",
			"fingerprint", resp.Fingerprint,
			"version", resp.Version,
		)
		s.restartSSHD("first-time CA key install")

	case ActionRotationStarted:
		s.log.Info("CA key rotation started — overlap window active",
			"fingerprint", resp.Fingerprint,
			"version", resp.Version,
			"overlap_window", s.cfg.OverlapWindow,
		)
		s.restartSSHD("rotation overlap started")

		// Track the rotation state
		// Read the old fingerprint from the current state or generate one
		oldFP := "unknown"
		if s.state.HasPending() {
			oldFP = s.state.OldFingerprint
		}
		s.state.Start(oldFP, resp.Fingerprint)
		s.state.NewPublicKey = resp.PublicKey
		if err := s.state.Save(); err != nil {
			s.log.Warn("failed to save rotation state", "error", err)
		}

	case ActionUnchanged:
		s.log.Debug("CA key unchanged", "fingerprint", resp.Fingerprint)
	}

	return nil
}

// restartSSHD restarts the sshd service if configured.
func (s *Syncer) restartSSHD(reason string) {
	if !s.cfg.RestartSSHD {
		s.log.Debug("sshd restart skipped (disabled in config)", "reason", reason)
		return
	}

	s.log.Info("restarting sshd", "reason", reason)

	// Use os/exec to restart sshd
	// Import is deferred to avoid breaking tests
	restartSSHDService(s.log)
}

// nonEmptyLines splits text into non-empty trimmed lines.
func nonEmptyLines(s string) []string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
