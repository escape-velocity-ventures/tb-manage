// Package reconciler provides the main reconcile loop that ties together
// ConfigMap listing, YAML merging, file writing, and rolling service restarts.
// It runs on a configurable interval (default 60s) as part of the tb-manage daemon.
package reconciler

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"k8s.io/client-go/kubernetes"
)

// ReconcileResult contains the outcome of reconciling a single target.
type ReconcileResult struct {
	ConfigMapName string
	TargetPath    string
	Changed       bool
	Restarted     bool
	Error         error
}

// Reconciler orchestrates the config reconciliation pipeline.
type Reconciler struct {
	client     kubernetes.Interface
	namespace  string
	nodeName   string
	nodeLabels map[string]string
	interval   time.Duration
	dryRun     bool
	hostRoot   string
}

// New creates a Reconciler. hostRoot is the prefix for host filesystem paths
// (e.g., "/host" when the DaemonSet mounts host paths under /host).
func New(client kubernetes.Interface, namespace, nodeName string, nodeLabels map[string]string, interval time.Duration, dryRun bool, hostRoot string) *Reconciler {
	return &Reconciler{
		client:     client,
		namespace:  namespace,
		nodeName:   nodeName,
		nodeLabels: nodeLabels,
		interval:   interval,
		dryRun:     dryRun,
		hostRoot:   hostRoot,
	}
}

// Run starts the reconcile loop. Blocks until ctx is cancelled.
func (r *Reconciler) Run(ctx context.Context) error {
	log.Printf("config-reconciler: starting (interval=%s, namespace=%s, node=%s, dry-run=%t, host-root=%s)",
		r.interval, r.namespace, r.nodeName, r.dryRun, r.hostRoot)

	// Run once immediately on startup
	results, err := r.RunOnce(ctx)
	if err != nil {
		log.Printf("config-reconciler: initial pass error: %v", err)
	} else {
		r.logResults(results)
	}

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("config-reconciler: shutting down")
			return nil
		case <-ticker.C:
			results, err := r.RunOnce(ctx)
			if err != nil {
				log.Printf("config-reconciler: reconcile error: %v", err)
				continue
			}
			r.logResults(results)
		}
	}
}

// RunOnce executes a single reconcile pass. Called by Run on each interval.
// Also useful for testing.
func (r *Reconciler) RunOnce(ctx context.Context) ([]ReconcileResult, error) {
	// Step 1: List targets
	targets, err := ListTargets(ctx, r.client, r.namespace, r.nodeLabels)
	if err != nil {
		return nil, err
	}

	if len(targets) == 0 {
		return nil, nil
	}

	var results []ReconcileResult

	// Step 2: Process each target
	for _, target := range targets {
		result := r.reconcileTarget(ctx, target)
		results = append(results, result)
	}

	return results, nil
}

// reconcileTarget processes a single ReconcileTarget through the pipeline:
// read existing -> merge -> write -> restart (if needed).
func (r *Reconciler) reconcileTarget(ctx context.Context, target ReconcileTarget) ReconcileResult {
	result := ReconcileResult{
		ConfigMapName: target.ConfigMapName,
		TargetPath:    target.TargetPath,
	}

	// Resolve the host-prefixed path with traversal protection
	// Guard against empty hostRoot which would collapse the check
	cleanRoot := filepath.Clean(r.hostRoot)
	if cleanRoot == "." || cleanRoot == "" {
		result.Error = fmt.Errorf("hostRoot must be an absolute path, got %q", r.hostRoot)
		return result
	}
	fullPath := filepath.Clean(filepath.Join(cleanRoot, target.TargetPath))
	if !strings.HasPrefix(fullPath, cleanRoot) {
		result.Error = fmt.Errorf("path traversal blocked: %s escapes host root %s", target.TargetPath, r.hostRoot)
		return result
	}

	// Get the desired config data from ConfigMap
	// Use "config.yaml" key by convention; fall back to first key
	desired := r.getConfigData(target)
	if desired == "" {
		result.Error = nil // No data to reconcile — skip silently
		return result
	}

	// Step 2a: Read existing file
	existing, readErr := os.ReadFile(fullPath)
	if readErr != nil && !os.IsNotExist(readErr) {
		result.Error = readErr
		return result
	}

	// Step 2b: Merge
	merged, mergeErr := Merge(existing, []byte(desired), target.MergeStrategy)
	if mergeErr != nil {
		result.Error = mergeErr
		return result
	}

	// Dry-run: compute what would change but don't write or restart
	if r.dryRun {
		hash := ContentHash(merged)
		existingHash := ContentHash(existing)
		changed := hash != existingHash
		result.Changed = changed
		if changed {
			log.Printf("config-reconciler: [DRY-RUN] WOULD update %s from ConfigMap %s (hash: %s)",
				fullPath, target.ConfigMapName, hash)
			if target.RestartService != "" {
				log.Printf("config-reconciler: [DRY-RUN] WOULD restart service %s", target.RestartService)
			}
		} else {
			log.Printf("config-reconciler: [DRY-RUN] no change for %s from ConfigMap %s",
				fullPath, target.ConfigMapName)
		}
		return result
	}

	// Step 2c: Write file
	writeResult, writeErr := WriteFile(fullPath, merged)
	if writeErr != nil {
		result.Error = writeErr
		return result
	}

	result.Changed = writeResult.Changed

	if !writeResult.Changed {
		log.Printf("config-reconciler: no change for %s from ConfigMap %s",
			fullPath, target.ConfigMapName)
		return result
	}

	log.Printf("config-reconciler: updated %s from ConfigMap %s (hash: %s)",
		fullPath, target.ConfigMapName, writeResult.Hash)

	// Step 2d: Restart service if configured
	if target.RestartService != "" {
		restarted := r.handleRestart(ctx, target)
		result.Restarted = restarted
	}

	return result
}

// handleRestart attempts to acquire the restart lock, restart the service,
// and wait for health. Returns true if the restart was executed.
func (r *Reconciler) handleRestart(ctx context.Context, target ReconcileTarget) bool {
	// Update coordinator's maxConcurrent from target
	coordinator := NewRestartCoordinator(r.client, r.namespace, r.nodeName, target.MaxConcurrent)

	acquired, err := coordinator.AcquireLock(ctx, target.RestartService)
	if err != nil {
		log.Printf("config-reconciler: failed to acquire restart lock for %s: %v",
			target.RestartService, err)
		return false
	}
	if !acquired {
		log.Printf("config-reconciler: restart lock unavailable for %s (another node is restarting), will retry next cycle",
			target.RestartService)
		return false
	}

	log.Printf("config-reconciler: restarting service %s on node %s",
		target.RestartService, r.nodeName)

	if err := RestartService(target.RestartService); err != nil {
		log.Printf("config-reconciler: restart failed for %s: %v", target.RestartService, err)
		_ = coordinator.ReleaseLock(ctx, "failed")
		return false
	}

	if err := coordinator.WaitForHealth(ctx, target.RestartService, 5*time.Minute); err != nil {
		log.Printf("config-reconciler: health check failed after restart of %s: %v (circuit breaker)",
			target.RestartService, err)
		_ = coordinator.ReleaseLock(ctx, "failed")
		return false
	}

	log.Printf("config-reconciler: service %s restarted and healthy on node %s",
		target.RestartService, r.nodeName)
	_ = coordinator.ReleaseLock(ctx, "healthy")
	return true
}

// getConfigData extracts the config content from the ConfigMap data map.
// Prefers "config.yaml" key, then falls back to the first available key.
func (r *Reconciler) getConfigData(target ReconcileTarget) string {
	if v, ok := target.Data["config.yaml"]; ok {
		return v
	}
	// Fall back to first key
	for _, v := range target.Data {
		return v
	}
	return ""
}

// logResults logs a summary of reconcile results.
func (r *Reconciler) logResults(results []ReconcileResult) {
	if len(results) == 0 {
		return
	}
	changed := 0
	restarted := 0
	errored := 0
	for _, res := range results {
		if res.Error != nil {
			errored++
		}
		if res.Changed {
			changed++
		}
		if res.Restarted {
			restarted++
		}
	}
	log.Printf("config-reconciler: pass complete — %d targets, %d changed, %d restarted, %d errors",
		len(results), changed, restarted, errored)
}
