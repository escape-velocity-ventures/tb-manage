// Package reconciler provides ConfigMap-driven config reconciliation for tb-manage.
// This file implements atomic file writing with YAML validation and backup.
package reconciler

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// WriteResult contains the outcome of a file write operation.
type WriteResult struct {
	Changed    bool   // true if file content was different
	BackupPath string // path to backup file (empty if no change)
	Hash       string // SHA256 of written content
}

// ContentHash returns SHA256 hex digest of content.
func ContentHash(content []byte) string {
	sum := sha256.Sum256(content)
	return fmt.Sprintf("%x", sum)
}

// ValidateYAML checks if content is valid YAML that represents a mapping.
// Empty content is accepted (valid empty document).
// Non-mapping YAML (e.g. bare scalar) is rejected since config files must be maps.
func ValidateYAML(content []byte) error {
	if len(content) == 0 {
		return nil
	}
	var m map[string]interface{}
	if err := yaml.Unmarshal(content, &m); err != nil {
		return err
	}
	if m == nil {
		return fmt.Errorf("YAML content is not a mapping")
	}
	return nil
}

// WriteFile atomically writes content to path with safety checks.
//  1. Read existing file (if any)
//  2. Compare content -- if identical, return Changed=false (no-op)
//  3. Validate content is parseable YAML
//  4. Backup existing file to path.bak.YYYYMMDDHHMMSS
//  5. Write to path.tmp, then os.Rename to path (atomic)
//  6. Return WriteResult with hash
func WriteFile(path string, content []byte) (WriteResult, error) {
	hash := ContentHash(content)

	// Step 3: Validate YAML before anything else
	if err := ValidateYAML(content); err != nil {
		return WriteResult{}, fmt.Errorf("YAML validation failed: %w", err)
	}

	// Step 1 & 2: Read existing file and compare
	existing, readErr := os.ReadFile(path)
	if readErr == nil && ContentHash(existing) == hash {
		return WriteResult{Changed: false, Hash: hash}, nil
	}

	// Preserve file permissions from existing file
	perm := os.FileMode(0644)
	if info, err := os.Stat(path); err == nil {
		perm = info.Mode().Perm()
	}

	// Step 4: Backup existing file before overwriting
	var backupPath string
	if readErr == nil {
		backupPath = uniqueBackupPath(path)
		if err := os.WriteFile(backupPath, existing, perm); err != nil {
			return WriteResult{}, fmt.Errorf("backup failed: %w", err)
		}
	}

	// Step 5: Atomic write -- write to tmp, then rename
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return WriteResult{}, fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	// Clean up tmp on any failure
	cleanup := func() {
		tmp.Close()
		os.Remove(tmpPath)
	}

	if _, err := tmp.Write(content); err != nil {
		cleanup()
		return WriteResult{}, fmt.Errorf("failed to write temp file: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		cleanup()
		return WriteResult{}, fmt.Errorf("failed to set permissions: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return WriteResult{}, fmt.Errorf("failed to close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return WriteResult{}, fmt.Errorf("atomic rename failed: %w", err)
	}

	// Step 6: Return result
	return WriteResult{Changed: true, BackupPath: backupPath, Hash: hash}, nil
}

// uniqueBackupPath generates a backup path with timestamp, adding a sequence
// suffix if a backup with that timestamp already exists (handles sub-second writes).
func uniqueBackupPath(path string) string {
	ts := time.Now().Format("20060102150405")
	candidate := fmt.Sprintf("%s.bak.%s", path, ts)
	if _, err := os.Stat(candidate); os.IsNotExist(err) {
		return candidate
	}
	// Collision: append sequence number
	for i := 1; i < 1000; i++ {
		candidate = fmt.Sprintf("%s.bak.%s.%d", path, ts, i)
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate
		}
	}
	// Extremely unlikely fallback
	return fmt.Sprintf("%s.bak.%s.%d", path, ts, time.Now().UnixNano())
}
