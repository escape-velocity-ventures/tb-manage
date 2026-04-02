package reconciler

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestContentHash_Deterministic(t *testing.T) {
	content := []byte("hello: world\n")
	h1 := ContentHash(content)
	h2 := ContentHash(content)
	if h1 != h2 {
		t.Fatalf("ContentHash not deterministic: %s != %s", h1, h2)
	}
	// Verify it matches raw SHA256
	sum := sha256.Sum256(content)
	expected := fmt.Sprintf("%x", sum)
	if h1 != expected {
		t.Fatalf("ContentHash mismatch: got %s, want %s", h1, expected)
	}
}

func TestContentHash_DifferentContent(t *testing.T) {
	h1 := ContentHash([]byte("a: 1\n"))
	h2 := ContentHash([]byte("b: 2\n"))
	if h1 == h2 {
		t.Fatal("different content should produce different hashes")
	}
}

func TestValidateYAML_Valid(t *testing.T) {
	valid := []byte("key: value\nlist:\n  - one\n  - two\n")
	if err := ValidateYAML(valid); err != nil {
		t.Fatalf("valid YAML rejected: %v", err)
	}
}

func TestValidateYAML_EmptyContent(t *testing.T) {
	if err := ValidateYAML([]byte("")); err != nil {
		t.Fatalf("empty content should be valid YAML: %v", err)
	}
}

func TestValidateYAML_Malformed(t *testing.T) {
	malformed := []byte("key: [invalid\n  broken: yaml\n")
	if err := ValidateYAML(malformed); err == nil {
		t.Fatal("malformed YAML should be rejected")
	}
}

func TestValidateYAML_RejectsNonMapping(t *testing.T) {
	// A bare scalar is technically valid YAML but not a config file
	scalar := []byte("just a string\n")
	if err := ValidateYAML(scalar); err == nil {
		t.Fatal("non-mapping YAML should be rejected for config files")
	}
}

func TestWriteFile_NewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new.yaml")
	content := []byte("key: value\n")

	result, err := WriteFile(path, content)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if !result.Changed {
		t.Fatal("new file should report Changed=true")
	}
	if result.BackupPath != "" {
		t.Fatal("new file should have no backup")
	}
	if result.Hash != ContentHash(content) {
		t.Fatalf("hash mismatch: got %s, want %s", result.Hash, ContentHash(content))
	}

	// Verify file was written
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("file not written: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("content mismatch: got %q, want %q", got, content)
	}
}

func TestWriteFile_NoOpWhenUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.yaml")
	content := []byte("key: value\n")

	// Write initial file
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	result, err := WriteFile(path, content)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if result.Changed {
		t.Fatal("identical content should report Changed=false")
	}
	if result.BackupPath != "" {
		t.Fatal("no-op should have no backup")
	}
	if result.Hash != ContentHash(content) {
		t.Fatal("hash should still be returned even on no-op")
	}
}

func TestWriteFile_BackupCreatedOnChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	original := []byte("key: old\n")
	updated := []byte("key: new\n")

	if err := os.WriteFile(path, original, 0644); err != nil {
		t.Fatal(err)
	}

	result, err := WriteFile(path, updated)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if !result.Changed {
		t.Fatal("different content should report Changed=true")
	}
	if result.BackupPath == "" {
		t.Fatal("backup path should be set when file changed")
	}

	// Verify backup exists and has original content
	backup, err := os.ReadFile(result.BackupPath)
	if err != nil {
		t.Fatalf("backup file not readable: %v", err)
	}
	if string(backup) != string(original) {
		t.Fatalf("backup content mismatch: got %q, want %q", backup, original)
	}

	// Verify new content was written
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(updated) {
		t.Fatalf("updated content mismatch: got %q, want %q", got, updated)
	}
}

func TestWriteFile_BackupNamingFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("old: true\n"), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := WriteFile(path, []byte("new: true\n"))
	if err != nil {
		t.Fatal(err)
	}

	// Backup should match pattern: config.yaml.bak.YYYYMMDDHHMMSS (with optional .N suffix for collisions)
	pattern := regexp.MustCompile(`config\.yaml\.bak\.\d{14}(\.\d+)?$`)
	if !pattern.MatchString(result.BackupPath) {
		t.Fatalf("backup path %q does not match expected pattern config.yaml.bak.YYYYMMDDHHMMSS", result.BackupPath)
	}
}

func TestWriteFile_PreservesPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("old: true\n"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := WriteFile(path, []byte("new: true\n"))
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("permissions not preserved: got %o, want %o", info.Mode().Perm(), 0600)
	}
}

func TestWriteFile_NewFileDefaultPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "brand-new.yaml")

	_, err := WriteFile(path, []byte("key: value\n"))
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Default should be 0644 for new files
	if info.Mode().Perm() != 0644 {
		t.Fatalf("new file permissions: got %o, want %o", info.Mode().Perm(), 0644)
	}
}

func TestWriteFile_RejectsMalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	malformed := []byte("key: [broken\n  yaml: bad\n")

	_, err := WriteFile(path, malformed)
	if err == nil {
		t.Fatal("malformed YAML should be rejected")
	}
	if !strings.Contains(err.Error(), "YAML validation") {
		t.Fatalf("error should mention YAML validation, got: %v", err)
	}

	// File should not exist (never written)
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatal("malformed YAML should not create a file")
	}
}

func TestWriteFile_RejectsMalformedYAML_ExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	original := []byte("key: original\n")
	if err := os.WriteFile(path, original, 0644); err != nil {
		t.Fatal(err)
	}

	malformed := []byte("key: [broken\n  yaml: bad\n")
	_, err := WriteFile(path, malformed)
	if err == nil {
		t.Fatal("malformed YAML should be rejected")
	}

	// Original file should be untouched
	got, _ := os.ReadFile(path)
	if string(got) != string(original) {
		t.Fatalf("original file was corrupted: got %q, want %q", got, original)
	}
}

func TestWriteFile_AtomicWrite_NoTmpLeftBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	_, err := WriteFile(path, []byte("key: value\n"))
	if err != nil {
		t.Fatal(err)
	}

	// No .tmp files should remain
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("tmp file left behind: %s", e.Name())
		}
	}
}

func TestWriteFile_InvalidDirectory(t *testing.T) {
	path := "/nonexistent/dir/config.yaml"
	_, err := WriteFile(path, []byte("key: value\n"))
	if err == nil {
		t.Fatal("should fail when parent directory does not exist")
	}
}

func TestWriteFile_HashMatchesContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := []byte("key: value\nother: data\n")

	result, err := WriteFile(path, content)
	if err != nil {
		t.Fatal(err)
	}
	if result.Hash != ContentHash(content) {
		t.Fatalf("returned hash does not match ContentHash: got %s, want %s", result.Hash, ContentHash(content))
	}
}

func TestWriteFile_SequentialWritesCreateBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	// Write v1
	if _, err := WriteFile(path, []byte("version: 1\n")); err != nil {
		t.Fatal(err)
	}

	// Write v2 (should backup v1)
	r2, err := WriteFile(path, []byte("version: 2\n"))
	if err != nil {
		t.Fatal(err)
	}
	if r2.BackupPath == "" {
		t.Fatal("second write should create backup")
	}
	b2, _ := os.ReadFile(r2.BackupPath)
	if string(b2) != "version: 1\n" {
		t.Fatalf("backup should contain v1, got %q", b2)
	}

	// Write v3 (should backup v2)
	r3, err := WriteFile(path, []byte("version: 3\n"))
	if err != nil {
		t.Fatal(err)
	}
	if r3.BackupPath == "" {
		t.Fatal("third write should create backup")
	}
	b3, _ := os.ReadFile(r3.BackupPath)
	if string(b3) != "version: 2\n" {
		t.Fatalf("backup should contain v2, got %q", b3)
	}

	// Both backups should exist (different timestamps or content)
	if r2.BackupPath == r3.BackupPath {
		t.Fatal("sequential backups should have different paths")
	}
}
