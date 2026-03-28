package casync

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// --- Fetcher tests ---

func TestFetchCAKey_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ssh/ca-public-key" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("missing or wrong auth header: %s", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"publicKey":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest","fingerprint":"SHA256:testfp","version":1}`)
	}))
	defer server.Close()

	f := NewFetcher(server.URL, "test-token", "anon-key")
	resp, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}
	if resp.PublicKey != "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest" {
		t.Errorf("unexpected public key: %s", resp.PublicKey)
	}
	if resp.Fingerprint != "SHA256:testfp" {
		t.Errorf("unexpected fingerprint: %s", resp.Fingerprint)
	}
	if resp.Version != 1 {
		t.Errorf("unexpected version: %d", resp.Version)
	}
}

func TestFetchCAKey_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"internal"}`)
	}))
	defer server.Close()

	f := NewFetcher(server.URL, "test-token", "anon-key")
	_, err := f.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected error on 500")
	}
}

func TestFetchCAKey_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `not json`)
	}))
	defer server.Close()

	f := NewFetcher(server.URL, "test-token", "anon-key")
	_, err := f.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected error on invalid JSON")
	}
}

func TestFetchCAKey_EmptyPublicKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"publicKey":"","fingerprint":"SHA256:fp","version":1}`)
	}))
	defer server.Close()

	f := NewFetcher(server.URL, "test-token", "anon-key")
	_, err := f.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected error on empty public key")
	}
}

// --- Writer tests ---

func TestWriteCAKey_FirstTime(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "tb_ca.pub")

	w := NewWriter(keyPath, testLogger())
	action, err := w.Apply("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfirst", "SHA256:fp1")
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if action != ActionInstalled {
		t.Errorf("expected action %s, got %s", ActionInstalled, action)
	}

	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	if strings.TrimSpace(string(data)) != "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfirst" {
		t.Errorf("unexpected file content: %q", string(data))
	}
}

func TestWriteCAKey_SameKey_NoAction(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "tb_ca.pub")

	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsame"
	if err := os.WriteFile(keyPath, []byte(key+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	w := NewWriter(keyPath, testLogger())
	action, err := w.Apply(key, "SHA256:fp1")
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if action != ActionUnchanged {
		t.Errorf("expected action %s, got %s", ActionUnchanged, action)
	}
}

func TestWriteCAKey_Rotation_OverlapPhase(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "tb_ca.pub")

	oldKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIold"
	if err := os.WriteFile(keyPath, []byte(oldKey+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	newKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAInew"
	w := NewWriter(keyPath, testLogger())
	action, err := w.Apply(newKey, "SHA256:fp2")
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if action != ActionRotationStarted {
		t.Errorf("expected action %s, got %s", ActionRotationStarted, action)
	}

	// File should contain BOTH keys (old + new)
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	lines := nonEmptyLines(string(data))
	if len(lines) != 2 {
		t.Fatalf("expected 2 keys during overlap, got %d: %v", len(lines), lines)
	}
	if lines[0] != oldKey {
		t.Errorf("first line should be old key, got: %s", lines[0])
	}
	if lines[1] != newKey {
		t.Errorf("second line should be new key, got: %s", lines[1])
	}
}

func TestWriteCAKey_Rotation_FinalizePhase(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "tb_ca.pub")

	oldKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIold"
	newKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAInew"

	// Simulate overlap state: file has both keys
	if err := os.WriteFile(keyPath, []byte(oldKey+"\n"+newKey+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	w := NewWriter(keyPath, testLogger())
	// When we apply the same new key and the file is already in overlap,
	// Apply returns Unchanged because the new key is already present.
	// Finalization is handled by FinalizeRotation.
	action, err := w.Apply(newKey, "SHA256:fp2")
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	// The new key is already in the file (overlap state), so no change needed
	if action != ActionUnchanged {
		t.Errorf("expected action %s, got %s", ActionUnchanged, action)
	}

	// Finalize removes the old key
	finalized, err := w.FinalizeRotation(newKey)
	if err != nil {
		t.Fatalf("finalize failed: %v", err)
	}
	if !finalized {
		t.Error("expected finalize to return true")
	}

	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	lines := nonEmptyLines(string(data))
	if len(lines) != 1 {
		t.Fatalf("expected 1 key after finalize, got %d: %v", len(lines), lines)
	}
	if lines[0] != newKey {
		t.Errorf("remaining key should be new key, got: %s", lines[0])
	}
}

func TestWriteCAKey_FinalizeRotation_NotNeeded(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "tb_ca.pub")

	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsingle"
	if err := os.WriteFile(keyPath, []byte(key+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	w := NewWriter(keyPath, testLogger())
	finalized, err := w.FinalizeRotation(key)
	if err != nil {
		t.Fatalf("finalize failed: %v", err)
	}
	if finalized {
		t.Error("expected finalize to return false when only one key present")
	}
}

func TestWriteCAKey_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "tb_ca.pub")

	w := NewWriter(keyPath, testLogger())
	_, err := w.Apply("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIperm", "SHA256:fp")
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	// File should be 0644 (root-readable, world-readable for sshd)
	perm := info.Mode().Perm()
	if perm != 0644 {
		t.Errorf("expected permissions 0644, got %04o", perm)
	}
}

// --- Rotation State tests ---

func TestRotationState_Persistence(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "rotation.json")

	rs := NewRotationState(statePath)

	// Initially no pending rotation
	if rs.HasPending() {
		t.Error("expected no pending rotation initially")
	}

	// Start a rotation
	rs.Start("SHA256:oldfp", "SHA256:newfp")
	if !rs.HasPending() {
		t.Error("expected pending rotation after Start")
	}

	// Save and reload
	if err := rs.Save(); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	rs2 := NewRotationState(statePath)
	if err := rs2.Load(); err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if !rs2.HasPending() {
		t.Error("expected pending rotation after reload")
	}
	if rs2.NewFingerprint != "SHA256:newfp" {
		t.Errorf("unexpected new fingerprint: %s", rs2.NewFingerprint)
	}
}

func TestRotationState_ReadyToFinalize(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "rotation.json")

	rs := NewRotationState(statePath)
	rs.Start("SHA256:old", "SHA256:new")

	// Not ready immediately
	if rs.ReadyToFinalize(24 * time.Hour) {
		t.Error("should not be ready to finalize immediately")
	}

	// Hack the start time to 25 hours ago
	rs.StartedAt = time.Now().Add(-25 * time.Hour)
	if !rs.ReadyToFinalize(24 * time.Hour) {
		t.Error("should be ready to finalize after 25 hours with 24h overlap")
	}
}

func TestRotationState_Complete(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "rotation.json")

	rs := NewRotationState(statePath)
	rs.Start("SHA256:old", "SHA256:new")
	rs.Complete()

	if rs.HasPending() {
		t.Error("expected no pending rotation after Complete")
	}
}

// --- Syncer integration tests ---

func TestSyncer_FirstTimeSetup(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "tb_ca.pub")
	statePath := filepath.Join(dir, "rotation.json")

	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsyncer"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"publicKey":"%s","fingerprint":"SHA256:syncfp","version":1}`, key)
	}))
	defer server.Close()

	s := NewSyncer(Config{
		SaaSURL:        server.URL,
		Token:          "test",
		AnonKey:        "anon",
		CAKeyPath:      keyPath,
		StatePath:      statePath,
		OverlapWindow:  24 * time.Hour,
		SyncInterval:   1 * time.Hour,
		RestartSSHD:    false, // Don't restart sshd in tests
	}, testLogger())

	err := s.SyncOnce(context.Background())
	if err != nil {
		t.Fatalf("sync failed: %v", err)
	}

	// Verify key was written
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if strings.TrimSpace(string(data)) != key {
		t.Errorf("unexpected key content: %q", string(data))
	}
}

func TestSyncer_KeyRotation(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "tb_ca.pub")
	statePath := filepath.Join(dir, "rotation.json")

	oldKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIold"
	newKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAInew"

	// Pre-populate with old key
	if err := os.WriteFile(keyPath, []byte(oldKey+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"publicKey":"%s","fingerprint":"SHA256:newfp","version":2}`, newKey)
	}))
	defer server.Close()

	s := NewSyncer(Config{
		SaaSURL:        server.URL,
		Token:          "test",
		AnonKey:        "anon",
		CAKeyPath:      keyPath,
		StatePath:      statePath,
		OverlapWindow:  24 * time.Hour,
		SyncInterval:   1 * time.Hour,
		RestartSSHD:    false,
	}, testLogger())

	err := s.SyncOnce(context.Background())
	if err != nil {
		t.Fatalf("sync failed: %v", err)
	}

	// Should be in overlap state
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	lines := nonEmptyLines(string(data))
	if len(lines) != 2 {
		t.Fatalf("expected 2 keys during overlap, got %d", len(lines))
	}

	// Rotation state should be persisted
	rs := NewRotationState(statePath)
	if err := rs.Load(); err != nil {
		t.Fatalf("load state: %v", err)
	}
	if !rs.HasPending() {
		t.Error("expected pending rotation in state file")
	}
}

func TestSyncer_FinalizesAfterOverlap(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "tb_ca.pub")
	statePath := filepath.Join(dir, "rotation.json")

	oldKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIold"
	newKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAInew"

	// Set up overlap state: both keys in file
	if err := os.WriteFile(keyPath, []byte(oldKey+"\n"+newKey+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Set up rotation state with expired overlap
	rs := NewRotationState(statePath)
	rs.Start("SHA256:oldfp", "SHA256:newfp")
	rs.NewPublicKey = newKey
	rs.StartedAt = time.Now().Add(-25 * time.Hour) // Expired overlap
	if err := rs.Save(); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"publicKey":"%s","fingerprint":"SHA256:newfp","version":2}`, newKey)
	}))
	defer server.Close()

	s := NewSyncer(Config{
		SaaSURL:        server.URL,
		Token:          "test",
		AnonKey:        "anon",
		CAKeyPath:      keyPath,
		StatePath:      statePath,
		OverlapWindow:  24 * time.Hour,
		SyncInterval:   1 * time.Hour,
		RestartSSHD:    false,
	}, testLogger())

	err := s.SyncOnce(context.Background())
	if err != nil {
		t.Fatalf("sync failed: %v", err)
	}

	// After finalization, only the new key should remain
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	lines := nonEmptyLines(string(data))
	if len(lines) != 1 {
		t.Fatalf("expected 1 key after finalization, got %d: %v", len(lines), lines)
	}
	if lines[0] != newKey {
		t.Errorf("expected new key after finalization, got: %s", lines[0])
	}

	// Rotation state should be cleared
	rs2 := NewRotationState(statePath)
	if err := rs2.Load(); err != nil {
		t.Fatalf("load state: %v", err)
	}
	if rs2.HasPending() {
		t.Error("expected no pending rotation after finalization")
	}
}

func TestSyncer_RunLoop_StopsOnCancel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"publicKey":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIloop","fingerprint":"SHA256:fp","version":1}`)
	}))
	defer server.Close()

	dir := t.TempDir()

	s := NewSyncer(Config{
		SaaSURL:       server.URL,
		Token:         "test",
		AnonKey:       "anon",
		CAKeyPath:     filepath.Join(dir, "tb_ca.pub"),
		StatePath:     filepath.Join(dir, "rotation.json"),
		OverlapWindow: 24 * time.Hour,
		SyncInterval:  100 * time.Millisecond,
		RestartSSHD:   false,
	}, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(done)
	}()

	// Let it run a couple cycles
	time.Sleep(350 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Clean shutdown
	case <-time.After(5 * time.Second):
		t.Fatal("syncer did not stop after cancel")
	}
}

// nonEmptyLines is defined in casync.go — same package, no redeclaration needed.
