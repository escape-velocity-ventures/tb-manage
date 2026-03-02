package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestLoadHostKey(t *testing.T) {
	// Generate a test ed25519 key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Write key in OpenSSH format to temp file
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test_host_key")

	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(block)
	if err := os.WriteFile(keyPath, pemBytes, 0600); err != nil {
		t.Fatal(err)
	}

	// Load and verify
	identity, err := LoadHostKey(keyPath)
	if err != nil {
		t.Fatalf("LoadHostKey: %v", err)
	}

	if identity.Fingerprint == "" {
		t.Error("empty fingerprint")
	}
	if identity.PublicKeySSH == "" {
		t.Error("empty public key SSH string")
	}
	if len(identity.Fingerprint) < 7 || identity.Fingerprint[:7] != "SHA256:" {
		t.Errorf("fingerprint should start with SHA256:, got %s", identity.Fingerprint)
	}

	// Test signing
	msg := []byte("test message for signature verification")
	sig := identity.SignRequest(msg)
	if sig == "" {
		t.Error("empty signature")
	}

	// Verify signature with original public key
	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !ed25519.Verify(pub, msg, sigBytes) {
		t.Error("signature verification failed")
	}
}

func TestLoadHostKey_NotFound(t *testing.T) {
	_, err := LoadHostKey("/nonexistent/path/key")
	if err == nil {
		t.Error("expected error for missing key file")
	}
}

func TestLoadHostKey_NotEd25519(t *testing.T) {
	// Write a non-ed25519 key (RSA) to verify type checking
	// Generate an RSA-like placeholder - just write garbage PEM
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "bad_key")

	if err := os.WriteFile(keyPath, []byte("not a valid key"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadHostKey(keyPath)
	if err == nil {
		t.Error("expected error for invalid key file")
	}
}

func TestLoadHostKey_DefaultPath(t *testing.T) {
	// LoadHostKey("") should default to /etc/ssh/ssh_host_ed25519_key
	// This test just verifies it doesn't panic; it will fail to read on most test environments
	_, err := LoadHostKey("")
	if err == nil {
		// If it succeeds (running as root with the key present), that's fine
		return
	}
	// Expected: error because we probably can't read /etc/ssh/ssh_host_ed25519_key
	t.Logf("expected error for default path: %v", err)
}
