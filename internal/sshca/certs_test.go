package sshca

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// generateTestCert creates a self-signed SSH certificate for testing.
func generateTestCert(t *testing.T, validAfter, validBefore time.Time, principals []string, keyID string) string {
	t.Helper()

	// Generate CA key
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}

	// Generate user key
	userPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshUserPub, err := ssh.NewPublicKey(userPub)
	if err != nil {
		t.Fatal(err)
	}

	cert := &ssh.Certificate{
		Key:             sshUserPub,
		KeyId:           keyID,
		CertType:        ssh.UserCert,
		ValidPrincipals: principals,
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
	}

	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}

	return string(ssh.MarshalAuthorizedKey(cert))
}

func TestListCerts(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	certsDir := filepath.Join(dir, ".tb-manage", "certs")
	if err := os.MkdirAll(certsDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Create a valid cert (expires in 1 hour)
	validCert := generateTestCert(t,
		time.Now().Add(-1*time.Hour),
		time.Now().Add(1*time.Hour),
		[]string{"operator"},
		"tb:admin:test:operator:12345",
	)
	if err := os.WriteFile(filepath.Join(certsDir, "test-valid-cert.pub"), []byte(validCert), 0644); err != nil {
		t.Fatal(err)
	}

	// Create an expired cert
	expiredCert := generateTestCert(t,
		time.Now().Add(-2*time.Hour),
		time.Now().Add(-1*time.Hour),
		[]string{"agent:oncall-bot"},
		"agent:oncall-bot:test@ev.org:@12345",
	)
	if err := os.WriteFile(filepath.Join(certsDir, "test-expired-cert.pub"), []byte(expiredCert), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a non-cert file (should be ignored)
	if err := os.WriteFile(filepath.Join(certsDir, "not-a-cert.txt"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	certs, err := ListCerts()
	if err != nil {
		t.Fatal(err)
	}

	if len(certs) != 2 {
		t.Fatalf("got %d certs, want 2", len(certs))
	}

	// Find the valid and expired certs
	var validFound, expiredFound bool
	for _, c := range certs {
		if c.KeyIdentity == "tb:admin:test:operator:12345" {
			validFound = true
			if c.Expired {
				t.Error("valid cert marked as expired")
			}
			if len(c.Principals) != 1 || c.Principals[0] != "operator" {
				t.Errorf("valid cert principals = %v, want [operator]", c.Principals)
			}
		}
		if c.KeyIdentity == "agent:oncall-bot:test@ev.org:@12345" {
			expiredFound = true
			if !c.Expired {
				t.Error("expired cert not marked as expired")
			}
		}
	}

	if !validFound {
		t.Error("valid cert not found")
	}
	if !expiredFound {
		t.Error("expired cert not found")
	}
}

func TestCleanExpiredCerts(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	certsDir := filepath.Join(dir, ".tb-manage", "certs")
	if err := os.MkdirAll(certsDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Create a valid cert
	validCert := generateTestCert(t,
		time.Now().Add(-1*time.Hour),
		time.Now().Add(1*time.Hour),
		[]string{"operator"},
		"valid-cert",
	)
	if err := os.WriteFile(filepath.Join(certsDir, "valid-cert.pub"), []byte(validCert), 0644); err != nil {
		t.Fatal(err)
	}

	// Create an expired cert + key + pub
	expiredCert := generateTestCert(t,
		time.Now().Add(-2*time.Hour),
		time.Now().Add(-1*time.Hour),
		[]string{"agent:expired"},
		"expired-cert",
	)
	if err := os.WriteFile(filepath.Join(certsDir, "expired-cert.pub"), []byte(expiredCert), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certsDir, "expired"), []byte("privkey"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certsDir, "expired.pub"), []byte("pubkey"), 0644); err != nil {
		t.Fatal(err)
	}

	removed, err := CleanExpiredCerts()
	if err != nil {
		t.Fatal(err)
	}

	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}

	// Valid cert should still exist
	if _, err := os.Stat(filepath.Join(certsDir, "valid-cert.pub")); err != nil {
		t.Error("valid cert was removed")
	}

	// Expired cert and associated files should be gone
	if _, err := os.Stat(filepath.Join(certsDir, "expired-cert.pub")); !os.IsNotExist(err) {
		t.Error("expired cert was not removed")
	}
	if _, err := os.Stat(filepath.Join(certsDir, "expired")); !os.IsNotExist(err) {
		t.Error("expired private key was not removed")
	}
	if _, err := os.Stat(filepath.Join(certsDir, "expired.pub")); !os.IsNotExist(err) {
		t.Error("expired public key was not removed")
	}
}

func TestStoreCert(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	kp, err := GenerateEphemeralKeypair()
	if err != nil {
		t.Fatal(err)
	}
	defer kp.Cleanup()

	certPEM := generateTestCert(t,
		time.Now().Add(-1*time.Minute),
		time.Now().Add(1*time.Hour),
		[]string{"agent:test-bot"},
		"agent:test-bot:test@ev.org:@12345",
	)

	certPath, err := StoreCert("test-bot", kp, certPEM)
	if err != nil {
		t.Fatal(err)
	}

	// Check cert file exists
	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("cert file not found: %v", err)
	}

	// Check private key exists
	privKeyPath := certPath[:len(certPath)-len("-cert.pub")]
	if _, err := os.Stat(privKeyPath); err != nil {
		t.Errorf("private key not found: %v", err)
	}

	// Check private key permissions
	info, err := os.Stat(privKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("private key permissions = %o, want 0600", info.Mode().Perm())
	}
}

func TestListCerts_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	// Don't create the certs dir
	certs, err := ListCerts()
	if err != nil {
		t.Fatal(err)
	}

	if len(certs) != 0 {
		t.Errorf("got %d certs, want 0", len(certs))
	}
}
