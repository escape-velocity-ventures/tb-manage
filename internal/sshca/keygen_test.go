package sshca

import (
	"os"
	"strings"
	"testing"
)

func TestGenerateEphemeralKeypair(t *testing.T) {
	kp, err := GenerateEphemeralKeypair()
	if err != nil {
		t.Fatal(err)
	}
	defer kp.Cleanup()

	// Check that all paths exist
	if _, err := os.Stat(kp.PrivateKeyPath); err != nil {
		t.Errorf("private key not found: %v", err)
	}
	if _, err := os.Stat(kp.PublicKeyPath); err != nil {
		t.Errorf("public key not found: %v", err)
	}

	// Check private key permissions
	info, err := os.Stat(kp.PrivateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("private key permissions = %o, want 0600", info.Mode().Perm())
	}

	// Check public key format
	if !strings.HasPrefix(kp.PublicKeyString, "ssh-ed25519 ") {
		t.Errorf("public key doesn't start with ssh-ed25519: %q", kp.PublicKeyString[:30])
	}

	// Check cert path is set
	if !strings.HasSuffix(kp.CertPath, "-cert.pub") {
		t.Errorf("cert path doesn't end with -cert.pub: %q", kp.CertPath)
	}
}

func TestEphemeralKeypair_WriteCert(t *testing.T) {
	kp, err := GenerateEphemeralKeypair()
	if err != nil {
		t.Fatal(err)
	}
	defer kp.Cleanup()

	certPEM := "ssh-ed25519-cert-v01@openssh.com AAAA..."
	if err := kp.WriteCert(certPEM); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(kp.CertPath)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(string(data), certPEM) {
		t.Errorf("cert file content mismatch")
	}
}

func TestEphemeralKeypair_Cleanup(t *testing.T) {
	kp, err := GenerateEphemeralKeypair()
	if err != nil {
		t.Fatal(err)
	}

	dir := kp.Dir
	kp.Cleanup()

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("temp dir not cleaned up: %s", dir)
	}
}
