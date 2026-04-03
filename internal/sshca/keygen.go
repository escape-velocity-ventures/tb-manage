package sshca

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// EphemeralKeypair holds a temporary SSH keypair used for a single session.
type EphemeralKeypair struct {
	// Dir is the temporary directory containing the key files
	Dir string
	// PrivateKeyPath is the path to the private key file
	PrivateKeyPath string
	// PublicKeyPath is the path to the public key file
	PublicKeyPath string
	// CertPath is where the signed certificate will be written
	CertPath string
	// PublicKeyString is the SSH public key in authorized_keys format
	PublicKeyString string
}

// GenerateEphemeralKeypair creates a temporary ed25519 keypair.
// The caller must call Cleanup() when done.
func GenerateEphemeralKeypair() (*EphemeralKeypair, error) {
	dir, err := os.MkdirTemp("", "tb-ssh-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	// Generate ed25519 keypair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}

	// Marshal private key to OpenSSH format
	privKeyBytes, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("marshal private key: %w", err)
	}

	privKeyPath := filepath.Join(dir, "tb_ssh_key")
	if err := os.WriteFile(privKeyPath, pem.EncodeToMemory(privKeyBytes), 0600); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("write private key: %w", err)
	}

	// Marshal public key
	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("convert public key: %w", err)
	}

	pubKeyStr := string(ssh.MarshalAuthorizedKey(sshPub))
	pubKeyPath := filepath.Join(dir, "tb_ssh_key.pub")
	if err := os.WriteFile(pubKeyPath, []byte(pubKeyStr), 0644); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("write public key: %w", err)
	}

	return &EphemeralKeypair{
		Dir:             dir,
		PrivateKeyPath:  privKeyPath,
		PublicKeyPath:   pubKeyPath,
		CertPath:        filepath.Join(dir, "tb_ssh_key-cert.pub"),
		PublicKeyString: pubKeyStr,
	}, nil
}

// WriteCert writes the signed certificate to the cert path.
func (kp *EphemeralKeypair) WriteCert(certPEM string) error {
	if err := os.WriteFile(kp.CertPath, []byte(certPEM+"\n"), 0644); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	return nil
}

// Cleanup removes the temporary directory and all key material.
func (kp *EphemeralKeypair) Cleanup() {
	if kp.Dir != "" {
		os.RemoveAll(kp.Dir)
	}
}
