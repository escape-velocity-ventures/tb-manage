// Package auth provides SSH host key-based identity for tb-manage.
// The host's SSH ed25519 key serves as its SaaS identity - no tokens needed.
package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// DefaultHostKeyPath is the standard SSH host key location.
const DefaultHostKeyPath = "/etc/ssh/ssh_host_ed25519_key"

// HostIdentity holds the SSH host key used for SaaS authentication.
// The private key is unexported to prevent direct access — use SignRequest.
type HostIdentity struct {
	privateKey   ed25519.PrivateKey
	PublicKey    ed25519.PublicKey
	Fingerprint  string // SHA256:base64...
	PublicKeySSH string // "ssh-ed25519 AAAA..." for registration
}

// LoadHostKey reads and parses the SSH host ed25519 private key.
func LoadHostKey(path string) (*HostIdentity, error) {
	if path == "" {
		path = DefaultHostKeyPath
	}

	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read host key %s: %w (is tb-manage running as root?)", path, err)
	}

	rawKey, err := ssh.ParseRawPrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse host key: %w", err)
	}

	edKey, ok := rawKey.(*ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("host key is not ed25519 (got %T)", rawKey)
	}

	pubKey := edKey.Public().(ed25519.PublicKey)
	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("convert to SSH public key: %w", err)
	}

	return &HostIdentity{
		privateKey:   *edKey,
		PublicKey:    pubKey,
		Fingerprint:  ssh.FingerprintSHA256(sshPub),
		PublicKeySSH: string(ssh.MarshalAuthorizedKey(sshPub)),
	}, nil
}

// SignRequest signs a request body with the host's private key.
func (h *HostIdentity) SignRequest(body []byte) string {
	sig := ed25519.Sign(h.privateKey, body)
	return base64.StdEncoding.EncodeToString(sig)
}
