package sshca

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// CertInfo holds metadata about a stored SSH certificate.
type CertInfo struct {
	// Path is the filesystem path to the cert file
	Path string
	// KeyIdentity from the certificate
	KeyIdentity string
	// Principals listed in the certificate
	Principals []string
	// ValidBefore is the certificate expiry time
	ValidBefore time.Time
	// ValidAfter is the certificate start time
	ValidAfter time.Time
	// Expired is true if the certificate is past its ValidBefore
	Expired bool
	// Remaining is the time until expiry (negative if expired)
	Remaining time.Duration
}

// ListCerts scans ~/.tb-manage/certs/ for SSH certificates and returns their metadata.
func ListCerts() ([]CertInfo, error) {
	certsDir, err := CertsDir()
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(certsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read certs dir: %w", err)
	}

	var certs []CertInfo
	now := time.Now()

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), "-cert.pub") {
			continue
		}

		path := filepath.Join(certsDir, entry.Name())
		info, err := parseCertFile(path, now)
		if err != nil {
			// Skip unparseable files
			continue
		}
		certs = append(certs, *info)
	}

	return certs, nil
}

// CleanExpiredCerts removes expired certificates from ~/.tb-manage/certs/.
func CleanExpiredCerts() (int, error) {
	certs, err := ListCerts()
	if err != nil {
		return 0, err
	}

	removed := 0
	for _, cert := range certs {
		if cert.Expired {
			// Remove cert file
			os.Remove(cert.Path)
			// Remove corresponding private key if it exists
			keyPath := strings.TrimSuffix(cert.Path, "-cert.pub")
			os.Remove(keyPath)
			// Remove corresponding public key if it exists
			os.Remove(keyPath + ".pub")
			removed++
		}
	}

	return removed, nil
}

// StoreCert saves a certificate and its associated keypair to ~/.tb-manage/certs/.
// The filename is derived from the agent name and a timestamp.
func StoreCert(agentName string, kp *EphemeralKeypair, certPEM string) (string, error) {
	certsDir, err := CertsDir()
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(certsDir, 0700); err != nil {
		return "", fmt.Errorf("create certs dir: %w", err)
	}

	ts := time.Now().Unix()
	baseName := fmt.Sprintf("%s-%d", agentName, ts)

	// Copy private key
	privKeyData, err := os.ReadFile(kp.PrivateKeyPath)
	if err != nil {
		return "", fmt.Errorf("read private key: %w", err)
	}
	privKeyPath := filepath.Join(certsDir, baseName)
	if err := os.WriteFile(privKeyPath, privKeyData, 0600); err != nil {
		return "", fmt.Errorf("write private key: %w", err)
	}

	// Copy public key
	pubKeyPath := filepath.Join(certsDir, baseName+".pub")
	if err := os.WriteFile(pubKeyPath, []byte(kp.PublicKeyString), 0644); err != nil {
		return "", fmt.Errorf("write public key: %w", err)
	}

	// Write cert
	certPath := filepath.Join(certsDir, baseName+"-cert.pub")
	if err := os.WriteFile(certPath, []byte(certPEM+"\n"), 0644); err != nil {
		return "", fmt.Errorf("write certificate: %w", err)
	}

	return certPath, nil
}

func parseCertFile(path string, now time.Time) (*CertInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}

	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("not a certificate: %s", path)
	}

	validBefore := time.Unix(int64(cert.ValidBefore), 0)
	validAfter := time.Unix(int64(cert.ValidAfter), 0)
	// ssh.CertTimeInfinity means no expiry
	if cert.ValidBefore == ssh.CertTimeInfinity {
		validBefore = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	}

	expired := now.After(validBefore)
	remaining := time.Until(validBefore)

	return &CertInfo{
		Path:        path,
		KeyIdentity: cert.KeyId,
		Principals:  cert.ValidPrincipals,
		ValidBefore: validBefore,
		ValidAfter:  validAfter,
		Expired:     expired,
		Remaining:   remaining,
	}, nil
}
