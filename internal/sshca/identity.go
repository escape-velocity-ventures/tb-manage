// Package sshca provides SSH CA certificate operations for tb-manage.
// It wraps the TinkerBelle SaaS ssh-sign edge function, managing
// ephemeral keypairs, cert requests, and local cert storage.
package sshca

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Identity holds the local operator or agent identity used to authenticate
// with the TinkerBelle SaaS SSH CA.
type Identity struct {
	// User is the operator's email (e.g., benjamin@escape-velocity-ventures.org)
	User string `yaml:"user"`
	// OrgID is the Supabase organization UUID
	OrgID string `yaml:"org_id,omitempty"`
	// SaaSURL is the TinkerBelle SaaS base URL
	SaaSURL string `yaml:"saas_url"`
	// AnonKey is the Supabase anon key for API auth
	AnonKey string `yaml:"anon_key,omitempty"`
}

// DefaultIdentityDir returns ~/.tb-manage
func DefaultIdentityDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}
	return filepath.Join(home, ".tb-manage"), nil
}

// DefaultIdentityPath returns ~/.tb-manage/identity.yaml
func DefaultIdentityPath() (string, error) {
	dir, err := DefaultIdentityDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "identity.yaml"), nil
}

// CertsDir returns ~/.tb-manage/certs/
func CertsDir() (string, error) {
	dir, err := DefaultIdentityDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "certs"), nil
}

// LoadIdentity reads the identity config from disk.
// Environment variables override file values:
//
//	TB_SAAS_URL    -> SaaSURL
//	TB_ANON_KEY    -> AnonKey
//	TB_USER        -> User
//	TB_ORG_ID      -> OrgID
func LoadIdentity(path string) (*Identity, error) {
	if path == "" {
		var err error
		path, err = DefaultIdentityPath()
		if err != nil {
			return nil, err
		}
	}

	id := &Identity{}

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read identity %s: %w", path, err)
		}
		// File doesn't exist — rely on env vars
	} else {
		if err := yaml.Unmarshal(data, id); err != nil {
			return nil, fmt.Errorf("parse identity %s: %w", path, err)
		}
	}

	// Env var overrides
	if v := os.Getenv("TB_SAAS_URL"); v != "" {
		id.SaaSURL = v
	}
	if v := os.Getenv("TB_ANON_KEY"); v != "" {
		id.AnonKey = v
	}
	if v := os.Getenv("TB_USER"); v != "" {
		id.User = v
	}
	if v := os.Getenv("TB_ORG_ID"); v != "" {
		id.OrgID = v
	}

	return id, nil
}

// Save writes the identity config to disk, creating directories as needed.
func (id *Identity) Save(path string) error {
	if path == "" {
		var err error
		path, err = DefaultIdentityPath()
		if err != nil {
			return err
		}
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create identity dir %s: %w", dir, err)
	}

	data, err := yaml.Marshal(id)
	if err != nil {
		return fmt.Errorf("marshal identity: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write identity %s: %w", path, err)
	}

	return nil
}

// Validate checks that the identity has the minimum required fields.
func (id *Identity) Validate() error {
	if id.SaaSURL == "" {
		return fmt.Errorf("saas_url is required (set TB_SAAS_URL or configure ~/.tb-manage/identity.yaml)")
	}
	if id.User == "" {
		return fmt.Errorf("user is required (set TB_USER or configure ~/.tb-manage/identity.yaml)")
	}
	return nil
}

// EnsureIdentityDir creates ~/.tb-manage/ and ~/.tb-manage/certs/ if they don't exist.
func EnsureIdentityDir() error {
	dir, err := DefaultIdentityDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	certsDir := filepath.Join(dir, "certs")
	if err := os.MkdirAll(certsDir, 0700); err != nil {
		return fmt.Errorf("create %s: %w", certsDir, err)
	}
	return nil
}
