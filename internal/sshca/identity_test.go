package sshca

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadIdentity_FromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.yaml")
	content := `user: test@example.com
org_id: org-123
saas_url: https://test.supabase.co
anon_key: test-anon-key
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	id, err := LoadIdentity(path)
	if err != nil {
		t.Fatal(err)
	}

	if id.User != "test@example.com" {
		t.Errorf("User = %q, want %q", id.User, "test@example.com")
	}
	if id.OrgID != "org-123" {
		t.Errorf("OrgID = %q, want %q", id.OrgID, "org-123")
	}
	if id.SaaSURL != "https://test.supabase.co" {
		t.Errorf("SaaSURL = %q, want %q", id.SaaSURL, "https://test.supabase.co")
	}
	if id.AnonKey != "test-anon-key" {
		t.Errorf("AnonKey = %q, want %q", id.AnonKey, "test-anon-key")
	}
}

func TestLoadIdentity_EnvOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.yaml")
	content := `user: file@example.com
saas_url: https://file.supabase.co
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("TB_SAAS_URL", "https://env.supabase.co")
	t.Setenv("TB_USER", "env@example.com")

	id, err := LoadIdentity(path)
	if err != nil {
		t.Fatal(err)
	}

	if id.User != "env@example.com" {
		t.Errorf("User = %q, want env override %q", id.User, "env@example.com")
	}
	if id.SaaSURL != "https://env.supabase.co" {
		t.Errorf("SaaSURL = %q, want env override %q", id.SaaSURL, "https://env.supabase.co")
	}
}

func TestLoadIdentity_MissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.yaml")

	t.Setenv("TB_SAAS_URL", "https://env.supabase.co")
	t.Setenv("TB_USER", "env@example.com")

	id, err := LoadIdentity(path)
	if err != nil {
		t.Fatal(err)
	}

	if id.User != "env@example.com" {
		t.Errorf("User = %q, want %q", id.User, "env@example.com")
	}
	if id.SaaSURL != "https://env.supabase.co" {
		t.Errorf("SaaSURL = %q, want %q", id.SaaSURL, "https://env.supabase.co")
	}
}

func TestIdentity_Validate(t *testing.T) {
	tests := []struct {
		name    string
		id      Identity
		wantErr bool
	}{
		{
			name:    "valid",
			id:      Identity{User: "test@example.com", SaaSURL: "https://test.supabase.co"},
			wantErr: false,
		},
		{
			name:    "missing user",
			id:      Identity{SaaSURL: "https://test.supabase.co"},
			wantErr: true,
		},
		{
			name:    "missing saas_url",
			id:      Identity{User: "test@example.com"},
			wantErr: true,
		},
		{
			name:    "empty",
			id:      Identity{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.id.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIdentity_SaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.yaml")

	original := &Identity{
		User:    "test@example.com",
		OrgID:   "org-456",
		SaaSURL: "https://test.supabase.co",
		AnonKey: "my-anon-key",
	}

	if err := original.Save(path); err != nil {
		t.Fatal(err)
	}

	// Clear env to avoid interference
	t.Setenv("TB_SAAS_URL", "")
	t.Setenv("TB_USER", "")
	t.Setenv("TB_ANON_KEY", "")
	t.Setenv("TB_ORG_ID", "")

	loaded, err := LoadIdentity(path)
	if err != nil {
		t.Fatal(err)
	}

	if loaded.User != original.User {
		t.Errorf("User = %q, want %q", loaded.User, original.User)
	}
	if loaded.OrgID != original.OrgID {
		t.Errorf("OrgID = %q, want %q", loaded.OrgID, original.OrgID)
	}
	if loaded.SaaSURL != original.SaaSURL {
		t.Errorf("SaaSURL = %q, want %q", loaded.SaaSURL, original.SaaSURL)
	}
	if loaded.AnonKey != original.AnonKey {
		t.Errorf("AnonKey = %q, want %q", loaded.AnonKey, original.AnonKey)
	}

	// Check file permissions
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("file permissions = %o, want 0600", info.Mode().Perm())
	}
}

func TestEnsureIdentityDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	if err := EnsureIdentityDir(); err != nil {
		t.Fatal(err)
	}

	// Check directories exist
	tbDir := filepath.Join(dir, ".tb-manage")
	if info, err := os.Stat(tbDir); err != nil {
		t.Errorf("~/.tb-manage not created: %v", err)
	} else if !info.IsDir() {
		t.Error("~/.tb-manage is not a directory")
	}

	certsDir := filepath.Join(tbDir, "certs")
	if info, err := os.Stat(certsDir); err != nil {
		t.Errorf("~/.tb-manage/certs not created: %v", err)
	} else if !info.IsDir() {
		t.Error("~/.tb-manage/certs is not a directory")
	}
}
