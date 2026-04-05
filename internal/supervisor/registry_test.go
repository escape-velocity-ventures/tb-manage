package supervisor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultRegistry_HasAllAgents(t *testing.T) {
	r := DefaultRegistry()
	expected := []string{"tinkerbelle", "cybill", "aurelia", "blades"}
	for _, name := range expected {
		cfg, ok := r.Get(name)
		if !ok {
			t.Errorf("default registry missing agent %q", name)
			continue
		}
		if cfg.Skill == "" {
			t.Errorf("agent %q has empty skill", name)
		}
		if cfg.Channel == "" {
			t.Errorf("agent %q has empty channel", name)
		}
	}
}

func TestDefaultRegistry_TinkerbelleEnv(t *testing.T) {
	r := DefaultRegistry()
	cfg, _ := r.Get("tinkerbelle")
	if cfg.Env["ONCALL_SEVERITY"] != "all" {
		t.Errorf("expected ONCALL_SEVERITY=all, got %q", cfg.Env["ONCALL_SEVERITY"])
	}
}

func TestRegistry_GetNotFound(t *testing.T) {
	r := DefaultRegistry()
	_, ok := r.Get("nonexistent")
	if ok {
		t.Error("expected agent not found")
	}
}

func TestRegistry_Names(t *testing.T) {
	r := DefaultRegistry()
	names := r.Names()
	if len(names) != 4 {
		t.Errorf("expected 4 agents, got %d", len(names))
	}
}

func TestBuildCommand_WithChannel(t *testing.T) {
	r := DefaultRegistry()
	cmd, err := r.BuildCommand("cybill")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := "claude --dangerously-load-development-channels server:cybill-channel"
	if cmd != expected {
		t.Errorf("expected %q, got %q", expected, cmd)
	}
}

func TestBuildCommand_NotFound(t *testing.T) {
	r := DefaultRegistry()
	_, err := r.BuildCommand("nonexistent")
	if err == nil {
		t.Fatal("expected error for non-existent agent")
	}
}

func TestLoadRegistry_FromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agents.yaml")
	content := `agents:
  testbot:
    skill: testing
    channel: test-channel
    env:
      DEBUG: "true"
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	r, err := LoadRegistry(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfg, ok := r.Get("testbot")
	if !ok {
		t.Fatal("expected testbot agent")
	}
	if cfg.Skill != "testing" {
		t.Errorf("expected skill testing, got %q", cfg.Skill)
	}
	if cfg.Channel != "test-channel" {
		t.Errorf("expected channel test-channel, got %q", cfg.Channel)
	}
	if cfg.Env["DEBUG"] != "true" {
		t.Errorf("expected DEBUG=true, got %q", cfg.Env["DEBUG"])
	}
}

func TestLoadRegistry_FileNotFound(t *testing.T) {
	r, err := LoadRegistry("/nonexistent/agents.yaml")
	if err != nil {
		t.Fatalf("expected fallback to defaults, got error: %v", err)
	}
	// Should return defaults
	_, ok := r.Get("tinkerbelle")
	if !ok {
		t.Error("expected default tinkerbelle agent")
	}
}

func TestLoadRegistry_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agents.yaml")
	if err := os.WriteFile(path, []byte(":::invalid:::"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadRegistry(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadRegistry_EmptyAgents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agents.yaml")
	content := `agents: {}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadRegistry(path)
	if err == nil {
		t.Fatal("expected error for empty agents")
	}
}
