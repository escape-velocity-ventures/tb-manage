package supervisor

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// AgentConfig describes a single Claude Code agent.
type AgentConfig struct {
	Skill   string            `yaml:"skill"`
	Channel string            `yaml:"channel"`
	Env     map[string]string `yaml:"env,omitempty"`
}

// RegistryConfig is the top-level agents.yaml structure.
type RegistryConfig struct {
	Agents map[string]AgentConfig `yaml:"agents"`
}

// Registry holds the agent configuration registry.
type Registry struct {
	agents map[string]AgentConfig
}

// DefaultRegistry returns a registry with built-in agent defaults.
func DefaultRegistry() *Registry {
	return &Registry{
		agents: map[string]AgentConfig{
			"tinkerbelle": {
				Skill:   "oncall",
				Channel: "oncall-slack",
				Env:     map[string]string{"ONCALL_SEVERITY": "all"},
			},
			"cybill": {
				Skill:   "review",
				Channel: "cybill-channel",
			},
			"aurelia": {
				Skill:   "core",
				Channel: "aurelia-channel",
			},
			"blades": {
				Skill:   "orchestrator",
				Channel: "blades-channel",
			},
		},
	}
}

// LoadRegistry loads agent configuration from a YAML file.
// Falls back to defaults if the file doesn't exist.
func LoadRegistry(path string) (*Registry, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return DefaultRegistry(), nil
		}
		path = filepath.Join(home, ".config", "tb-manage", "agents.yaml")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultRegistry(), nil
		}
		return nil, fmt.Errorf("read registry %s: %w", path, err)
	}

	var cfg RegistryConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse registry %s: %w", path, err)
	}

	if len(cfg.Agents) == 0 {
		return nil, fmt.Errorf("registry %s: no agents defined", path)
	}

	return &Registry{agents: cfg.Agents}, nil
}

// Get returns the config for a named agent.
func (r *Registry) Get(name string) (AgentConfig, bool) {
	cfg, ok := r.agents[name]
	return cfg, ok
}

// Names returns all registered agent names.
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.agents))
	for name := range r.agents {
		names = append(names, name)
	}
	return names
}

// BuildCommand constructs the claude CLI command for an agent.
func (r *Registry) BuildCommand(name string) (string, error) {
	cfg, ok := r.agents[name]
	if !ok {
		return "", fmt.Errorf("agent %q not found in registry", name)
	}

	if cfg.Channel != "" {
		return fmt.Sprintf("claude --dangerously-load-development-channels server:%s", cfg.Channel), nil
	}

	// Fallback: just run claude
	return "claude", nil
}
