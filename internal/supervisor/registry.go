package supervisor

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// safeIdentifier validates names and channels against injection.
var safeIdentifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

// shellQuote escapes a value for safe use in a shell string.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

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

// BuildCommand constructs the claude CLI command for an agent (without env vars).
func (r *Registry) BuildCommand(name string) (string, error) {
	cfg, ok := r.agents[name]
	if !ok {
		return "", fmt.Errorf("agent %q not found in registry", name)
	}

	if cfg.Channel != "" {
		// Validate channel name to prevent shell injection
		if !safeIdentifier.MatchString(cfg.Channel) {
			return "", fmt.Errorf("agent %q: channel name %q contains unsafe characters", name, cfg.Channel)
		}
		return fmt.Sprintf("claude --dangerously-load-development-channels server:%s", cfg.Channel), nil
	}

	// Fallback: just run claude
	return "claude", nil
}

// BuildFullCommand constructs the complete command including env var prefix.
// Used by both CLI start and health checker restart to ensure consistent behavior.
func (r *Registry) BuildFullCommand(name string) (string, error) {
	command, err := r.BuildCommand(name)
	if err != nil {
		return "", err
	}

	cfg, ok := r.agents[name]
	if !ok {
		return command, nil
	}

	if len(cfg.Env) > 0 {
		var envPrefix []string
		for k, v := range cfg.Env {
			// Validate key, shell-quote value to prevent injection
			if !safeIdentifier.MatchString(k) {
				return "", fmt.Errorf("agent %q: env key %q contains unsafe characters", name, k)
			}
			envPrefix = append(envPrefix, fmt.Sprintf("%s=%s", k, shellQuote(v)))
		}
		sort.Strings(envPrefix)
		command = strings.Join(envPrefix, " ") + " " + command
	}

	return command, nil
}
