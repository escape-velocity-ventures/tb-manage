package config

import (
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// SessionGCConfig holds garbage collection settings for tmux sessions.
type SessionGCConfig struct {
	StaleTimeout  time.Duration `yaml:"stale_timeout"`   // default: 30m
	DeadReapDelay time.Duration `yaml:"dead_reap_delay"` // default: 5s
	Interval      time.Duration `yaml:"interval"`        // default: 60s
	Enabled       *bool         `yaml:"enabled"`         // default: true
}

// ServiceConfig describes a long-running local service supervised via tmux.
type ServiceConfig struct {
	Name        string            `yaml:"name"`
	Command     string            `yaml:"command"`
	WorkDir     string            `yaml:"work_dir"`
	Env         map[string]string `yaml:"env"`
	HealthURL   string            `yaml:"health_url"`
	AutoRestart bool              `yaml:"auto_restart"`
	Enabled     bool              `yaml:"enabled"`
}

// Config holds all tb-manage configuration.
type Config struct {
	Token             string        `yaml:"token"`
	URL               string        `yaml:"url"`
	Gateway           string        `yaml:"gateway"`
	Identity          string        `yaml:"identity"` // "token" or "ssh-host-key"
	AnonKey           string        `yaml:"anon_key"`
	Profile           string        `yaml:"profile"`
	ScanInterval      time.Duration `yaml:"scan_interval"`
	LogLevel          string        `yaml:"log_level"`
	Permissions       []string      `yaml:"permissions"`        // e.g., ["terminal", "scan"]
	ExcludeNamespaces []string      `yaml:"exclude_namespaces"` // namespaces to skip during k8s scan
	TokenInURLFallback bool          `yaml:"token_in_url_fallback"` // DEPRECATED: also send token as query param (default true for migration)
	SessionGC         SessionGCConfig `yaml:"session_gc"`
	Services          []ServiceConfig `yaml:"services"`           // long-running services to supervise via tmux
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Profile:      "standard",
		ScanInterval: 5 * time.Minute,
		TokenInURLFallback: true,
		LogLevel:     "info",
		Permissions:  []string{"scan"},
	}
}

// Load reads a YAML config file and overlays environment variables.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, err
			}
			// File doesn't exist, use defaults
		} else {
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, err
			}
		}
	}

	// Environment variable overrides
	if v := os.Getenv("TB_TOKEN"); v != "" {
		cfg.Token = v
	}
	if v := os.Getenv("TB_URL"); v != "" {
		cfg.URL = v
	}
	if v := os.Getenv("TB_PROFILE"); v != "" {
		cfg.Profile = v
	}
	if v := os.Getenv("TB_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := os.Getenv("EXCLUDE_NAMESPACES"); v != "" {
		var ns []string
		for _, s := range strings.Split(v, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				ns = append(ns, s)
			}
		}
		cfg.ExcludeNamespaces = ns
	}

	return cfg, nil
}
