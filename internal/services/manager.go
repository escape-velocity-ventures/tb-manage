package services

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// svcSessionPrefix is prepended to service names for tmux session names.
	// This distinguishes service sessions from interactive terminal sessions (tb-)
	// and agent sessions.
	svcSessionPrefix = "tb-svc-"
)

// ServiceStatus reports the current state of a managed service.
type ServiceStatus struct {
	Name    string       `json:"name"`
	Running bool         `json:"running"`
	Health  HealthStatus `json:"health"`
	Uptime  string       `json:"uptime,omitempty"`
}

// TmuxBackend abstracts tmux operations for testability.
type TmuxBackend interface {
	HasSession(name string) bool
	StartSession(name, command string) error
	StopSession(name string) error
	ListSessions() []string
}

// Manager supervises long-running services in tmux sessions.
type Manager struct {
	mu       sync.Mutex
	configs  map[string]ServiceConfig
	started  map[string]time.Time // track when each service was started
	tmux     TmuxBackend
	log      *slog.Logger
}

// NewManager creates a service manager with the given configs and tmux backend.
func NewManager(configs []ServiceConfig, tmux TmuxBackend, log *slog.Logger) *Manager {
	cfgMap := make(map[string]ServiceConfig, len(configs))
	for _, c := range configs {
		cfgMap[c.Name] = c
	}
	return &Manager{
		configs: cfgMap,
		started: make(map[string]time.Time),
		tmux:    tmux,
		log:     log,
	}
}

// StartAll starts all enabled services.
func (m *Manager) StartAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []string
	for _, cfg := range m.configs {
		if !cfg.Enabled {
			m.log.Info("service disabled, skipping", "service", cfg.Name)
			continue
		}
		if err := m.startLocked(cfg); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", cfg.Name, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("failed to start services: %s", strings.Join(errs, "; "))
	}
	return nil
}

// StopAll stops all managed services.
func (m *Manager) StopAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []string
	for name := range m.configs {
		sessionName := svcSessionPrefix + name
		if m.tmux.HasSession(sessionName) {
			if err := m.tmux.StopSession(sessionName); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", name, err))
			} else {
				delete(m.started, name)
				m.log.Info("service stopped", "service", name)
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("failed to stop services: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Start starts a single service by name.
func (m *Manager) Start(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cfg, ok := m.configs[name]
	if !ok {
		return fmt.Errorf("service %q not configured", name)
	}
	return m.startLocked(cfg)
}

// Stop stops a single service by name.
func (m *Manager) Stop(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.configs[name]; !ok {
		return fmt.Errorf("service %q not configured", name)
	}

	sessionName := svcSessionPrefix + name
	if !m.tmux.HasSession(sessionName) {
		return fmt.Errorf("service %q is not running", name)
	}
	if err := m.tmux.StopSession(sessionName); err != nil {
		return fmt.Errorf("stop service %q: %w", name, err)
	}
	delete(m.started, name)
	m.log.Info("service stopped", "service", name)
	return nil
}

// Restart stops (if running) and starts a service.
func (m *Manager) Restart(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cfg, ok := m.configs[name]
	if !ok {
		return fmt.Errorf("service %q not configured", name)
	}

	sessionName := svcSessionPrefix + name
	if m.tmux.HasSession(sessionName) {
		if err := m.tmux.StopSession(sessionName); err != nil {
			return fmt.Errorf("stop service %q: %w", name, err)
		}
		delete(m.started, name)
	}

	return m.startLocked(cfg)
}

// Status returns the status of all configured services.
func (m *Manager) Status() []ServiceStatus {
	m.mu.Lock()
	defer m.mu.Unlock()

	var statuses []ServiceStatus
	for _, cfg := range m.configs {
		sessionName := svcSessionPrefix + cfg.Name
		running := m.tmux.HasSession(sessionName)

		health := HealthUnknown
		if running && cfg.HealthURL != "" {
			health = CheckHealth(cfg.HealthURL)
		}

		var uptime string
		if running {
			if startTime, ok := m.started[cfg.Name]; ok {
				uptime = time.Since(startTime).Truncate(time.Second).String()
			}
		}

		statuses = append(statuses, ServiceStatus{
			Name:    cfg.Name,
			Running: running,
			Health:  health,
			Uptime:  uptime,
		})
	}

	sort.Slice(statuses, func(i, j int) bool {
		return statuses[i].Name < statuses[j].Name
	})
	return statuses
}

// ManagedSessionIDs returns the tmux session IDs (without tb- prefix) for all
// running services. Used by the session GC to exclude service sessions from
// stale-based reaping.
func (m *Manager) ManagedSessionIDs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	var ids []string
	for name := range m.started {
		// tmux session name is "tb-svc-<name>", ID (without tb- prefix) is "svc-<name>"
		ids = append(ids, "svc-"+name)
	}
	return ids
}

// buildCommand constructs the shell command for a service, including workdir and env.
func buildCommand(cfg ServiceConfig) string {
	var parts []string

	// Prepend env vars
	if len(cfg.Env) > 0 {
		keys := make([]string, 0, len(cfg.Env))
		for k := range cfg.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("export %s=%s;", k, shellQuote(cfg.Env[k])))
		}
	}

	// Change to working directory if specified
	if cfg.WorkDir != "" {
		parts = append(parts, fmt.Sprintf("cd %s &&", shellQuote(cfg.WorkDir)))
	}

	parts = append(parts, cfg.Command)
	return strings.Join(parts, " ")
}

// shellQuote escapes a value for safe use in a shell string.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// startLocked starts a service (caller must hold m.mu).
func (m *Manager) startLocked(cfg ServiceConfig) error {
	sessionName := svcSessionPrefix + cfg.Name
	if m.tmux.HasSession(sessionName) {
		return fmt.Errorf("service %q is already running", cfg.Name)
	}

	command := buildCommand(cfg)
	if err := m.tmux.StartSession(sessionName, command); err != nil {
		return fmt.Errorf("start service %q: %w", cfg.Name, err)
	}

	m.started[cfg.Name] = time.Now()
	m.log.Info("service started", "service", cfg.Name, "session", sessionName)
	return nil
}
