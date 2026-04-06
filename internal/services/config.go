package services

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
