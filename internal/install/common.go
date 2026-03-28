package install

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultConfigDir is the base config directory.
	DefaultConfigDir = "/etc/tb-manage"
	// DefaultConfigFile is the config file path.
	DefaultConfigFile = "/etc/tb-manage/config.yaml"
	// ServiceName is the service name for systemd/launchd.
	ServiceName = "tb-manage"
)

// InstallConfig holds the parameters for installation.
type InstallConfig struct {
	Token    string
	URL      string
	Profile  string
	Identity string
}

// ServiceStatus holds the current state of the installed service.
type ServiceStatus struct {
	Installed  bool
	Running    bool
	BinaryPath string
	ConfigPath string
	Platform   string
}

// BinaryPath returns the absolute path of the currently running binary.
func BinaryPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve executable path: %w", err)
	}
	return filepath.EvalSymlinks(exe)
}

// WriteConfig writes the config file to the default location.
func WriteConfig(cfg InstallConfig) error {
	if err := os.MkdirAll(DefaultConfigDir, 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data := map[string]interface{}{
		"url":     cfg.URL,
		"profile": cfg.Profile,
	}
	if cfg.Token != "" {
		data["token"] = cfg.Token
	}
	if cfg.Identity != "" {
		data["identity"] = cfg.Identity
	}

	out, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(DefaultConfigFile, out, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	return nil
}

// RemoveConfig removes the config directory.
func RemoveConfig() error {
	return os.RemoveAll(DefaultConfigDir)
}

// ConfigExists checks if the config file exists.
func ConfigExists() bool {
	_, err := os.Stat(DefaultConfigFile)
	return err == nil
}

// Install installs the service for the current platform.
func Install(cfg InstallConfig) error {
	binPath, err := BinaryPath()
	if err != nil {
		return err
	}

	if err := WriteConfig(cfg); err != nil {
		return err
	}

	switch runtime.GOOS {
	case "linux":
		return installSystemd(binPath)
	case "darwin":
		return installLaunchd(binPath)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// Uninstall removes the service. If purge is true, also removes config.
func Uninstall(purge bool) error {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = uninstallSystemd()
	case "darwin":
		err = uninstallLaunchd()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	if err != nil {
		return err
	}

	if purge {
		return RemoveConfig()
	}
	return nil
}

// Status returns the current service status.
func Status() ServiceStatus {
	s := ServiceStatus{
		Platform:   runtime.GOOS,
		ConfigPath: DefaultConfigFile,
	}

	if binPath, err := BinaryPath(); err == nil {
		s.BinaryPath = binPath
	}

	s.Installed = ConfigExists()

	switch runtime.GOOS {
	case "linux":
		s.Running = isSystemdRunning()
	case "darwin":
		s.Running = isLaunchdRunning()
	}

	return s
}

// runCommand runs a command and returns any error.
func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
