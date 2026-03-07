package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"k8s.io/client-go/tools/clientcmd"
)

// ServicesScanner detects platforms, services, ports, and dev tools.
type ServicesScanner struct{}

// NewServicesScanner creates a new ServicesScanner.
func NewServicesScanner() *ServicesScanner {
	return &ServicesScanner{}
}

func (s *ServicesScanner) Name() string       { return "services" }
func (s *ServicesScanner) Platforms() []string { return nil }

func (s *ServicesScanner) Scan(ctx context.Context, runner CommandRunner) (json.RawMessage, error) {
	info := ServicesInfo{}

	// Platform detection (OS-specific)
	info.Platforms = detectPlatforms(ctx, runner)

	// System services (OS-specific)
	info.Services = listServices(ctx, runner)

	// Listening ports (OS-specific)
	info.ListeningPorts = listListeningPorts(ctx, runner)

	// Kubeconfig contexts (cross-platform)
	info.KubeContexts = loadKubeContexts()

	// Dev tools (cross-platform)
	info.DevTools = detectDevTools(ctx, runner)

	// Kubelet running check (cross-platform)
	// k3s embeds kubelet in a single binary — no separate "kubelet" process
	if _, err := runner.Run(ctx, "pgrep kubelet"); err == nil {
		info.KubeletRunning = true
	} else if _, err := runner.Run(ctx, "pgrep k3s"); err == nil {
		info.KubeletRunning = true
	} else if _, err := runner.Run(ctx, "pgrep k0s"); err == nil {
		info.KubeletRunning = true
	}

	return json.Marshal(info)
}

// loadKubeContexts reads kubeconfig and returns all contexts.
// Checks KUBECONFIG, ~/.kube/config, and /etc/rancher/k3s/k3s.yaml (k3s default).
func loadKubeContexts() []KubeContext {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
	}

	config, err := clientcmd.LoadFromFile(kubeconfig)
	if err != nil {
		// Try k3s default location
		config, err = clientcmd.LoadFromFile("/etc/rancher/k3s/k3s.yaml")
		if err != nil {
			return nil
		}
	}

	var contexts []KubeContext
	for name, ctx := range config.Contexts {
		contexts = append(contexts, KubeContext{
			Name:      name,
			Cluster:   ctx.Cluster,
			User:      ctx.AuthInfo,
			Namespace: ctx.Namespace,
			IsCurrent: name == config.CurrentContext,
		})
	}
	return contexts
}

// detectDevTools checks for common development tools.
func detectDevTools(ctx context.Context, runner CommandRunner) []DevTool {
	tools := []struct {
		name       string
		versionCmd string
	}{
		{"go", "go version"},
		{"node", "node --version"},
		{"python3", "python3 --version"},
		{"bun", "bun --version"},
		{"rustc", "rustc --version"},
		{"java", "java -version 2>&1"},
		{"terraform", "terraform version -json"},
		{"helm", "helm version --short"},
		{"kubectl", "kubectl version --client --short 2>/dev/null || kubectl version --client 2>&1"},
	}

	var found []DevTool
	for _, tool := range tools {
		pathOut, err := runner.Run(ctx, "command -v "+tool.name)
		if err != nil {
			continue
		}
		dt := DevTool{
			Name: tool.name,
			Path: trimOutput(pathOut),
		}
		if verOut, err := runner.Run(ctx, tool.versionCmd); err == nil {
			dt.Version = parseVersionString(tool.name, trimOutput(verOut))
		}
		found = append(found, dt)
	}
	return found
}

// parseVersionString extracts a clean version from tool-specific output.
func parseVersionString(tool, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	switch tool {
	case "go":
		// "go version go1.22.0 darwin/arm64" -> "1.22.0"
		if strings.HasPrefix(raw, "go version go") {
			parts := strings.Fields(raw)
			if len(parts) >= 3 {
				return strings.TrimPrefix(parts[2], "go")
			}
		}
	case "node", "bun":
		// "v20.11.0" -> "20.11.0"
		return strings.TrimPrefix(raw, "v")
	case "python3":
		// "Python 3.12.0" -> "3.12.0"
		return strings.TrimPrefix(raw, "Python ")
	case "rustc":
		// "rustc 1.75.0 (82e1608df 2023-12-21)" -> "1.75.0"
		parts := strings.Fields(raw)
		if len(parts) >= 2 {
			return parts[1]
		}
	case "helm":
		// "v3.14.0+g3fc9f4b" -> "3.14.0"
		v := strings.TrimPrefix(raw, "v")
		if idx := strings.Index(v, "+"); idx > 0 {
			return v[:idx]
		}
		return v
	case "terraform":
		// JSON output: {"terraform_version":"1.7.0",...}
		var tfVer struct {
			Version string `json:"terraform_version"`
		}
		if json.Unmarshal([]byte(raw), &tfVer) == nil && tfVer.Version != "" {
			return tfVer.Version
		}
	}

	// Fallback: return first line, truncated
	if idx := strings.IndexByte(raw, '\n'); idx > 0 {
		raw = raw[:idx]
	}
	if len(raw) > 60 {
		raw = raw[:60]
	}
	return raw
}

// checkBinaryExists returns true if the binary is in PATH.
func checkBinaryExists(ctx context.Context, runner CommandRunner, name string) bool {
	_, err := runner.Run(ctx, "command -v "+name)
	return err == nil
}

// getBinaryVersion runs "name --version" and returns first line.
func getBinaryVersion(ctx context.Context, runner CommandRunner, name string) string {
	out, err := runner.Run(ctx, name+" --version 2>/dev/null")
	if err != nil {
		return ""
	}
	v := trimOutput(out)
	if idx := strings.IndexByte(v, '\n'); idx > 0 {
		v = v[:idx]
	}
	return v
}

// checkProcessRunning returns true if any process with the given name is running.
func checkProcessRunning(ctx context.Context, runner CommandRunner, process string) bool {
	_, err := runner.Run(ctx, "pgrep -x "+process+" >/dev/null 2>&1")
	return err == nil
}

