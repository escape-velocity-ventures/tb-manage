//go:build darwin

package scanner

import (
	"context"
	"strconv"
	"strings"
)

// detectPlatforms checks for container and VM platforms on macOS.
func detectPlatforms(ctx context.Context, runner CommandRunner) []PlatformInfo {
	var platforms []PlatformInfo

	// Docker Desktop
	if checkBinaryExists(ctx, runner, "docker") {
		p := PlatformInfo{
			Name:        "docker",
			DisplayName: "Docker Desktop",
			Type:        "container",
			Desktop:     true,
		}
		if out, err := runner.Run(ctx, "docker version --format '{{.Server.Version}}' 2>/dev/null"); err == nil {
			p.Version = trimOutput(out)
			p.Running = true
		} else {
			p.Running = checkProcessRunning(ctx, runner, "com.docker.backend")
		}
		platforms = append(platforms, p)
	}

	// Podman / Podman Desktop
	if checkBinaryExists(ctx, runner, "podman") {
		p := PlatformInfo{
			Name:        "podman",
			DisplayName: "Podman",
			Type:        "container",
		}
		if checkProcessRunning(ctx, runner, "Podman Desktop") {
			p.DisplayName = "Podman Desktop"
			p.Desktop = true
		}
		if out, err := runner.Run(ctx, "podman version --format '{{.Version}}' 2>/dev/null"); err == nil {
			p.Version = trimOutput(out)
			p.Running = true
		}
		platforms = append(platforms, p)
	}

	// VirtualBox
	if checkBinaryExists(ctx, runner, "VBoxManage") {
		p := PlatformInfo{
			Name:        "virtualbox",
			DisplayName: "VirtualBox",
			Type:        "hypervisor",
		}
		if out, err := runner.Run(ctx, "VBoxManage --version 2>/dev/null"); err == nil {
			p.Version = trimOutput(out)
			p.Running = true
		}
		if out, err := runner.Run(ctx, "VBoxManage list vms 2>/dev/null"); err == nil {
			p.VMInstances = parseVBoxManageList(trimOutput(out))
		}
		platforms = append(platforms, p)
	}

	// VMware Fusion
	if checkBinaryExists(ctx, runner, "vmrun") {
		p := PlatformInfo{
			Name:        "vmware-fusion",
			DisplayName: "VMware Fusion",
			Type:        "hypervisor",
		}
		p.Running = checkProcessRunning(ctx, runner, "vmware-vmx")
		if out, err := runner.Run(ctx, "vmrun list 2>/dev/null"); err == nil {
			p.VMInstances = parseVmrunList(trimOutput(out))
			if len(p.VMInstances) > 0 {
				p.Running = true
			}
		}
		platforms = append(platforms, p)
	}

	// Parallels Desktop
	if checkBinaryExists(ctx, runner, "prlctl") {
		p := PlatformInfo{
			Name:        "parallels",
			DisplayName: "Parallels Desktop",
			Type:        "hypervisor",
			Desktop:     true,
		}
		p.Running = checkProcessRunning(ctx, runner, "prl_client_app")
		if out, err := runner.Run(ctx, "prlctl list -a 2>/dev/null"); err == nil {
			p.VMInstances = parsePrlctlList(trimOutput(out))
			if len(p.VMInstances) > 0 {
				p.Running = true
			}
		}
		platforms = append(platforms, p)
	}

	// UTM
	if checkBinaryExists(ctx, runner, "utmctl") {
		p := PlatformInfo{
			Name:        "utm",
			DisplayName: "UTM",
			Type:        "hypervisor",
			Desktop:     true,
		}
		p.Running = checkProcessRunning(ctx, runner, "UTM")
		if out, err := runner.Run(ctx, "utmctl list 2>/dev/null"); err == nil {
			p.VMInstances = parseUtmctlList(trimOutput(out))
		}
		platforms = append(platforms, p)
	}

	// Lima
	if checkBinaryExists(ctx, runner, "limactl") {
		p := PlatformInfo{
			Name:        "lima",
			DisplayName: "Lima",
			Type:        "vm-manager",
		}
		p.Version = getBinaryVersion(ctx, runner, "limactl")
		if out, err := runner.Run(ctx, `limactl list --format '{{.Name}}\t{{.Status}}' 2>/dev/null`); err == nil {
			p.VMInstances = parseLimaList(trimOutput(out))
			p.Running = len(p.VMInstances) > 0
		}
		platforms = append(platforms, p)
	}

	// Multipass
	if checkBinaryExists(ctx, runner, "multipass") {
		p := PlatformInfo{
			Name:        "multipass",
			DisplayName: "Multipass",
			Type:        "vm-manager",
		}
		p.Version = getBinaryVersion(ctx, runner, "multipass")
		if out, err := runner.Run(ctx, "multipass list --format csv 2>/dev/null"); err == nil {
			p.VMInstances = parseMultipassList(trimOutput(out))
			p.Running = true
		}
		platforms = append(platforms, p)
	}

	// Colima
	if checkBinaryExists(ctx, runner, "colima") {
		p := PlatformInfo{
			Name:        "colima",
			DisplayName: "Colima",
			Type:        "vm-manager",
		}
		p.Version = getBinaryVersion(ctx, runner, "colima")
		if out, err := runner.Run(ctx, "colima status 2>/dev/null"); err == nil {
			if strings.Contains(string(out), "Running") {
				p.Running = true
			}
		}
		platforms = append(platforms, p)
	}

	return platforms
}

// listServices parses launchctl list for running services on macOS.
func listServices(ctx context.Context, runner CommandRunner) []ServiceEntry {
	out, err := runner.Run(ctx, "launchctl list 2>/dev/null")
	if err != nil {
		return nil
	}

	var services []ServiceEntry
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "PID") {
			continue
		}
		// Format: PID Status Label
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		label := fields[2]

		// Filter out Apple internal services
		if strings.HasPrefix(label, "com.apple.") {
			continue
		}

		pid := fields[0]
		running := pid != "-"

		services = append(services, ServiceEntry{
			Name:    label,
			Running: running,
			Source:  "launchd",
		})
	}
	return services
}

// listListeningPorts parses lsof -iTCP -sTCP:LISTEN for listening ports on macOS.
func listListeningPorts(ctx context.Context, runner CommandRunner) []ListeningPort {
	out, err := runner.Run(ctx, "lsof -iTCP -sTCP:LISTEN -nP 2>/dev/null")
	if err != nil {
		return nil
	}

	var ports []ListeningPort
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "COMMAND") {
			continue
		}
		// Format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}

		processName := fields[0]
		pid, _ := strconv.Atoi(fields[1])
		nameField := fields[len(fields)-1] // e.g., "*:8080" or "127.0.0.1:3000"

		lastColon := strings.LastIndex(nameField, ":")
		if lastColon < 0 {
			continue
		}
		bindAddr := nameField[:lastColon]
		port, err := strconv.Atoi(nameField[lastColon+1:])
		if err != nil {
			continue
		}

		ports = append(ports, ListeningPort{
			Port:        port,
			BindAddress: bindAddr,
			Protocol:    "tcp",
			ProcessName: processName,
			PID:         pid,
		})
	}
	return ports
}
