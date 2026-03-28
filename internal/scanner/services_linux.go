//go:build linux

package scanner

import (
	"context"
	"strconv"
	"strings"
)

// detectPlatforms checks for container and VM platforms on Linux.
func detectPlatforms(ctx context.Context, runner CommandRunner) []PlatformInfo {
	var platforms []PlatformInfo

	// Docker
	if checkBinaryExists(ctx, runner, "docker") {
		p := PlatformInfo{
			Name:        "docker",
			DisplayName: "Docker Engine",
			Type:        "container",
		}
		if out, err := runner.Run(ctx, "docker version --format '{{.Server.Version}}' 2>/dev/null"); err == nil {
			p.Version = trimOutput(out)
			p.Running = true
		} else {
			p.Running = checkProcessRunning(ctx, runner, "dockerd")
		}
		platforms = append(platforms, p)
	}

	// Podman
	if checkBinaryExists(ctx, runner, "podman") {
		p := PlatformInfo{
			Name:        "podman",
			DisplayName: "Podman",
			Type:        "container",
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

	// QEMU/KVM
	if checkBinaryExists(ctx, runner, "qemu-system-x86_64") || checkBinaryExists(ctx, runner, "qemu-system-aarch64") {
		p := PlatformInfo{
			Name:        "qemu",
			DisplayName: "QEMU",
			Type:        "hypervisor",
		}
		if out, err := runner.Run(ctx, "qemu-system-x86_64 --version 2>/dev/null || qemu-system-aarch64 --version 2>/dev/null"); err == nil {
			v := trimOutput(out)
			// "QEMU emulator version 8.2.0" -> "8.2.0"
			if idx := strings.LastIndex(v, " "); idx > 0 {
				p.Version = v[idx+1:]
			}
		}
		p.Running = checkProcessRunning(ctx, runner, "qemu")
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

	return platforms
}

// listServices parses systemctl to find running services.
func listServices(ctx context.Context, runner CommandRunner) []ServiceEntry {
	out, err := runner.Run(ctx, "systemctl list-units --type=service --state=running --no-pager --plain 2>/dev/null")
	if err != nil {
		return nil
	}

	var services []ServiceEntry
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "UNIT") {
			continue
		}
		// Format: UNIT LOAD ACTIVE SUB DESCRIPTION...
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		name := fields[0]
		name = strings.TrimSuffix(name, ".service")
		services = append(services, ServiceEntry{
			Name:        name,
			DisplayName: strings.Join(fields[4:], " "),
			Running:     true,
			Source:       "systemd",
		})
	}
	return services
}

// listListeningPorts parses ss -tlnp for listening TCP ports.
func listListeningPorts(ctx context.Context, runner CommandRunner) []ListeningPort {
	out, err := runner.Run(ctx, "ss -tlnp 2>/dev/null")
	if err != nil {
		return nil
	}

	var ports []ListeningPort
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "State") {
			continue
		}
		// Format: State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		localAddr := fields[3]

		// Parse address:port
		lastColon := strings.LastIndex(localAddr, ":")
		if lastColon < 0 {
			continue
		}
		bindAddr := localAddr[:lastColon]
		port, err := strconv.Atoi(localAddr[lastColon+1:])
		if err != nil {
			continue
		}

		lp := ListeningPort{
			Port:        port,
			BindAddress: bindAddr,
			Protocol:    "tcp",
		}

		// Extract process name and PID from users:(...) field
		for _, f := range fields[5:] {
			if strings.HasPrefix(f, "users:") {
				lp.ProcessName, lp.PID = parseSSProcessInfo(f)
				break
			}
		}

		ports = append(ports, lp)
	}
	return ports
}

// parseSSProcessInfo extracts process name and PID from ss users field.
// Format: users:(("process",pid=1234,fd=5))
func parseSSProcessInfo(field string) (string, int) {
	// Extract content between (( and ))
	start := strings.Index(field, "((")
	end := strings.LastIndex(field, "))")
	if start < 0 || end <= start {
		return "", 0
	}
	inner := field[start+2 : end]

	var name string
	var pid int

	parts := strings.Split(inner, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "\"") && strings.HasSuffix(p, "\"") {
			name = strings.Trim(p, "\"")
		} else if strings.HasPrefix(p, "pid=") {
			pid, _ = strconv.Atoi(strings.TrimPrefix(p, "pid="))
		}
	}
	return name, pid
}
