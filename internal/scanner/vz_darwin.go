//go:build darwin

package scanner

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"strings"
)

// platformVMScanners returns VM discovery scanners for macOS.
func platformVMScanners() []Scanner {
	return []Scanner{NewVZScanner(), NewLimaScanner()}
}

// VZScanner discovers VZ framework VMs on macOS by finding running tb-node processes.
type VZScanner struct{}

func NewVZScanner() *VZScanner { return &VZScanner{} }

func (s *VZScanner) Name() string        { return "vms" }
func (s *VZScanner) Platforms() []string  { return []string{"darwin"} }

func (s *VZScanner) Scan(ctx context.Context, runner CommandRunner) (json.RawMessage, error) {
	result := VMScanResult{
		Hypervisor: "vz",
	}

	// Find running tb-node processes
	out, err := runner.Run(ctx, "ps -eo pid,args | grep '[t]b-node'")
	if err != nil {
		// No VMs running — not an error
		return json.Marshal(result)
	}

	// Parse DHCP leases for NAT VM IP resolution
	leases := parseDHCPLeases()

	// Collect all reachable VZ NAT IPs (unique, deduplicated by MAC)
	activeIPs := resolveActiveVZIPs(ctx, runner, leases)

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var vms []*VMInfo
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		vm := parseVZProcess(line)
		if vm == nil {
			continue
		}
		vm.Hypervisor = "vz"
		vm.State = "Running"
		vms = append(vms, vm)
	}

	// Assign IPs and roles to VMs
	// If there's exactly one VM and one IP, it's obvious.
	// For multiple VMs, assign IPs in order (best effort — VZ doesn't expose per-process MAC mapping).
	for i, vm := range vms {
		if i < len(activeIPs) {
			vm.IP = activeIPs[i]
		}
		vm.Role = InferVMRole(vm.Name)
		result.VMs = append(result.VMs, *vm)
	}

	return json.Marshal(result)
}

// parseVZProcess extracts VM info from a ps line like:
// 12345 /path/to/tb-node --efi vz-efi --disk disk.raw --cpus 4 --memory 8 --nat
func parseVZProcess(psLine string) *VMInfo {
	if !strings.Contains(psLine, "tb-node") || strings.Contains(psLine, "grep") {
		return nil
	}

	parts := strings.Fields(psLine)
	if len(parts) < 2 {
		return nil
	}

	vm := &VMInfo{}

	args := parts[1:] // skip PID
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--disk":
			if i+1 < len(args) {
				i++
				vm.Name = vmNameFromDisk(args[i])
			}
		case "--cpus":
			if i+1 < len(args) {
				i++
				vm.CPUCores, _ = strconv.Atoi(args[i])
			}
		case "--memory":
			if i+1 < len(args) {
				i++
				gb, _ := strconv.Atoi(args[i])
				vm.MemoryMB = gb * 1024
			}
		}
	}

	if vm.Name == "" {
		vm.Name = "vz-vm"
	}

	return vm
}

// vmNameFromDisk extracts a VM name from the disk path.
// e.g., "/path/to/plato-k3s/disk.raw" -> "plato-k3s"
// e.g., "Resources/disk.raw" -> "tb-node-vm"
func vmNameFromDisk(diskPath string) string {
	parts := strings.Split(diskPath, "/")
	for i := len(parts) - 2; i >= 0; i-- {
		dir := parts[i]
		if dir != "" && dir != "." && dir != "Resources" {
			return dir
		}
	}
	if len(parts) > 0 && parts[0] != "disk.raw" {
		return strings.TrimSuffix(parts[0], ".raw")
	}
	return "tb-node-vm"
}

// DHCPLease represents an entry from /var/db/dhcpd_leases.
type DHCPLease struct {
	Name      string
	IPAddress string
	HWAddress string
}

// parseDHCPLeases reads the macOS DHCP lease file used by VZ NAT networking.
func parseDHCPLeases() []DHCPLease {
	data, err := os.ReadFile("/var/db/dhcpd_leases")
	if err != nil {
		return nil
	}

	var leases []DHCPLease
	var current DHCPLease
	inBlock := false

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "{":
			inBlock = true
			current = DHCPLease{}
		case line == "}":
			if inBlock && current.IPAddress != "" {
				leases = append(leases, current)
			}
			inBlock = false
		case inBlock:
			if k, v, ok := strings.Cut(line, "="); ok {
				switch strings.TrimSpace(k) {
				case "name":
					current.Name = strings.TrimSpace(v)
				case "ip_address":
					current.IPAddress = strings.TrimSpace(v)
				case "hw_address":
					current.HWAddress = strings.TrimSpace(v)
				}
			}
		}
	}

	return leases
}

// resolveActiveVZIPs returns all reachable VZ NAT IPs from DHCP leases.
// Deduplicates by MAC address (keeps most recent lease per MAC).
func resolveActiveVZIPs(ctx context.Context, runner CommandRunner, leases []DHCPLease) []string {
	// Deduplicate: keep most recent lease per MAC (file is append-only)
	byMAC := make(map[string]string) // MAC -> IP
	for _, l := range leases {
		if strings.HasPrefix(l.IPAddress, "192.168.64.") {
			byMAC[l.HWAddress] = l.IPAddress
		}
	}

	// Ping-test each unique IP
	var active []string
	for _, ip := range byMAC {
		if _, err := runner.Run(ctx, "ping -c1 -W1 "+ip+" >/dev/null 2>&1"); err == nil {
			active = append(active, ip)
		}
	}

	// Sort for deterministic VM↔IP assignment across runs
	sort.Strings(active)
	return active
}
