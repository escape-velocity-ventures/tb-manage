package scanner

import (
	"context"
	"encoding/json"
	"strings"
)

// InferVMRole guesses the k3s role from the VM name.
// Returns "k3s-server" if the name contains "k3s" or "server",
// "k3s-agent" if it contains "worker" or "agent",
// "generic" otherwise.
func InferVMRole(name string) string {
	lower := strings.ToLower(name)
	// Check agent/worker first — a name like "k3s-worker" should be agent, not server.
	switch {
	case strings.Contains(lower, "worker") || strings.Contains(lower, "agent"):
		return "k3s-agent"
	case strings.Contains(lower, "k3s") || strings.Contains(lower, "server"):
		return "k3s-server"
	default:
		return "generic"
	}
}

// --- Lima Scanner ---

// limaInstance matches the JSON output of `limactl list --json`.
type limaInstance struct {
	Name    string        `json:"name"`
	Status  string        `json:"status"`
	Arch    string        `json:"arch"`
	CPUs    int           `json:"cpus"`
	Memory  int64         `json:"memory"` // bytes
	Network []limaNetwork `json:"network"`
}

type limaNetwork struct {
	VNL       string `json:"vnl"`
	Interface string `json:"interface"`
	IPAddress string `json:"ipAddress"`
}

// ParseLimaJSON parses the JSON output of `limactl list --json` into VMInfo slice.
func ParseLimaJSON(data []byte) []VMInfo {
	var instances []limaInstance
	if err := json.Unmarshal(data, &instances); err != nil {
		return []VMInfo{}
	}
	if len(instances) == 0 {
		return []VMInfo{}
	}

	vms := make([]VMInfo, 0, len(instances))
	for _, inst := range instances {
		vm := VMInfo{
			Name:       inst.Name,
			State:      inst.Status,
			Hypervisor: "lima",
			CPUCores:   inst.CPUs,
			MemoryMB:   int(inst.Memory / (1024 * 1024)),
			Role:       InferVMRole(inst.Name),
		}

		// Use the first IP address found
		for _, net := range inst.Network {
			if net.IPAddress != "" {
				vm.IP = net.IPAddress
				break
			}
		}

		vms = append(vms, vm)
	}
	return vms
}

// LimaScanner discovers Lima VMs.
type LimaScanner struct{}

func NewLimaScanner() *LimaScanner { return &LimaScanner{} }

func (s *LimaScanner) Name() string       { return "vms" }
func (s *LimaScanner) Platforms() []string { return []string{"darwin", "linux"} }

func (s *LimaScanner) Scan(ctx context.Context, runner CommandRunner) (json.RawMessage, error) {
	result := VMScanResult{
		Hypervisor: "lima",
	}

	out, err := runner.Run(ctx, "limactl list --json")
	if err != nil {
		// Lima not installed or no instances
		return json.Marshal(result)
	}

	result.VMs = ParseLimaJSON(out)
	return json.Marshal(result)
}

// --- QEMU/virsh Scanner ---

// ParseVirshList parses the output of `virsh list --all`.
func ParseVirshList(data []byte) []VMInfo {
	var vms []VMInfo
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines, header, and separator
		if line == "" || strings.HasPrefix(line, "Id") || strings.HasPrefix(line, "---") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		// Format: Id Name State (state can be two words like "shut off")
		// Id is a number or "-" for stopped VMs — either way, name is fields[1]
		name := fields[1]
		state := strings.Join(fields[2:], " ")

		vms = append(vms, VMInfo{
			Name:       name,
			State:      state,
			Hypervisor: "qemu",
			Role:       InferVMRole(name),
		})
	}
	return vms
}

// QEMUScanner discovers QEMU/KVM VMs via virsh.
type QEMUScanner struct{}

func NewQEMUScanner() *QEMUScanner { return &QEMUScanner{} }

func (s *QEMUScanner) Name() string       { return "vms" }
func (s *QEMUScanner) Platforms() []string { return []string{"linux"} }

func (s *QEMUScanner) Scan(ctx context.Context, runner CommandRunner) (json.RawMessage, error) {
	result := VMScanResult{
		Hypervisor: "qemu",
	}

	out, err := runner.Run(ctx, "virsh list --all")
	if err != nil {
		// virsh not installed or not accessible
		return json.Marshal(result)
	}

	result.VMs = ParseVirshList(out)
	return json.Marshal(result)
}
