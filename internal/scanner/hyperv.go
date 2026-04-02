package scanner

// VMInfo represents a discovered virtual machine.
// Defined here (no build tag) so upload and result code can reference it cross-platform.
// The actual HyperVScanner is in hyperv_windows.go.
type VMInfo struct {
	Name       string `json:"name"`
	State      string `json:"state"`
	Role       string `json:"role"`                // k3s-server, k3s-agent, generic
	CPUCores   int    `json:"cpu_cores,omitempty"`
	MemoryMB   int    `json:"memory_mb,omitempty"`
	IP         string `json:"ip,omitempty"`
	OS         string `json:"os,omitempty"`
	Hypervisor string `json:"hypervisor"`
}

// VMScanResult holds all discovered VMs.
type VMScanResult struct {
	Hypervisor string   `json:"hypervisor"`
	VMs        []VMInfo `json:"vms"`
}
