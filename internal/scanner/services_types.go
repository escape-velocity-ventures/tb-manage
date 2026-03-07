package scanner

// ServicesInfo is the data collected by the services scanner.
type ServicesInfo struct {
	Platforms      []PlatformInfo  `json:"platforms"`
	KubeContexts   []KubeContext   `json:"kube_contexts,omitempty"`
	Services       []ServiceEntry  `json:"services,omitempty"`
	ListeningPorts []ListeningPort `json:"listening_ports,omitempty"`
	DevTools       []DevTool       `json:"dev_tools,omitempty"`
	KubeletRunning bool            `json:"kubelet_running"`
}

// PlatformInfo describes a container/VM platform detected on the host.
type PlatformInfo struct {
	Name        string       `json:"name"`                   // docker, podman, virtualbox, vmware-fusion, etc.
	DisplayName string       `json:"display_name"`           // "Docker Desktop", "VMware Fusion", etc.
	Type        string       `json:"type"`                   // container, hypervisor, vm-manager
	Version     string       `json:"version,omitempty"`
	Running     bool         `json:"running"`
	Desktop     bool         `json:"desktop,omitempty"`      // true for Desktop variants (Docker Desktop, Podman Desktop)
	VMInstances []VMInstance `json:"vm_instances,omitempty"`
}

// VMInstance represents a virtual machine managed by a platform.
type VMInstance struct {
	Name   string `json:"name"`
	Status string `json:"status"` // running, stopped, paused, suspended, etc.
	UUID   string `json:"uuid,omitempty"`
}

// KubeContext represents a kubectl context from kubeconfig.
type KubeContext struct {
	Name      string `json:"name"`
	Cluster   string `json:"cluster"`
	User      string `json:"user"`
	Namespace string `json:"namespace,omitempty"`
	IsCurrent bool   `json:"is_current,omitempty"`
}

// ServiceEntry represents a running system service.
type ServiceEntry struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Running     bool   `json:"running"`
	Source      string `json:"source"` // systemd, launchd
}

// ListeningPort represents a network port in LISTEN state.
type ListeningPort struct {
	Port        int    `json:"port"`
	BindAddress string `json:"bind_address"`
	Protocol    string `json:"protocol"` // tcp, tcp6, udp
	ProcessName string `json:"process_name,omitempty"`
	PID         int    `json:"pid,omitempty"`
}

// DevTool represents a development tool found on the host.
type DevTool struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Path    string `json:"path,omitempty"`
}
