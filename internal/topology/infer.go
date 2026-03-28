package topology

// InferredRole is the topology role derived from network interfaces.
type InferredRole string

const (
	RoleBareMetal    InferredRole = "baremetal"
	RoleBaremetalK8s InferredRole = "baremetal-k8s"
	RoleHypervisor   InferredRole = "hypervisor"
	RoleVM           InferredRole = "vm"
	RoleVMK8s        InferredRole = "vm-k8s"
	RoleCloud        InferredRole = "cloud"
	RoleUnknown      InferredRole = "unknown"
)

// HostType returns the simplified type for the edge-ingest API.
func (r InferredRole) HostType() string {
	switch r {
	case RoleBareMetal, RoleBaremetalK8s, RoleHypervisor:
		return "baremetal"
	case RoleVM, RoleVMK8s:
		return "vm"
	case RoleCloud:
		return "cloud"
	default:
		return "baremetal" // fallback — "unknown" isn't valid in the DB
	}
}

// NICSet summarizes the types of NICs present on a host.
type NICSet struct {
	HasPhysical bool
	HasCNI      bool
	HasBridge   bool
	HasVirtio   bool
	HasTunnel   bool
	HasWireless bool
}

// ClassifyInterfaces builds a NICSet from interface names.
func ClassifyInterfaces(names []string) NICSet {
	set := NICSet{}
	for _, name := range names {
		switch ClassifyNIC(name) {
		case NICPhysical:
			set.HasPhysical = true
		case NICCNI:
			set.HasCNI = true
		case NICBridge:
			set.HasBridge = true
		case NICVirtio:
			set.HasVirtio = true
		case NICTunnel:
			set.HasTunnel = true
		case NICWireless:
			set.HasWireless = true
		}
	}
	return set
}

// InferRole determines the host's role from its NIC set.
// Priority order (from design doc):
//   1. Physical + CNI     → bare metal k8s node
//   2. Physical + Bridge  → hypervisor
//   3. Virtio + CNI       → VM k8s node
//   4. Virtio only        → VM guest
//   5. Physical only      → bare metal (standalone)
func InferRole(set NICSet) InferredRole {
	switch {
	case set.HasPhysical && set.HasCNI:
		return RoleBaremetalK8s
	case set.HasPhysical && set.HasBridge:
		return RoleHypervisor
	case set.HasVirtio && set.HasCNI:
		return RoleVMK8s
	case set.HasVirtio:
		return RoleVM
	case set.HasPhysical || set.HasWireless:
		return RoleBareMetal
	default:
		return RoleUnknown
	}
}
