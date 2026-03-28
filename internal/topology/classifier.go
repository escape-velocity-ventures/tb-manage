package topology

import "strings"

// NICType classifies a network interface by its name pattern.
type NICType int

const (
	NICUnknown  NICType = iota
	NICPhysical         // en0, eth0, eno1
	NICCNI              // cali*, flannel*, cilium*, vxlan*, weave*
	NICBridge           // vmnet*, virbr*, br-*
	NICVirtio           // enp0s*, ens*
	NICTunnel           // wg*, tun*, utun*
	NICWireless         // wlan*, wlp*
	NICLoopback         // lo, lo0
)

// String returns a human-readable name for the NIC type.
func (t NICType) String() string {
	switch t {
	case NICPhysical:
		return "physical"
	case NICCNI:
		return "cni"
	case NICBridge:
		return "bridge"
	case NICVirtio:
		return "virtio"
	case NICTunnel:
		return "tunnel"
	case NICWireless:
		return "wireless"
	case NICLoopback:
		return "loopback"
	default:
		return "unknown"
	}
}

// ClassifyNIC determines the NIC type from its name.
func ClassifyNIC(name string) NICType {
	lower := strings.ToLower(name)

	// Loopback
	if lower == "lo" || lower == "lo0" {
		return NICLoopback
	}

	// CNI interfaces (Kubernetes networking)
	cniPrefixes := []string{"cali", "flannel", "cilium", "vxlan", "weave", "cni", "veth"}
	for _, p := range cniPrefixes {
		if strings.HasPrefix(lower, p) {
			return NICCNI
		}
	}

	// Bridge interfaces (hypervisor)
	bridgePrefixes := []string{"vmnet", "virbr", "br-", "bridge", "docker"}
	for _, p := range bridgePrefixes {
		if strings.HasPrefix(lower, p) {
			return NICBridge
		}
	}

	// Tunnel / VPN
	tunnelPrefixes := []string{"wg", "tun", "utun", "tailscale", "nordlynx"}
	for _, p := range tunnelPrefixes {
		if strings.HasPrefix(lower, p) {
			return NICTunnel
		}
	}

	// Wireless
	wirelessPrefixes := []string{"wlan", "wlp"}
	for _, p := range wirelessPrefixes {
		if strings.HasPrefix(lower, p) {
			return NICWireless
		}
	}

	// Virtio / cloud VM guest — must check before physical since both start with "en"
	// enp0s* = virtio-net, ens* = GCP/some cloud, enX* = AWS ENA (Elastic Network Adapter)
	virtioPrefixes := []string{"enp0s", "ens", "enx"}
	for _, p := range virtioPrefixes {
		if strings.HasPrefix(lower, p) {
			return NICVirtio
		}
	}

	// Physical interfaces
	physicalPrefixes := []string{"en", "eth", "eno", "em"}
	for _, p := range physicalPrefixes {
		if strings.HasPrefix(lower, p) {
			return NICPhysical
		}
	}

	return NICUnknown
}
