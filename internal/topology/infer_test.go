package topology

import "testing"

func TestInferRole(t *testing.T) {
	tests := []struct {
		name       string
		interfaces []string
		wantRole   InferredRole
		wantType   string
	}{
		{
			name:       "bare metal k8s node (physical + CNI)",
			interfaces: []string{"en0", "cali12345", "lo"},
			wantRole:   RoleBaremetalK8s,
			wantType:   "baremetal",
		},
		{
			name:       "bare metal k8s node (eth + flannel)",
			interfaces: []string{"eth0", "flannel.1", "cni0", "lo"},
			wantRole:   RoleBaremetalK8s,
			wantType:   "baremetal",
		},
		{
			name:       "hypervisor (physical + bridge)",
			interfaces: []string{"en0", "vmnet0", "vmnet1", "bridge0", "lo0"},
			wantRole:   RoleHypervisor,
			wantType:   "baremetal",
		},
		{
			name:       "VM k8s node (virtio + CNI)",
			interfaces: []string{"enp0s1", "cali98765", "lo"},
			wantRole:   RoleVMK8s,
			wantType:   "vm",
		},
		{
			name:       "VM guest (virtio only)",
			interfaces: []string{"enp0s3", "lo"},
			wantRole:   RoleVM,
			wantType:   "vm",
		},
		{
			name:       "bare metal standalone (physical only)",
			interfaces: []string{"en0", "lo0"},
			wantRole:   RoleBareMetal,
			wantType:   "baremetal",
		},
		{
			name:       "bare metal with wireless",
			interfaces: []string{"wlan0", "lo"},
			wantRole:   RoleBareMetal,
			wantType:   "baremetal",
		},
		{
			name:       "bare metal with tunnel (VPN)",
			interfaces: []string{"eth0", "wg0", "lo"},
			wantRole:   RoleBareMetal,
			wantType:   "baremetal",
		},
		{
			name:       "macOS with vmnet (hypervisor)",
			interfaces: []string{"en0", "en1", "vmnet0", "vmnet1", "utun0", "lo0"},
			wantRole:   RoleHypervisor,
			wantType:   "baremetal",
		},
		{
			name:       "unknown (only loopback) — defaults to baremetal",
			interfaces: []string{"lo"},
			wantRole:   RoleUnknown,
			wantType:   "baremetal",
		},
		{
			name:       "hypervisor with docker bridge",
			interfaces: []string{"eth0", "docker0", "lo"},
			wantRole:   RoleHypervisor,
			wantType:   "baremetal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := ClassifyInterfaces(tt.interfaces)
			gotRole := InferRole(set)
			if gotRole != tt.wantRole {
				t.Errorf("InferRole() = %v, want %v", gotRole, tt.wantRole)
			}
			if gotRole.HostType() != tt.wantType {
				t.Errorf("HostType() = %v, want %v", gotRole.HostType(), tt.wantType)
			}
		})
	}
}
