package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

// vmsMockRunner implements CommandRunner for VM scanner tests.
type vmsMockRunner struct {
	responses map[string]vmsMockResp
}

type vmsMockResp struct {
	output []byte
	err    error
}

func (m *vmsMockRunner) Run(_ context.Context, cmd string) ([]byte, error) {
	if resp, ok := m.responses[cmd]; ok {
		return resp.output, resp.err
	}
	return nil, fmt.Errorf("command not found: %s", cmd)
}

func TestInferVMRole(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"plato-k3s", "k3s-server"},
		{"k3s-server-01", "k3s-server"},
		{"my-server", "k3s-server"},
		{"aristotle-k3s-worker", "k3s-agent"},
		{"worker-01", "k3s-agent"},
		{"my-agent-node", "k3s-agent"},
		{"dev-box", "generic"},
		{"ubuntu-desktop", "generic"},
		{"", "generic"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := InferVMRole(tc.name)
			if got != tc.want {
				t.Errorf("InferVMRole(%q) = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

func TestParseLimaJSON(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect []VMInfo
	}{
		{
			name: "two instances",
			input: `[
				{
					"name": "k3s-server",
					"status": "Running",
					"arch": "aarch64",
					"cpus": 4,
					"memory": 8589934592,
					"network": [{"vnl": "shared", "interface": "lima0", "ipAddress": "192.168.5.15"}]
				},
				{
					"name": "default",
					"status": "Stopped",
					"arch": "aarch64",
					"cpus": 2,
					"memory": 4294967296,
					"network": []
				}
			]`,
			expect: []VMInfo{
				{Name: "k3s-server", State: "Running", Hypervisor: "lima", CPUCores: 4, MemoryMB: 8192, IP: "192.168.5.15", Role: "k3s-server"},
				{Name: "default", State: "Stopped", Hypervisor: "lima", CPUCores: 2, MemoryMB: 4096, Role: "generic"},
			},
		},
		{
			name:   "empty array",
			input:  `[]`,
			expect: []VMInfo{},
		},
		{
			name:   "invalid json",
			input:  `not json`,
			expect: []VMInfo{},
		},
		{
			name: "instance with worker in name",
			input: `[{"name": "k3s-worker-01", "status": "Running", "arch": "aarch64", "cpus": 2, "memory": 2147483648, "network": []}]`,
			expect: []VMInfo{
				{Name: "k3s-worker-01", State: "Running", Hypervisor: "lima", CPUCores: 2, MemoryMB: 2048, Role: "k3s-agent"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseLimaJSON([]byte(tc.input))
			if len(got) != len(tc.expect) {
				t.Fatalf("got %d VMs, want %d\ngot: %+v", len(got), len(tc.expect), got)
			}
			for i := range tc.expect {
				assertVMInfo(t, i, got[i], tc.expect[i])
			}
		})
	}
}

func TestParseVirshList(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect []VMInfo
	}{
		{
			name: "two VMs running and shut off",
			input: ` Id   Name              State
------------------------------------
 1    k3s-server-01     running
 -    dev-worker        shut off
`,
			expect: []VMInfo{
				{Name: "k3s-server-01", State: "running", Hypervisor: "qemu", Role: "k3s-server"},
				{Name: "dev-worker", State: "shut off", Hypervisor: "qemu", Role: "k3s-agent"},
			},
		},
		{
			name: "header only no VMs",
			input: ` Id   Name              State
------------------------------------
`,
			expect: nil,
		},
		{
			name:   "empty output",
			input:  "",
			expect: nil,
		},
		{
			name: "paused VM",
			input: ` Id   Name              State
------------------------------------
 3    test-vm           paused
`,
			expect: []VMInfo{
				{Name: "test-vm", State: "paused", Hypervisor: "qemu", Role: "generic"},
			},
		},
		{
			name: "multiple states",
			input: ` Id   Name              State
------------------------------------
 1    my-server         running
 2    my-agent-node     running
 -    backup-box        shut off
`,
			expect: []VMInfo{
				{Name: "my-server", State: "running", Hypervisor: "qemu", Role: "k3s-server"},
				{Name: "my-agent-node", State: "running", Hypervisor: "qemu", Role: "k3s-agent"},
				{Name: "backup-box", State: "shut off", Hypervisor: "qemu", Role: "generic"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseVirshList([]byte(tc.input))
			if len(got) != len(tc.expect) {
				t.Fatalf("got %d VMs, want %d\ngot: %+v", len(got), len(tc.expect), got)
			}
			for i := range tc.expect {
				assertVMInfo(t, i, got[i], tc.expect[i])
			}
		})
	}
}

func TestLimaScanner_NoLimaInstalled(t *testing.T) {
	runner := &vmsMockRunner{responses: map[string]vmsMockResp{}}
	s := NewLimaScanner()

	data, err := s.Scan(t.Context(), runner)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	var result VMScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}
	if len(result.VMs) != 0 {
		t.Errorf("expected 0 VMs, got %d", len(result.VMs))
	}
	if result.Hypervisor != "lima" {
		t.Errorf("Hypervisor: got %q, want %q", result.Hypervisor, "lima")
	}
}

func TestLimaScanner_WithVMs(t *testing.T) {
	limaJSON := `[{"name":"k3s-server","status":"Running","arch":"aarch64","cpus":4,"memory":8589934592,"network":[{"vnl":"shared","interface":"lima0","ipAddress":"192.168.5.15"}]}]`
	runner := &vmsMockRunner{responses: map[string]vmsMockResp{
		"limactl list --json": {output: []byte(limaJSON)},
	}}
	s := NewLimaScanner()

	data, err := s.Scan(t.Context(), runner)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	var result VMScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}
	if len(result.VMs) != 1 {
		t.Fatalf("expected 1 VM, got %d", len(result.VMs))
	}
	vm := result.VMs[0]
	if vm.Name != "k3s-server" {
		t.Errorf("Name: got %q, want %q", vm.Name, "k3s-server")
	}
	if vm.Role != "k3s-server" {
		t.Errorf("Role: got %q, want %q", vm.Role, "k3s-server")
	}
	if vm.CPUCores != 4 {
		t.Errorf("CPUCores: got %d, want 4", vm.CPUCores)
	}
	if vm.MemoryMB != 8192 {
		t.Errorf("MemoryMB: got %d, want 8192", vm.MemoryMB)
	}
	if vm.IP != "192.168.5.15" {
		t.Errorf("IP: got %q, want %q", vm.IP, "192.168.5.15")
	}
}

func TestQEMUScanner_NoVirsh(t *testing.T) {
	runner := &vmsMockRunner{responses: map[string]vmsMockResp{}}
	s := NewQEMUScanner()

	data, err := s.Scan(t.Context(), runner)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	var result VMScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}
	if len(result.VMs) != 0 {
		t.Errorf("expected 0 VMs, got %d", len(result.VMs))
	}
}

func TestQEMUScanner_WithVMs(t *testing.T) {
	virshOutput := ` Id   Name              State
------------------------------------
 1    k3s-server-01     running
 -    dev-worker        shut off
`
	runner := &vmsMockRunner{responses: map[string]vmsMockResp{
		"virsh list --all": {output: []byte(virshOutput)},
	}}
	s := NewQEMUScanner()

	data, err := s.Scan(t.Context(), runner)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	var result VMScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}
	if len(result.VMs) != 2 {
		t.Fatalf("expected 2 VMs, got %d", len(result.VMs))
	}
	if result.VMs[0].Name != "k3s-server-01" {
		t.Errorf("VM[0].Name: got %q, want %q", result.VMs[0].Name, "k3s-server-01")
	}
	if result.VMs[0].Role != "k3s-server" {
		t.Errorf("VM[0].Role: got %q, want %q", result.VMs[0].Role, "k3s-server")
	}
	if result.VMs[1].Role != "k3s-agent" {
		t.Errorf("VM[1].Role: got %q, want %q", result.VMs[1].Role, "k3s-agent")
	}
}

func TestLimaScanner_Interface(t *testing.T) {
	var _ Scanner = NewLimaScanner()
}

func TestQEMUScanner_Interface(t *testing.T) {
	var _ Scanner = NewQEMUScanner()
}

func TestLimaScanner_Name(t *testing.T) {
	s := NewLimaScanner()
	if s.Name() != "vms" {
		t.Errorf("Name(): got %q, want %q", s.Name(), "vms")
	}
}

func TestQEMUScanner_Name(t *testing.T) {
	s := NewQEMUScanner()
	if s.Name() != "vms" {
		t.Errorf("Name(): got %q, want %q", s.Name(), "vms")
	}
}

func TestVMInfoRole_InJSON(t *testing.T) {
	vm := VMInfo{
		Name:       "k3s-server-01",
		State:      "running",
		Hypervisor: "qemu",
		Role:       "k3s-server",
		CPUCores:   4,
		MemoryMB:   8192,
	}

	data, err := json.Marshal(vm)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	role, ok := parsed["role"]
	if !ok {
		t.Fatal("role field missing from JSON output")
	}
	if role != "k3s-server" {
		t.Errorf("role: got %q, want %q", role, "k3s-server")
	}
}

func TestVZScanner_RoleAssignment(t *testing.T) {
	// Test that VZ scanner assigns roles to detected VMs
	psOutput := "12345 /usr/local/bin/tb-node --efi vz-efi --disk /vms/plato-k3s/disk.raw --cpus 4 --memory 8 --nat"
	runner := &vmsMockRunner{responses: map[string]vmsMockResp{
		"ps -eo pid,args | grep '[t]b-node'": {output: []byte(psOutput)},
		"ping -c1 -W1 192.168.64.5 >/dev/null 2>&1": {output: nil, err: fmt.Errorf("unreachable")},
	}}

	s := NewVZScanner()
	data, err := s.Scan(t.Context(), runner)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	var result VMScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if len(result.VMs) != 1 {
		t.Fatalf("expected 1 VM, got %d", len(result.VMs))
	}
	if result.VMs[0].Role != "k3s-server" {
		t.Errorf("Role: got %q, want %q", result.VMs[0].Role, "k3s-server")
	}
}

// assertVMInfo compares two VMInfo structs field by field.
func assertVMInfo(t *testing.T, idx int, got, expect VMInfo) {
	t.Helper()
	if got.Name != expect.Name {
		t.Errorf("[%d] Name: got %q, want %q", idx, got.Name, expect.Name)
	}
	if got.State != expect.State {
		t.Errorf("[%d] State: got %q, want %q", idx, got.State, expect.State)
	}
	if got.Hypervisor != expect.Hypervisor {
		t.Errorf("[%d] Hypervisor: got %q, want %q", idx, got.Hypervisor, expect.Hypervisor)
	}
	if got.Role != expect.Role {
		t.Errorf("[%d] Role: got %q, want %q", idx, got.Role, expect.Role)
	}
	if expect.CPUCores != 0 && got.CPUCores != expect.CPUCores {
		t.Errorf("[%d] CPUCores: got %d, want %d", idx, got.CPUCores, expect.CPUCores)
	}
	if expect.MemoryMB != 0 && got.MemoryMB != expect.MemoryMB {
		t.Errorf("[%d] MemoryMB: got %d, want %d", idx, got.MemoryMB, expect.MemoryMB)
	}
	if expect.IP != "" && got.IP != expect.IP {
		t.Errorf("[%d] IP: got %q, want %q", idx, got.IP, expect.IP)
	}
}
