//go:build darwin

package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

func TestVZScanner_RoleAssignment(t *testing.T) {
	psOutput := "12345 /usr/local/bin/tb-node --efi vz-efi --disk /vms/plato-k3s/disk.raw --cpus 4 --memory 8 --nat"
	runner := &vmsMockRunner{responses: map[string]vmsMockResp{
		"ps -eo pid,args | grep '[t]b-node'": {output: []byte(psOutput)},
		"ping -c1 -W1 192.168.64.5 >/dev/null 2>&1": {output: nil, err: fmt.Errorf("unreachable")},
	}}

	s := NewVZScanner()
	data, err := s.Scan(context.Background(), runner)
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

func TestVZScanner_Interface(t *testing.T) {
	var _ Scanner = NewVZScanner()
}

func TestVZScanner_Name(t *testing.T) {
	s := NewVZScanner()
	if s.Name() != "vms" {
		t.Errorf("Name(): got %q, want %q", s.Name(), "vms")
	}
}
