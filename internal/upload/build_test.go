package upload

import (
	"encoding/json"
	"testing"

	"github.com/tinkerbelle-io/tb-discover/internal/scanner"
)

func TestBuildRequestHostMapping(t *testing.T) {
	hostJSON := `{
		"name": "test-host",
		"type": "baremetal",
		"system": {
			"os": "linux",
			"os_version": "Ubuntu 22.04",
			"arch": "amd64",
			"cpu_model": "Intel Xeon",
			"cpu_cores": 8,
			"memory_gb": 32
		}
	}`

	netJSON := `{
		"hostname": "test-host.local",
		"interfaces": [
			{"name": "eth0", "ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff", "mtu": 1500, "state": "up"},
			{"name": "lo", "ip": "127.0.0.1", "mtu": 65536, "state": "up"},
			{"name": "cali123", "mtu": 1450, "state": "up"}
		]
	}`

	result := scanner.NewResult()
	result.Host = json.RawMessage(hostJSON)
	result.Network = json.RawMessage(netJSON)
	result.Meta.Version = "test-v1"
	result.Meta.DurationMS = 42
	result.Meta.Phases = []string{"host", "network"}
	result.Meta.SourceHost = "test-host.local"

	req := BuildRequest(result)

	// Check host mapping
	if req.Host == nil {
		t.Fatal("expected host in request")
	}
	if req.Host.Name != "test-host" {
		t.Errorf("host name = %q, want test-host", req.Host.Name)
	}
	if req.Host.Type != "baremetal" {
		t.Errorf("host type = %q, want baremetal", req.Host.Type)
	}
	if req.Host.System.CPUCores != 8 {
		t.Errorf("cpu_cores = %d, want 8", req.Host.System.CPUCores)
	}
	if req.Host.System.MemoryGB != 32 {
		t.Errorf("memory_gb = %f, want 32", req.Host.System.MemoryGB)
	}

	// Check interfaces — all interfaces included (sysfs may lack IPs)
	if len(req.Host.Network.Interfaces) != 3 {
		t.Errorf("expected 3 interfaces, got %d", len(req.Host.Network.Interfaces))
	}

	// Check hostname — uses hostInfo.Name (OverrideHostName-patched), not netInfo.Hostname
	if req.Host.Network.Hostname != "test-host" {
		t.Errorf("hostname = %q, want test-host", req.Host.Network.Hostname)
	}

	// Check meta
	if req.Meta.Version != "test-v1" {
		t.Errorf("version = %q, want test-v1", req.Meta.Version)
	}
	if req.Meta.DurationMS != 42 {
		t.Errorf("duration_ms = %d, want 42", req.Meta.DurationMS)
	}
}

func TestBuildRequestJSONCompatibility(t *testing.T) {
	// Verify the output JSON matches the edge-ingest contract
	hostJSON := `{"name":"h1","type":"vm","system":{"os":"linux","arch":"arm64","cpu_cores":4,"memory_gb":8}}`
	netJSON := `{"hostname":"h1","interfaces":[{"name":"enp0s1","ip":"10.0.0.5","mac":"aa:bb:cc:dd:ee:ff"}]}`

	result := scanner.NewResult()
	result.Host = json.RawMessage(hostJSON)
	result.Network = json.RawMessage(netJSON)
	result.Meta.Version = "v0.1.0"
	result.Meta.DurationMS = 100
	result.Meta.Phases = []string{"host", "network"}
	result.Meta.SourceHost = "h1"

	req := BuildRequest(result)
	req.AgentToken = "test-token"

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Unmarshal to map to verify field names match edge-ingest expectations
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal to map failed: %v", err)
	}

	// Check required top-level fields
	if _, ok := m["agent_token"]; !ok {
		t.Error("missing agent_token")
	}
	if _, ok := m["meta"]; !ok {
		t.Error("missing meta")
	}

	// Check host structure
	host, ok := m["host"].(map[string]interface{})
	if !ok {
		t.Fatal("missing or invalid host")
	}
	if _, ok := host["name"]; !ok {
		t.Error("missing host.name")
	}
	if _, ok := host["type"]; !ok {
		t.Error("missing host.type")
	}

	system, ok := host["system"].(map[string]interface{})
	if !ok {
		t.Fatal("missing host.system")
	}
	// Verify the exact field names edge-ingest expects
	for _, field := range []string{"os", "arch", "cpu_cores", "memory_gb"} {
		if _, ok := system[field]; !ok {
			t.Errorf("missing host.system.%s", field)
		}
	}

	network, ok := host["network"].(map[string]interface{})
	if !ok {
		t.Fatal("missing host.network")
	}
	if _, ok := network["hostname"]; !ok {
		t.Error("missing host.network.hostname")
	}
	if _, ok := network["interfaces"]; !ok {
		t.Error("missing host.network.interfaces")
	}

	// Check meta structure
	meta, ok := m["meta"].(map[string]interface{})
	if !ok {
		t.Fatal("missing or invalid meta")
	}
	for _, field := range []string{"version", "duration_ms", "phases", "source_host"} {
		if _, ok := meta[field]; !ok {
			t.Errorf("missing meta.%s", field)
		}
	}
}
