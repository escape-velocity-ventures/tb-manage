package upload

import (
	"encoding/json"
	"testing"

	"github.com/tinkerbelle-io/tb-discover/internal/scanner"
)

// TestFullScanToEdgeIngestContract verifies that a complete scan result
// transforms to JSON that matches the edge-ingest TypeScript contract exactly.
func TestFullScanToEdgeIngestContract(t *testing.T) {
	// Simulate a full scan result with all phases
	result := scanner.NewResult()
	result.Set("host", json.RawMessage(`{
		"name": "plato",
		"type": "baremetal",
		"system": {
			"os": "linux",
			"os_version": "Ubuntu 24.04",
			"arch": "arm64",
			"cpu_model": "Apple M2 Ultra",
			"cpu_cores": 24,
			"memory_gb": 192
		}
	}`))
	result.Set("network", json.RawMessage(`{
		"hostname": "plato.local",
		"interfaces": [
			{"name": "en0", "ip": "192.168.1.100", "mac": "aa:bb:cc:dd:ee:ff", "mtu": 1500, "state": "up", "type": "physical"},
			{"name": "cali1234", "mtu": 1450, "state": "up", "type": "cni"},
			{"name": "lo0", "ip": "127.0.0.1", "mtu": 65536, "state": "up"}
		],
		"routes": [
			{"destination": "default", "gateway": "192.168.1.1", "interface": "en0"}
		]
	}`))
	result.Set("storage", json.RawMessage(`{
		"disks": [{"name": "nvme0n1", "size_gb": 2000, "type": "nvme"}],
		"filesystems": [{"mount": "/", "size_gb": 1800, "used_gb": 400, "available_gb": 1400}]
	}`))
	result.Set("containers", json.RawMessage(`{
		"runtime": "containerd",
		"containers": [{"id": "abc123", "image": "nginx:latest", "state": "running"}]
	}`))
	result.Set("cluster", json.RawMessage(`{
		"name": "plato-k3s",
		"version": "v1.31.4+k3s1",
		"nodes": [{"name": "plato", "status": "Ready", "roles": ["control-plane"]}],
		"namespaces": [
			{
				"name": "default",
				"workloads": [{"kind": "Deployment", "name": "nginx", "namespace": "default", "replicas": 1, "ready_replicas": 1}],
				"services": [{"name": "kubernetes", "namespace": "default", "type": "ClusterIP", "clusterIP": "10.43.0.1"}]
			}
		]
	}`))
	result.Set("power", json.RawMessage(`{
		"providers": ["wol"],
		"targets": [],
		"relationships": []
	}`))
	result.Set("iot", json.RawMessage(`{
		"providers": ["mdns"],
		"devices": [
			{"id": "mdns-_airplay._tcp-plato", "name": "plato", "type": "iot/media", "state": "discovered", "source": "mdns"}
		]
	}`))

	result.Meta.Version = "v0.1.0"
	result.Meta.DurationMS = 1234
	result.Meta.Phases = []string{"host", "network", "storage", "containers", "cluster", "power", "iot"}
	result.Meta.SourceHost = "plato.local"
	result.Meta.InferredRole = "baremetal-k8s"

	req := BuildRequest(result)
	req.AgentToken = "test-agent-token"

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}

	// === Verify top-level structure matches edge-ingest ===

	t.Run("top_level_fields", func(t *testing.T) {
		required := []string{"agent_token", "meta"}
		for _, field := range required {
			if _, ok := m[field]; !ok {
				t.Errorf("missing required field %q", field)
			}
		}

		optional := []string{"host", "cluster", "network"}
		for _, field := range optional {
			if _, ok := m[field]; !ok {
				t.Errorf("expected optional field %q to be present", field)
			}
		}
	})

	// === Verify agent_token ===

	t.Run("agent_token", func(t *testing.T) {
		if m["agent_token"] != "test-agent-token" {
			t.Errorf("agent_token = %v, want test-agent-token", m["agent_token"])
		}
	})

	// === Verify meta structure ===

	t.Run("meta_structure", func(t *testing.T) {
		meta, ok := m["meta"].(map[string]interface{})
		if !ok {
			t.Fatal("meta is not an object")
		}

		metaFields := map[string]interface{}{
			"version":     "v0.1.0",
			"source_host": "plato.local",
		}
		for field, expected := range metaFields {
			if meta[field] != expected {
				t.Errorf("meta.%s = %v, want %v", field, meta[field], expected)
			}
		}

		if meta["duration_ms"].(float64) != 1234 {
			t.Errorf("meta.duration_ms = %v, want 1234", meta["duration_ms"])
		}

		phases, ok := meta["phases"].([]interface{})
		if !ok {
			t.Fatal("meta.phases is not an array")
		}
		if len(phases) != 7 {
			t.Errorf("meta.phases has %d entries, want 7", len(phases))
		}
	})

	// === Verify host structure (edge-ingest: infra_hosts upsert) ===

	t.Run("host_structure", func(t *testing.T) {
		host, ok := m["host"].(map[string]interface{})
		if !ok {
			t.Fatal("host is not an object")
		}

		if host["name"] != "plato" {
			t.Errorf("host.name = %v", host["name"])
		}
		if host["type"] != "baremetal" {
			t.Errorf("host.type = %v", host["type"])
		}

		// host.system
		system, ok := host["system"].(map[string]interface{})
		if !ok {
			t.Fatal("host.system is not an object")
		}
		systemChecks := map[string]interface{}{
			"os":   "linux",
			"arch": "arm64",
		}
		for field, expected := range systemChecks {
			if system[field] != expected {
				t.Errorf("host.system.%s = %v, want %v", field, system[field], expected)
			}
		}
		if system["cpu_cores"].(float64) != 24 {
			t.Errorf("host.system.cpu_cores = %v, want 24", system["cpu_cores"])
		}
		if system["memory_gb"].(float64) != 192 {
			t.Errorf("host.system.memory_gb = %v, want 192", system["memory_gb"])
		}

		// host.network
		network, ok := host["network"].(map[string]interface{})
		if !ok {
			t.Fatal("host.network is not an object")
		}
		if network["hostname"] != "plato.local" {
			t.Errorf("host.network.hostname = %v", network["hostname"])
		}

		ifaces, ok := network["interfaces"].([]interface{})
		if !ok {
			t.Fatal("host.network.interfaces is not an array")
		}
		// Only interfaces with IPs should be included
		if len(ifaces) != 2 {
			t.Errorf("expected 2 interfaces (with IPs only), got %d", len(ifaces))
		}

		// First interface should have name, ip, mac
		if len(ifaces) > 0 {
			iface := ifaces[0].(map[string]interface{})
			for _, field := range []string{"name", "ip"} {
				if _, ok := iface[field]; !ok {
					t.Errorf("interface missing field %q", field)
				}
			}
		}

		// host.storage and host.containers should be passed through
		if _, ok := host["storage"]; !ok {
			t.Error("missing host.storage (should be passed through to scan_data)")
		}
		if _, ok := host["containers"]; !ok {
			t.Error("missing host.containers (should be passed through to scan_data)")
		}
	})

	// === Verify cluster is passed through as raw JSON ===

	t.Run("cluster_passthrough", func(t *testing.T) {
		cluster, ok := m["cluster"].(map[string]interface{})
		if !ok {
			t.Fatal("cluster is not an object")
		}
		if cluster["name"] != "plato-k3s" {
			t.Errorf("cluster.name = %v", cluster["name"])
		}
		if _, ok := cluster["nodes"]; !ok {
			t.Error("cluster missing nodes")
		}
		if _, ok := cluster["namespaces"]; !ok {
			t.Error("cluster missing namespaces")
		}
	})

	// === Verify network is passed through ===

	t.Run("network_passthrough", func(t *testing.T) {
		network, ok := m["network"].(map[string]interface{})
		if !ok {
			t.Fatal("network is not an object")
		}
		if _, ok := network["interfaces"]; !ok {
			t.Error("network missing interfaces")
		}
	})
}

// TestEdgeIngestRequestJSONFieldNames verifies every JSON field name in the
// request matches what edge-ingest/index.ts expects.
func TestEdgeIngestRequestJSONFieldNames(t *testing.T) {
	req := &EdgeIngestRequest{
		AgentToken: "tok",
		Host: &HostScanResult{
			Name: "h1",
			Type: "vm",
			System: HostSystem{
				OS:       "linux",
				Arch:     "amd64",
				CPUCores: 4,
				MemoryGB: 8,
			},
			Network: HostNetwork{
				Hostname: "h1",
				Interfaces: []HostInterface{
					{Name: "eth0", IP: "10.0.0.1", MAC: "aa:bb:cc:dd:ee:ff"},
				},
			},
			Kubernetes: &HostKubernetes{ClusterName: "test-cluster"},
		},
		Cluster:       json.RawMessage(`{"name":"test-cluster"}`),
		Observability: json.RawMessage(`{"prometheus":{"detected":true}}`),
		Network:       json.RawMessage(`{"hostname":"h1"}`),
		Exposure:      json.RawMessage(`{"routes":[]}`),
		Insights:      []json.RawMessage{json.RawMessage(`{"type":"warning","message":"test"}`)},
		Meta: EdgeIngestMeta{
			Version:    "v0.1.0",
			DurationMS: 100,
			Phases:     []string{"host"},
			SourceHost: "h1",
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var m map[string]interface{}
	json.Unmarshal(data, &m)

	// Top-level field names per edge-ingest contract
	expectedTopLevel := []string{
		"agent_token", "host", "cluster", "observability",
		"network", "exposure", "insights", "meta",
	}
	for _, field := range expectedTopLevel {
		if _, ok := m[field]; !ok {
			t.Errorf("top-level field %q missing", field)
		}
	}

	// host.system field names
	host := m["host"].(map[string]interface{})
	system := host["system"].(map[string]interface{})
	for _, field := range []string{"os", "arch", "cpu_cores", "memory_gb"} {
		if _, ok := system[field]; !ok {
			t.Errorf("host.system.%s missing", field)
		}
	}

	// host.network field names
	network := host["network"].(map[string]interface{})
	for _, field := range []string{"hostname", "interfaces"} {
		if _, ok := network[field]; !ok {
			t.Errorf("host.network.%s missing", field)
		}
	}

	// host.network.interfaces[0] field names
	ifaces := network["interfaces"].([]interface{})
	iface := ifaces[0].(map[string]interface{})
	for _, field := range []string{"name", "ip", "mac"} {
		if _, ok := iface[field]; !ok {
			t.Errorf("host.network.interfaces[].%s missing", field)
		}
	}

	// host.kubernetes field names
	k8s := host["kubernetes"].(map[string]interface{})
	if _, ok := k8s["cluster_name"]; !ok {
		t.Error("host.kubernetes.cluster_name missing")
	}

	// meta field names
	meta := m["meta"].(map[string]interface{})
	for _, field := range []string{"version", "duration_ms", "phases", "source_host"} {
		if _, ok := meta[field]; !ok {
			t.Errorf("meta.%s missing", field)
		}
	}
}

// TestEdgeIngestResponseShape verifies the response struct matches expected shape.
func TestEdgeIngestResponseShape(t *testing.T) {
	respJSON := `{
		"success": true,
		"session_id": "sess-123",
		"cluster_id": "clust-456",
		"resource_count": 42,
		"phases": ["host", "cluster"]
	}`

	var resp EdgeIngestResponse
	if err := json.Unmarshal([]byte(respJSON), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if !resp.Success {
		t.Error("success should be true")
	}
	if resp.SessionID != "sess-123" {
		t.Errorf("session_id = %q", resp.SessionID)
	}
	if resp.ClusterID != "clust-456" {
		t.Errorf("cluster_id = %q", resp.ClusterID)
	}
	if resp.ResourceCount != 42 {
		t.Errorf("resource_count = %d", resp.ResourceCount)
	}
	if len(resp.Phases) != 2 {
		t.Errorf("phases = %v", resp.Phases)
	}
}

// TestMinimalScanRequest verifies that a minimal scan (host only) produces valid JSON.
func TestMinimalScanRequest(t *testing.T) {
	result := scanner.NewResult()
	result.Set("host", json.RawMessage(`{"name":"test","type":"vm","system":{"os":"linux","arch":"amd64","cpu_cores":2,"memory_gb":4}}`))
	result.Meta.Version = "v0.1.0"
	result.Meta.DurationMS = 50
	result.Meta.Phases = []string{"host"}
	result.Meta.SourceHost = "test"

	req := BuildRequest(result)
	req.AgentToken = "tok"

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var m map[string]interface{}
	json.Unmarshal(data, &m)

	// Must have agent_token and meta
	if m["agent_token"] != "tok" {
		t.Error("missing agent_token")
	}
	if _, ok := m["meta"]; !ok {
		t.Error("missing meta")
	}

	// host should be present
	if _, ok := m["host"]; !ok {
		t.Error("missing host")
	}

	// cluster, observability, exposure should be absent (omitempty)
	for _, field := range []string{"cluster", "observability", "exposure", "insights"} {
		if _, ok := m[field]; ok {
			t.Errorf("field %q should be omitted when not set", field)
		}
	}
}

// TestScanResultJSONRoundTrip verifies scanner.Result can be marshaled and
// its top-level structure includes all phase fields.
func TestScanResultJSONRoundTrip(t *testing.T) {
	result := scanner.NewResult()
	result.Set("host", json.RawMessage(`{"name":"test"}`))
	result.Set("network", json.RawMessage(`{"hostname":"test"}`))
	result.Set("storage", json.RawMessage(`{"disks":[]}`))
	result.Set("containers", json.RawMessage(`{"runtime":"docker"}`))
	result.Set("cluster", json.RawMessage(`{"name":"test-cluster"}`))
	result.Set("power", json.RawMessage(`{"providers":["wol"]}`))
	result.Set("iot", json.RawMessage(`{"providers":["mdns"]}`))

	result.Meta.Version = "v0.1.0"
	result.Meta.DurationMS = 100
	result.Meta.Phases = []string{"host", "network", "storage", "containers", "cluster", "power", "iot"}
	result.Meta.SourceHost = "test"

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var m map[string]interface{}
	json.Unmarshal(data, &m)

	for _, field := range []string{"host", "network", "storage", "containers", "cluster", "power", "iot", "meta"} {
		if _, ok := m[field]; !ok {
			t.Errorf("scanner.Result JSON missing field %q", field)
		}
	}
}

// TestUploadClientRetryConfig verifies client configuration.
func TestUploadClientRetryConfig(t *testing.T) {
	c := NewClient("https://example.com", "test-token", "test-anon-key")
	if c.maxRetries != 3 {
		t.Errorf("maxRetries = %d, want 3", c.maxRetries)
	}
	if c.httpClient.Timeout.Seconds() != 30 {
		t.Errorf("timeout = %v, want 30s", c.httpClient.Timeout)
	}
	if c.baseURL != "https://example.com" {
		t.Errorf("baseURL = %q", c.baseURL)
	}
}
