package upload

import "encoding/json"

// EdgeIngestRequest is the top-level request to the edge-ingest function.
// Must match the TypeScript interface in edge-ingest/index.ts exactly.
type EdgeIngestRequest struct {
	AgentToken    string              `json:"agent_token"`
	Host          *HostScanResult     `json:"host,omitempty"`
	Cluster       json.RawMessage     `json:"cluster,omitempty"`
	Observability json.RawMessage     `json:"observability,omitempty"`
	Network       json.RawMessage     `json:"network,omitempty"`
	Exposure      json.RawMessage     `json:"exposure,omitempty"`
	Insights      []json.RawMessage   `json:"insights,omitempty"`
	Meta          EdgeIngestMeta      `json:"meta"`
}

// EdgeIngestMeta holds scan metadata.
type EdgeIngestMeta struct {
	Version    string   `json:"version"`
	DurationMS int      `json:"duration_ms"`
	Phases     []string `json:"phases"`
	SourceHost string   `json:"source_host"`
}

// HostScanResult matches the edge-ingest HostScanResult interface.
type HostScanResult struct {
	Name            string            `json:"name"`
	Type            string            `json:"type"` // baremetal, vm, cloud
	DiscoveryMethod string            `json:"discovery_method,omitempty"`
	System          HostSystem        `json:"system"`
	Network         HostNetwork       `json:"network"`
	Kubernetes      *HostKubernetes   `json:"kubernetes,omitempty"`

	// Extra fields go into scan_data via [key: string]: unknown
	Storage    json.RawMessage   `json:"storage,omitempty"`
	Containers json.RawMessage   `json:"containers,omitempty"`
	GPU        json.RawMessage   `json:"gpu,omitempty"`
	Services   json.RawMessage   `json:"services,omitempty"`
}

// HostSystem matches the system field in HostScanResult.
type HostSystem struct {
	OS       string  `json:"os"`
	Arch     string  `json:"arch"`
	CPUCores int     `json:"cpu_cores"`
	MemoryGB float64 `json:"memory_gb"`
}

// HostNetwork matches the network field in HostScanResult.
type HostNetwork struct {
	Hostname      string          `json:"hostname"`
	PublicIP      string          `json:"public_ip,omitempty"`
	CloudProvider string          `json:"cloud_provider,omitempty"`
	Interfaces    []HostInterface `json:"interfaces"`
}

// HostInterface matches the interface shape expected by edge-ingest.
type HostInterface struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
	MAC  string `json:"mac,omitempty"`
}

// HostKubernetes holds optional k8s info on the host.
type HostKubernetes struct {
	ClusterName string `json:"cluster_name,omitempty"`
}

// EdgeIngestResponse is the response from edge-ingest on success.
type EdgeIngestResponse struct {
	Success       bool     `json:"success"`
	SessionID     string   `json:"session_id"`
	ClusterID     string   `json:"cluster_id"`
	ResourceCount int      `json:"resource_count"`
	Phases        []string `json:"phases"`
}

// Upstream defines a single SaaS target (staging, production, etc.).
// Matches the tb-agent UPSTREAMS JSON format.
type Upstream struct {
	Name        string   `json:"name"`
	URL         string   `json:"url"`
	Token       string   `json:"token"`
	AnonKey     string   `json:"anonKey"`
	Permissions []string `json:"permissions,omitempty"`
}

// ParseUpstreams parses a JSON array of upstream configs.
func ParseUpstreams(data string) ([]Upstream, error) {
	var upstreams []Upstream
	if err := json.Unmarshal([]byte(data), &upstreams); err != nil {
		return nil, err
	}
	return upstreams, nil
}
