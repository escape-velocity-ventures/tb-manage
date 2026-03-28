package scanner

// ClusterScanResult matches the edge-ingest ClusterScanResult interface.
type ClusterScanResult struct {
	Name               string                      `json:"name,omitempty"`
	Provider           string                      `json:"provider,omitempty"`
	Version            string                      `json:"version,omitempty"`
	Nodes              []NodeScanResult             `json:"nodes"`
	Namespaces         []NamespaceScanResult        `json:"namespaces"`
	FluxDetected       bool                         `json:"fluxDetected,omitempty"`
	FluxKustomizations []FluxKustomizationResult    `json:"fluxKustomizations,omitempty"`
}

// NodeScanResult matches the edge-ingest NodeScanResult.
type NodeScanResult struct {
	Name             string   `json:"name"`
	Status           string   `json:"status"`
	Roles            []string `json:"roles"`
	Version          string   `json:"version"`
	OS               string   `json:"os"`
	OSImage          string   `json:"os_image"`
	Arch             string   `json:"arch,omitempty"`
	CPUCores         int      `json:"cpu_cores,omitempty"`
	MemoryBytes      int64    `json:"memory_bytes,omitempty"`
	ContainerRuntime string   `json:"container_runtime,omitempty"`
	InternalIP       string   `json:"internal_ip,omitempty"`
	ExternalIP       string   `json:"external_ip,omitempty"`
}

// NamespaceScanResult matches the edge-ingest NamespaceScanResult.
type NamespaceScanResult struct {
	Name              string                      `json:"name"`
	Labels            map[string]string            `json:"labels"`
	Workloads         []WorkloadScanResult         `json:"workloads"`
	Services          []K8sServiceScanResult       `json:"services"`
	Ingresses         []IngressScanResult          `json:"ingresses"`
	ConfigMaps        []ConfigMapScanResult        `json:"configMaps"`
	Secrets           []SecretScanResult           `json:"secrets"`
	PVCs              []PVCScanResult              `json:"pvcs"`
	CronJobs          []CronJobScanResult          `json:"cronJobs"`
	NetworkPolicies   []NetworkPolicyScanResult    `json:"networkPolicies"`
	PDBs              []PDBScanResult              `json:"pdbs"`
	ExternalSecrets   []ExternalSecretScanResult   `json:"externalSecrets"`
}

// WorkloadScanResult matches the edge-ingest WorkloadScanResult.
type WorkloadScanResult struct {
	Name                   string                `json:"name"`
	Namespace              string                `json:"namespace"`
	Kind                   string                `json:"kind"`
	Replicas               *int32                `json:"replicas,omitempty"`
	ReadyReplicas          *int32                `json:"readyReplicas,omitempty"`
	AvailableReplicas      *int32                `json:"availableReplicas,omitempty"`
	DesiredNumberScheduled *int32                `json:"desiredNumberScheduled,omitempty"`
	NumberReady            *int32                `json:"numberReady,omitempty"`
	Strategy               string                `json:"strategy,omitempty"`
	Containers             []ContainerInfoK8s    `json:"containers"`
	Requests               *ResourceRequirements `json:"requests,omitempty"`
	Limits                 *ResourceRequirements `json:"limits,omitempty"`
}

// ContainerInfoK8s matches the edge-ingest ContainerInfo.
type ContainerInfoK8s struct {
	Name  string `json:"name"`
	Image string `json:"image"`
}

// ResourceRequirements for CPU/memory.
type ResourceRequirements struct {
	CPUMillicores int64 `json:"cpu_millicores"`
	MemoryBytes   int64 `json:"memory_bytes"`
}

// K8sServiceScanResult matches the edge-ingest K8sServiceScanResult.
type K8sServiceScanResult struct {
	Name        string              `json:"name"`
	Namespace   string              `json:"namespace"`
	Type        string              `json:"type"`
	ClusterIP   string              `json:"clusterIP"`
	Ports       []ServicePort       `json:"ports"`
	Selector    map[string]string   `json:"selector"`
	ExternalIPs []string            `json:"externalIPs,omitempty"`
}

// ServicePort matches the edge-ingest port shape.
type ServicePort struct {
	Name       string `json:"name,omitempty"`
	Protocol   string `json:"protocol"`
	Port       int32  `json:"port"`
	TargetPort string `json:"targetPort"`
	NodePort   int32  `json:"nodePort,omitempty"`
}

// IngressScanResult matches the edge-ingest IngressScanResult.
type IngressScanResult struct {
	Name         string         `json:"name"`
	Namespace    string         `json:"namespace"`
	IngressClass string         `json:"ingressClass,omitempty"`
	Rules        []IngressRule  `json:"rules"`
	TLS          []IngressTLS   `json:"tls,omitempty"`
}

// IngressRule matches the edge-ingest IngressRule.
type IngressRule struct {
	Host  string        `json:"host"`
	Paths []IngressPath `json:"paths"`
}

// IngressPath matches the edge-ingest path shape.
type IngressPath struct {
	Path    string `json:"path"`
	Backend string `json:"backend"`
	Port    string `json:"port"`
}

// IngressTLS holds TLS config for an ingress.
type IngressTLS struct {
	Hosts      []string `json:"hosts"`
	SecretName string   `json:"secretName"`
}

// ConfigMapScanResult matches the edge-ingest ConfigMapScanResult.
type ConfigMapScanResult struct {
	Name      string   `json:"name"`
	Namespace string   `json:"namespace"`
	DataKeys  []string `json:"dataKeys"`
}

// SecretScanResult matches the edge-ingest SecretScanResult.
type SecretScanResult struct {
	Name      string   `json:"name"`
	Namespace string   `json:"namespace"`
	Type      string   `json:"type"`
	DataKeys  []string `json:"dataKeys"`
}

// PVCScanResult matches the edge-ingest PVCScanResult.
type PVCScanResult struct {
	Name         string   `json:"name"`
	Namespace    string   `json:"namespace"`
	StorageClass string   `json:"storageClass"`
	AccessModes  []string `json:"accessModes"`
	Capacity     string   `json:"capacity"`
	Status       string   `json:"status"`
}

// CronJobScanResult matches the edge-ingest CronJobScanResult.
type CronJobScanResult struct {
	Name             string  `json:"name"`
	Namespace        string  `json:"namespace"`
	Schedule         string  `json:"schedule"`
	Suspend          bool    `json:"suspend"`
	LastScheduleTime *string `json:"lastScheduleTime,omitempty"`
}

// NetworkPolicyScanResult matches the edge-ingest NetworkPolicyScanResult.
type NetworkPolicyScanResult struct {
	Name        string                 `json:"name"`
	Namespace   string                 `json:"namespace"`
	PodSelector map[string]interface{} `json:"podSelector"`
	PolicyTypes []string               `json:"policyTypes"`
}

// PDBScanResult matches the edge-ingest PDBScanResult.
type PDBScanResult struct {
	Name           string                 `json:"name"`
	Namespace      string                 `json:"namespace"`
	MinAvailable   *string                `json:"minAvailable,omitempty"`
	MaxUnavailable *string                `json:"maxUnavailable,omitempty"`
	Selector       map[string]interface{} `json:"selector"`
}

// ExternalSecretScanResult matches the edge-ingest ExternalSecretScanResult.
type ExternalSecretScanResult struct {
	Name            string                 `json:"name"`
	Namespace       string                 `json:"namespace"`
	SecretStoreName string                 `json:"secretStoreName"`
	SecretStoreKind string                 `json:"secretStoreKind"`
	RefreshInterval string                 `json:"refreshInterval"`
	Target          map[string]interface{} `json:"target"`
}

// FluxKustomizationResult matches the edge-ingest FluxKustomizationScanResult.
type FluxKustomizationResult struct {
	Name            string                 `json:"name"`
	Path            string                 `json:"path"`
	TargetNamespace string                 `json:"targetNamespace"`
	SourceRef       map[string]interface{} `json:"sourceRef"`
	Interval        string                 `json:"interval"`
	Prune           bool                   `json:"prune"`
}
