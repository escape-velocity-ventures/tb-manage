package upload

import (
	"encoding/json"
	"math"

	"github.com/tinkerbelle-io/tb-manage/internal/scanner"
)

// BuildRequest converts scan results to an EdgeIngestRequest.
func BuildRequest(result *scanner.Result) *EdgeIngestRequest {
	req := &EdgeIngestRequest{
		Meta: EdgeIngestMeta{
			Version:    result.Meta.Version,
			DurationMS: result.Meta.DurationMS,
			Phases:     result.Meta.Phases,
			SourceHost: result.Meta.SourceHost,
		},
	}

	if result.Host != nil {
		var hostInfo scanner.HostInfo
		if err := json.Unmarshal(result.Host, &hostInfo); err == nil {
			host := &HostScanResult{
				Name: hostInfo.Name,
				Type: hostInfo.Type,
				System: HostSystem{
					OS:       hostInfo.System.OS,
					Arch:     hostInfo.System.Arch,
					CPUCores: hostInfo.System.CPUCores,
					MemoryGB: hostInfo.System.MemoryGB,
				},
				Network: HostNetwork{
					Hostname:   hostInfo.Name,
					Interfaces: []HostInterface{},
				},
			}

			if result.Network != nil {
				var netInfo scanner.NetworkInfo
				if err := json.Unmarshal(result.Network, &netInfo); err == nil {
					host.Network.PublicIP = netInfo.PublicIP
					host.Network.CloudProvider = netInfo.CloudProvider
					for _, iface := range netInfo.Interfaces {
						host.Network.Interfaces = append(host.Network.Interfaces, HostInterface{
							Name: iface.Name,
							IP:   iface.IP,
							MAC:  iface.MAC,
						})
					}
					// If cloud provider detected, override host type to "cloud"
					if netInfo.CloudProvider != "" && host.Type != "vm" {
						host.Type = "cloud"
					}
				}
			}

			host.Storage = result.Storage
			host.Containers = result.Containers
			host.GPU = result.GPU
			host.Services = result.Services

			req.Host = host
		}
	}

	if result.Network != nil {
		req.Network = result.Network
	}

	if result.Cluster != nil {
		req.Cluster = result.Cluster
	}

	return req
}

// BuildNodeHostRequests converts cluster node scan results into individual
// EdgeIngestRequests for host discovery. Each node becomes a minimal host
// entry with discovery_method="k8s_api".
func BuildNodeHostRequests(clusterData json.RawMessage, clusterName, version string) []*EdgeIngestRequest {
	var cluster scanner.ClusterScanResult
	if err := json.Unmarshal(clusterData, &cluster); err != nil {
		return nil
	}

	var requests []*EdgeIngestRequest
	for _, node := range cluster.Nodes {
		// Convert memory from bytes to GB (rounded to 1 decimal)
		memoryGB := math.Round(float64(node.MemoryBytes)/1073741824.0*10) / 10

		// Build primary IP from node addresses
		primaryIP := node.InternalIP
		if primaryIP == "" {
			primaryIP = node.ExternalIP
		}

		// Build interfaces from known IPs
		var interfaces []HostInterface
		if node.InternalIP != "" {
			interfaces = append(interfaces, HostInterface{Name: "internal", IP: node.InternalIP})
		}
		if node.ExternalIP != "" {
			interfaces = append(interfaces, HostInterface{Name: "external", IP: node.ExternalIP})
		}

		req := &EdgeIngestRequest{
			Host: &HostScanResult{
				Name:            node.Name,
				Type:            "baremetal",
				DiscoveryMethod: "k8s_api",
				System: HostSystem{
					OS:       node.OS,
					Arch:     node.Arch,
					CPUCores: node.CPUCores,
					MemoryGB: memoryGB,
				},
				Network: HostNetwork{
					Hostname:   node.Name,
					Interfaces: interfaces,
				},
				Kubernetes: &HostKubernetes{
					ClusterName: clusterName,
				},
			},
			Meta: EdgeIngestMeta{
				Version:    version,
				Phases:     []string{"k8s_node_discovery"},
				SourceHost: "controller",
			},
		}
		requests = append(requests, req)
	}
	return requests
}
