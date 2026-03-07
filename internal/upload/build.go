package upload

import (
	"encoding/json"

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
