package scanner

import (
	"encoding/json"

	"github.com/tinkerbelle-io/tb-discover/internal/topology"
)

// ApplyTopology sets the host type based on network interface topology inference.
func ApplyTopology(result *Result) {
	if result.Host == nil || result.Network == nil {
		return
	}

	var netInfo NetworkInfo
	if err := json.Unmarshal(result.Network, &netInfo); err != nil {
		return
	}

	names := make([]string, len(netInfo.Interfaces))
	for i, iface := range netInfo.Interfaces {
		names[i] = iface.Name
	}

	nicSet := topology.ClassifyInterfaces(names)
	role := topology.InferRole(nicSet)

	var hostInfo HostInfo
	if err := json.Unmarshal(result.Host, &hostInfo); err != nil {
		return
	}

	hostInfo.Type = role.HostType()

	if updated, err := json.Marshal(hostInfo); err == nil {
		result.Host = updated
		result.Phases["host"] = updated
	}

	result.Meta.InferredRole = string(role)
}

// OverrideHostName replaces the host name in the scan result.
// In Kubernetes, the HostScanner's `hostname` command returns the pod name,
// not the node name. This function patches it with the real node name.
func OverrideHostName(result *Result, name string) {
	if result.Host == nil {
		return
	}

	var hostInfo HostInfo
	if err := json.Unmarshal(result.Host, &hostInfo); err != nil {
		return
	}

	hostInfo.Name = name

	if updated, err := json.Marshal(hostInfo); err == nil {
		result.Host = updated
		result.Phases["host"] = updated
	}
}
