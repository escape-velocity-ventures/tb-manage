package scanner

// RegistryOptions configures scanner construction.
type RegistryOptions struct {
	ExcludeNamespaces []string
}

// Registry maps profiles to their scanners.
type Registry struct {
	scanners map[Profile][]Scanner
}

// NewRegistry creates a registry with all known scanners assigned to profiles.
func NewRegistry() *Registry {
	return NewRegistryWithOptions(RegistryOptions{})
}

// NewRegistryWithOptions creates a registry with custom options.
func NewRegistryWithOptions(opts RegistryOptions) *Registry {
	r := &Registry{
		scanners: make(map[Profile][]Scanner),
	}

	// Build k8s scanner with exclusion config
	var k8s *K8sScanner
	if len(opts.ExcludeNamespaces) > 0 {
		k8s = NewK8sScannerWithExclusions(opts.ExcludeNamespaces)
	} else {
		k8s = NewK8sScanner()
	}

	// Minimal: just host info
	minimal := []Scanner{
		NewHostScanner(),
	}

	// Standard: host + network + storage + gpu + services + topology
	standard := append(minimal,
		NewNetworkScanner(),
		NewStorageScanner(),
		NewGPUScanner(),
		NewServicesScanner(),
	)

	// Full: standard + containers + k8s + power + iot
	full := append(standard,
		NewContainerScanner(),
		k8s,
		NewPowerScanner(),
		NewIoTScanner(),
	)

	r.scanners[ProfileMinimal] = minimal
	r.scanners[ProfileStandard] = standard
	r.scanners[ProfileFull] = full

	return r
}

// ForProfile returns the scanners for the given profile, filtered to the current platform.
func (r *Registry) ForProfile(p Profile) []Scanner {
	all := r.scanners[p]
	var result []Scanner
	for _, s := range all {
		if SupportsCurrentPlatform(s) {
			result = append(result, s)
		}
	}
	return result
}
