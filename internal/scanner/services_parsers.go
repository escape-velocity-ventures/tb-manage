package scanner

import (
	"path/filepath"
	"strings"
)

// parseVBoxManageList parses `VBoxManage list vms` output.
// Format: "VM Name" {uuid}
func parseVBoxManageList(output string) []VMInstance {
	var vms []VMInstance
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Find quoted name and {uuid}
		nameStart := strings.Index(line, "\"")
		nameEnd := strings.LastIndex(line, "\"")
		if nameStart < 0 || nameEnd <= nameStart {
			continue
		}
		name := line[nameStart+1 : nameEnd]

		uuid := ""
		braceStart := strings.Index(line, "{")
		braceEnd := strings.Index(line, "}")
		if braceStart >= 0 && braceEnd > braceStart {
			uuid = line[braceStart+1 : braceEnd]
		}

		vms = append(vms, VMInstance{
			Name:   name,
			Status: "unknown",
			UUID:   uuid,
		})
	}
	return vms
}

// parseVmrunList parses `vmrun list` output.
// First line: "Total running VMs: N"
// Subsequent lines: full paths to .vmx files
func parseVmrunList(output string) []VMInstance {
	var vms []VMInstance
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Total running VMs:") {
			continue
		}
		// Extract VM name from path (e.g., /path/to/MyVM.vmwarevm/MyVM.vmx -> MyVM)
		base := filepath.Base(line)
		name := strings.TrimSuffix(base, filepath.Ext(base))
		vms = append(vms, VMInstance{
			Name:   name,
			Status: "running",
		})
	}
	return vms
}

// parsePrlctlList parses `prlctl list -a` output.
// Format: {uuid}  status  -  name
// First line is a header: UUID STATUS IP_ADDR NAME
func parsePrlctlList(output string) []VMInstance {
	var vms []VMInstance
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || i == 0 { // skip header
			continue
		}
		// Parse: {uuid}  status  -  name
		// UUID is enclosed in braces
		braceStart := strings.Index(line, "{")
		braceEnd := strings.Index(line, "}")
		if braceStart < 0 || braceEnd <= braceStart {
			continue
		}
		uuid := line[braceStart+1 : braceEnd]

		rest := strings.TrimSpace(line[braceEnd+1:])
		// rest is "status  -  name"
		parts := strings.SplitN(rest, " - ", 2)
		if len(parts) < 2 {
			continue
		}
		status := strings.TrimSpace(parts[0])
		name := strings.TrimSpace(parts[1])

		vms = append(vms, VMInstance{
			Name:   name,
			Status: status,
			UUID:   uuid,
		})
	}
	return vms
}

// parseUtmctlList parses `utmctl list` output.
// Format: uuid  name  status
// First line is a header
func parseUtmctlList(output string) []VMInstance {
	var vms []VMInstance
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || i == 0 { // skip header
			continue
		}
		// Split on whitespace, expect at least 3 fields: uuid name status
		// But name could contain spaces, so we need to be careful.
		// UTM format: UUID  Name  Status (tab or multi-space separated)
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		uuid := fields[0]
		status := fields[len(fields)-1]
		name := strings.Join(fields[1:len(fields)-1], " ")

		vms = append(vms, VMInstance{
			Name:   name,
			Status: strings.ToLower(status),
			UUID:   uuid,
		})
	}
	return vms
}

// parseLimaList parses `limactl list --format '{{.Name}}\t{{.Status}}'` output.
// Format: name\tstatus (TSV, no header)
func parseLimaList(output string) []VMInstance {
	var vms []VMInstance
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) < 2 {
			continue
		}
		vms = append(vms, VMInstance{
			Name:   strings.TrimSpace(parts[0]),
			Status: strings.ToLower(strings.TrimSpace(parts[1])),
		})
	}
	return vms
}

// parseMultipassList parses `multipass list --format csv` output.
// Format: Name,State,IPv4,Image (CSV with header)
func parseMultipassList(output string) []VMInstance {
	var vms []VMInstance
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || i == 0 { // skip header
			continue
		}
		fields := strings.SplitN(line, ",", 4)
		if len(fields) < 2 {
			continue
		}
		vms = append(vms, VMInstance{
			Name:   strings.TrimSpace(fields[0]),
			Status: strings.ToLower(strings.TrimSpace(fields[1])),
		})
	}
	return vms
}
