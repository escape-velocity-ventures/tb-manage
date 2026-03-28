package scanner

import (
	"context"
	"strconv"
	"strings"
)

func collectGPUInfo(ctx context.Context, runner CommandRunner) GPUInfo {
	info := GPUInfo{}

	// 1. Tegra/Jetson: check device-tree for integrated NVIDIA SoC
	tegra := detectTegra(ctx, runner)
	if len(tegra) > 0 {
		info.GPUs = append(info.GPUs, tegra...)
	}

	// 2. Discrete NVIDIA: nvidia-smi CSV output
	// Skip if Tegra was found — detectTegra already used nvidia-smi for enrichment,
	// and running it again would add a duplicate tagged "discrete".
	if len(tegra) == 0 {
		if gpus := detectNvidiaSMI(ctx, runner); len(gpus) > 0 {
			info.GPUs = append(info.GPUs, gpus...)
		}
	}

	// 3. Fallback: lspci for any GPU not already found
	if len(info.GPUs) == 0 {
		if gpus := detectLspci(ctx, runner); len(gpus) > 0 {
			info.GPUs = append(info.GPUs, gpus...)
		}
	}

	return info
}

// detectTegra reads /proc/device-tree/compatible for nvidia,tegra* entries.
func detectTegra(ctx context.Context, runner CommandRunner) []GPUDevice {
	out, err := runner.Run(ctx, "cat /proc/device-tree/compatible 2>/dev/null")
	if err != nil {
		return nil
	}

	// compatible is null-separated strings
	compat := string(out)
	if !strings.Contains(compat, "nvidia,tegra") {
		return nil
	}

	model := "NVIDIA Tegra"
	if mout, err := runner.Run(ctx, "cat /proc/device-tree/model 2>/dev/null"); err == nil {
		m := strings.TrimRight(string(mout), "\x00\n ")
		if m != "" {
			model = m
		}
	}

	dev := GPUDevice{
		Type:     "nvidia",
		Platform: "tegra",
		Model:    model,
		Index:    0,
	}

	// JetPack 6+ has nvidia-smi — try for memory/driver
	if out, err := runner.Run(ctx, "nvidia-smi --query-gpu=memory.total,driver_version --format=csv,noheader,nounits 2>/dev/null"); err == nil {
		fields := strings.Split(strings.TrimSpace(string(out)), ", ")
		if len(fields) >= 2 {
			if mem, err := strconv.Atoi(strings.TrimSpace(fields[0])); err == nil {
				dev.MemoryMB = mem
			}
			dev.Driver = strings.TrimSpace(fields[1])
		}
	}

	return []GPUDevice{dev}
}

// detectNvidiaSMI parses nvidia-smi CSV for discrete GPUs.
func detectNvidiaSMI(ctx context.Context, runner CommandRunner) []GPUDevice {
	out, err := runner.Run(ctx, "nvidia-smi --query-gpu=index,name,memory.total,driver_version,compute_cap --format=csv,noheader,nounits 2>/dev/null")
	if err != nil {
		return nil
	}

	var gpus []GPUDevice
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		gpu := parseNvidiaSMILine(line)
		if gpu != nil {
			gpus = append(gpus, *gpu)
		}
	}
	return gpus
}

// parseNvidiaSMILine parses a single CSV line: index, name, memory.total, driver_version, compute_cap
func parseNvidiaSMILine(line string) *GPUDevice {
	fields := strings.Split(line, ", ")
	if len(fields) < 5 {
		return nil
	}

	idx, err := strconv.Atoi(strings.TrimSpace(fields[0]))
	if err != nil {
		return nil
	}

	dev := &GPUDevice{
		Type:     "nvidia",
		Platform: "discrete",
		Model:    strings.TrimSpace(fields[1]),
		Index:    idx,
	}

	if mem, err := strconv.Atoi(strings.TrimSpace(fields[2])); err == nil {
		dev.MemoryMB = mem
	}
	dev.Driver = strings.TrimSpace(fields[3])
	dev.ComputeCapability = strings.TrimSpace(fields[4])

	return dev
}

// detectLspci uses lspci as a last-resort GPU detector.
func detectLspci(ctx context.Context, runner CommandRunner) []GPUDevice {
	out, err := runner.Run(ctx, `lspci 2>/dev/null | grep -iE 'vga|3d|display'`)
	if err != nil {
		return nil
	}

	var gpus []GPUDevice
	for i, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		gpu := parseLspciLine(line, i)
		if gpu != nil {
			gpus = append(gpus, *gpu)
		}
	}
	return gpus
}

// parseLspciLine extracts GPU type and model from an lspci line.
// Format: "XX:XX.X VGA compatible controller: NVIDIA Corporation GeForce RTX 3080 (rev a1)"
func parseLspciLine(line string, index int) *GPUDevice {
	// Split on first ": " to separate address+class from device description
	parts := strings.SplitN(line, ": ", 2)
	if len(parts) < 2 {
		return nil
	}
	desc := parts[1]

	dev := &GPUDevice{
		Platform: "discrete",
		Model:    desc,
		Index:    index,
	}

	lower := strings.ToLower(desc)
	switch {
	case strings.Contains(lower, "nvidia"):
		dev.Type = "nvidia"
	case strings.Contains(lower, "amd") || strings.Contains(lower, "radeon"):
		dev.Type = "amd"
	case strings.Contains(lower, "intel"):
		dev.Type = "intel"
	default:
		dev.Type = "unknown"
	}

	return dev
}
