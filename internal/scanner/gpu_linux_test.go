package scanner

import (
	"context"
	"fmt"
	"testing"
)

func TestParseNvidiaSMILine(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		expect *GPUDevice
	}{
		{
			name: "RTX 3080",
			line: "0, NVIDIA GeForce RTX 3080, 10240, 535.183.01, 8.6",
			expect: &GPUDevice{
				Type:              "nvidia",
				Platform:          "discrete",
				Model:             "NVIDIA GeForce RTX 3080",
				MemoryMB:          10240,
				Driver:            "535.183.01",
				ComputeCapability: "8.6",
				Index:             0,
			},
		},
		{
			name: "A100",
			line: "0, NVIDIA A100-SXM4-80GB, 81920, 535.129.03, 8.0",
			expect: &GPUDevice{
				Type:              "nvidia",
				Platform:          "discrete",
				Model:             "NVIDIA A100-SXM4-80GB",
				MemoryMB:          81920,
				Driver:            "535.129.03",
				ComputeCapability: "8.0",
				Index:             0,
			},
		},
		{
			name: "second GPU",
			line: "1, NVIDIA GeForce RTX 4090, 24564, 545.29.06, 8.9",
			expect: &GPUDevice{
				Type:              "nvidia",
				Platform:          "discrete",
				Model:             "NVIDIA GeForce RTX 4090",
				MemoryMB:          24564,
				Driver:            "545.29.06",
				ComputeCapability: "8.9",
				Index:             1,
			},
		},
		{
			name:   "too few fields",
			line:   "0, NVIDIA GeForce",
			expect: nil,
		},
		{
			name:   "bad index",
			line:   "x, NVIDIA GeForce, 1024, 535.0, 8.0",
			expect: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseNvidiaSMILine(tc.line)
			if tc.expect == nil {
				if got != nil {
					t.Errorf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil result")
			}
			if got.Type != tc.expect.Type {
				t.Errorf("type: got %q, want %q", got.Type, tc.expect.Type)
			}
			if got.Platform != tc.expect.Platform {
				t.Errorf("platform: got %q, want %q", got.Platform, tc.expect.Platform)
			}
			if got.Model != tc.expect.Model {
				t.Errorf("model: got %q, want %q", got.Model, tc.expect.Model)
			}
			if got.MemoryMB != tc.expect.MemoryMB {
				t.Errorf("memory: got %d, want %d", got.MemoryMB, tc.expect.MemoryMB)
			}
			if got.Driver != tc.expect.Driver {
				t.Errorf("driver: got %q, want %q", got.Driver, tc.expect.Driver)
			}
			if got.ComputeCapability != tc.expect.ComputeCapability {
				t.Errorf("compute_cap: got %q, want %q", got.ComputeCapability, tc.expect.ComputeCapability)
			}
			if got.Index != tc.expect.Index {
				t.Errorf("index: got %d, want %d", got.Index, tc.expect.Index)
			}
		})
	}
}

func TestParseLspciLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		index    int
		expect   *GPUDevice
	}{
		{
			name:  "NVIDIA discrete",
			line:  "01:00.0 VGA compatible controller: NVIDIA Corporation GeForce RTX 3080 (rev a1)",
			index: 0,
			expect: &GPUDevice{
				Type:     "nvidia",
				Platform: "discrete",
				Model:    "NVIDIA Corporation GeForce RTX 3080 (rev a1)",
				Index:    0,
			},
		},
		{
			name:  "AMD Radeon",
			line:  "06:00.0 VGA compatible controller: Advanced Micro Devices, Inc. [AMD/ATI] Navi 21 [Radeon RX 6800/6800 XT / 6900 XT]",
			index: 1,
			expect: &GPUDevice{
				Type:     "amd",
				Platform: "discrete",
				Model:    "Advanced Micro Devices, Inc. [AMD/ATI] Navi 21 [Radeon RX 6800/6800 XT / 6900 XT]",
				Index:    1,
			},
		},
		{
			name:  "Intel integrated",
			line:  "00:02.0 VGA compatible controller: Intel Corporation UHD Graphics 630",
			index: 0,
			expect: &GPUDevice{
				Type:     "intel",
				Platform: "discrete",
				Model:    "Intel Corporation UHD Graphics 630",
				Index:    0,
			},
		},
		{
			name:   "no colon separator",
			line:   "garbage line",
			index:  0,
			expect: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseLspciLine(tc.line, tc.index)
			if tc.expect == nil {
				if got != nil {
					t.Errorf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil result")
			}
			if got.Type != tc.expect.Type {
				t.Errorf("type: got %q, want %q", got.Type, tc.expect.Type)
			}
			if got.Model != tc.expect.Model {
				t.Errorf("model: got %q, want %q", got.Model, tc.expect.Model)
			}
			if got.Index != tc.expect.Index {
				t.Errorf("index: got %d, want %d", got.Index, tc.expect.Index)
			}
		})
	}
}

func TestDetectTegraWithMockRunner(t *testing.T) {
	runner := &mockCommandRunner{
		responses: map[string]mockResponse{
			"cat /proc/device-tree/compatible 2>/dev/null": {
				output: []byte("nvidia,p3768-0000+p3767-0005\x00nvidia,tegra234\x00"),
			},
			"cat /proc/device-tree/model 2>/dev/null": {
				output: []byte("NVIDIA Jetson Orin NX Engineering Reference Developer Kit\x00"),
			},
			"nvidia-smi --query-gpu=memory.total,driver_version --format=csv,noheader,nounits 2>/dev/null": {
				output: []byte("7611, 36.4.0\n"),
			},
		},
	}

	gpus := detectTegra(t.Context(), runner)
	if len(gpus) != 1 {
		t.Fatalf("expected 1 GPU, got %d", len(gpus))
	}

	gpu := gpus[0]
	if gpu.Type != "nvidia" {
		t.Errorf("type: got %q, want %q", gpu.Type, "nvidia")
	}
	if gpu.Platform != "tegra" {
		t.Errorf("platform: got %q, want %q", gpu.Platform, "tegra")
	}
	if gpu.Model != "NVIDIA Jetson Orin NX Engineering Reference Developer Kit" {
		t.Errorf("model: got %q", gpu.Model)
	}
	if gpu.MemoryMB != 7611 {
		t.Errorf("memory: got %d, want 7611", gpu.MemoryMB)
	}
	if gpu.Driver != "36.4.0" {
		t.Errorf("driver: got %q, want %q", gpu.Driver, "36.4.0")
	}
}

func TestDetectTegraWithoutNvidiaSMI(t *testing.T) {
	runner := &mockCommandRunner{
		responses: map[string]mockResponse{
			"cat /proc/device-tree/compatible 2>/dev/null": {
				output: []byte("nvidia,p3509-0000+p3668-0001\x00nvidia,tegra194\x00"),
			},
			"cat /proc/device-tree/model 2>/dev/null": {
				output: []byte("NVIDIA Jetson Xavier NX Developer Kit\x00"),
			},
		},
	}

	gpus := detectTegra(t.Context(), runner)
	if len(gpus) != 1 {
		t.Fatalf("expected 1 GPU, got %d", len(gpus))
	}

	gpu := gpus[0]
	if gpu.Model != "NVIDIA Jetson Xavier NX Developer Kit" {
		t.Errorf("model: got %q", gpu.Model)
	}
	if gpu.MemoryMB != 0 {
		t.Errorf("memory should be 0 without nvidia-smi, got %d", gpu.MemoryMB)
	}
	if gpu.Driver != "" {
		t.Errorf("driver should be empty without nvidia-smi, got %q", gpu.Driver)
	}
}

func TestDetectTegraNotPresent(t *testing.T) {
	runner := &mockCommandRunner{
		responses: map[string]mockResponse{
			"cat /proc/device-tree/compatible 2>/dev/null": {
				output: []byte("raspberrypi,4-model-b\x00brcm,bcm2711\x00"),
			},
		},
	}

	gpus := detectTegra(t.Context(), runner)
	if len(gpus) != 0 {
		t.Errorf("expected 0 GPUs for non-Tegra device, got %d", len(gpus))
	}
}

func TestDetectNvidiaSMIMultiGPU(t *testing.T) {
	runner := &mockCommandRunner{
		responses: map[string]mockResponse{
			"nvidia-smi --query-gpu=index,name,memory.total,driver_version,compute_cap --format=csv,noheader,nounits 2>/dev/null": {
				output: []byte("0, NVIDIA A100-SXM4-80GB, 81920, 535.129.03, 8.0\n1, NVIDIA A100-SXM4-80GB, 81920, 535.129.03, 8.0\n"),
			},
		},
	}

	gpus := detectNvidiaSMI(t.Context(), runner)
	if len(gpus) != 2 {
		t.Fatalf("expected 2 GPUs, got %d", len(gpus))
	}
	if gpus[0].Index != 0 {
		t.Errorf("first GPU index: got %d, want 0", gpus[0].Index)
	}
	if gpus[1].Index != 1 {
		t.Errorf("second GPU index: got %d, want 1", gpus[1].Index)
	}
}

func TestCollectGPUInfoEmpty(t *testing.T) {
	// All commands fail → empty GPUInfo
	runner := &mockCommandRunner{responses: map[string]mockResponse{}}
	info := collectGPUInfo(t.Context(), runner)
	if len(info.GPUs) != 0 {
		t.Errorf("expected 0 GPUs when all detection fails, got %d", len(info.GPUs))
	}
}

// mockCommandRunner implements CommandRunner for tests.
type mockCommandRunner struct {
	responses map[string]mockResponse
}

type mockResponse struct {
	output []byte
	err    error
}

func (m *mockCommandRunner) Run(_ context.Context, cmd string) ([]byte, error) {
	if resp, ok := m.responses[cmd]; ok {
		return resp.output, resp.err
	}
	return nil, fmt.Errorf("command not found: %s", cmd)
}
