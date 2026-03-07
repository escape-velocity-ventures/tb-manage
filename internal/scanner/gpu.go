package scanner

import (
	"context"
	"encoding/json"
)

// GPUInfo is the data collected by the GPU scanner.
type GPUInfo struct {
	GPUs []GPUDevice `json:"gpus"`
}

// GPUDevice represents a single GPU.
type GPUDevice struct {
	Type              string `json:"type"`                         // nvidia, amd, intel, apple
	Platform          string `json:"platform"`                     // tegra, discrete, apple-gpu
	Model             string `json:"model"`
	MemoryMB          int    `json:"memory_mb,omitempty"`
	Driver            string `json:"driver,omitempty"`
	ComputeCapability string `json:"compute_capability,omitempty"`
	Index             int    `json:"index"`
}

// GPUScanner detects GPU hardware.
type GPUScanner struct{}

// NewGPUScanner creates a new GPUScanner.
func NewGPUScanner() *GPUScanner {
	return &GPUScanner{}
}

func (s *GPUScanner) Name() string       { return "gpu" }
func (s *GPUScanner) Platforms() []string { return nil } // delegates to platform-specific impl

func (s *GPUScanner) Scan(ctx context.Context, runner CommandRunner) (json.RawMessage, error) {
	info := collectGPUInfo(ctx, runner)
	return json.Marshal(info)
}
