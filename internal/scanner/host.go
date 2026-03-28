package scanner

import (
	"context"
	"encoding/json"
	"os"
	"runtime"
	"strings"
)

// HostInfo is the data collected by the host scanner.
type HostInfo struct {
	Name   string     `json:"name"`
	Type   string     `json:"type"` // Set later by topology inference
	System SystemInfo `json:"system"`
}

// SystemInfo contains OS and hardware details.
type SystemInfo struct {
	OS           string  `json:"os"`
	OSVersion    string  `json:"os_version,omitempty"`
	Arch         string  `json:"arch"`
	CPUModel     string  `json:"cpu_model,omitempty"`
	CPUCores     int     `json:"cpu_cores"`
	MemoryGB     float64 `json:"memory_gb"`
	SerialNumber string  `json:"serial_number,omitempty"`
	MachineID    string  `json:"machine_id,omitempty"`
}

// junkSerials are DMI serial values that indicate no real serial is available.
var junkSerials = map[string]bool{
	"":                          true,
	"0":                         true,
	"none":                      true,
	"not specified":             true,
	"to be filled by o.e.m.":   true,
	"default string":           true,
	"system serial number":     true,
	"chassis serial number":    true,
}

// IsJunkSerial returns true if the serial is a known placeholder.
func IsJunkSerial(s string) bool {
	return junkSerials[strings.ToLower(strings.TrimSpace(s))]
}

// HostScanner collects basic host information.
type HostScanner struct{}

// NewHostScanner creates a new HostScanner.
func NewHostScanner() *HostScanner {
	return &HostScanner{}
}

func (s *HostScanner) Name() string        { return "host" }
func (s *HostScanner) Platforms() []string  { return nil } // all platforms
func (s *HostScanner) Scan(ctx context.Context, runner CommandRunner) (json.RawMessage, error) {
	hostname, _ := os.Hostname()

	info := HostInfo{
		Name: hostname,
		Type: "unknown", // Will be set by topology inference
		System: SystemInfo{
			OS:   runtime.GOOS,
			Arch: runtime.GOARCH,
		},
	}

	// Collect platform-specific data
	if err := collectHostInfo(ctx, runner, &info); err != nil {
		return nil, err
	}

	return json.Marshal(info)
}
