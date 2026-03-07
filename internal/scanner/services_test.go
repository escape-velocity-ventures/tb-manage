package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

// servicesMockRunner implements CommandRunner for services tests.
// Separate from gpu_linux_test.go's mockCommandRunner to avoid
// redefinition on Linux where both files compile.
type servicesMockRunner struct {
	responses map[string]servicesMockResp
}

type servicesMockResp struct {
	output []byte
	err    error
}

func (m *servicesMockRunner) Run(_ context.Context, cmd string) ([]byte, error) {
	if resp, ok := m.responses[cmd]; ok {
		return resp.output, resp.err
	}
	return nil, fmt.Errorf("command not found: %s", cmd)
}

func TestParseVBoxManageList(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect []VMInstance
	}{
		{
			name:  "two VMs",
			input: "\"Ubuntu Server\" {a1b2c3d4-e5f6-7890-abcd-ef1234567890}\n\"Windows 11\" {f0e1d2c3-b4a5-6789-0abc-def012345678}\n",
			expect: []VMInstance{
				{Name: "Ubuntu Server", Status: "unknown", UUID: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
				{Name: "Windows 11", Status: "unknown", UUID: "f0e1d2c3-b4a5-6789-0abc-def012345678"},
			},
		},
		{
			name:   "empty output",
			input:  "",
			expect: nil,
		},
		{
			name:   "malformed line",
			input:  "garbage without quotes\n",
			expect: nil,
		},
		{
			name:  "single VM no UUID braces",
			input: "\"TestVM\" no-braces\n",
			expect: []VMInstance{
				{Name: "TestVM", Status: "unknown", UUID: ""},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseVBoxManageList(tc.input)
			assertVMInstances(t, got, tc.expect)
		})
	}
}

func TestParseVmrunList(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect []VMInstance
	}{
		{
			name:  "two running VMs",
			input: "Total running VMs: 2\n/Users/ben/VMs/Ubuntu.vmwarevm/Ubuntu.vmx\n/Users/ben/VMs/CentOS.vmwarevm/CentOS.vmx\n",
			expect: []VMInstance{
				{Name: "Ubuntu", Status: "running"},
				{Name: "CentOS", Status: "running"},
			},
		},
		{
			name:   "no VMs running",
			input:  "Total running VMs: 0\n",
			expect: nil,
		},
		{
			name:   "empty output",
			input:  "",
			expect: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseVmrunList(tc.input)
			assertVMInstances(t, got, tc.expect)
		})
	}
}

func TestParsePrlctlList(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect []VMInstance
	}{
		{
			name:  "mixed status VMs",
			input: "UUID                                    STATUS       IP_ADDR         NAME\n{a1b2c3d4-e5f6-7890-abcd-ef1234567890} running - Ubuntu 22.04\n{f0e1d2c3-b4a5-6789-0abc-def012345678} stopped - Windows 11\n",
			expect: []VMInstance{
				{Name: "Ubuntu 22.04", Status: "running", UUID: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
				{Name: "Windows 11", Status: "stopped", UUID: "f0e1d2c3-b4a5-6789-0abc-def012345678"},
			},
		},
		{
			name:   "header only",
			input:  "UUID                                    STATUS       IP_ADDR         NAME\n",
			expect: nil,
		},
		{
			name:   "empty output",
			input:  "",
			expect: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parsePrlctlList(tc.input)
			assertVMInstances(t, got, tc.expect)
		})
	}
}

func TestParseUtmctlList(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect []VMInstance
	}{
		{
			name:  "two VMs",
			input: "UUID  Name  Status\nA1B2C3D4-E5F6-7890-ABCD-EF1234567890 Ubuntu Server started\nF0E1D2C3-B4A5-6789-0ABC-DEF012345678 Fedora 39 stopped\n",
			expect: []VMInstance{
				{Name: "Ubuntu Server", Status: "started", UUID: "A1B2C3D4-E5F6-7890-ABCD-EF1234567890"},
				{Name: "Fedora 39", Status: "stopped", UUID: "F0E1D2C3-B4A5-6789-0ABC-DEF012345678"},
			},
		},
		{
			name:   "header only",
			input:  "UUID  Name  Status\n",
			expect: nil,
		},
		{
			name:   "empty output",
			input:  "",
			expect: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseUtmctlList(tc.input)
			assertVMInstances(t, got, tc.expect)
		})
	}
}

func TestParseLimaList(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect []VMInstance
	}{
		{
			name:  "two instances",
			input: "default\tRunning\nk3s\tStopped\n",
			expect: []VMInstance{
				{Name: "default", Status: "running"},
				{Name: "k3s", Status: "stopped"},
			},
		},
		{
			name:   "empty output",
			input:  "",
			expect: nil,
		},
		{
			name:   "no tab separator",
			input:  "malformed line\n",
			expect: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseLimaList(tc.input)
			assertVMInstances(t, got, tc.expect)
		})
	}
}

func TestParseMultipassList(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect []VMInstance
	}{
		{
			name:  "two instances",
			input: "Name,State,IPv4,Image\nprimary,Running,192.168.64.2,Ubuntu 22.04 LTS\ndev,Stopped,,Ubuntu 24.04 LTS\n",
			expect: []VMInstance{
				{Name: "primary", Status: "running"},
				{Name: "dev", Status: "stopped"},
			},
		},
		{
			name:   "header only",
			input:  "Name,State,IPv4,Image\n",
			expect: nil,
		},
		{
			name:   "empty output",
			input:  "",
			expect: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseMultipassList(tc.input)
			assertVMInstances(t, got, tc.expect)
		})
	}
}

func TestServicesScanner_ImplementsInterface(t *testing.T) {
	var _ Scanner = NewServicesScanner()
}

func TestServicesScanner_Name(t *testing.T) {
	s := NewServicesScanner()
	if s.Name() != "services" {
		t.Errorf("Name(): got %q, want %q", s.Name(), "services")
	}
}

func TestServicesScanner_Platforms(t *testing.T) {
	s := NewServicesScanner()
	if p := s.Platforms(); p != nil {
		t.Errorf("Platforms(): got %v, want nil (all platforms)", p)
	}
}

func TestServicesScanner_ScanReturnsValidJSON(t *testing.T) {
	// All commands fail -> minimal but valid JSON
	runner := &servicesMockRunner{responses: map[string]servicesMockResp{}}
	s := NewServicesScanner()
	data, err := s.Scan(t.Context(), runner)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	var info ServicesInfo
	if err := json.Unmarshal(data, &info); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	// Should still have valid (empty) structure
	if info.KubeletRunning {
		t.Error("KubeletRunning should be false when pgrep fails")
	}
}

func TestParseVersionString(t *testing.T) {
	tests := []struct {
		tool, raw, expect string
	}{
		{"go", "go version go1.22.0 darwin/arm64", "1.22.0"},
		{"node", "v20.11.0", "20.11.0"},
		{"bun", "v1.0.25", "1.0.25"},
		{"python3", "Python 3.12.0", "3.12.0"},
		{"rustc", "rustc 1.75.0 (82e1608df 2023-12-21)", "1.75.0"},
		{"helm", "v3.14.0+g3fc9f4b", "3.14.0"},
		{"terraform", `{"terraform_version":"1.7.0","platform":"darwin_arm64"}`, "1.7.0"},
		{"unknown", "some version output", "some version output"},
		{"go", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.tool+"_"+tc.raw, func(t *testing.T) {
			got := parseVersionString(tc.tool, tc.raw)
			if got != tc.expect {
				t.Errorf("parseVersionString(%q, %q) = %q, want %q", tc.tool, tc.raw, got, tc.expect)
			}
		})
	}
}

func TestResultSet_Services(t *testing.T) {
	r := NewResult()
	data := json.RawMessage(`{"platforms":[],"kubelet_running":false}`)
	r.Set("services", data)

	if r.Services == nil {
		t.Fatal("Services should be set after Set(\"services\", ...)")
	}
	if string(r.Services) != string(data) {
		t.Errorf("Services: got %s, want %s", r.Services, data)
	}
}

// assertVMInstances compares two VMInstance slices.
func assertVMInstances(t *testing.T, got, expect []VMInstance) {
	t.Helper()
	if len(got) != len(expect) {
		t.Fatalf("got %d VMs, want %d\ngot: %+v", len(got), len(expect), got)
	}
	for i := range expect {
		if got[i].Name != expect[i].Name {
			t.Errorf("[%d] Name: got %q, want %q", i, got[i].Name, expect[i].Name)
		}
		if got[i].Status != expect[i].Status {
			t.Errorf("[%d] Status: got %q, want %q", i, got[i].Status, expect[i].Status)
		}
		if got[i].UUID != expect[i].UUID {
			t.Errorf("[%d] UUID: got %q, want %q", i, got[i].UUID, expect[i].UUID)
		}
	}
}
