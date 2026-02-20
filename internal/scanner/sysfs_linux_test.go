package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectHostInterfacesFromProcNetDev(t *testing.T) {
	// Create a fake /proc/1/net/dev file
	root := t.TempDir()
	devPath := filepath.Join(root, "proc", "1", "net")
	if err := os.MkdirAll(devPath, 0o755); err != nil {
		t.Fatal(err)
	}

	// Real /proc/net/dev content from worker1
	content := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  cni0: 783649833831 194887922    0    0    0     0          0         0 505776602885 276040021    0    0    0     0       0          0
  eth0: 452698464934 709126800 146203 1687775    0     0          0    103949 983787744722 955845802    0    0    0     0       0          0
flannel.1: 202264510440 140570370    0    0    0     0          0         0 715068220544 102315614    0    0    0    28       0          0
    lo: 232655232168 408740959    0    0    0     0          0         0 232655232168 408740959    0    0    0     0       0          0
veth75825756: 72475154  298752    0    0    0     0          0         0 41952077  400385    0    0    0     0       0          0
`
	if err := os.WriteFile(filepath.Join(devPath, "dev"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	ifaces := collectHostInterfaces(filepath.Join(devPath, "dev"))

	if len(ifaces) != 5 {
		t.Fatalf("expected 5 interfaces, got %d: %+v", len(ifaces), ifaces)
	}

	// Build lookup
	byName := make(map[string]InterfaceInfo)
	for _, iface := range ifaces {
		byName[iface.Name] = iface
	}

	// Check expected interfaces
	for _, expected := range []string{"cni0", "eth0", "flannel.1", "lo", "veth75825756"} {
		if _, ok := byName[expected]; !ok {
			t.Errorf("missing interface %q", expected)
		}
	}
}

func TestCollectHostInterfacesNonexistentPath(t *testing.T) {
	ifaces := collectHostInterfaces("/nonexistent/path")
	if ifaces != nil {
		t.Errorf("expected nil for nonexistent path, got %d interfaces", len(ifaces))
	}
}

func TestHostProcNetDev(t *testing.T) {
	// No HOST_ROOT set
	t.Setenv("HOST_ROOT", "")
	if got := hostProcNetDev(); got != "" {
		t.Errorf("expected empty, got %q", got)
	}

	// HOST_ROOT set
	t.Setenv("HOST_ROOT", "/host")
	if got := hostProcNetDev(); got != "/host/proc/1/net/dev" {
		t.Errorf("expected /host/proc/1/net/dev, got %q", got)
	}
}
