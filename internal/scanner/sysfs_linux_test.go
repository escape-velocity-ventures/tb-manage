package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectHostInterfaces(t *testing.T) {
	// Create a fake sysfs tree
	root := t.TempDir()
	netDir := filepath.Join(root, "sys", "class", "net")

	// eth0 — physical NIC
	mkSysfsIface(t, netDir, "eth0", "aa:bb:cc:dd:ee:01", "1500", "up")
	// cali12345 — CNI interface
	mkSysfsIface(t, netDir, "cali12345abc", "ee:ee:ee:ee:ee:ee", "1450", "up")
	// flannel.1 — CNI overlay
	mkSysfsIface(t, netDir, "flannel.1", "fe:12:34:56:78:90", "1450", "up")
	// lo — loopback
	mkSysfsIface(t, netDir, "lo", "00:00:00:00:00:00", "65536", "unknown")

	sysfsPath := filepath.Join(root, "sys", "class", "net")
	ifaces := collectHostInterfaces(sysfsPath)

	if len(ifaces) != 4 {
		t.Fatalf("expected 4 interfaces, got %d", len(ifaces))
	}

	// Build lookup
	byName := make(map[string]InterfaceInfo)
	for _, iface := range ifaces {
		byName[iface.Name] = iface
	}

	// Check eth0
	if eth0, ok := byName["eth0"]; !ok {
		t.Error("missing eth0")
	} else {
		if eth0.MAC != "aa:bb:cc:dd:ee:01" {
			t.Errorf("eth0 MAC = %q, want %q", eth0.MAC, "aa:bb:cc:dd:ee:01")
		}
		if eth0.MTU != 1500 {
			t.Errorf("eth0 MTU = %d, want 1500", eth0.MTU)
		}
		if eth0.State != "up" {
			t.Errorf("eth0 state = %q, want up", eth0.State)
		}
	}

	// Check CNI interface present
	if _, ok := byName["cali12345abc"]; !ok {
		t.Error("missing cali12345abc")
	}
	if _, ok := byName["flannel.1"]; !ok {
		t.Error("missing flannel.1")
	}
}

func TestCollectHostInterfacesNonexistentPath(t *testing.T) {
	ifaces := collectHostInterfaces("/nonexistent/path")
	if ifaces != nil {
		t.Errorf("expected nil for nonexistent path, got %d interfaces", len(ifaces))
	}
}

func TestHostSysfsRoot(t *testing.T) {
	// No HOST_ROOT set
	t.Setenv("HOST_ROOT", "")
	if got := hostSysfsRoot(); got != "" {
		t.Errorf("expected empty, got %q", got)
	}

	// HOST_ROOT set
	t.Setenv("HOST_ROOT", "/host")
	if got := hostSysfsRoot(); got != "/host/sys/class/net" {
		t.Errorf("expected /host/sys/class/net, got %q", got)
	}
}

func mkSysfsIface(t *testing.T, netDir, name, mac, mtu, state string) {
	t.Helper()
	dir := filepath.Join(netDir, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeSysfsFile(t, dir, "address", mac)
	writeSysfsFile(t, dir, "mtu", mtu)
	writeSysfsFile(t, dir, "operstate", state)
}

func writeSysfsFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}
