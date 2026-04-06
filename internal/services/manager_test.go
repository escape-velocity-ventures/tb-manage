package services

import (
	"fmt"
	"log/slog"
	"os"
	"testing"
)

// mockTmux implements TmuxBackend for testing.
type mockTmux struct {
	sessions map[string]bool
	started  []string // track start order
	stopped  []string
	startErr map[string]error
	stopErr  map[string]error
}

func newMockTmux() *mockTmux {
	return &mockTmux{
		sessions: make(map[string]bool),
		startErr: make(map[string]error),
		stopErr:  make(map[string]error),
	}
}

func (m *mockTmux) HasSession(name string) bool {
	return m.sessions[name]
}

func (m *mockTmux) StartSession(name, command string) error {
	if err, ok := m.startErr[name]; ok {
		return err
	}
	m.sessions[name] = true
	m.started = append(m.started, name)
	return nil
}

func (m *mockTmux) StopSession(name string) error {
	if err, ok := m.stopErr[name]; ok {
		return err
	}
	delete(m.sessions, name)
	m.stopped = append(m.stopped, name)
	return nil
}

func (m *mockTmux) ListSessions() []string {
	var names []string
	for name := range m.sessions {
		names = append(names, name)
	}
	return names
}

func testLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestManager_StartAll_EnabledOnly(t *testing.T) {
	mt := newMockTmux()
	configs := []ServiceConfig{
		{Name: "svc-a", Command: "echo a", Enabled: true},
		{Name: "svc-b", Command: "echo b", Enabled: false},
		{Name: "svc-c", Command: "echo c", Enabled: true},
	}
	mgr := NewManager(configs, mt, testLog())

	err := mgr.StartAll()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mt.started) != 2 {
		t.Errorf("expected 2 started, got %d: %v", len(mt.started), mt.started)
	}

	// Verify disabled service was not started
	for _, name := range mt.started {
		if name == "tb-svc-svc-b" {
			t.Error("disabled service svc-b should not have been started")
		}
	}
}

func TestManager_StartAll_AlreadyRunning(t *testing.T) {
	mt := newMockTmux()
	mt.sessions["tb-svc-running"] = true

	configs := []ServiceConfig{
		{Name: "running", Command: "echo run", Enabled: true},
	}
	mgr := NewManager(configs, mt, testLog())

	err := mgr.StartAll()
	if err == nil {
		t.Fatal("expected error for already running service")
	}
}

func TestManager_Stop_Success(t *testing.T) {
	mt := newMockTmux()
	mt.sessions["tb-svc-myservice"] = true

	configs := []ServiceConfig{
		{Name: "myservice", Command: "echo run", Enabled: true},
	}
	mgr := NewManager(configs, mt, testLog())

	err := mgr.Stop("myservice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mt.sessions["tb-svc-myservice"] {
		t.Error("session should have been removed")
	}
}

func TestManager_Stop_NotRunning(t *testing.T) {
	mt := newMockTmux()
	configs := []ServiceConfig{
		{Name: "myservice", Command: "echo run", Enabled: true},
	}
	mgr := NewManager(configs, mt, testLog())

	err := mgr.Stop("myservice")
	if err == nil {
		t.Fatal("expected error for service not running")
	}
}

func TestManager_Stop_NotConfigured(t *testing.T) {
	mt := newMockTmux()
	mgr := NewManager(nil, mt, testLog())

	err := mgr.Stop("nonexistent")
	if err == nil {
		t.Fatal("expected error for unconfigured service")
	}
}

func TestManager_Start_Single(t *testing.T) {
	mt := newMockTmux()
	configs := []ServiceConfig{
		{Name: "svc-x", Command: "python serve.py", Enabled: true},
	}
	mgr := NewManager(configs, mt, testLog())

	err := mgr.Start("svc-x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mt.sessions["tb-svc-svc-x"] {
		t.Error("session should exist after start")
	}
}

func TestManager_Start_NotConfigured(t *testing.T) {
	mt := newMockTmux()
	mgr := NewManager(nil, mt, testLog())

	err := mgr.Start("ghost")
	if err == nil {
		t.Fatal("expected error for unconfigured service")
	}
}

func TestManager_Restart(t *testing.T) {
	mt := newMockTmux()
	mt.sessions["tb-svc-webapp"] = true

	configs := []ServiceConfig{
		{Name: "webapp", Command: "node server.js", Enabled: true},
	}
	mgr := NewManager(configs, mt, testLog())

	err := mgr.Restart("webapp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mt.stopped) != 1 || mt.stopped[0] != "tb-svc-webapp" {
		t.Errorf("expected stop of tb-svc-webapp, got %v", mt.stopped)
	}
	if !mt.sessions["tb-svc-webapp"] {
		t.Error("session should exist after restart")
	}
}

func TestManager_Restart_NotRunning(t *testing.T) {
	mt := newMockTmux()
	configs := []ServiceConfig{
		{Name: "webapp", Command: "node server.js", Enabled: true},
	}
	mgr := NewManager(configs, mt, testLog())

	// Restart when not running should just start
	err := mgr.Restart("webapp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mt.sessions["tb-svc-webapp"] {
		t.Error("session should exist after restart-from-stopped")
	}
}

func TestManager_Status(t *testing.T) {
	mt := newMockTmux()
	mt.sessions["tb-svc-alpha"] = true

	configs := []ServiceConfig{
		{Name: "alpha", Command: "echo a", Enabled: true},
		{Name: "beta", Command: "echo b", Enabled: true},
	}
	mgr := NewManager(configs, mt, testLog())

	statuses := mgr.Status()
	if len(statuses) != 2 {
		t.Fatalf("expected 2 statuses, got %d", len(statuses))
	}

	// Sorted by name: alpha, beta
	if statuses[0].Name != "alpha" {
		t.Errorf("expected first status to be alpha, got %s", statuses[0].Name)
	}
	if !statuses[0].Running {
		t.Error("expected alpha to be running")
	}
	if statuses[1].Name != "beta" {
		t.Errorf("expected second status to be beta, got %s", statuses[1].Name)
	}
	if statuses[1].Running {
		t.Error("expected beta to not be running")
	}
}

func TestManager_StopAll(t *testing.T) {
	mt := newMockTmux()
	mt.sessions["tb-svc-a"] = true
	mt.sessions["tb-svc-b"] = true

	configs := []ServiceConfig{
		{Name: "a", Command: "echo a", Enabled: true},
		{Name: "b", Command: "echo b", Enabled: true},
	}
	mgr := NewManager(configs, mt, testLog())

	err := mgr.StopAll()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mt.sessions) != 0 {
		t.Errorf("expected all sessions stopped, got %v", mt.sessions)
	}
}

func TestManager_StopAll_PartialFailure(t *testing.T) {
	mt := newMockTmux()
	mt.sessions["tb-svc-a"] = true
	mt.sessions["tb-svc-b"] = true
	mt.stopErr["tb-svc-b"] = fmt.Errorf("tmux error")

	configs := []ServiceConfig{
		{Name: "a", Command: "echo a", Enabled: true},
		{Name: "b", Command: "echo b", Enabled: true},
	}
	mgr := NewManager(configs, mt, testLog())

	err := mgr.StopAll()
	if err == nil {
		t.Fatal("expected error for partial failure")
	}
}

func TestBuildCommand_Simple(t *testing.T) {
	cfg := ServiceConfig{
		Name:    "test",
		Command: "python serve.py",
	}
	cmd := buildCommand(cfg)
	if cmd != "python serve.py" {
		t.Errorf("expected simple command, got %q", cmd)
	}
}

func TestBuildCommand_WithWorkDir(t *testing.T) {
	cfg := ServiceConfig{
		Name:    "test",
		Command: "python serve.py",
		WorkDir: "/opt/myapp",
	}
	cmd := buildCommand(cfg)
	expected := "cd '/opt/myapp' && python serve.py"
	if cmd != expected {
		t.Errorf("expected %q, got %q", expected, cmd)
	}
}

func TestBuildCommand_WithEnv(t *testing.T) {
	cfg := ServiceConfig{
		Name:    "test",
		Command: "python serve.py",
		Env:     map[string]string{"PORT": "8080", "DEBUG": "true"},
	}
	cmd := buildCommand(cfg)
	// Env vars should be sorted alphabetically
	expected := "export DEBUG='true'; export PORT='8080'; python serve.py"
	if cmd != expected {
		t.Errorf("expected %q, got %q", expected, cmd)
	}
}

func TestBuildCommand_WithWorkDirAndEnv(t *testing.T) {
	cfg := ServiceConfig{
		Name:    "test",
		Command: "python serve.py",
		WorkDir: "/opt/myapp",
		Env:     map[string]string{"PORT": "8080"},
	}
	cmd := buildCommand(cfg)
	expected := "export PORT='8080'; cd '/opt/myapp' && python serve.py"
	if cmd != expected {
		t.Errorf("expected %q, got %q", expected, cmd)
	}
}
