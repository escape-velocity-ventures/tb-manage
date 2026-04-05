package supervisor

import (
	"fmt"
	"testing"
)

// mockCommander records calls and returns configured results.
type mockCommander struct {
	calls   []mockCall
	results map[string]mockResult
}

type mockCall struct {
	name string
	args []string
}

type mockResult struct {
	output []byte
	err    error
}

func newMockCommander() *mockCommander {
	return &mockCommander{
		results: make(map[string]mockResult),
	}
}

func (m *mockCommander) key(name string, args ...string) string {
	return fmt.Sprintf("%s %v", name, args)
}

func (m *mockCommander) On(name string, args []string, output []byte, err error) {
	m.results[m.key(name, args...)] = mockResult{output: output, err: err}
}

func (m *mockCommander) Run(name string, args ...string) ([]byte, error) {
	m.calls = append(m.calls, mockCall{name: name, args: args})
	k := m.key(name, args...)
	if r, ok := m.results[k]; ok {
		return r.output, r.err
	}
	return nil, fmt.Errorf("unexpected call: %s", k)
}

func (m *mockCommander) lastCall() mockCall {
	if len(m.calls) == 0 {
		return mockCall{}
	}
	return m.calls[len(m.calls)-1]
}

// --- HasSession tests ---

func TestHasSession_Exists(t *testing.T) {
	mc := newMockCommander()
	mc.On("tmux", []string{"has-session", "-t", "tinkerbelle"}, nil, nil)
	tm := NewTmuxManager(mc)

	if !tm.HasSession("tinkerbelle") {
		t.Error("expected session to exist")
	}
}

func TestHasSession_NotExists(t *testing.T) {
	mc := newMockCommander()
	mc.On("tmux", []string{"has-session", "-t", "nope"}, nil, fmt.Errorf("no session"))
	tm := NewTmuxManager(mc)

	if tm.HasSession("nope") {
		t.Error("expected session to not exist")
	}
}

// --- StartSession tests ---

func TestStartSession_Success(t *testing.T) {
	mc := newMockCommander()
	// has-session returns error (not exists)
	mc.On("tmux", []string{"has-session", "-t", "cybill"}, nil, fmt.Errorf("no session"))
	// new-session succeeds
	mc.On("tmux", []string{"new-session", "-d", "-s", "cybill", "claude --skill review"}, nil, nil)
	tm := NewTmuxManager(mc)

	err := tm.StartSession("cybill", "claude --skill review")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStartSession_AlreadyExists(t *testing.T) {
	mc := newMockCommander()
	mc.On("tmux", []string{"has-session", "-t", "cybill"}, nil, nil) // exists
	tm := NewTmuxManager(mc)

	err := tm.StartSession("cybill", "claude --skill review")
	if err == nil {
		t.Fatal("expected error for existing session")
	}
	if err.Error() != `session "cybill" already exists` {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStartSession_EmptyName(t *testing.T) {
	mc := newMockCommander()
	tm := NewTmuxManager(mc)

	err := tm.StartSession("", "cmd")
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestStartSession_EmptyCommand(t *testing.T) {
	mc := newMockCommander()
	tm := NewTmuxManager(mc)

	err := tm.StartSession("test", "")
	if err == nil {
		t.Fatal("expected error for empty command")
	}
}

// --- StopSession tests ---

func TestStopSession_Success(t *testing.T) {
	mc := newMockCommander()
	mc.On("tmux", []string{"has-session", "-t", "cybill"}, nil, nil)          // exists
	mc.On("tmux", []string{"kill-session", "-t", "cybill"}, nil, nil)         // kill succeeds
	tm := NewTmuxManager(mc)

	err := tm.StopSession("cybill")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStopSession_NotFound(t *testing.T) {
	mc := newMockCommander()
	mc.On("tmux", []string{"has-session", "-t", "nope"}, nil, fmt.Errorf("no session"))
	tm := NewTmuxManager(mc)

	err := tm.StopSession("nope")
	if err == nil {
		t.Fatal("expected error for non-existent session")
	}
	if err.Error() != `session "nope" not found` {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStopSession_EmptyName(t *testing.T) {
	mc := newMockCommander()
	tm := NewTmuxManager(mc)

	err := tm.StopSession("")
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

// --- ListSessions tests ---

func TestListSessions_Multiple(t *testing.T) {
	mc := newMockCommander()
	output := "tinkerbelle\t1712000000\t1712001000\ncybill\t1712000100\t1712001100\n"
	mc.On("tmux", []string{"list-sessions", "-F", "#{session_name}\t#{session_created}\t#{session_activity}"}, []byte(output), nil)
	tm := NewTmuxManager(mc)

	sessions := tm.ListSessions()
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}
	if sessions[0].Name != "tinkerbelle" {
		t.Errorf("expected name tinkerbelle, got %s", sessions[0].Name)
	}
	if sessions[1].Name != "cybill" {
		t.Errorf("expected name cybill, got %s", sessions[1].Name)
	}
	if sessions[0].Created.Unix() != 1712000000 {
		t.Errorf("expected created 1712000000, got %d", sessions[0].Created.Unix())
	}
}

func TestListSessions_Empty(t *testing.T) {
	mc := newMockCommander()
	mc.On("tmux", []string{"list-sessions", "-F", "#{session_name}\t#{session_created}\t#{session_activity}"}, nil, fmt.Errorf("no server"))
	tm := NewTmuxManager(mc)

	sessions := tm.ListSessions()
	if len(sessions) != 0 {
		t.Fatalf("expected 0 sessions, got %d", len(sessions))
	}
}

// --- CaptureLogs tests ---

func TestCaptureLogs_Success(t *testing.T) {
	mc := newMockCommander()
	mc.On("tmux", []string{"capture-pane", "-t", "cybill", "-p", "-S", "-50"}, []byte("line1\nline2\nline3\n"), nil)
	tm := NewTmuxManager(mc)

	logs := tm.CaptureLogs("cybill", 50)
	if logs != "line1\nline2\nline3" {
		t.Errorf("unexpected logs: %q", logs)
	}
}

func TestCaptureLogs_DefaultLines(t *testing.T) {
	mc := newMockCommander()
	mc.On("tmux", []string{"capture-pane", "-t", "test", "-p", "-S", "-100"}, []byte("output\n"), nil)
	tm := NewTmuxManager(mc)

	logs := tm.CaptureLogs("test", 0) // should default to 100
	if logs != "output" {
		t.Errorf("unexpected logs: %q", logs)
	}
}

func TestCaptureLogs_Error(t *testing.T) {
	mc := newMockCommander()
	mc.On("tmux", []string{"capture-pane", "-t", "nope", "-p", "-S", "-100"}, nil, fmt.Errorf("no session"))
	tm := NewTmuxManager(mc)

	logs := tm.CaptureLogs("nope", 0)
	if logs != "" {
		t.Errorf("expected empty logs, got %q", logs)
	}
}
