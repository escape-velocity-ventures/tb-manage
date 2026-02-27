package agent

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

func testLogger() *slog.Logger {
	return slog.Default().With("component", "test")
}

func TestConnectSendsTokenInHeader(t *testing.T) {
	var gotHeaders http.Header
	var gotPath string

	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		gotPath = r.URL.RawQuery
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("upgrade: %v", err)
		}
		conn.Close()
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	// Test with fallback disabled — token should NOT be in URL
	a := &Agent{
		wsURL:              wsURL,
		token:              "test-secret-token",
		tokenInURLFallback: false,
		log:                testLogger(),
	}

	err := a.connect()
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	a.conn.Close()

	if got := gotHeaders.Get("Authorization"); got != "Bearer test-secret-token" {
		t.Errorf("expected Authorization header 'Bearer test-secret-token', got %q", got)
	}
	if strings.Contains(gotPath, "test-secret-token") {
		t.Error("token should NOT be in URL query when fallback is disabled")
	}

	// Test with fallback enabled — token should be in BOTH
	a2 := &Agent{
		wsURL:              wsURL,
		token:              "test-secret-token",
		tokenInURLFallback: true,
		log:                testLogger(),
	}

	err = a2.connect()
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	a2.conn.Close()

	if got := gotHeaders.Get("Authorization"); got != "Bearer test-secret-token" {
		t.Errorf("expected Authorization header, got %q", got)
	}
	if !strings.Contains(gotPath, "test-secret-token") {
		t.Error("token should be in URL query when fallback is enabled")
	}
}
