package services

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckHealth_EmptyURL(t *testing.T) {
	status := CheckHealth("")
	if status != HealthUnknown {
		t.Errorf("expected unknown for empty URL, got %s", status)
	}
}

func TestCheckHealth_Healthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	status := CheckHealth(srv.URL)
	if status != HealthHealthy {
		t.Errorf("expected healthy, got %s", status)
	}
}

func TestCheckHealth_Unhealthy500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	status := CheckHealth(srv.URL)
	if status != HealthUnhealthy {
		t.Errorf("expected unhealthy, got %s", status)
	}
}

func TestCheckHealth_UnhealthyConnectionRefused(t *testing.T) {
	// Use a URL that will definitely refuse connections
	status := CheckHealth("http://127.0.0.1:1")
	if status != HealthUnhealthy {
		t.Errorf("expected unhealthy for connection refused, got %s", status)
	}
}

func TestCheckHealth_Healthy201(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	status := CheckHealth(srv.URL)
	if status != HealthHealthy {
		t.Errorf("expected healthy for 201, got %s", status)
	}
}

func TestCheckHealth_Unhealthy404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	status := CheckHealth(srv.URL)
	if status != HealthUnhealthy {
		t.Errorf("expected unhealthy for 404, got %s", status)
	}
}
