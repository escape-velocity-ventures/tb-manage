package services

import (
	"net/http"
	"time"
)

// HealthStatus represents the result of a health check.
type HealthStatus string

const (
	HealthHealthy   HealthStatus = "healthy"
	HealthUnhealthy HealthStatus = "unhealthy"
	HealthUnknown   HealthStatus = "unknown"
)

// healthCheckTimeout is the HTTP client timeout for health checks.
const healthCheckTimeout = 5 * time.Second

// CheckHealth performs an HTTP GET to the given URL and returns the health status.
// Returns HealthUnknown if url is empty, HealthHealthy on 2xx, HealthUnhealthy otherwise.
func CheckHealth(url string) HealthStatus {
	return checkHealthWith(url, &http.Client{Timeout: healthCheckTimeout})
}

// checkHealthWith allows injecting a custom HTTP client for testing.
func checkHealthWith(url string, client *http.Client) HealthStatus {
	if url == "" {
		return HealthUnknown
	}

	resp, err := client.Get(url)
	if err != nil {
		return HealthUnhealthy
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return HealthHealthy
	}
	return HealthUnhealthy
}
