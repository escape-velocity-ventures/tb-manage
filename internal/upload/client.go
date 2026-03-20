package upload

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/tinkerbelle-io/tb-manage/internal/auth"
)

// Client uploads scan results to the edge-ingest Supabase function.
type Client struct {
	baseURL    string
	token      string
	anonKey    string
	httpClient *http.Client
	maxRetries int
	// Host key identity (alternative to token auth)
	identityMode string // "token" or "ssh-host-key"
	hostIdentity *auth.HostIdentity
}

// NewClient creates a new upload client.
func NewClient(baseURL, token, anonKey string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		anonKey: anonKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		maxRetries: 3,
	}
}

// NewHostKeyClient creates an upload client using SSH host key identity.
// If token is provided, it's included in the body for cluster routing while
// host key headers provide cryptographic identity verification.
func NewHostKeyClient(baseURL, anonKey, token string, identity *auth.HostIdentity) *Client {
	return &Client{
		baseURL:      baseURL,
		token:        token,
		anonKey:      anonKey,
		identityMode: "ssh-host-key",
		hostIdentity: identity,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		maxRetries: 3,
	}
}

// Upload sends scan results to edge-ingest.
func (c *Client) Upload(ctx context.Context, req *EdgeIngestRequest) (*EdgeIngestResponse, error) {
	if c.token != "" {
		req.AgentToken = c.token
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/functions/v1/edge-ingest", c.baseURL)

	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(math.Pow(2, float64(attempt-1))) * time.Second
			log.Printf("retry %d/%d after %v", attempt, c.maxRetries, backoff)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")
		if c.anonKey != "" {
			httpReq.Header.Set("Authorization", "Bearer "+c.anonKey)
			httpReq.Header.Set("apikey", c.anonKey)
		}

		// SSH host key identity: sign timestamp:nonce:body and send identity headers.
		// Timestamp + nonce prevent replay attacks (gateway must verify within window).
		if c.identityMode == "ssh-host-key" && c.hostIdentity != nil {
			hostname, _ := os.Hostname()
			ts := strconv.FormatInt(time.Now().Unix(), 10)
			nonce := fmt.Sprintf("%x", time.Now().UnixNano())
			// Sign the concatenation of timestamp, nonce, and body
			signedPayload := append([]byte(ts+":"+nonce+":"), body...)
			httpReq.Header.Set("X-TB-Node", hostname)
			httpReq.Header.Set("X-TB-Key-Fingerprint", c.hostIdentity.Fingerprint)
			httpReq.Header.Set("X-TB-Timestamp", ts)
			httpReq.Header.Set("X-TB-Nonce", nonce)
			httpReq.Header.Set("X-TB-Signature", c.hostIdentity.SignRequest(signedPayload))
		}

		resp, err := c.httpClient.Do(httpReq)
		if err != nil {
			lastErr = fmt.Errorf("HTTP request: %w", err)
			continue
		}

		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("server error %d: %s", resp.StatusCode, string(respBody))
			continue
		}

		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("upload failed (HTTP %d): %s", resp.StatusCode, string(respBody))
		}

		var result EdgeIngestResponse
		if err := json.Unmarshal(respBody, &result); err != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}

		return &result, nil
	}

	return nil, fmt.Errorf("upload failed after %d retries: %w", c.maxRetries, lastErr)
}
