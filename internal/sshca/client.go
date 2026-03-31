package sshca

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// SignRequest is the payload sent to the ssh-sign edge function.
type SignRequest struct {
	PublicKey       string   `json:"publicKey"`
	Principals      []string `json:"principals"`
	ValiditySeconds int      `json:"validitySeconds,omitempty"`
	KeyIdentity     string   `json:"keyIdentity,omitempty"`
	SourceAddress   string   `json:"sourceAddress,omitempty"`
	ForceCommand    string   `json:"forceCommand,omitempty"`
	OrgID           string   `json:"orgId,omitempty"`
}

// SignResponse is the payload returned by the ssh-sign edge function.
type SignResponse struct {
	Certificate string   `json:"certificate"`
	ExpiresAt   string   `json:"expiresAt"`
	Principals  []string `json:"principals"`
	KeyIdentity string   `json:"keyIdentity"`
}

// Client communicates with the TinkerBelle SaaS ssh-sign edge function.
type Client struct {
	baseURL    string
	anonKey    string
	authToken  string
	httpClient *http.Client
}

// NewClient creates a new SSH CA client.
//   - baseURL: the Supabase project URL (e.g., https://xxx.supabase.co)
//   - anonKey: the Supabase anon key for API auth
//   - authToken: a Supabase user JWT or agent JWT (Bearer token)
func NewClient(baseURL, anonKey, authToken string) *Client {
	return &Client{
		baseURL:   strings.TrimRight(baseURL, "/"),
		anonKey:   anonKey,
		authToken: authToken,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// RequestCert calls POST /functions/v1/ssh-sign to get a signed SSH certificate.
func (c *Client) RequestCert(req *SignRequest) (*SignResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal sign request: %w", err)
	}

	url := c.baseURL + "/functions/v1/ssh-sign"
	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.authToken)
	if c.anonKey != "" {
		httpReq.Header.Set("apikey", c.anonKey)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ssh-sign request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		// Try to extract error message from JSON response
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("ssh-sign error (%d): %s", resp.StatusCode, errResp.Error)
		}
		return nil, fmt.Errorf("ssh-sign error (%d): %s", resp.StatusCode, string(respBody))
	}

	var signResp SignResponse
	if err := json.Unmarshal(respBody, &signResp); err != nil {
		return nil, fmt.Errorf("parse sign response: %w", err)
	}

	return &signResp, nil
}
