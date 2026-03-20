package scanner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// CloudMetadata holds cloud instance metadata from IMDS.
type CloudMetadata struct {
	Provider     string `json:"provider"`               // aws, gcp, azure
	InstanceType string `json:"instance_type,omitempty"` // t3.medium, e2-standard-2
	Region       string `json:"region,omitempty"`        // us-east-2, us-central1
	Zone         string `json:"zone,omitempty"`          // us-east-2a, us-central1-a
	InstanceID   string `json:"instance_id,omitempty"`   // i-0abc123
}

// NetworkInfo holds all network data from a scan.
type NetworkInfo struct {
	Hostname      string          `json:"hostname"`
	PublicIP      string          `json:"public_ip,omitempty"`
	CloudProvider string          `json:"cloud_provider,omitempty"` // gcp, aws, azure, or empty
	Cloud         *CloudMetadata  `json:"cloud,omitempty"`
	Interfaces    []InterfaceInfo `json:"interfaces"`
	Routes        []RouteInfo     `json:"routes,omitempty"`
}

// InterfaceInfo represents a single network interface.
type InterfaceInfo struct {
	Name  string `json:"name"`
	IP    string `json:"ip,omitempty"`
	IPv6  string `json:"ipv6,omitempty"`
	MAC   string `json:"mac,omitempty"`
	MTU   int    `json:"mtu,omitempty"`
	State string `json:"state,omitempty"` // up, down
	Type  string `json:"type,omitempty"`  // physical, cni, bridge, virtual, tunnel, wireless
}

// RouteInfo represents a network route.
type RouteInfo struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Interface   string `json:"interface,omitempty"`
	Metric      int    `json:"metric,omitempty"`
}

// NetworkScanner collects network interface and routing information.
type NetworkScanner struct{}

// NewNetworkScanner creates a new NetworkScanner.
func NewNetworkScanner() *NetworkScanner {
	return &NetworkScanner{}
}

func (s *NetworkScanner) Name() string       { return "network" }
func (s *NetworkScanner) Platforms() []string { return nil }

func (s *NetworkScanner) Scan(ctx context.Context, runner CommandRunner) (json.RawMessage, error) {
	info := NetworkInfo{}

	// Hostname
	if out, err := runner.Run(ctx, "hostname"); err == nil {
		info.Hostname = trimOutput(out)
	}

	// Collect platform-specific interface and route data
	if err := collectNetworkInfo(ctx, runner, &info); err != nil {
		return nil, err
	}

	// Detect public IP and cloud provider via metadata services
	info.PublicIP, info.CloudProvider, info.Cloud = detectCloudMetadata(ctx)

	return json.Marshal(info)
}

// detectCloudMetadata tries cloud metadata endpoints, returns public IP, provider, and instance metadata.
func detectCloudMetadata(ctx context.Context) (publicIP, provider string, cloud *CloudMetadata) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// Per-request timeout must be short enough that sequential probes
	// (GCP, AWS, Azure, ifconfig.me) fit within the 3s context window.
	client := &http.Client{Timeout: 500 * time.Millisecond}
	gcpHeaders := map[string]string{"Metadata-Flavor": "Google"}

	// Try GCP metadata
	if ip := httpGetIP(ctx, client, "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip", gcpHeaders); ip != "" {
		cm := &CloudMetadata{Provider: "gcp"}
		// Machine type: returns projects/PROJECT/zones/ZONE/machineTypes/TYPE
		if raw := httpGetBody(ctx, client, "GET", "http://metadata.google.internal/computeMetadata/v1/instance/machine-type", gcpHeaders); raw != "" {
			if parts := strings.Split(raw, "/"); len(parts) > 0 {
				cm.InstanceType = parts[len(parts)-1]
			}
		}
		// Zone: returns projects/PROJECT/zones/ZONE
		if raw := httpGetBody(ctx, client, "GET", "http://metadata.google.internal/computeMetadata/v1/instance/zone", gcpHeaders); raw != "" {
			if parts := strings.Split(raw, "/"); len(parts) > 0 {
				cm.Zone = parts[len(parts)-1]
				// Derive region from zone (e.g., us-central1-a -> us-central1)
				if zp := strings.Split(cm.Zone, "-"); len(zp) >= 3 {
					cm.Region = strings.Join(zp[:len(zp)-1], "-")
				}
			}
		}
		// Instance ID
		cm.InstanceID = httpGetBody(ctx, client, "GET", "http://metadata.google.internal/computeMetadata/v1/instance/id", gcpHeaders)
		return ip, "gcp", cm
	}

	// Try AWS IMDS v2 (get token first, then query)
	if token := httpGetBody(ctx, client, "PUT", "http://169.254.169.254/latest/api/token", map[string]string{"X-aws-ec2-metadata-token-ttl-seconds": "30"}); token != "" {
		awsHeaders := map[string]string{"X-aws-ec2-metadata-token": token}
		ip := httpGetIP(ctx, client, "http://169.254.169.254/latest/meta-data/public-ipv4", awsHeaders)
		cm := &CloudMetadata{Provider: "aws"}
		cm.InstanceType = httpGetBody(ctx, client, "GET", "http://169.254.169.254/latest/meta-data/instance-type", awsHeaders)
		cm.InstanceID = httpGetBody(ctx, client, "GET", "http://169.254.169.254/latest/meta-data/instance-id", awsHeaders)
		cm.Zone = httpGetBody(ctx, client, "GET", "http://169.254.169.254/latest/meta-data/placement/availability-zone", awsHeaders)
		cm.Region = httpGetBody(ctx, client, "GET", "http://169.254.169.254/latest/meta-data/placement/region", awsHeaders)
		return ip, "aws", cm
	}

	// IMDSv1 fallback removed: IMDSv1 is a known SSRF escalation path and is
	// disabled by default on modern AWS instances. If IMDSv2 fails, we skip AWS.

	// Try Azure IMDS (JSON endpoint for full metadata)
	if body := httpGetLargeBody(ctx, client, "GET", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", map[string]string{"Metadata": "true"}); body != "" {
		cm := &CloudMetadata{Provider: "azure"}
		var azMeta struct {
			Compute struct {
				VMSize   string `json:"vmSize"`
				Location string `json:"location"`
				VMID     string `json:"vmId"`
				Zone     string `json:"zone"`
			} `json:"compute"`
			Network struct {
				Interfaces []struct {
					IPv4 struct {
						IPAddress []struct {
							PublicIPAddress string `json:"publicIpAddress"`
						} `json:"ipAddress"`
					} `json:"ipv4"`
				} `json:"interface"`
			} `json:"network"`
		}
		if err := json.Unmarshal([]byte(body), &azMeta); err == nil {
			cm.InstanceType = azMeta.Compute.VMSize
			cm.Region = azMeta.Compute.Location
			cm.Zone = azMeta.Compute.Zone
			cm.InstanceID = azMeta.Compute.VMID
			var pubIP string
			if len(azMeta.Network.Interfaces) > 0 && len(azMeta.Network.Interfaces[0].IPv4.IPAddress) > 0 {
				pubIP = azMeta.Network.Interfaces[0].IPv4.IPAddress[0].PublicIPAddress
			}
			return pubIP, "azure", cm
		}
	}

	// Fallback: external service (no provider detection)
	if ip := httpGetIP(ctx, client, "https://ifconfig.me/ip", nil); ip != "" {
		return ip, "", nil
	}

	return "", "", nil
}

func httpGetIP(ctx context.Context, client *http.Client, url string, headers map[string]string) string {
	return httpGetBody(ctx, client, "GET", url, headers)
}

func httpGetBody(ctx context.Context, client *http.Client, method, url string, headers map[string]string) string {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return ""
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}

// httpGetLargeBody is like httpGetBody but allows up to 8KB responses (for Azure IMDS JSON).
func httpGetLargeBody(ctx context.Context, client *http.Client, method, url string, headers map[string]string) string {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return ""
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}
