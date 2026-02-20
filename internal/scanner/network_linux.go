package scanner

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/tinkerbelle-io/tb-discover/internal/scanner/parser"
)

func collectNetworkInfo(ctx context.Context, runner CommandRunner, info *NetworkInfo) error {
	// Prefer host's /proc/1/net/dev when running in a container with hostPID.
	// PID 1 is the host's init, so /proc/1/net/dev shows the host's real
	// interfaces. sysfs (/sys/class/net/) does NOT work — it's namespace-filtered.
	if procPath := hostProcNetDev(); procPath != "" {
		if hostIfaces := collectHostInterfaces(procPath); len(hostIfaces) > 0 {
			info.Interfaces = hostIfaces
		}
	}

	// Fall back to ip commands (works on bare metal or when sysfs not mounted)
	if len(info.Interfaces) == 0 {
		// Try ip -j first (JSON output from iproute2)
		if out, err := runner.Run(ctx, "ip -j addr show 2>/dev/null"); err == nil {
			var ipAddrs []parser.IPAddrJSON
			if jsonErr := json.Unmarshal(out, &ipAddrs); jsonErr == nil {
				info.Interfaces = convertParserInterfaces(parser.ParseIPAddrJSON(ipAddrs))
			}
		}
	}

	// Fallback to text parsing if neither sysfs nor JSON worked
	if len(info.Interfaces) == 0 {
		if out, err := runner.Run(ctx, "ip addr show 2>/dev/null"); err == nil {
			info.Interfaces = convertParserInterfaces(parser.ParseIPAddr(string(out)))
		}
	}

	// Routes
	if out, err := runner.Run(ctx, "ip -j route show 2>/dev/null"); err == nil {
		var ipRoutes []parser.IPRouteJSON
		if jsonErr := json.Unmarshal(out, &ipRoutes); jsonErr == nil {
			info.Routes = parseIPRouteJSON(ipRoutes)
		}
	}

	if len(info.Routes) == 0 {
		if out, err := runner.Run(ctx, "ip route show 2>/dev/null"); err == nil {
			info.Routes = parseIPRouteText(string(out))
		}
	}

	return nil
}

func parseIPRouteJSON(routes []parser.IPRouteJSON) []RouteInfo {
	var result []RouteInfo
	for _, r := range routes {
		result = append(result, RouteInfo{
			Destination: r.Dst,
			Gateway:     r.Gateway,
			Interface:   r.Dev,
			Metric:      r.Metric,
		})
	}
	return result
}

func parseIPRouteText(output string) []RouteInfo {
	var routes []RouteInfo
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		route := RouteInfo{
			Destination: fields[0],
		}
		for i := 1; i < len(fields)-1; i++ {
			switch fields[i] {
			case "via":
				route.Gateway = fields[i+1]
			case "dev":
				route.Interface = fields[i+1]
			}
		}
		routes = append(routes, route)
	}
	return routes
}
