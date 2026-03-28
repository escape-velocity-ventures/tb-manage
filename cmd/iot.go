package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tinkerbelle-io/tb-manage/internal/iot"
	"github.com/tinkerbelle-io/tb-manage/internal/logging"
)

var (
	iotJSON     bool
	iotProvider string
)

var iotCmd = &cobra.Command{
	Use:   "iot",
	Short: "Discover IoT devices on the network",
	Long: `Scan for IoT devices using available providers: mDNS, Home Assistant,
Philips Hue, and UniFi. Each provider is auto-detected and only queried
if available.

Environment variables:
  HA_URL         Home Assistant URL (e.g., http://homeassistant.local:8123)
  HA_TOKEN       Home Assistant long-lived access token
  HUE_BRIDGE_IP  Philips Hue bridge IP address
  HUE_USERNAME   Philips Hue API username
  UNIFI_URL      UniFi controller URL
  UNIFI_USER     UniFi username
  UNIFI_PASS     UniFi password`,
	RunE: runIoT,
}

func init() {
	iotCmd.Flags().BoolVar(&iotJSON, "json", false, "Output as JSON")
	iotCmd.Flags().StringVar(&iotProvider, "provider", "", "Only use this provider (mdns, homeassistant, hue, unifi)")
	rootCmd.AddCommand(iotCmd)
}

func runIoT(cmd *cobra.Command, args []string) error {
	logging.Setup(flagLogLevel)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := iot.NewRegistry().Scan(ctx)

	// Filter by provider if specified
	if iotProvider != "" {
		var filteredDevices []iot.Device
		for _, d := range result.Devices {
			if d.Source == iotProvider {
				filteredDevices = append(filteredDevices, d)
			}
		}
		var filteredProviders []string
		for _, p := range result.Providers {
			if p == iotProvider {
				filteredProviders = append(filteredProviders, p)
			}
		}
		result.Devices = filteredDevices
		result.Providers = filteredProviders
	}

	if iotJSON {
		return outputJSON(result)
	}

	fmt.Println()
	if len(result.Providers) > 0 {
		printKV("Providers:", strings.Join(result.Providers, ", "))
	} else {
		fmt.Println("  No IoT providers detected.")
		return nil
	}

	if len(result.Devices) > 0 {
		headers := []string{"DEVICE", "TYPE", "STATE", "SOURCE"}
		var rows [][]string
		for _, d := range result.Devices {
			state := d.State
			if state == "" {
				state = "-"
			}
			rows = append(rows, []string{d.Name, string(d.Type), state, d.Source})
		}
		printTable(headers, rows)
	}

	fmt.Printf("\n  %d devices from %d providers\n\n", len(result.Devices), len(result.Providers))

	return nil
}
