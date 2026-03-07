package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/tinkerbelle-io/tb-manage/internal/logging"
	"github.com/tinkerbelle-io/tb-manage/internal/scanner"
	"github.com/tinkerbelle-io/tb-manage/internal/topology"
)

var netJSON bool

var netCmd = &cobra.Command{
	Use:   "net",
	Short: "Show network interfaces and cloud metadata",
	Long: `Scan network interfaces, detect public IP, and probe cloud metadata
endpoints (AWS, GCP, Azure). Each interface is classified by type using
the topology classifier.`,
	RunE: runNet,
}

func init() {
	netCmd.Flags().BoolVar(&netJSON, "json", false, "Output as JSON")
	rootCmd.AddCommand(netCmd)
}

func runNet(cmd *cobra.Command, args []string) error {
	logging.Setup(flagLogLevel)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	raw, err := scanner.NewNetworkScanner().Scan(ctx, scanner.LocalRunner{})
	if err != nil {
		return fmt.Errorf("network scan: %w", err)
	}

	var info scanner.NetworkInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return fmt.Errorf("unmarshal network: %w", err)
	}

	if netJSON {
		return outputJSON(info)
	}

	// Header
	fmt.Println()
	printKV("HOST", info.Hostname)
	if info.PublicIP != "" {
		label := info.PublicIP
		if info.Cloud != nil && info.Cloud.Region != "" {
			label += fmt.Sprintf(" (%s %s)", info.Cloud.Provider, info.Cloud.Region)
		}
		printKV("PUBLIC", label)
	}
	if info.Cloud != nil {
		parts := info.Cloud.Provider
		if info.Cloud.InstanceType != "" {
			parts += " · " + info.Cloud.InstanceType
		}
		if info.Cloud.Zone != "" {
			parts += " · " + info.Cloud.Zone
		}
		if info.Cloud.InstanceID != "" {
			parts += " · " + info.Cloud.InstanceID
		}
		printKV("CLOUD", parts)
	}

	// Interface table
	headers := []string{"INTERFACE", "IP", "TYPE", "STATE", "MTU"}
	var rows [][]string
	for _, iface := range info.Interfaces {
		nicType := topology.ClassifyNIC(iface.Name).String()
		mtu := ""
		if iface.MTU > 0 {
			mtu = fmt.Sprintf("%d", iface.MTU)
		}
		rows = append(rows, []string{iface.Name, iface.IP, nicType, iface.State, mtu})
	}
	printTable(headers, rows)
	fmt.Println()

	return nil
}
