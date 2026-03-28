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

var topoJSON bool

var topoCmd = &cobra.Command{
	Use:   "topology",
	Short: "Infer this machine's role from network interfaces",
	Long: `Classify network interfaces and infer the host's topology role
(baremetal, hypervisor, vm, vm-k8s, baremetal-k8s, cloud).
The inference is based on NIC naming patterns — physical NICs, CNI
interfaces, bridge interfaces, and virtio devices.`,
	RunE: runTopology,
}

func init() {
	topoCmd.Flags().BoolVar(&topoJSON, "json", false, "Output as JSON")
	rootCmd.AddCommand(topoCmd)
}

func runTopology(cmd *cobra.Command, args []string) error {
	logging.Setup(flagLogLevel)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	raw, err := scanner.NewNetworkScanner().Scan(ctx, scanner.LocalRunner{})
	if err != nil {
		return fmt.Errorf("network scan: %w", err)
	}

	var info scanner.NetworkInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return fmt.Errorf("unmarshal network: %w", err)
	}

	// Classify all interface names
	var names []string
	for _, iface := range info.Interfaces {
		names = append(names, iface.Name)
	}
	nicSet := topology.ClassifyInterfaces(names)
	role := topology.InferRole(nicSet)

	if topoJSON {
		return outputJSON(map[string]any{
			"role":       string(role),
			"host_type":  role.HostType(),
			"interfaces": info.Interfaces,
			"nic_set":    nicSet,
		})
	}

	// Determine reason string
	var reasons []string
	for _, iface := range info.Interfaces {
		t := topology.ClassifyNIC(iface.Name)
		switch t {
		case topology.NICPhysical:
			reasons = append(reasons, fmt.Sprintf("Physical NIC (%s)", iface.Name))
		case topology.NICBridge:
			reasons = append(reasons, fmt.Sprintf("Bridge (%s)", iface.Name))
		case topology.NICCNI:
			reasons = append(reasons, fmt.Sprintf("CNI (%s)", iface.Name))
		case topology.NICVirtio:
			reasons = append(reasons, fmt.Sprintf("Virtio (%s)", iface.Name))
		}
	}
	var reasonStr string
	if len(reasons) > 0 {
		reasonStr = reasons[0]
		if len(reasons) > 1 {
			reasonStr += " + " + reasons[1]
			if len(reasons) > 2 {
				reasonStr += fmt.Sprintf(" (+%d more)", len(reasons)-2)
			}
		}
	}

	fmt.Println()
	printKV("Role:", string(role))
	printKV("Host Type:", role.HostType())
	if reasonStr != "" {
		printKV("Reason:", reasonStr)
	}

	// Interface type table
	headers := []string{"INTERFACE", "TYPE"}
	var rows [][]string
	for _, iface := range info.Interfaces {
		rows = append(rows, []string{iface.Name, topology.ClassifyNIC(iface.Name).String()})
	}
	printTable(headers, rows)
	fmt.Println()

	return nil
}
