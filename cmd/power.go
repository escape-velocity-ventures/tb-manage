package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/tinkerbelle-io/tb-manage/internal/logging"
	"github.com/tinkerbelle-io/tb-manage/internal/power"
)

var powerJSON bool

var powerCmd = &cobra.Command{
	Use:   "power",
	Short: "Discover power control capabilities",
	Long: `Detect available power control providers (IPMI, Wake-on-LAN, hypervisor,
smart plugs, PoE, cloud API) and list controllable targets with their
current power state.`,
	RunE: runPower,
}

func init() {
	powerCmd.Flags().BoolVar(&powerJSON, "json", false, "Output as JSON")
	rootCmd.AddCommand(powerCmd)
}

func runPower(cmd *cobra.Command, args []string) error {
	logging.Setup(flagLogLevel)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	caps := power.NewRegistry().Scan(ctx)

	if powerJSON {
		return outputJSON(caps)
	}

	fmt.Println()
	if len(caps.Providers) > 0 {
		printKV("Providers:", joinStrings(caps.Providers))
	} else {
		fmt.Println("  No power providers detected.")
		return nil
	}

	if len(caps.Targets) > 0 {
		headers := []string{"TARGET", "METHOD", "STATE"}
		var rows [][]string
		for _, t := range caps.Targets {
			rows = append(rows, []string{t.Name, string(t.Method), string(t.State)})
		}
		printTable(headers, rows)
	}

	fmt.Printf("\n  %d targets, %d providers\n\n", len(caps.Targets), len(caps.Providers))

	return nil
}
