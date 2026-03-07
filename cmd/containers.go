package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/tinkerbelle-io/tb-manage/internal/logging"
	"github.com/tinkerbelle-io/tb-manage/internal/scanner"
)

var containersJSON bool

var containersCmd = &cobra.Command{
	Use:   "containers",
	Short: "List container runtime and running containers",
	Long: `Detect the local container runtime (Docker, Podman, or nerdctl),
list running containers and available images.`,
	RunE: runContainers,
}

func init() {
	containersCmd.Flags().BoolVar(&containersJSON, "json", false, "Output as JSON")
	rootCmd.AddCommand(containersCmd)
}

func runContainers(cmd *cobra.Command, args []string) error {
	logging.Setup(flagLogLevel)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	raw, err := scanner.NewContainerScanner().Scan(ctx, scanner.LocalRunner{})
	if err != nil {
		return fmt.Errorf("container scan: %w", err)
	}

	var info scanner.ContainerInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return fmt.Errorf("unmarshal containers: %w", err)
	}

	if containersJSON {
		return outputJSON(info)
	}

	if info.Runtime == "" {
		fmt.Println("\n  No container runtime detected.")
		return nil
	}

	fmt.Println()
	runtimeLabel := info.Runtime
	if info.Version != "" {
		runtimeLabel += " " + info.Version
	}
	printKV("Runtime:", runtimeLabel)

	if len(info.Containers) > 0 {
		headers := []string{"CONTAINER", "IMAGE", "STATE"}
		var rows [][]string
		for _, c := range info.Containers {
			rows = append(rows, []string{c.Name, c.Image, c.State})
		}
		printTable(headers, rows)
	} else {
		fmt.Println("\n  No running containers.")
	}

	if len(info.Images) > 0 {
		summary := fmt.Sprintf("%d", len(info.Images))
		if len(info.Images) <= 5 {
			summary += " (" + joinStrings(info.Images) + ")"
		} else {
			summary += " (" + joinStrings(info.Images[:3]) + ", ...)"
		}
		fmt.Printf("\n  Images: %s\n", summary)
	}
	fmt.Println()

	return nil
}

func joinStrings(ss []string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += ", "
		}
		result += s
	}
	return result
}
