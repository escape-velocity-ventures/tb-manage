package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tinkerbelle-io/tb-manage/internal/insights"
	"github.com/tinkerbelle-io/tb-manage/internal/logging"
	"github.com/tinkerbelle-io/tb-manage/internal/scanner"
	"k8s.io/client-go/kubernetes"
)

var (
	checkJSON             bool
	checkNamespace        string
	checkExcludeNamespace []string
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Lint the current Kubernetes cluster for issues",
	Long: `Run 10 insight analyzers against the current kubeconfig context and print
detected issues sorted by severity. Useful in CI pipelines — exits with
code 1 if any action or warning level issues are found.`,
	RunE: runCheck,
}

func init() {
	checkCmd.Flags().BoolVar(&checkJSON, "json", false, "Output as JSON")
	checkCmd.Flags().StringVar(&checkNamespace, "namespace", "", "Only check this namespace")
	checkCmd.Flags().StringSliceVar(&checkExcludeNamespace, "exclude-namespace", nil, "Namespaces to exclude")
	rootCmd.AddCommand(checkCmd)
}

func runCheck(cmd *cobra.Command, args []string) error {
	logging.Setup(flagLogLevel)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	config, err := scanner.GetK8sConfig()
	if err != nil {
		return fmt.Errorf("k8s config: %w (is KUBECONFIG set or ~/.kube/config present?)", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("k8s clientset: %w", err)
	}

	exclude := checkExcludeNamespace
	if len(exclude) == 0 {
		exclude = scanner.DefaultExcludeNamespaces
	}

	engine := insights.NewEngine(exclude)
	allInsights := engine.Analyze(ctx, clientset)

	// Filter by namespace if specified
	if checkNamespace != "" {
		var filtered []insights.ClusterInsight
		for _, ins := range allInsights {
			if ins.TargetNS == checkNamespace {
				filtered = append(filtered, ins)
			}
		}
		allInsights = filtered
	}

	if checkJSON {
		return outputJSON(allInsights)
	}

	if len(allInsights) == 0 {
		fmt.Println("\n  No issues found.")
		return nil
	}

	// Count by severity
	counts := map[string]int{}
	hasActionOrWarning := false
	for _, ins := range allInsights {
		counts[ins.Severity]++
		if ins.Severity == "action" || ins.Severity == "warning" {
			hasActionOrWarning = true
		}
	}

	// Print insights
	fmt.Println()
	for _, ins := range allInsights {
		target := ins.TargetNS + "/" + ins.TargetName
		fmt.Printf("  %-8s %-40s %s\n", strings.ToUpper(ins.Severity), ins.Title, target)
	}

	// Summary
	var parts []string
	for _, sev := range []string{"action", "warning", "suggestion", "info"} {
		if c := counts[sev]; c > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c, sev))
		}
	}
	fmt.Printf("\n  %d issues (%s)\n", len(allInsights), strings.Join(parts, ", "))

	if hasActionOrWarning {
		// Return error to trigger exit code 1
		return fmt.Errorf("%d issues require attention", counts["action"]+counts["warning"])
	}
	return nil
}
