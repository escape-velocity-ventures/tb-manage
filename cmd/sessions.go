package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/tinkerbelle-io/tb-manage/internal/terminal"
)

var (
	flagGCForce bool
)

var sessionsCmd = &cobra.Command{
	Use:   "sessions",
	Short: "Manage tmux terminal sessions",
}

var sessionsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all tmux sessions with activity and process status",
	RunE:  runSessionsList,
}

var sessionsGCCmd = &cobra.Command{
	Use:   "gc",
	Short: "Run session garbage collection (dry-run by default, --force to reap)",
	RunE:  runSessionsGC,
}

var sessionsKillCmd = &cobra.Command{
	Use:   "kill <id>",
	Short: "Destroy a specific tmux session",
	Args:  cobra.ExactArgs(1),
	RunE:  runSessionsKill,
}

func init() {
	sessionsGCCmd.Flags().BoolVar(&flagGCForce, "force", false, "Actually destroy sessions (default is dry-run)")

	sessionsCmd.AddCommand(sessionsListCmd)
	sessionsCmd.AddCommand(sessionsGCCmd)
	sessionsCmd.AddCommand(sessionsKillCmd)
	rootCmd.AddCommand(sessionsCmd)
}

func runSessionsList(cmd *cobra.Command, args []string) error {
	if !terminal.TmuxAvailable() {
		return fmt.Errorf("tmux is not installed or not on PATH")
	}

	sessions, err := terminal.InspectAllSessions()
	if err != nil {
		return err
	}

	if len(sessions) == 0 {
		fmt.Println("No active sessions.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tCREATED\tLAST ACTIVITY\tPROCESS\tWINDOWS")

	for _, s := range sessions {
		process := "alive"
		if !s.HasProcess {
			process = "dead"
		}
		idle := time.Since(s.LastActivity).Truncate(time.Second)
		fmt.Fprintf(w, "%s\t%s\t%s ago\t%s\t%d\n",
			s.ID,
			s.Created.Format("2006-01-02 15:04"),
			idle,
			process,
			s.WindowCount,
		)
	}
	return w.Flush()
}

func runSessionsGC(cmd *cobra.Command, args []string) error {
	if !terminal.TmuxAvailable() {
		return fmt.Errorf("tmux is not installed or not on PATH")
	}

	cfg := terminal.DefaultGCConfig()

	if !flagGCForce {
		// Dry-run: use evaluateGC logic via inspect + evaluate
		sessions, err := terminal.InspectAllSessions()
		if err != nil {
			return err
		}

		result := terminal.EvaluateGCPublic(sessions, cfg, nil, time.Now())

		if len(result.Reaped) == 0 {
			fmt.Println("No sessions would be reaped.")
			return nil
		}

		fmt.Println("Sessions that would be reaped (pass --force to execute):")
		for _, id := range result.Reaped {
			fmt.Printf("  %s  (%s)\n", id, result.Reasons[id])
		}
		return nil
	}

	result, err := terminal.RunGC(cfg, nil)
	if err != nil {
		return err
	}

	if len(result.Reaped) == 0 {
		fmt.Println("No sessions reaped.")
		return nil
	}

	fmt.Printf("Reaped %d session(s):\n", len(result.Reaped))
	for _, id := range result.Reaped {
		fmt.Printf("  %s  (%s)\n", id, result.Reasons[id])
	}
	return nil
}

func runSessionsKill(cmd *cobra.Command, args []string) error {
	if !terminal.TmuxAvailable() {
		return fmt.Errorf("tmux is not installed or not on PATH")
	}

	id := args[0]
	if !terminal.TmuxSessionExists(id) {
		return fmt.Errorf("session %q does not exist", id)
	}

	if err := terminal.DestroyTmuxSession(id); err != nil {
		return fmt.Errorf("failed to destroy session %q: %w", id, err)
	}

	fmt.Printf("Session %q destroyed.\n", id)
	return nil
}
