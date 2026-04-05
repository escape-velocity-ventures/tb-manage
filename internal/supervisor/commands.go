package supervisor

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// NewAgentCommand returns the "agent" parent command with all subcommands.
func NewAgentCommand() *cobra.Command {
	agentCmd := &cobra.Command{
		Use:   "agent",
		Short: "Manage Claude Code agent sessions",
		Long:  "Launch, stop, and monitor Claude Code agents running in tmux sessions.",
	}

	var registryPath string
	agentCmd.PersistentFlags().StringVar(&registryPath, "registry", "", "Path to agents.yaml (default: ~/.config/tb-manage/agents.yaml)")

	agentCmd.AddCommand(
		newAgentStartCmd(&registryPath),
		newAgentStopCmd(&registryPath),
		newAgentStatusCmd(&registryPath),
		newAgentRestartCmd(&registryPath),
		newAgentLogsCmd(&registryPath),
	)

	return agentCmd
}

func loadDeps(registryPath *string) (*TmuxManager, *Registry, error) {
	tm := NewTmuxManager(&ExecCommander{})
	r, err := LoadRegistry(*registryPath)
	if err != nil {
		return nil, nil, err
	}
	return tm, r, nil
}

func newAgentStartCmd(registryPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "start <name>",
		Short: "Launch an agent in a tmux session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			tm, reg, err := loadDeps(registryPath)
			if err != nil {
				return err
			}

			command, err := reg.BuildCommand(name)
			if err != nil {
				return err
			}

			// Set env vars for the agent if configured
			cfg, _ := reg.Get(name)
			if len(cfg.Env) > 0 {
				var envPrefix []string
				for k, v := range cfg.Env {
					envPrefix = append(envPrefix, fmt.Sprintf("%s=%s", k, v))
				}
				sort.Strings(envPrefix)
				command = strings.Join(envPrefix, " ") + " " + command
			}

			if err := tm.StartSession(name, command); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Agent %s started\n", name)
			return nil
		},
	}
}

func newAgentStopCmd(registryPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "stop <name>",
		Short: "Stop an agent tmux session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			tm := NewTmuxManager(&ExecCommander{})
			if err := tm.StopSession(name); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Agent %s stopped\n", name)
			return nil
		},
	}
}

func newAgentStatusCmd(registryPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "List all agent sessions",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			tm := NewTmuxManager(&ExecCommander{})
			_, reg, err := loadDeps(registryPath)
			if err != nil {
				return err
			}

			sessions := tm.ListSessions()
			alive := make(map[string]SessionInfo)
			for _, s := range sessions {
				alive[s.Name] = s
			}

			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%-15s %-8s %-20s %-20s\n", "AGENT", "STATUS", "CREATED", "LAST ACTIVITY")
			fmt.Fprintf(w, "%-15s %-8s %-20s %-20s\n", "-----", "------", "-------", "-------------")

			names := reg.Names()
			sort.Strings(names)
			for _, name := range names {
				if info, ok := alive[name]; ok {
					fmt.Fprintf(w, "%-15s %-8s %-20s %-20s\n",
						name,
						"running",
						formatTime(info.Created),
						formatTime(info.Activity),
					)
				} else {
					fmt.Fprintf(w, "%-15s %-8s %-20s %-20s\n",
						name,
						"stopped",
						"-",
						"-",
					)
				}
			}
			return nil
		},
	}
}

func newAgentRestartCmd(registryPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "restart <name>",
		Short: "Restart an agent (stop + start)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			tm, reg, err := loadDeps(registryPath)
			if err != nil {
				return err
			}

			// Stop if running (ignore error if not running)
			if tm.HasSession(name) {
				if err := tm.StopSession(name); err != nil {
					return fmt.Errorf("stop: %w", err)
				}
			}

			command, err := reg.BuildCommand(name)
			if err != nil {
				return err
			}

			cfg, _ := reg.Get(name)
			if len(cfg.Env) > 0 {
				var envPrefix []string
				for k, v := range cfg.Env {
					envPrefix = append(envPrefix, fmt.Sprintf("%s=%s", k, v))
				}
				sort.Strings(envPrefix)
				command = strings.Join(envPrefix, " ") + " " + command
			}

			if err := tm.StartSession(name, command); err != nil {
				return fmt.Errorf("start: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Agent %s restarted\n", name)
			return nil
		},
	}
}

func newAgentLogsCmd(registryPath *string) *cobra.Command {
	var lines int
	cmd := &cobra.Command{
		Use:   "logs <name>",
		Short: "Capture recent output from an agent session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			tm := NewTmuxManager(&ExecCommander{})
			output := tm.CaptureLogs(name, lines)
			if output == "" {
				return fmt.Errorf("no output captured for %q (session may not exist)", name)
			}
			fmt.Fprintln(cmd.OutOrStdout(), output)
			return nil
		},
	}
	cmd.Flags().IntVarP(&lines, "lines", "n", 100, "Number of lines to capture")
	return cmd
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format("2006-01-02 15:04:05")
}
