package cmd

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"
	"github.com/tinkerbelle-io/tb-manage/internal/config"
	"github.com/tinkerbelle-io/tb-manage/internal/services"
)

func init() {
	rootCmd.AddCommand(newServicesCmd())
}

func newServicesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "services",
		Short: "Manage supervised local services",
		Long:  "List, start, stop, and restart long-running services supervised via tmux.",
	}

	cmd.AddCommand(
		newServicesListCmd(),
		newServicesStartCmd(),
		newServicesStopCmd(),
		newServicesRestartCmd(),
	)

	return cmd
}

// loadServiceManager loads config and builds a service manager.
func loadServiceManager() (*services.Manager, error) {
	cfg, err := config.Load(flagConfig)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	if len(cfg.Services) == 0 {
		return nil, fmt.Errorf("no services configured in config file")
	}

	svcConfigs := make([]services.ServiceConfig, len(cfg.Services))
	for i, sc := range cfg.Services {
		svcConfigs[i] = services.ServiceConfig{
			Name:        sc.Name,
			Command:     sc.Command,
			WorkDir:     sc.WorkDir,
			Env:         sc.Env,
			HealthURL:   sc.HealthURL,
			AutoRestart: sc.AutoRestart,
			Enabled:     sc.Enabled,
		}
	}

	return services.NewManager(svcConfigs, services.NewRealTmuxBackend(), slog.Default()), nil
}

func newServicesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all configured services with status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, err := loadServiceManager()
			if err != nil {
				return err
			}

			statuses := mgr.Status()
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%-20s %-10s %-12s %-15s\n", "SERVICE", "STATUS", "HEALTH", "UPTIME")
			fmt.Fprintf(w, "%-20s %-10s %-12s %-15s\n", "-------", "------", "------", "------")

			for _, s := range statuses {
				status := "stopped"
				if s.Running {
					status = "running"
				}
				fmt.Fprintf(w, "%-20s %-10s %-12s %-15s\n",
					s.Name,
					status,
					string(s.Health),
					s.Uptime,
				)
			}
			return nil
		},
	}
}

func newServicesStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start <name>",
		Short: "Start a service",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, err := loadServiceManager()
			if err != nil {
				return err
			}
			if err := mgr.Start(args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Service %s started\n", args[0])
			return nil
		},
	}
}

func newServicesStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop <name>",
		Short: "Stop a service",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, err := loadServiceManager()
			if err != nil {
				return err
			}
			if err := mgr.Stop(args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Service %s stopped\n", args[0])
			return nil
		},
	}
}

func newServicesRestartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restart <name>",
		Short: "Restart a service (stop + start)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, err := loadServiceManager()
			if err != nil {
				return err
			}
			if err := mgr.Restart(args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Service %s restarted\n", args[0])
			return nil
		},
	}
}
