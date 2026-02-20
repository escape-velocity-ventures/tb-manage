package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	// Flags
	flagToken    string
	flagURL      string
	flagAnonKey  string
	flagConfig   string
	flagLogLevel string
)

var rootCmd = &cobra.Command{
	Use:   "tb-discover",
	Short: "TinkerBelle infrastructure discovery agent",
	Long: `tb-discover is a unified infrastructure discovery agent that scans hosts,
networks, storage, containers, and Kubernetes clusters. It reports discovered
infrastructure to TinkerBelle SaaS and can serve as a terminal session agent.`,
	SilenceUsage: true,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&flagToken, "token", "", "Agent authentication token (env: TB_TOKEN)")
	rootCmd.PersistentFlags().StringVar(&flagURL, "url", "", "TinkerBelle SaaS URL (env: TB_URL)")
	rootCmd.PersistentFlags().StringVar(&flagAnonKey, "anon-key", "", "Supabase anon key for API auth (env: TB_ANON_KEY)")
	rootCmd.PersistentFlags().StringVar(&flagConfig, "config", "", "Config file path (default: /etc/tb-discover/config.yaml)")
	rootCmd.PersistentFlags().StringVar(&flagLogLevel, "log-level", "info", "Log level: debug, info, warn, error")
}

// Execute runs the root command.
func Execute(version string) {
	rootCmd.Version = version
	rootCmd.SetVersionTemplate(fmt.Sprintf("tb-discover %s\n", version))
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// resolveToken returns the token from flag or environment.
func resolveToken() string {
	if flagToken != "" {
		return flagToken
	}
	return os.Getenv("TB_TOKEN")
}

// resolveURL returns the URL from flag or environment.
func resolveURL() string {
	if flagURL != "" {
		return flagURL
	}
	return os.Getenv("TB_URL")
}

// resolveAnonKey returns the anon key from flag or environment.
func resolveAnonKey() string {
	if flagAnonKey != "" {
		return flagAnonKey
	}
	return os.Getenv("TB_ANON_KEY")
}

// lookupEnv wraps os.LookupEnv.
func lookupEnv(key string) (string, bool) {
	return os.LookupEnv(key)
}
