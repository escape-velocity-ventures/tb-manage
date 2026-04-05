package cmd

import (
	"github.com/tinkerbelle-io/tb-manage/internal/supervisor"
)

func init() {
	rootCmd.AddCommand(supervisor.NewAgentCommand())
}
