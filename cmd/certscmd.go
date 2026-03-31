package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tinkerbelle-io/tb-manage/internal/sshca"
)

var flagCertsClean bool

var certsCmd = &cobra.Command{
	Use:   "certs",
	Short: "Manage locally stored SSH CA certificates",
}

var certsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List locally stored SSH certificates with expiry status",
	Long: `Show all SSH certificates in ~/.tb-manage/certs/ with their
principal, expiry time, and remaining validity.

Use --clean to remove expired certificates.`,
	RunE: runCertsList,
}

func init() {
	certsListCmd.Flags().BoolVar(&flagCertsClean, "clean", false, "Remove expired certificates")
	certsCmd.AddCommand(certsListCmd)
	rootCmd.AddCommand(certsCmd)
}

func runCertsList(_ *cobra.Command, _ []string) error {
	if flagCertsClean {
		removed, err := sshca.CleanExpiredCerts()
		if err != nil {
			return fmt.Errorf("clean expired certs: %w", err)
		}
		if removed > 0 {
			fmt.Printf("Removed %d expired certificate(s)\n\n", removed)
		}
	}

	certs, err := sshca.ListCerts()
	if err != nil {
		return fmt.Errorf("list certs: %w", err)
	}

	if len(certs) == 0 {
		fmt.Println("No certificates found in ~/.tb-manage/certs/")
		return nil
	}

	fmt.Printf("%-40s  %-25s  %-10s  %s\n", "IDENTITY", "PRINCIPALS", "STATUS", "EXPIRES")
	fmt.Printf("%-40s  %-25s  %-10s  %s\n",
		strings.Repeat("-", 40),
		strings.Repeat("-", 25),
		strings.Repeat("-", 10),
		strings.Repeat("-", 25),
	)

	for _, cert := range certs {
		principals := strings.Join(cert.Principals, ",")
		if len(principals) > 25 {
			principals = principals[:22] + "..."
		}

		identity := cert.KeyIdentity
		if len(identity) > 40 {
			identity = identity[:37] + "..."
		}

		var status string
		if cert.Expired {
			status = "EXPIRED"
		} else {
			status = formatDuration(cert.Remaining)
		}

		fmt.Printf("%-40s  %-25s  %-10s  %s\n",
			identity,
			principals,
			status,
			cert.ValidBefore.Format("2006-01-02 15:04:05"),
		)
	}

	return nil
}

func formatDuration(d time.Duration) string {
	hours := d.Hours()
	if hours >= 1 {
		return fmt.Sprintf("%.0fh left", hours)
	}
	minutes := d.Minutes()
	if minutes >= 1 {
		return fmt.Sprintf("%.0fm left", minutes)
	}
	return "<1m left"
}
