package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/awkto/minidns/internal/config"
)

// isCobraUsage recognizes the errors cobra itself produces for a bad command
// line, so they exit with the usage code.
func isCobraUsage(err error) bool {
	msg := err.Error()
	for _, p := range []string{"unknown command", "unknown flag", "unknown shorthand", "accepts ", "requires at least", "requires at most", "flag needs an argument", "invalid argument"} {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}

// cloudCmd groups the read-only replicas of cloud-hosted zones. v0.1 called
// these `minidns zone …`; that word now means local authoritative zones.
func cloudCmd() *cobra.Command {
	cloud := &cobra.Command{Use: "cloud", Short: "Read-only local replicas of cloud-hosted zones"}

	zone := &cobra.Command{Use: "zone", Short: "Replicated zones"}
	sub := func(use, short string, readOnly bool) *cobra.Command {
		verb := strings.Fields(use)[0]
		c := &cobra.Command{
			Use: use, Short: short, DisableFlagParsing: true,
			RunE: func(cmd *cobra.Command, args []string) error { return cmdZone(append([]string{verb}, args...)) },
		}
		if readOnly {
			markReadOnly(c)
		}
		return c
	}
	zone.AddCommand(
		sub("add <zone> [--provider digitalocean]", "Replicate a zone from a cloud provider", false),
		sub("list", "List replicas with serial and last sync", true),
		sub("sync [<zone>] [--quiet]", "Pull fresh copies now (a timer does this every 5 minutes)", false),
		sub("remove <zone> [--force]", "Stop replicating a zone", false),
		overlayCmd(),
	)

	provider := &cobra.Command{Use: "provider", Short: "Cloud DNS providers"}
	plist := &cobra.Command{
		Use: "list", Short: "Show supported providers and whether credentials are configured", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			_, tokErr := cfg.DOToken()
			type row struct {
				Name       string `json:"name"`
				Configured bool   `json:"configured"`
				Zones      int    `json:"zones"`
			}
			n := 0
			for _, z := range cfg.CloudZones {
				if z.Provider == "digitalocean" || z.Provider == "do" || z.Provider == "" {
					n++
				}
			}
			rows := []row{{"digitalocean", tokErr == nil, n}}
			return emit(rows, func() {
				fmt.Printf("%-16s %-12s %s\n", "PROVIDER", "CREDENTIALS", "ZONES")
				for _, r := range rows {
					fmt.Printf("%-16s %-12s %d\n", r.Name, map[bool]string{true: "configured", false: "missing"}[r.Configured], r.Zones)
				}
				if tokErr != nil {
					fmt.Fprintln(os.Stderr, "\n"+tokErr.Error())
				}
			})
		},
	}
	markReadOnly(plist)
	provider.AddCommand(plist)

	cloud.AddCommand(zone, provider)
	return cloud
}
