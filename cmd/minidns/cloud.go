package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/awkto/minidns/internal/config"
	"github.com/awkto/minidns/internal/paths"
	"github.com/awkto/minidns/internal/zones"
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
	var tokenFile string
	setToken := &cobra.Command{
		Use: "set-token <provider>", Short: "Store a provider API token (read from stdin, never from the command line)", Args: cobra.ExactArgs(1),
		Example: "  minidns cloud provider set-token digitalocean < token.txt\n  minidns cloud provider set-token digitalocean --from-file /root/do.token",
		RunE: func(cmd *cobra.Command, args []string) error {
			if args[0] != "digitalocean" && args[0] != "do" {
				return fmt.Errorf("%w: unsupported provider %q (supported: digitalocean)", zones.ErrInvalid, args[0])
			}
			var raw []byte
			var err error
			if tokenFile != "" {
				raw, err = os.ReadFile(tokenFile)
			} else {
				if st, _ := os.Stdin.Stat(); st != nil && st.Mode()&os.ModeCharDevice != 0 {
					note("paste the token and press Enter, then Ctrl-D:")
				}
				raw, err = io.ReadAll(io.LimitReader(os.Stdin, 4096))
			}
			if err != nil {
				return err
			}
			token := strings.TrimSpace(string(raw))
			if token == "" || strings.ContainsAny(token, " \t\r\n") {
				return fmt.Errorf("%w: that does not look like an API token", zones.ErrInvalid)
			}
			cr, err := config.LoadCredentials()
			if err != nil {
				return err
			}
			cr.DigitalOcean.Token = token
			if err := config.SaveCredentials(cr); err != nil {
				return err
			}
			return emit(map[string]any{"provider": "digitalocean", "configured": true}, func() {
				fmt.Printf("Token for digitalocean stored in %s (readable by root only).\n", paths.CredentialsFile())
			})
		},
	}
	setToken.Flags().StringVar(&tokenFile, "from-file", "", "read the token from this file instead of stdin")

	markReadOnly(plist)
	provider.AddCommand(plist, setToken)

	cloud.AddCommand(zone, provider)
	return cloud
}
