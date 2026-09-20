// minidns — a tiny wrapper that turns unbound into a home DNS server with
// local zones, a firewall, adblocking, cloud-zone replicas, query logs and
// metrics.
package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/spf13/cobra"
)

var version = "dev"

const (
	groupSetup    = "setup"
	groupDNS      = "dns"
	groupFilter   = "filter"
	groupResolver = "resolver"
	groupObserve  = "observe"
)

// legacy wraps a v0.1 command implementation (which parses its own
// arguments) as a cobra command.
func legacy(use, short, group string, readOnly bool, run func([]string) error) *cobra.Command {
	c := &cobra.Command{
		Use: use, Short: short, GroupID: group, DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error { return run(args) },
	}
	if readOnly {
		markReadOnly(c)
	}
	return c
}

func setupGroup(c *cobra.Command) *cobra.Command {
	c.GroupID = groupSetup
	return c
}

func hide(c *cobra.Command) *cobra.Command {
	c.Hidden = true
	return c
}

func markReadOnly(cmds ...*cobra.Command) {
	for _, c := range cmds {
		if c.Annotations == nil {
			c.Annotations = map[string]string{}
		}
		c.Annotations["readonly"] = "true"
	}
}

func deprecated(old, replacement string) {
	fmt.Fprintf(os.Stderr, "warning: `minidns %s` is deprecated and will be removed in a future release; use `minidns %s`\n", old, replacement)
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "minidns",
		Short:         "Tiny home DNS manager (unbound under the hood)",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// unbound runs unprivileged and has to read what we write; don't
			// let a restrictive root umask make zone and config files unreadable
			syscall.Umask(0o022)
			if cmd.Annotations["readonly"] == "true" || cmd.Name() == "help" || cmd.Name() == "completion" || cmd.Name() == "__complete" {
				return nil
			}
			if os.Geteuid() != 0 && os.Getenv("MINIDNS_PREFIX") == "" {
				return fmt.Errorf("%w: `%s` changes the system — run it with sudo", os.ErrPermission, cmd.CommandPath())
			}
			return lockState()
		},
	}
	root.SetVersionTemplate("minidns {{.Version}}\n")
	root.PersistentFlags().BoolVar(&jsonOut, "json", false, "machine-readable output on stdout")
	root.AddGroup(
		&cobra.Group{ID: groupSetup, Title: "Setup"},
		&cobra.Group{ID: groupDNS, Title: "Zones and records"},
		&cobra.Group{ID: groupFilter, Title: "Filtering"},
		&cobra.Group{ID: groupResolver, Title: "Resolver"},
		&cobra.Group{ID: groupObserve, Title: "Observability"},
	)

	zone, record, rzone, host, cloud := zoneCmd(), recordCmd(), reverseZoneCmd(), hostCmd(), cloudCmd()
	for _, c := range []*cobra.Command{zone, record, rzone, host, cloud} {
		c.GroupID = groupDNS
	}

	forwarder, query := forwarderCmd(), queryCmd()
	forwarder.GroupID, query.GroupID = groupResolver, groupResolver

	block, allow, blocklist := blockCmd(), allowCmd(), blocklistCmd()
	for _, c := range []*cobra.Command{block, allow, blocklist} {
		c.GroupID = groupFilter
	}

	root.AddCommand(
		legacy("setup", "First run: config, unbound, timers, lists", groupSetup, false, cmdSetup),
		legacy("apply", "Regenerate the unbound config and reload", groupSetup, false, func([]string) error { return cmdApply(true) }),
		doctorCmd(), setupGroup(configCmd()), setupGroup(backupCmd()), setupGroup(restoreCmd()),
		legacy("status", "Service, mode, blocking and zone summary", groupSetup, true, cmdStatus),
		legacy("test <domain> [type]", "Resolve via the local server and show the policy verdict", groupSetup, true, cmdTest),

		zone, record, rzone, host, cloud,

		block, allow, blocklist,
		hide(legacy("unblock <domain>...", "Remove a manual block", groupFilter, false, cmdUnblock)),
		hide(legacy("unallow <domain>...", "Remove from the allowlist", groupFilter, false, cmdUnallow)),
		hide(legacy("adblock status|on|off|update|list", "Subscribed blocklists", groupFilter, false, cmdAdblock)),

		forwarder, query,
		hide(legacy("upstream [set <addr>... [--tls]]", "Show or set upstream forwarders", groupResolver, false, cmdUpstream)),
		legacy("recursion on|off|status", "Full recursion instead of forwarding", groupResolver, false, cmdRecursion),

		legacy("logs [-n N] [-f] [--client IP] [--blocked]", "Query log", groupObserve, true, cmdLogs),
		legacy("top [-n N] [--clients] [--client IP] [--since 24h]", "Top domains or clients", groupObserve, true, cmdTop),
		legacy("stats", "unbound cache and query statistics", groupObserve, true, cmdStats),
		legacy("exporter", "Run the Prometheus exporter", groupObserve, true, cmdExporter),
		&cobra.Command{Use: "version", Short: "Print the version", Annotations: map[string]string{"readonly": "true"},
			Run: func(*cobra.Command, []string) { fmt.Println("minidns", version) }},
	)
	return root
}

func main() {
	root := rootCmd()
	err := root.Execute()
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, "minidns:", err)
	code := exitCodeFor(err)
	// cobra's own complaints (unknown command/flag, wrong arg count) are usage errors
	var ue usageError
	if code == exitError && !errors.As(err, &ue) && isCobraUsage(err) {
		code = exitUsage
	}
	os.Exit(code)
}
