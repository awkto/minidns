// minidns — a tiny wrapper that turns unbound into a home DNS server with
// a firewall, adblocking, local cloud-zone mirrors, query logs and metrics.
package main

import (
	"fmt"
	"os"
)

var version = "dev"

const usageText = `minidns %s — tiny home DNS manager (unbound under the hood)

Setup
  minidns setup                      first-run: config, unbound, timers, lists
  minidns apply                      regenerate unbound config + reload
  minidns status                     service, mode, blocking and zone summary
  minidns test <domain> [type]       resolve via the local server, show verdict

Firewall (feature 1)
  minidns block <domain>...          block a domain (and subdomains)
  minidns unblock <domain>...        remove a manual block
  minidns allow <domain>...          allowlist (wins over all blocking)
  minidns unallow <domain>...        remove from allowlist
  minidns blocklist                  show manual blocks + allows

Adblock (feature 2)
  minidns adblock status|on|off      show / enable / disable adblocking
  minidns adblock update             re-download lists now
  minidns adblock list add <url> [--name n] [--format hosts|domains|rpz]
  minidns adblock list remove <name>

Zone mirror (feature 3)
  minidns zone add <zone> [--provider digitalocean]
  minidns zone remove <zone>
  minidns zone list
  minidns zone sync [<zone>] [--quiet]   pull fresh copies (timer runs this)

Resolver
  minidns upstream                   show upstream forwarders
  minidns upstream set <addr>... [--tls]
  minidns recursion on|off|status    full recursion instead of forwarding

Observability
  minidns logs [-n N] [-f] [--client IP] [--blocked]
  minidns top [-n N] [--clients] [--client IP] [--since 24h]
  minidns stats                      unbound cache/query stats snapshot
  minidns exporter                   run Prometheus exporter (see config)

  minidns version
`

func usage() { fmt.Printf(usageText, version) }

func main() {
	if len(os.Args) < 2 || os.Args[1] == "help" || os.Args[1] == "--help" || os.Args[1] == "-h" {
		usage()
		os.Exit(0)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "setup":
		err = cmdSetup(args)
	case "apply":
		err = cmdApply(true)
	case "status":
		err = cmdStatus(args)
	case "test":
		err = cmdTest(args)
	case "block":
		err = cmdBlock(args)
	case "unblock":
		err = cmdUnblock(args)
	case "allow":
		err = cmdAllow(args)
	case "unallow":
		err = cmdUnallow(args)
	case "blocklist":
		err = cmdBlocklist(args)
	case "adblock":
		err = cmdAdblock(args)
	case "zone":
		err = cmdZone(args)
	case "upstream":
		err = cmdUpstream(args)
	case "recursion":
		err = cmdRecursion(args)
	case "logs":
		err = cmdLogs(args)
	case "top":
		err = cmdTop(args)
	case "stats":
		err = cmdStats(args)
	case "exporter":
		err = cmdExporter(args)
	case "version", "--version", "-v":
		fmt.Println("minidns", version)
	default:
		fmt.Fprintf(os.Stderr, "minidns: unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "minidns:", err)
		os.Exit(1)
	}
}
