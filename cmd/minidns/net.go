package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/awkto/minidns/internal/config"
	"github.com/awkto/minidns/internal/zones"
)

func cmdUpstream(args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	deprecated("upstream", "forwarder add|remove|list|test")
	if len(args) == 0 {
		tls := ""
		if cfg.UpstreamTLS {
			tls = " (DNS-over-TLS)"
		}
		if cfg.Recursion {
			fmt.Println("recursion mode is ON — upstreams are not used")
		}
		fmt.Printf("upstreams%s: %s\n", tls, strings.Join(cfg.Upstreams, ", "))
		return nil
	}
	if args[0] != "set" {
		return fmt.Errorf("usage: minidns upstream [set <addr>... [--tls]]")
	}
	// accept --tls anywhere, not just before the addresses
	tls := false
	var addrs []string
	for _, a := range args[1:] {
		if a == "--tls" || a == "-tls" {
			tls = true
		} else {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) == 0 {
		return fmt.Errorf("usage: minidns upstream set <addr>... [--tls]")
	}
	for i, a := range addrs {
		f, err := config.ParseForwarder(a)
		if err != nil {
			return err
		}
		addrs[i] = f.String()
	}
	cfg.Upstreams = addrs
	cfg.UpstreamTLS = tls
	if err := config.Save(cfg); err != nil {
		return err
	}
	if err := cmdApply(true); err != nil {
		return err
	}
	fmt.Printf("upstreams set: %s (tls: %v)\n", strings.Join(cfg.Upstreams, ", "), tls)
	return nil
}

func recursionCmd() *cobra.Command {
	rc := &cobra.Command{
		Use: "recursion on|off|status", Short: "Resolver mode: full recursion from the roots, or forwarding", GroupID: groupResolver,
		Args: cobra.MaximumNArgs(1), ValidArgs: []string{"on", "off", "status"},
		RunE: func(cmd *cobra.Command, args []string) error {
			want := "status"
			if len(args) == 1 {
				want = args[0]
			}
			var cfg *config.Config
			var err error
			switch want {
			case "status":
				cfg, err = config.Load()
			case "on", "off":
				if os.Geteuid() != 0 && os.Getenv("MINIDNS_PREFIX") == "" {
					return fmt.Errorf("%w: `minidns recursion %s` changes the system — run it with sudo", os.ErrPermission, want)
				}
				if err := lockState(); err != nil {
					return err
				}
				cfg, err = changeConfig(func(c *config.Config) error {
					if want == "off" && len(c.Upstreams) == 0 {
						return fmt.Errorf("%w: there is no global forwarder to forward to — `minidns forwarder add <address>` first", zones.ErrConflict)
					}
					c.Recursion = want == "on"
					return nil
				})
			default:
				return usagef("usage: minidns recursion on|off|status")
			}
			if err != nil {
				return err
			}
			mode := map[bool]string{true: "recursion", false: "forwarding"}[cfg.Recursion]
			return emit(map[string]any{"mode": mode, "recursion": cfg.Recursion, "forwarders": cfg.Upstreams}, func() {
				switch {
				case cfg.Recursion && want == "status":
					fmt.Println("recursion: on (resolving directly from the roots)")
				case cfg.Recursion:
					fmt.Println("recursion: on — unbound now resolves from the root servers directly")
					fmt.Println("compare latency with `minidns query <name>`; revert with `minidns recursion off`")
				case want == "status":
					fmt.Printf("recursion: off (forwarding to %s)\n", strings.Join(cfg.Upstreams, ", "))
				default:
					fmt.Println("recursion: off — forwarding to", strings.Join(cfg.Upstreams, ", "))
				}
			})
		},
	}
	// `status` is the default and reads only; on/off check for root themselves
	markReadOnly(rc)
	supportsDryRun(rc)
	return rc
}
