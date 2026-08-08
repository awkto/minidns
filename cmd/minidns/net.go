package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/awkto/minidns/internal/config"
)

func cmdUpstream(args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
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
	for _, a := range addrs {
		host := a
		if i := strings.IndexAny(host, "@#"); i >= 0 {
			host = host[:i]
		}
		if net.ParseIP(host) == nil {
			return fmt.Errorf("%q is not an IP address (use ip, ip@port, or ip@port#tlsname)", a)
		}
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

func cmdRecursion(args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if len(args) == 0 {
		args = []string{"status"}
	}
	switch args[0] {
	case "status":
		if cfg.Recursion {
			fmt.Println("recursion: on (resolving directly from the roots)")
		} else {
			fmt.Printf("recursion: off (forwarding to %s)\n", strings.Join(cfg.Upstreams, ", "))
		}
		return nil
	case "on", "off":
		cfg.Recursion = args[0] == "on"
		if err := config.Save(cfg); err != nil {
			return err
		}
		if err := cmdApply(true); err != nil {
			return err
		}
		if cfg.Recursion {
			fmt.Println("recursion: on — unbound now resolves from the root servers directly")
			fmt.Println("compare latency with `minidns test <domain>`; revert with `minidns recursion off`")
		} else {
			fmt.Println("recursion: off — forwarding to", strings.Join(cfg.Upstreams, ", "))
		}
		return nil
	}
	return fmt.Errorf("usage: minidns recursion on|off|status")
}
