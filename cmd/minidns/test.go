package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/awkto/minidns/internal/config"
	"github.com/awkto/minidns/internal/paths"
	"github.com/awkto/minidns/internal/rpz"
)

func cmdTest(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: minidns test <domain> [type]")
	}
	name := strings.TrimSuffix(strings.ToLower(args[0]), ".")
	qtypeStr := "A"
	if len(args) > 1 {
		qtypeStr = strings.ToUpper(args[1])
	}
	qtype, ok := dns.StringToType[qtypeStr]
	if !ok {
		return fmt.Errorf("unknown record type %q", qtypeStr)
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// static verdict from the RPZ files, so the user sees *why*
	verdict := ""
	if entry, ok := rpz.Contains(paths.AllowRPZ(), name); ok {
		verdict = fmt.Sprintf("allowlisted (matches %s)", entry)
	} else if entry, ok := rpz.Contains(paths.BlockRPZ(), name); ok && cfg.Firewall.Enabled {
		verdict = fmt.Sprintf("blocked by firewall (matches %s)", entry)
	} else if cfg.Adblock.Enabled {
		for _, l := range cfg.Adblock.Lists {
			if entry, ok := rpz.Contains(paths.AdblockRPZ(l.Name), name); ok {
				verdict = fmt.Sprintf("blocked by adblock list %q (matches %s)", l.Name, entry)
				break
			}
		}
	}
	if z := matchZone(cfg, name); z != nil {
		suffix := ""
		if verdict != "" {
			suffix = "; " + verdict
		}
		verdict = fmt.Sprintf("served from local mirror of %s%s", z.Name, suffix)
	}
	if verdict == "" {
		verdict = "not blocked"
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	c := &dns.Client{Timeout: 5 * time.Second}
	server := fmt.Sprintf("127.0.0.1:%d", cfg.Port)
	start := time.Now()
	resp, _, err := c.Exchange(m, server)
	elapsed := time.Since(start)

	fmt.Printf("query    %s %s @ %s\n", name, qtypeStr, server)
	fmt.Printf("policy   %s\n", verdict)
	if err != nil {
		return fmt.Errorf("query failed: %w (is unbound running? `minidns status`)", err)
	}
	fmt.Printf("rcode    %s in %s\n", dns.RcodeToString[resp.Rcode], elapsed.Round(time.Microsecond))
	if len(resp.Answer) == 0 {
		fmt.Println("answer   (empty)")
	}
	for _, rr := range resp.Answer {
		fmt.Println("answer  ", rr.String())
	}
	return nil
}

// matchZone returns the mirrored zone that name falls under, if any.
func matchZone(cfg *config.Config, name string) *config.Zone {
	for i := range cfg.Zones {
		z := &cfg.Zones[i]
		if name == z.Name || strings.HasSuffix(name, "."+z.Name) {
			return z
		}
	}
	return nil
}
