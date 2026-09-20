package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/awkto/minidns/internal/config"
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
	verdict := explain(cfg, name).oneLine()

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
	for i := range cfg.CloudZones {
		z := &cfg.CloudZones[i]
		if name == z.Name || strings.HasSuffix(name, "."+z.Name) {
			return z
		}
	}
	return nil
}
