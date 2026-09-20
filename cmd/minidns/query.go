package main

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"

	"github.com/awkto/minidns/internal/config"
	"github.com/awkto/minidns/internal/zones"
)

type queryResult struct {
	Server     string   `json:"server"`
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Rcode      string   `json:"rcode"`
	Flags      []string `json:"flags"`
	RTTms      float64  `json:"rtt_ms"`
	Answer     []string `json:"answer"`
	Authority  []string `json:"authority,omitempty"`
	Additional []string `json:"additional,omitempty"`
}

// exchange sends one question, retrying over TCP when the answer was truncated.
func exchange(server, name string, qtype uint16, recurse bool) (*dns.Msg, time.Duration, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = recurse
	m.SetEdns0(1232, true)
	c := &dns.Client{Timeout: 5 * time.Second}
	resp, rtt, err := c.Exchange(m, server)
	if err == nil && resp.Truncated {
		c.Net = "tcp"
		resp, rtt, err = c.Exchange(m, server)
	}
	return resp, rtt, err
}

func rrStrings(rrs []dns.RR) []string {
	out := []string{}
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		out = append(out, strings.Join(strings.Fields(rr.String()), " "))
	}
	return out
}

func toResult(server, name, qtype string, resp *dns.Msg, rtt time.Duration) queryResult {
	r := queryResult{Server: server, Name: name, Type: qtype, Rcode: dns.RcodeToString[resp.Rcode],
		RTTms: float64(rtt.Microseconds()) / 1000, Flags: []string{},
		Answer: rrStrings(resp.Answer), Authority: rrStrings(resp.Ns), Additional: rrStrings(resp.Extra)}
	for flag, on := range map[string]bool{"aa": resp.Authoritative, "ad": resp.AuthenticatedData, "ra": resp.RecursionAvailable, "tc": resp.Truncated} {
		if on {
			r.Flags = append(r.Flags, flag)
		}
	}
	sort.Strings(r.Flags)
	return r
}

// serverArg turns --server into host:port.
func serverArg(s string) (string, error) {
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return netip.AddrPortFrom(a, 53).String(), nil
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.String(), nil
	}
	if host, port, err := net.SplitHostPort(s); err == nil && host != "" {
		return net.JoinHostPort(host, port), nil
	}
	if _, ok := dns.IsDomainName(s); ok && !strings.ContainsAny(s, " /") {
		return net.JoinHostPort(s, "53"), nil
	}
	return "", fmt.Errorf("%w: --server %q is not an address, address:port or host name", zones.ErrInvalid, s)
}

func queryCmd() *cobra.Command {
	var server string
	var trace, full bool
	cmd := &cobra.Command{
		Use: "query <name|ip> [type]", Short: "Look a name up on this server (or another one)", Args: cobra.RangeArgs(1, 2),
		Example: "  minidns query nas.home.arpa\n  minidns query example.com MX\n  minidns query 10.20.0.10              (reverse lookup)\n  minidns query example.com --server 9.9.9.9\n  minidns query example.com --trace",
		RunE: func(cmd *cobra.Command, args []string) error {
			name, qtypeStr := strings.ToLower(args[0]), "A"
			if addr, err := netip.ParseAddr(name); err == nil {
				name, qtypeStr = strings.TrimSuffix(zones.PTRName(addr), "."), "PTR"
			}
			if len(args) == 2 {
				qtypeStr = strings.ToUpper(args[1])
			}
			qtype, ok := dns.StringToType[qtypeStr]
			if !ok {
				return fmt.Errorf("%w: unknown record type %q", zones.ErrInvalid, qtypeStr)
			}
			if _, ok := dns.IsDomainName(name); !ok {
				return fmt.Errorf("%w: %q is not a domain name", zones.ErrInvalid, args[0])
			}
			if trace {
				return runTrace(name, qtype, qtypeStr)
			}
			target := server
			if target == "" {
				cfg, err := config.Load()
				if err != nil {
					return err
				}
				target = serverAddr(cfg)
			} else {
				var err error
				if target, err = serverArg(target); err != nil {
					return err
				}
			}
			resp, rtt, err := exchange(target, name, qtype, true)
			if err != nil {
				return connError{fmt.Errorf("no answer from %s: %s", target, shortNetErr(err))}
			}
			res := toResult(target, name, qtypeStr, resp, rtt)
			return emit(res, func() {
				if full {
					fmt.Print(resp.String())
					return
				}
				fmt.Printf("%s %s @%s → %s in %s", name, qtypeStr, target, res.Rcode, rtt.Round(100*time.Microsecond))
				if len(res.Flags) > 0 {
					fmt.Printf("  [%s]", strings.Join(res.Flags, " "))
				}
				fmt.Println()
				for _, a := range res.Answer {
					fmt.Println("  " + a)
				}
				if len(res.Answer) == 0 {
					for _, a := range res.Authority {
						fmt.Println("  (authority) " + a)
					}
				}
			})
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "ask this server instead of the local one (address, address:port or name)")
	cmd.Flags().BoolVar(&trace, "trace", false, "resolve step by step from the root servers, bypassing this server")
	cmd.Flags().BoolVar(&full, "full", false, "print the complete response, dig-style")
	markReadOnly(cmd)
	return cmd
}

type traceStep struct {
	Zone   string      `json:"zone"`
	Server string      `json:"server"`
	Result queryResult `json:"result"`
}

// runTrace walks the delegation chain the way `dig +trace` does: ask a root
// server, follow each referral (using glue, else resolving the name server
// through the system resolver) until a server answers authoritatively.
func runTrace(name string, qtype uint16, qtypeStr string) error {
	servers := []string{"198.41.0.4", "199.9.14.201", "192.33.4.12"} // a, b, c.root-servers.net
	zone := "."
	var steps []traceStep
	for depth := 0; depth < 16; depth++ {
		var resp *dns.Msg
		var rtt time.Duration
		var used string
		var err error
		for _, s := range servers {
			used = net.JoinHostPort(s, "53")
			if resp, rtt, err = exchange(used, name, qtype, false); err == nil {
				break
			}
		}
		if err != nil {
			return connError{fmt.Errorf("trace stopped at zone %s: no server answered (%s)", zone, shortNetErr(err))}
		}
		step := traceStep{Zone: zone, Server: used, Result: toResult(used, name, qtypeStr, resp, rtt)}
		steps = append(steps, step)
		if !jsonOut {
			fmt.Printf("%-28s @%-22s %s", zone, used, step.Result.Rcode)
		}
		referral := len(resp.Answer) == 0 && resp.Rcode == dns.RcodeSuccess && !resp.Authoritative
		var next []string
		nextZone := zone
		if referral {
			glue := map[string][]string{}
			for _, rr := range resp.Extra {
				switch a := rr.(type) {
				case *dns.A:
					glue[strings.ToLower(a.Hdr.Name)] = append(glue[strings.ToLower(a.Hdr.Name)], a.A.String())
				case *dns.AAAA: // stay on IPv4: many hosts have no v6 route
				}
			}
			var nsNames []string
			for _, rr := range resp.Ns {
				if ns, ok := rr.(*dns.NS); ok {
					nextZone = strings.ToLower(ns.Hdr.Name)
					nsNames = append(nsNames, strings.ToLower(ns.Ns))
				}
			}
			for _, n := range nsNames {
				next = append(next, glue[n]...)
			}
			for i := 0; len(next) == 0 && i < len(nsNames); i++ {
				if ips, err := net.LookupIP(nsNames[i]); err == nil {
					for _, ip := range ips {
						if ip.To4() != nil {
							next = append(next, ip.String())
						}
					}
				}
			}
		}
		if !referral || len(next) == 0 {
			if !jsonOut {
				fmt.Println("  ← answer")
				for _, a := range step.Result.Answer {
					fmt.Println("  " + a)
				}
				if len(step.Result.Answer) == 0 {
					for _, a := range step.Result.Authority {
						fmt.Println("  (authority) " + a)
					}
				}
			}
			break
		}
		if !jsonOut {
			fmt.Printf("  → referral to %s\n", nextZone)
		}
		if len(next) > 3 {
			next = next[:3]
		}
		servers, zone = next, nextZone
	}
	if jsonOut {
		return emit(steps, func() {})
	}
	return nil
}
