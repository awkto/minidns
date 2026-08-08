package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/awkto/minidns/internal/config"
	"github.com/awkto/minidns/internal/paths"
	"github.com/awkto/minidns/internal/provider"
	"github.com/awkto/minidns/internal/unbound"
)

func cmdZone(args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	switch args[0] {
	case "add":
		fs := flag.NewFlagSet("zone add", flag.ContinueOnError)
		prov := fs.String("provider", "digitalocean", "dns provider (digitalocean; roadmap: route53, azure, cloudflare)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return fmt.Errorf("usage: minidns zone add <zone> [--provider digitalocean]")
		}
		name := strings.TrimSuffix(strings.ToLower(fs.Arg(0)), ".")
		if cfg.FindZone(name) != nil {
			return fmt.Errorf("zone %s is already mirrored", name)
		}
		z := config.Zone{Name: name, Provider: *prov}
		fmt.Printf("pulling %s from %s...\n", name, *prov)
		if err := syncZone(cfg, z, false); err != nil {
			return err
		}
		cfg.Zones = append(cfg.Zones, z)
		if err := config.Save(cfg); err != nil {
			return err
		}
		if err := cmdApply(true); err != nil {
			return err
		}
		fmt.Printf("zone %s mirrored — it will keep resolving locally even if your ISP is down\n", name)
		return nil

	case "remove":
		if len(args) != 2 {
			return fmt.Errorf("usage: minidns zone remove <zone>")
		}
		name := strings.TrimSuffix(strings.ToLower(args[1]), ".")
		if cfg.FindZone(name) == nil {
			return fmt.Errorf("zone %s is not mirrored", name)
		}
		out := cfg.Zones[:0]
		for _, z := range cfg.Zones {
			if z.Name != name {
				out = append(out, z)
			}
		}
		cfg.Zones = out
		if err := config.Save(cfg); err != nil {
			return err
		}
		os.Remove(paths.ZoneFile(name))
		if err := cmdApply(true); err != nil {
			return err
		}
		fmt.Println("removed zone", name)
		return nil

	case "list":
		if len(cfg.Zones) == 0 {
			fmt.Println("no zones mirrored — add one with `minidns zone add <zone>`")
			return nil
		}
		for _, z := range cfg.Zones {
			p := paths.ZoneFile(z.Name)
			if st, err := os.Stat(p); err == nil {
				fmt.Printf("%-30s %-14s serial %-12s synced %s\n", z.Name, z.Provider, zoneSerial(p), ago(st.ModTime()))
			} else {
				fmt.Printf("%-30s %-14s NOT SYNCED\n", z.Name, z.Provider)
			}
		}
		return nil

	case "sync":
		fs := flag.NewFlagSet("zone sync", flag.ContinueOnError)
		quiet := fs.Bool("quiet", false, "only print errors and changes")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		targets := cfg.Zones
		if fs.NArg() == 1 {
			z := cfg.FindZone(fs.Arg(0))
			if z == nil {
				return fmt.Errorf("zone %s is not mirrored", fs.Arg(0))
			}
			targets = []config.Zone{*z}
		}
		if len(targets) == 0 {
			if !*quiet {
				fmt.Println("no zones to sync")
			}
			return nil
		}
		var firstErr error
		for _, z := range targets {
			if err := syncZone(cfg, z, *quiet); err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", z.Name, err)
				if firstErr == nil {
					firstErr = err
				}
			}
		}
		return firstErr
	}
	return fmt.Errorf("usage: minidns zone add|remove|list|sync")
}

// syncZone pulls a fresh copy of the zone and hot-reloads it in unbound if
// it changed.
func syncZone(cfg *config.Config, z config.Zone, quiet bool) error {
	p, err := provider.For(cfg, z.Provider)
	if err != nil {
		return err
	}
	zonefile, err := p.FetchZone(z.Name)
	if err != nil {
		return err
	}
	target := paths.ZoneFile(z.Name)
	old, _ := os.ReadFile(target)
	if string(old) == zonefile {
		if !quiet {
			fmt.Printf("%s: unchanged (serial %s)\n", z.Name, zoneSerial(target))
		}
		// touch so `status` shows the real last-sync time
		return os.Chtimes(target, time.Now(), time.Now())
	}
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, []byte(zonefile), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		return err
	}
	if unbound.Active() {
		if err := unbound.ReloadZone(z.Name + "."); err != nil {
			return err
		}
	}
	fmt.Printf("%s: updated (serial %s)\n", z.Name, zoneSerial(target))
	return nil
}

var soaSerialRe = regexp.MustCompile(`(?i)\sSOA\s+\S+\s+\S+\s+(\d+)`)

// zoneSerial extracts the SOA serial from a zone file for display.
func zoneSerial(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "?"
	}
	if m := soaSerialRe.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return "?"
}
