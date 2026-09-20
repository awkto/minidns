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
	"github.com/awkto/minidns/internal/rpz"
	"github.com/awkto/minidns/internal/unbound"
	"github.com/awkto/minidns/internal/zonefile"
	"github.com/awkto/minidns/internal/zones"
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
		pos, err := parseArgs(fs, args[1:])
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return fmt.Errorf("usage: minidns cloud zone add <zone> [--provider digitalocean]")
		}
		name := rpz.Normalize(pos[0])
		if !rpz.ValidDomain(name) || strings.HasPrefix(name, "*.") {
			return fmt.Errorf("%q is not a valid zone name", pos[0])
		}
		if cfg.FindZone(name) != nil {
			return fmt.Errorf("zone %s is already mirrored", name)
		}
		if cfg.HasLocalZone(name) {
			return fmt.Errorf("%s is a local authoritative zone on this host; a name can be local or a replica, not both", name)
		}
		z := config.Zone{Name: name, Provider: *prov}
		fmt.Printf("pulling %s from %s...\n", name, *prov)
		if err := syncZone(cfg, z, false); err != nil {
			return err
		}
		cfg.CloudZones = append(cfg.CloudZones, z)
		if err := config.Save(cfg); err != nil {
			return err
		}
		if err := cmdApply(true); err != nil {
			return err
		}
		fmt.Printf("zone %s mirrored — it will keep resolving locally even if your ISP is down\n", name)
		return nil

	case "remove":
		fs := flag.NewFlagSet("zone remove", flag.ContinueOnError)
		force := fs.Bool("force", false, "also delete the zone's local overlay records")
		pos, err := parseArgs(fs, args[1:])
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return fmt.Errorf("usage: minidns cloud zone remove <zone> [--force]")
		}
		name := strings.TrimSuffix(strings.ToLower(pos[0]), ".")
		rz := cfg.FindZone(name)
		if rz == nil {
			return fmt.Errorf("zone %s is not mirrored", name)
		}
		if rz.Overlay {
			if ov, err := zones.LoadOverlay(name); err == nil && len(ov.Records) > 0 && !*force {
				return fmt.Errorf("%w: %s still has %d local overlay record(s); re-run with --force to delete them with the replica", zones.ErrConflict, name, len(ov.Records))
			}
		}
		out := cfg.CloudZones[:0]
		for _, z := range cfg.CloudZones {
			if z.Name != name {
				out = append(out, z)
			}
		}
		cfg.CloudZones = out
		if err := config.Save(cfg); err != nil {
			return err
		}
		// same ordering as list removal: config first, file second
		if err := cmdApply(true); err != nil {
			return err
		}
		os.Remove(paths.ZoneFile(name))
		os.Remove(paths.UpstreamFile(name))
		zones.RemoveOverlay(name)
		fmt.Println("removed zone", name)
		return nil

	case "list":
		if len(cfg.CloudZones) == 0 {
			fmt.Println("no zones replicated — add one with `minidns cloud zone add <zone>`")
			return nil
		}
		for _, z := range cfg.CloudZones {
			p := paths.ZoneFile(z.Name)
			if st, err := os.Stat(p); err == nil {
				synced := st.ModTime()
				overlay := ""
				if z.Overlay {
					if us, err := os.Stat(paths.UpstreamFile(z.Name)); err == nil {
						synced = us.ModTime()
					}
					if ov, err := zones.LoadOverlay(z.Name); err == nil {
						overlay = fmt.Sprintf("  +%d overlay record(s)", len(ov.Records))
					}
				}
				fmt.Printf("%-30s %-14s serial %-12s synced %s%s\n", z.Name, z.Provider, zoneSerial(p), ago(synced), overlay)
			} else {
				fmt.Printf("%-30s %-14s NOT SYNCED\n", z.Name, z.Provider)
			}
		}
		return nil

	case "sync":
		fs := flag.NewFlagSet("zone sync", flag.ContinueOnError)
		quiet := fs.Bool("quiet", false, "only print errors and changes")
		pos, err := parseArgs(fs, args[1:])
		if err != nil {
			return err
		}
		if len(pos) > 1 {
			return fmt.Errorf("usage: minidns cloud zone sync [<zone>] [--quiet]")
		}
		targets := cfg.CloudZones
		if len(pos) == 1 {
			z := cfg.FindZone(pos[0])
			if z == nil {
				return fmt.Errorf("zone %s is not mirrored", pos[0])
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
	return fmt.Errorf("usage: minidns cloud zone add|remove|list|sync")
}

// syncZone pulls a fresh copy of the zone and hot-reloads it in unbound if
// it changed.
func syncZone(cfg *config.Config, z config.Zone, quiet bool) error {
	p, err := provider.For(cfg, z.Provider)
	if err != nil {
		return err
	}
	data, err := p.FetchZone(z.Name)
	if err != nil {
		return err
	}
	// never activate data we can't vouch for — a bad API response must not
	// replace the last-known-good copy
	if _, err := zonefile.Validate(z.Name, data); err != nil {
		return fmt.Errorf("%s returned an unusable zone (keeping the current copy): %w", p.Name(), err)
	}
	if z.Overlay {
		return syncOverlaid(z, data, quiet)
	}
	target := paths.ZoneFile(z.Name)
	old, _ := os.ReadFile(target)
	if string(old) == data {
		if !quiet {
			fmt.Printf("%s: unchanged (serial %s)\n", z.Name, zoneSerial(target))
		}
		// touch so `status` shows the real last-sync time
		return os.Chtimes(target, time.Now(), time.Now())
	}
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, []byte(data), 0o644); err != nil {
		return err
	}
	// unbound runs unprivileged and must be able to read the zone even when
	// root's umask is restrictive
	if err := os.Chmod(tmp, 0o644); err != nil {
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

// syncOverlaid stores the provider's fresh data and re-merges the overlay.
func syncOverlaid(z config.Zone, data string, quiet bool) error {
	upstream := paths.UpstreamFile(z.Name)
	if old, _ := os.ReadFile(upstream); string(old) != data {
		if err := writeFileAtomic(upstream, []byte(data)); err != nil {
			return err
		}
	} else {
		os.Chtimes(upstream, time.Now(), time.Now())
	}
	serial, changed, err := rebuildReplica(z)
	if err != nil {
		return err
	}
	if !changed {
		if !quiet {
			fmt.Printf("%s: unchanged (serial %d)\n", z.Name, serial)
		}
		return nil
	}
	if unbound.Active() {
		if err := unbound.ReloadZone(z.Name + "."); err != nil {
			return err
		}
	}
	fmt.Printf("%s: updated (serial %d)\n", z.Name, serial)
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
