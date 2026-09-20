package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/awkto/minidns/internal/adblock"
	"github.com/awkto/minidns/internal/config"
	"github.com/awkto/minidns/internal/paths"
	"github.com/awkto/minidns/internal/rpz"
	"github.com/awkto/minidns/internal/unbound"
)

func cmdAdblock(args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	switch args[0] {
	case "status":
		state := "off"
		if cfg.Adblock.Enabled {
			state = "on"
		}
		fmt.Println("adblock:", state)
		for _, l := range cfg.Adblock.Lists {
			p := paths.AdblockRPZ(l.Name)
			entries := "not downloaded"
			if st, err := os.Stat(p); err == nil {
				entries = fmt.Sprintf("%d entries, updated %s", rpz.CountEntries(p), ago(st.ModTime()))
			}
			fmt.Printf("  %-14s %-7s %s\n      %s\n", l.Name, l.Format, entries, l.URL)
		}
		return nil

	case "on", "off":
		cfg.Adblock.Enabled = args[0] == "on"
		if err := config.Save(cfg); err != nil {
			return err
		}
		if err := cmdApply(true); err != nil {
			return err
		}
		fmt.Println("adblock:", args[0])
		return nil

	case "update":
		fs := flag.NewFlagSet("adblock update", flag.ContinueOnError)
		quiet := fs.Bool("quiet", false, "only print errors")
		if _, err := parseArgs(fs, args[1:]); err != nil {
			return err
		}
		if len(cfg.Adblock.Lists) == 0 {
			return fmt.Errorf("no lists configured — add one with `minidns adblock list add <url>`")
		}
		anyChanged := false
		var firstErr error
		for _, l := range cfg.Adblock.Lists {
			n, changed, err := adblock.Update(l)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", l.Name, err)
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			anyChanged = anyChanged || changed
			if !*quiet {
				fmt.Printf("%s: %d domains%s\n", l.Name, n, map[bool]string{true: " (changed)", false: " (unchanged)"}[changed])
			}
		}
		if anyChanged {
			// new list files may need wiring into the unbound config
			if err := cmdApply(false); err != nil {
				return err
			}
			if unbound.Active() {
				if err := unbound.Reload(); err != nil {
					return err
				}
			}
		}
		return firstErr

	case "list":
		if len(args) < 2 {
			return fmt.Errorf("usage: minidns adblock list add|remove ...")
		}
		switch args[1] {
		case "add":
			fs := flag.NewFlagSet("adblock list add", flag.ContinueOnError)
			name := fs.String("name", "", "short list name (default: derived from URL)")
			format := fs.String("format", "hosts", "list format: hosts|domains|rpz")
			pos, err := parseArgs(fs, args[2:])
			if err != nil {
				return err
			}
			if len(pos) != 1 {
				return fmt.Errorf("usage: minidns adblock list add <url> [--name n] [--format hosts|domains|rpz]")
			}
			url := pos[0]
			n := *name
			if n == "" {
				n = config.ListNameFromURL(url)
			}
			if !rpz.ValidListName(n) {
				return fmt.Errorf("invalid list name %q: use lowercase letters, digits, - and _ (set one with --name)", n)
			}
			if cfg.FindList(n) != nil {
				return fmt.Errorf("list %q already exists", n)
			}
			l := config.BlockList{Name: n, URL: url, Format: *format}
			fmt.Printf("downloading %s...\n", n)
			count, _, err := adblock.Update(l)
			if err != nil {
				return err
			}
			cfg.Adblock.Lists = append(cfg.Adblock.Lists, l)
			if err := config.Save(cfg); err != nil {
				return err
			}
			if err := cmdApply(true); err != nil {
				return err
			}
			fmt.Printf("added list %s (%d domains)\n", n, count)
			return nil
		case "remove":
			if len(args) != 3 {
				return fmt.Errorf("usage: minidns adblock list remove <name>")
			}
			n := args[2]
			if cfg.FindList(n) == nil {
				return fmt.Errorf("no list named %q", n)
			}
			out := cfg.Adblock.Lists[:0]
			for _, l := range cfg.Adblock.Lists {
				if l.Name != n {
					out = append(out, l)
				}
			}
			cfg.Adblock.Lists = out
			if err := config.Save(cfg); err != nil {
				return err
			}
			os.Remove(paths.AdblockRPZ(n))
			if err := cmdApply(true); err != nil {
				return err
			}
			fmt.Println("removed list", n)
			return nil
		}
		return fmt.Errorf("usage: minidns adblock list add|remove ...")
	}
	return fmt.Errorf("usage: minidns adblock status|on|off|update|list")
}
