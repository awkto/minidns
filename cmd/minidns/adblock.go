package main

import (
	"flag"
	"fmt"

	"github.com/awkto/minidns/internal/config"
)

// cmdAdblock is the v0.1 spelling of `minidns blocklist …`. The systemd unit
// of an old install may still call `adblock update` during an upgrade.
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
		deprecated("adblock status", "blocklist list")
		printBlocklists(cfg, blocklistRows(cfg, ""), false)
		return nil

	case "on", "off":
		deprecated("adblock "+args[0], map[string]string{"on": "blocklist enable", "off": "blocklist disable"}[args[0]])
		if err := setListEnabled("", args[0] == "on"); err != nil {
			return err
		}
		fmt.Println("adblock:", args[0])
		return nil

	case "update":
		deprecated("adblock update", "blocklist update")
		fs := flag.NewFlagSet("adblock update", flag.ContinueOnError)
		quiet := fs.Bool("quiet", false, "only print errors")
		if _, err := parseArgs(fs, args[1:]); err != nil {
			return err
		}
		return updateLists(cfg, nil, *quiet, false)

	case "list":
		if len(args) < 2 {
			return fmt.Errorf("usage: minidns adblock list add|remove ...")
		}
		switch args[1] {
		case "add":
			deprecated("adblock list add <url>", "blocklist add <name> --url <url>")
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
			n := *name
			if n == "" {
				n = config.ListNameFromURL(pos[0])
			}
			count, err := addList(cfg, n, pos[0], *format)
			if err != nil {
				return err
			}
			fmt.Printf("added list %s (%d domains)\n", n, count)
			return nil
		case "remove":
			deprecated("adblock list remove", "blocklist remove")
			if len(args) != 3 {
				return fmt.Errorf("usage: minidns adblock list remove <name>")
			}
			if err := removeList(cfg, args[2]); err != nil {
				return err
			}
			fmt.Println("removed list", args[2])
			return nil
		}
		return fmt.Errorf("usage: minidns adblock list add|remove ...")
	}
	return fmt.Errorf("usage: minidns adblock status|on|off|update|list")
}
