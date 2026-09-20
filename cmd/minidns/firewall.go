package main

import (
	"fmt"
	"os"

	"github.com/awkto/minidns/internal/paths"
	"github.com/awkto/minidns/internal/rpz"
	"github.com/awkto/minidns/internal/unbound"
)

// editRPZ applies add/remove edits to one of the manual RPZ zones and
// live-reloads it in unbound.
func editRPZ(path, action, zoneName string, add, remove []string) error {
	current, err := rpz.ReadDomains(path)
	if err != nil {
		return err
	}
	set := make(map[string]struct{}, len(current))
	for _, d := range current {
		set[d] = struct{}{}
	}
	for _, d := range add {
		d = rpz.Normalize(d)
		if !rpz.ValidDomain(d) {
			return fmt.Errorf("%q doesn't look like a domain", d)
		}
		set[d] = struct{}{}
	}
	for _, d := range remove {
		d = rpz.Normalize(d)
		if _, ok := set[d]; !ok {
			fmt.Fprintf(os.Stderr, "note: %s was not in the list\n", d)
		}
		delete(set, d)
	}
	all := make([]string, 0, len(set))
	for d := range set {
		all = append(all, d)
	}
	if _, err := rpz.Write(path, all, action, true); err != nil {
		return err
	}
	if unbound.Active() {
		return unbound.ReloadZone(zoneName)
	}
	return nil
}

func cmdUnblock(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: minidns block remove <domain>...")
	}
	deprecated("unblock", "block remove")
	if err := editRPZ(paths.BlockRPZ(), rpz.ActionBlock, "block.rpz.minidns.", nil, args); err != nil {
		return err
	}
	fmt.Printf("unblocked: %v\n", args)
	return nil
}

func cmdUnallow(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: minidns allow remove <domain>...")
	}
	deprecated("unallow", "allow remove")
	if err := editRPZ(paths.AllowRPZ(), rpz.ActionPassthru, "allow.rpz.minidns.", nil, args); err != nil {
		return err
	}
	fmt.Printf("removed from allowlist: %v\n", args)
	return nil
}

func cmdBlocklist(args []string) error {
	blocks, err := rpz.ReadDomains(paths.BlockRPZ())
	if err != nil {
		return err
	}
	allows, err := rpz.ReadDomains(paths.AllowRPZ())
	if err != nil {
		return err
	}
	if len(blocks) == 0 && len(allows) == 0 {
		fmt.Println("no manual entries — add with `minidns block <domain>` / `minidns allow <domain>`")
		return nil
	}
	for _, d := range blocks {
		fmt.Println("block", d)
	}
	for _, d := range allows {
		fmt.Println("allow", d)
	}
	return nil
}
