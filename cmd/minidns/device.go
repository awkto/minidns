package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/awkto/minidns/internal/store"
)

func addressLabel(a store.Address) string {
	s := a.IP
	if a.MAC != "" {
		s += " [" + a.MAC + "]"
	}
	return s
}

func deviceCmd() *cobra.Command {
	device := &cobra.Command{
		Use: "device", Short: "Names for the machines on your network, used in the query log and statistics",
		Long: "A device is a name plus the IP addresses it uses. minidns never guesses: addresses\n" +
			"are what you (or later a DHCP lease feed) say they are. Names are applied when a\n" +
			"report is read, so naming or renaming a device relabels its past queries too; and\n" +
			"when a device changes address, its history stays with it.",
	}

	var ips, tags []string
	var mac, description string
	add := &cobra.Command{
		Use: "add <name> [--ip <address>]...", Short: "Name a device", Args: cobra.ExactArgs(1),
		Example: "  minidns device add laptop --ip 10.20.0.5\n  minidns device add \"Living room TV\" --ip 10.20.0.31 --ip fd00::31 --tag media",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			defer s.Close()
			// check every address before creating anything
			for _, ip := range ips {
				if _, err := store.CleanIP(ip); err != nil {
					return storeErr(err)
				}
			}
			if err := s.AddDevice(args[0], description, tags); err != nil {
				return storeErr(err)
			}
			for i, ip := range ips {
				m := ""
				if i == 0 {
					m = mac
				}
				if _, err := s.AddAddress(args[0], ip, m, "manual"); err != nil {
					s.RemoveDevice(args[0])
					return storeErr(err)
				}
			}
			d, err := s.Device(args[0])
			if err != nil {
				return err
			}
			return emit(d, func() {
				fmt.Printf("Device %q added", d.Name)
				if len(d.Addresses) > 0 {
					fmt.Printf(" (%s) — its past queries from there now show under this name", joinAddresses(d.Addresses))
				}
				fmt.Println(".")
			})
		},
	}
	add.Flags().StringArrayVar(&ips, "ip", nil, "an address the device uses (repeatable, IPv4 or IPv6)")
	add.Flags().StringVar(&mac, "mac", "", "hardware address, for your own reference (minidns does not observe MACs)")
	add.Flags().StringVar(&description, "description", "", "free text")
	add.Flags().StringArrayVar(&tags, "tag", nil, "label for grouping (repeatable)")

	list := &cobra.Command{
		Use: "list", Short: "List devices", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			defer s.Close()
			all, err := s.Devices()
			if err != nil {
				return err
			}
			if all == nil {
				all = []store.Device{}
			}
			return emit(all, func() {
				if len(all) == 0 {
					fmt.Println("no devices yet — `minidns stats top-devices` shows who is asking; name one with `minidns device add <name> --ip <address>`")
					return
				}
				fmt.Printf("%-28s %-40s %s\n", "DEVICE", "CURRENT ADDRESSES", "TAGS")
				for _, d := range all {
					var cur []store.Address
					for _, a := range d.Addresses {
						if a.Current() {
							cur = append(cur, a)
						}
					}
					fmt.Printf("%-28s %-40s %s\n", d.Name, joinAddresses(cur), strings.Join(d.Tags, ","))
				}
			})
		},
	}

	show := &cobra.Command{
		Use: "show <name>", Short: "One device with its address history", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			defer s.Close()
			d, err := s.Device(args[0])
			if err != nil {
				return storeErr(err)
			}
			return emit(d, func() {
				fmt.Printf("%s\n", d.Name)
				if d.Description != "" {
					fmt.Printf("  description  %s\n", d.Description)
				}
				if len(d.Tags) > 0 {
					fmt.Printf("  tags         %s\n", strings.Join(d.Tags, ", "))
				}
				fmt.Printf("  added        %s\n", time.Unix(d.Created, 0).Format("2006-01-02"))
				for _, a := range d.Addresses {
					period := "current"
					if !a.Current() {
						period = "until " + time.Unix(a.ValidTo, 0).Format("2006-01-02 15:04")
					}
					if a.ValidFrom > 0 {
						period = "from " + time.Unix(a.ValidFrom, 0).Format("2006-01-02 15:04") + ", " + period
					}
					fmt.Printf("  address      %-30s %s (%s)\n", addressLabel(a), period, a.Source)
				}
				if len(d.Addresses) == 0 {
					fmt.Println("  address      none — `minidns device address add` gives it one")
				}
			})
		},
	}

	rename := &cobra.Command{
		Use: "rename <old> <new>", Short: "Rename a device (history follows)", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			defer s.Close()
			if err := s.RenameDevice(args[0], args[1]); err != nil {
				return storeErr(err)
			}
			return emit(map[string]any{"renamed": args[0], "to": strings.TrimSpace(args[1])}, func() {
				fmt.Printf("Device %q is now %q.\n", args[0], strings.TrimSpace(args[1]))
			})
		},
	}

	var setDescription string
	var setTags []string
	set := &cobra.Command{
		Use: "set <name> [--description <text>] [--tag <t>]...", Short: "Change description or tags", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			defer s.Close()
			var desc *string
			var tags *[]string
			if cmd.Flags().Changed("description") {
				desc = &setDescription
			}
			if cmd.Flags().Changed("tag") {
				tags = &setTags
			}
			if desc == nil && tags == nil {
				return usagef("nothing to change: give --description and/or --tag")
			}
			if err := s.UpdateDevice(args[0], desc, tags); err != nil {
				return storeErr(err)
			}
			d, _ := s.Device(args[0])
			return emit(d, func() { fmt.Printf("Device %q updated.\n", d.Name) })
		},
	}
	set.Flags().StringVar(&setDescription, "description", "", "free text")
	set.Flags().StringArrayVar(&setTags, "tag", nil, "replaces the tags (repeatable)")

	remove := &cobra.Command{
		Use: "remove <name>", Short: "Forget a device (its queries show under their IP addresses again)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			defer s.Close()
			if err := s.RemoveDevice(args[0]); err != nil {
				return storeErr(err)
			}
			return emit(map[string]any{"removed": args[0]}, func() { fmt.Printf("Device %q removed.\n", args[0]) })
		},
	}

	address := &cobra.Command{Use: "address", Short: "The addresses of a device"}
	var addrMAC string
	addrAdd := &cobra.Command{
		Use: "add <device> <ip>", Short: "The device uses this address from now on", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			defer s.Close()
			a, err := s.AddAddress(args[0], args[1], addrMAC, "manual")
			if err != nil {
				return storeErr(err)
			}
			return emit(map[string]any{"device": args[0], "address": a}, func() {
				since := "including its past queries"
				if a.ValidFrom > 0 {
					since = "from now on (it belonged to another device before)"
				}
				fmt.Printf("%s now belongs to %q, %s.\n", a.IP, args[0], since)
			})
		},
	}
	addrAdd.Flags().StringVar(&addrMAC, "mac", "", "hardware address, for your own reference")
	var forget bool
	addrRemove := &cobra.Command{
		Use: "remove <device> <ip>", Short: "The device stopped using this address (its history stays)", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			defer s.Close()
			if err := s.RemoveAddress(args[0], args[1], forget); err != nil {
				return storeErr(err)
			}
			return emit(map[string]any{"device": args[0], "removed": args[1], "forgotten": forget}, func() {
				if forget {
					fmt.Printf("%s was never %q's: the assignment is erased.\n", args[1], args[0])
				} else {
					fmt.Printf("%s no longer belongs to %q; what it asked until now stays in its history.\n", args[1], args[0])
				}
			})
		},
	}
	addrRemove.Flags().BoolVar(&forget, "forget", false, "erase the assignment entirely (it was a mistake)")
	address.AddCommand(addrAdd, addrRemove)

	// the database is its own lock; none of this touches unbound
	markReadOnly(list, show)
	markNoLock(add, rename, set, remove, addrAdd, addrRemove)
	device.AddCommand(add, list, show, rename, set, remove, address)
	return device
}

func joinAddresses(addrs []store.Address) string {
	parts := make([]string, len(addrs))
	for i, a := range addrs {
		parts[i] = addressLabel(a)
	}
	return strings.Join(parts, ", ")
}
