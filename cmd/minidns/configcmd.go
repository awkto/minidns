package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/awkto/minidns/internal/config"
	"github.com/awkto/minidns/internal/paths"
	"github.com/awkto/minidns/internal/unbound"
	"github.com/awkto/minidns/internal/zonefile"
	"github.com/awkto/minidns/internal/zones"
)

// validateAll checks everything `apply` would activate, without changing
// anything: config.yaml, every local zone and replica file, and the unbound
// configuration that would be generated.
func validateAll() (*config.Config, []string, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", zones.ErrInvalid, err)
	}
	var problems []string
	for _, name := range cfg.LocalZones {
		b, err := os.ReadFile(paths.LocalZoneFile(name))
		if err != nil {
			problems = append(problems, fmt.Sprintf("local zone %s: zone file missing", name))
		} else if _, err := zonefile.Validate(name, string(b)); err != nil {
			problems = append(problems, fmt.Sprintf("local zone %s: %v", name, err))
		}
	}
	for _, z := range cfg.CloudZones {
		if b, err := os.ReadFile(paths.ZoneFile(z.Name)); err == nil {
			if _, err := zonefile.Validate(z.Name, string(b)); err != nil {
				problems = append(problems, fmt.Sprintf("replica %s: %v", z.Name, err))
			}
		}
	}
	if err := unbound.CheckRendered(unbound.Render(cfg)); err != nil {
		problems = append(problems, err.Error())
	}
	return cfg, problems, nil
}

func configCmd() *cobra.Command {
	cc := &cobra.Command{Use: "config", Short: "Inspect, validate and apply the configuration"}

	show := &cobra.Command{
		Use: "show", Short: "Print the effective configuration (defaults filled in; never contains provider tokens)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			cfg.Providers.DigitalOcean.Token = "" // v0.1 layout: never echo it
			return emit(cfg, func() {
				b, _ := yaml.Marshal(cfg)
				fmt.Printf("# %s\n%s", paths.ConfigFile(), b)
			})
		},
	}

	validate := &cobra.Command{
		Use: "validate", Short: "Check config.yaml, the zone files and the unbound config they produce — changes nothing", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, problems, err := validateAll()
			if err != nil {
				return err
			}
			if problems == nil {
				problems = []string{}
			}
			if err := emit(map[string]any{"valid": len(problems) == 0, "problems": problems}, func() {
				for _, p := range problems {
					fmt.Println("problem:", p)
				}
				if len(problems) == 0 {
					fmt.Println("Configuration is valid.")
				}
			}); err != nil {
				return err
			}
			if len(problems) > 0 {
				return fmt.Errorf("%w: %d problem(s) found", zones.ErrInvalid, len(problems))
			}
			return nil
		},
	}

	render := &cobra.Command{
		Use: "render", Short: "Print the unbound configuration that would be generated", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			out := unbound.Render(cfg)
			return emit(map[string]any{"path": paths.UnboundConfFile(), "content": out}, func() { fmt.Print(out) })
		},
	}

	diff := &cobra.Command{
		Use: "diff", Short: "Compare the active unbound config with what `apply` would write", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			dir, err := os.MkdirTemp("", "minidns-diff")
			if err != nil {
				return err
			}
			defer os.RemoveAll(dir)
			next := filepath.Join(dir, "new")
			os.WriteFile(next, []byte(unbound.Render(cfg)), 0o644)
			active := paths.UnboundConfFile()
			if _, err := os.Stat(active); err != nil {
				active = "/dev/null"
			}
			out, _ := exec.Command("diff", "-u", "--label", "active: "+paths.UnboundConfFile(), "--label", "after `minidns apply`", active, next).CombinedOutput()
			return emit(map[string]any{"changed": len(out) > 0, "diff": string(out)}, func() {
				if len(out) == 0 {
					fmt.Println("No differences: the active unbound config is what config.yaml describes.")
					return
				}
				fmt.Print(string(out))
			})
		},
	}

	apply := &cobra.Command{
		Use: "apply", Short: "Validate, regenerate the unbound config and activate it (same as `minidns apply`)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { return cmdApply(true) },
	}

	markReadOnly(show, validate, render, diff)
	cc.AddCommand(show, validate, render, diff, apply)
	return cc
}
