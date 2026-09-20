package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/awkto/minidns/internal/config"
	"github.com/awkto/minidns/internal/paths"
	"github.com/awkto/minidns/internal/unbound"
	"github.com/awkto/minidns/internal/zonefile"
	"github.com/awkto/minidns/internal/zones"
)

// Overlay records are local-only records layered over a read-only cloud
// replica: the provider's data is kept pristine in paths.UpstreamFile, the
// overlay in paths.OverlayFile, and what unbound serves (paths.ZoneFile) is
// regenerated from the two whenever either changes.

func writeFileAtomic(target string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	// unbound runs unprivileged and must be able to read the zone even when
	// root's umask is restrictive
	if err := os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, target)
}

// rebuildReplica regenerates the served file of an overlay-enabled replica.
// The served serial only moves forward: the provider's serial when that is
// ahead, otherwise one more than what is being served, so that every change
// — provider or overlay — is visible as a new serial.
func rebuildReplica(z config.Zone) (serial uint32, changed bool, err error) {
	up, err := os.ReadFile(paths.UpstreamFile(z.Name))
	if err != nil {
		return 0, false, fmt.Errorf("no provider copy of %s yet — run `minidns cloud zone sync %s`", z.Name, z.Name)
	}
	ov, err := zones.LoadOverlay(z.Name)
	if err != nil {
		return 0, false, err
	}
	merged, _, err := zones.Merge(z.Name, string(up), ov.Records, z.Provider)
	if err != nil {
		return 0, false, err
	}
	target := paths.ZoneFile(z.Name)
	old, _ := os.ReadFile(target)
	var oldSerial uint32
	if info, err := zonefile.Validate(z.Name, string(old)); err == nil {
		oldSerial = info.Serial
	}
	if len(old) > 0 && merged.Render(oldSerial) == string(old) {
		return oldSerial, false, nil
	}
	serial = merged.Serial
	if serial <= oldSerial {
		serial = oldSerial + 1
	}
	data := merged.Render(serial)
	if _, err := zonefile.Validate(z.Name, data); err != nil {
		return 0, false, fmt.Errorf("refusing to serve the merged zone %s: %w", z.Name, err)
	}
	return serial, true, writeFileAtomic(target, []byte(data))
}

// activateOverlay serves a just-saved overlay and proves unbound took it;
// otherwise the previous overlay is restored and served again.
func activateOverlay(cfg *config.Config, z *zones.Zone) error {
	rz := cfg.FindZone(z.Name)
	if rz == nil || !rz.Overlay {
		return fmt.Errorf("%w: %s has no overlay", zones.ErrInvalid, z.Name)
	}
	serial, changed, err := rebuildReplica(*rz)
	if err != nil {
		z.Undo()
		return err
	}
	z.Serial = serial
	if !unbound.Active() {
		note("note: unbound is not running — the overlay of %s was written and will be served once it starts", z.Name)
		return nil
	}
	if !changed {
		return nil
	}
	if err := reloadAndVerify(cfg, z.Name, serial); err != nil {
		undoZone(cfg, z)
		return applyError{fmt.Errorf("unbound did not accept the change to %s (previous records restored): %w", z.Name, err)}
	}
	return nil
}

// undoZone puts back what z's last Save replaced and serves it again.
func undoZone(cfg *config.Config, z *zones.Zone) {
	if z.Undo() != nil {
		return
	}
	if z.Overlay {
		if rz := cfg.FindZone(z.Name); rz != nil {
			rebuildReplica(*rz)
		}
	}
	if unbound.Active() {
		unbound.Control("auth_zone_reload", z.Origin())
	}
}

// overlayShadows lists the provider records hidden by overlay records at name.
func overlayShadows(z config.Zone, name string) []zones.Record {
	up, err := os.ReadFile(paths.UpstreamFile(z.Name))
	if err != nil {
		return nil
	}
	ov, err := zones.LoadOverlay(z.Name)
	if err != nil {
		return nil
	}
	_, shadowed, _ := zones.Merge(z.Name, string(up), ov.Records, z.Provider)
	var out []zones.Record
	for _, r := range shadowed {
		if r.Name == name {
			out = append(out, r)
		}
	}
	return out
}

// replicaView is what a replica serves, record by record, with its source.
func replicaView(z config.Zone) (*zones.Zone, error) {
	if z.Overlay {
		up, err := os.ReadFile(paths.UpstreamFile(z.Name))
		if err == nil {
			ov, err := zones.LoadOverlay(z.Name)
			if err != nil {
				return nil, err
			}
			merged, _, err := zones.Merge(z.Name, string(up), ov.Records, z.Provider)
			return merged, err
		}
	}
	b, err := os.ReadFile(paths.ZoneFile(z.Name))
	if err != nil {
		return nil, fmt.Errorf("%w: %s has not been synced yet", zones.ErrNotFound, z.Name)
	}
	view, err := zones.Parse(z.Name, string(b))
	if err != nil {
		return nil, err
	}
	for i := range view.Records {
		view.Records[i].Source = z.Provider
	}
	return view, nil
}

func overlayCmd() *cobra.Command {
	overlay := &cobra.Command{
		Use: "overlay", Short: "Local-only records layered over a replica",
		Long: "A replica is a read-only copy of a zone hosted at a cloud provider. With the\n" +
			"overlay enabled, `minidns record` and `minidns host` can add records to it that\n" +
			"exist only on this resolver (for example LAN device names under your public\n" +
			"domain). The provider's zone is never written to; an overlay record hides a\n" +
			"provider record of the same name and type.",
	}

	enable := &cobra.Command{
		Use: "enable <zone>", Short: "Allow local overlay records on a replica", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			rz := cfg.FindZone(args[0])
			if rz == nil {
				return fmt.Errorf("%w: %s is not a cloud replica (see `minidns cloud zone list`)", zones.ErrNotFound, args[0])
			}
			if rz.Overlay {
				return emit(map[string]any{"zone": rz.Name, "overlay": true, "changed": false}, func() {
					fmt.Printf("Overlay already enabled for %s.\n", rz.Name)
				})
			}
			served, err := os.ReadFile(paths.ZoneFile(rz.Name))
			if err != nil {
				return fmt.Errorf("%s has not been synced yet — run `minidns cloud zone sync %s` first", rz.Name, rz.Name)
			}
			// without an overlay the served file is exactly the provider's data
			if err := writeFileAtomic(paths.UpstreamFile(rz.Name), served); err != nil {
				return err
			}
			rz.Overlay = true
			serial, _, err := rebuildReplica(*rz)
			if err == nil && unbound.Active() {
				err = reloadAndVerify(cfg, rz.Name, serial)
			}
			if err == nil {
				err = config.Save(cfg)
			}
			if err != nil {
				writeFileAtomic(paths.ZoneFile(rz.Name), served)
				os.Remove(paths.UpstreamFile(rz.Name))
				if unbound.Active() {
					unbound.ReloadZone(rz.Name + ".")
				}
				return applyError{fmt.Errorf("could not enable the overlay (nothing was changed): %w", err)}
			}
			return emit(map[string]any{"zone": rz.Name, "overlay": true, "changed": true}, func() {
				fmt.Printf("Overlay enabled for %s. Records added with `minidns record add %s …` exist only on this resolver.\n", rz.Name, rz.Name)
			})
		},
	}

	var force bool
	disable := &cobra.Command{
		Use: "disable <zone>", Short: "Serve the provider's data only again", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			rz := cfg.FindZone(args[0])
			if rz == nil {
				return fmt.Errorf("%w: %s is not a cloud replica", zones.ErrNotFound, args[0])
			}
			if !rz.Overlay {
				return emit(map[string]any{"zone": rz.Name, "overlay": false, "changed": false}, func() {
					fmt.Printf("Overlay is not enabled for %s.\n", rz.Name)
				})
			}
			ov, err := zones.LoadOverlay(rz.Name)
			if err != nil {
				return err
			}
			if n := len(ov.Records); n > 0 && !force {
				return fmt.Errorf("%w: %s still has %d overlay record(s); re-run with --force to delete them", zones.ErrConflict, rz.Name, n)
			}
			if err := dropOverlay(cfg, rz); err != nil {
				return err
			}
			if err := config.Save(cfg); err != nil {
				return err
			}
			return emit(map[string]any{"zone": rz.Name, "overlay": false, "changed": true, "removed": ov.Records}, func() {
				fmt.Printf("Overlay disabled for %s (%d overlay record(s) removed); serving the provider's data only.\n", rz.Name, len(ov.Records))
			})
		},
	}
	disable.Flags().BoolVar(&force, "force", false, "delete the overlay records that still exist")

	overlay.AddCommand(enable, disable)
	return overlay
}

// dropOverlay goes back to serving the provider's copy and deletes the
// overlay state. The caller saves cfg.
func dropOverlay(cfg *config.Config, rz *config.Zone) error {
	if up, err := os.ReadFile(paths.UpstreamFile(rz.Name)); err == nil {
		if err := writeFileAtomic(paths.ZoneFile(rz.Name), up); err != nil {
			return err
		}
		if unbound.Active() {
			if err := unbound.ReloadZone(rz.Name + "."); err != nil {
				return applyError{err}
			}
		}
	}
	rz.Overlay = false
	zones.RemoveOverlay(rz.Name)
	os.Remove(paths.UpstreamFile(rz.Name))
	return nil
}
