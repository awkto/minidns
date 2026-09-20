package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/awkto/minidns/internal/paths"
	"github.com/awkto/minidns/internal/unbound"
	"github.com/awkto/minidns/internal/zones"
)

const keepBackups = 10

func backupDir() string { return filepath.Join(paths.StateDir(), "backups") }

// backupSources are the things minidns cannot re-create: configuration,
// credentials, local zones, overlay records, manual block/allow rules. The
// replica copies ride along so a restore works offline. Subscribed
// blocklists are left out — `blocklist update` downloads them again.
func backupSources() []string {
	return []string{
		paths.ConfigFile(),
		paths.CredentialsFile(),
		paths.LocalZoneDir(),
		filepath.Join(paths.ZoneDir(), "overlay"),
		filepath.Join(paths.ZoneDir(), "upstream"),
		paths.ZoneDir(), // top-level *.zone only (replicas); see the walk
		paths.AllowRPZ(),
		paths.BlockRPZ(),
		filepath.Join(paths.StateDir(), "blocklists.json"),
	}
}

// createBackup writes a tarball of the state and returns its path. Archive
// member names are relative to the filesystem root (or MINIDNS_PREFIX).
func createBackup(label, output string) (string, int, error) {
	if output == "" {
		if err := os.MkdirAll(backupDir(), 0o700); err != nil {
			return "", 0, err
		}
		name := "minidns-" + time.Now().Format("20060102-150405")
		if label != "" {
			name += "-" + label
		}
		output = filepath.Join(backupDir(), name+".tar.gz")
	}
	f, err := os.OpenFile(output+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // holds credentials
	if err != nil {
		return "", 0, err
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	root := os.Getenv("MINIDNS_PREFIX") + "/"
	seen := map[string]bool{}
	count := 0
	addFile := func(p string, info os.FileInfo) error {
		if seen[p] || !info.Mode().IsRegular() || strings.HasSuffix(p, ".tmp") || strings.HasSuffix(p, ".prev") {
			return nil
		}
		seen[p] = true
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = strings.TrimPrefix(p, root)
		hdr.Uname, hdr.Gname = "", ""
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		src, err := os.Open(p)
		if err != nil {
			return err
		}
		defer src.Close()
		_, err = io.Copy(tw, src)
		count++
		return err
	}
	for _, src := range backupSources() {
		info, err := os.Stat(src)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			err = addFile(src, info)
		} else {
			entries, _ := os.ReadDir(src)
			for _, e := range entries {
				if fi, ferr := e.Info(); ferr == nil && err == nil {
					err = addFile(filepath.Join(src, e.Name()), fi)
				}
			}
		}
		if err != nil {
			f.Close()
			os.Remove(output + ".tmp")
			return "", 0, err
		}
	}
	if err := tw.Close(); err == nil {
		err = gz.Close()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(output + ".tmp")
		return "", 0, err
	}
	if err := os.Rename(output+".tmp", output); err != nil {
		return "", 0, err
	}
	if filepath.Dir(output) == backupDir() {
		pruneBackups()
	}
	return output, count, nil
}

type backupInfo struct {
	Path    string    `json:"path"`
	Created time.Time `json:"created"`
	Bytes   int64     `json:"bytes"`
}

func listBackups() []backupInfo {
	out := []backupInfo{}
	entries, _ := os.ReadDir(backupDir())
	for _, e := range entries {
		if info, err := e.Info(); err == nil && strings.HasSuffix(e.Name(), ".tar.gz") {
			out = append(out, backupInfo{filepath.Join(backupDir(), e.Name()), info.ModTime().UTC().Truncate(time.Second), info.Size()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path > out[j].Path }) // names sort by time
	return out
}

func pruneBackups() {
	for i, b := range listBackups() {
		if i >= keepBackups {
			os.Remove(b.Path)
		}
	}
}

// restorable reports whether an archive member may be written: only into
// the minidns config and state directories, never through a path trick.
func restorable(name string) bool {
	clean := filepath.Clean("/" + name)
	if clean != "/"+name || strings.Contains(name, "..") {
		return false
	}
	for _, dir := range []string{"/etc/minidns/", "/var/lib/minidns/"} {
		if strings.HasPrefix(clean, dir) && !strings.HasPrefix(clean, "/var/lib/minidns/backups/") {
			return true
		}
	}
	return false
}

func restoreBackup(archive string) (int, error) {
	f, err := os.Open(archive)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", zones.ErrNotFound, err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return 0, fmt.Errorf("%w: %s is not a minidns backup (%v)", zones.ErrInvalid, archive, err)
	}
	// read everything first: nothing is written unless the archive is sound
	type member struct {
		name string
		mode os.FileMode
		data []byte
	}
	var members []member
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("%w: %s is damaged (%v)", zones.ErrInvalid, archive, err)
		}
		if hdr.Typeflag != tar.TypeReg || !restorable(hdr.Name) {
			return 0, fmt.Errorf("%w: refusing archive member %q — not something a minidns backup contains", zones.ErrInvalid, hdr.Name)
		}
		data, err := io.ReadAll(io.LimitReader(tr, 64<<20))
		if err != nil {
			return 0, err
		}
		members = append(members, member{hdr.Name, os.FileMode(hdr.Mode).Perm(), data})
	}
	if len(members) == 0 {
		return 0, fmt.Errorf("%w: %s is empty", zones.ErrInvalid, archive)
	}
	root := os.Getenv("MINIDNS_PREFIX")
	for _, m := range members {
		target := filepath.Join(root, "/"+m.name)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return 0, err
		}
		if err := os.WriteFile(target+".tmp", m.data, m.mode); err != nil {
			return 0, err
		}
		os.Chmod(target+".tmp", m.mode)
		if err := os.Rename(target+".tmp", target); err != nil {
			return 0, err
		}
	}
	return len(members), nil
}

func backupCmd() *cobra.Command {
	backup := &cobra.Command{Use: "backup", Short: "Back up configuration, zones, overlay records and manual rules"}

	var output string
	create := &cobra.Command{
		Use: "create [--output <file>]", Short: "Write a backup (kept: the last 10 under /var/lib/minidns/backups)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, n, err := createBackup("", output)
			if err != nil {
				return err
			}
			return emit(map[string]any{"path": path, "files": n}, func() {
				fmt.Printf("Backup written: %s (%d files). It contains provider credentials — keep it private.\n", path, n)
			})
		},
	}
	create.Flags().StringVar(&output, "output", "", "write the archive here instead")

	list := &cobra.Command{
		Use: "list", Short: "List backups, newest first", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			all := listBackups()
			return emit(all, func() {
				if len(all) == 0 {
					fmt.Println("no backups yet — `minidns backup create`")
				}
				for _, b := range all {
					fmt.Printf("%s  %6d KB  %s\n", b.Created.Local().Format("2006-01-02 15:04"), b.Bytes>>10, b.Path)
				}
			})
		},
	}
	backup.AddCommand(create, list)
	return backup
}

func restoreCmd() *cobra.Command {
	return &cobra.Command{
		Use: "restore <backup.tar.gz>", Short: "Restore a backup (the current state is backed up first, and put back if unbound rejects the restored one)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			safety, _, err := createBackup("before-restore", "")
			if err != nil {
				return fmt.Errorf("could not back up the current state first: %w", err)
			}
			n, err := restoreBackup(args[0])
			if err != nil {
				return err
			}
			if err := cmdApplyQuiet(); err != nil {
				restoreBackup(safety)
				cmdApplyQuiet()
				return applyError{fmt.Errorf("unbound rejected the restored configuration (previous state put back): %w", err)}
			}
			if unbound.Active() {
				// zone and rule files may have changed under an unchanged config
				if err := unbound.Reload(); err != nil {
					restoreBackup(safety)
					cmdApplyQuiet()
					unbound.Reload()
					return applyError{fmt.Errorf("unbound did not come back with the restored state (previous state put back): %w", err)}
				}
			}
			return emit(map[string]any{"restored": n, "previous_state": safety}, func() {
				fmt.Printf("Restored %d files. The state from before is in %s.\n", n, safety)
				fmt.Println("Subscribed blocklists are not part of a backup — run `minidns blocklist update` if lists are missing.")
			})
		},
	}
}
