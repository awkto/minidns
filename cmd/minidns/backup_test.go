package main

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/awkto/minidns/internal/paths"
)

func TestBackupRestoreRoundTrip(t *testing.T) {
	t.Setenv("MINIDNS_PREFIX", t.TempDir())
	files := map[string]string{
		paths.ConfigFile():                 "port: 53\n",
		paths.CredentialsFile():            "digitalocean:\n  token: secret\n",
		paths.LocalZoneFile("home.arpa"):   "zone data",
		paths.OverlayFile("example.com"):   "overlay data",
		paths.ZoneFile("example.com"):      "replica data",
		paths.BlockRPZ():                   "block data",
		paths.AdblockRPZ("big"):            "not part of a backup",
		paths.LocalZoneFile("x") + ".prev": "rollback copy, not part of a backup",
	}
	for p, content := range files {
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(content), 0o644)
	}
	os.Chmod(paths.CredentialsFile(), 0o600)

	archive, n, err := createBackup("", "")
	if err != nil || n != 6 {
		t.Fatalf("createBackup: %d files, %v", n, err)
	}
	if st, _ := os.Stat(archive); st.Mode().Perm() != 0o600 {
		t.Errorf("the backup holds credentials but has mode %o", st.Mode().Perm())
	}

	os.WriteFile(paths.LocalZoneFile("home.arpa"), []byte("damaged"), 0o644)
	os.Remove(paths.CredentialsFile())
	if _, err := restoreBackup(archive); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(paths.LocalZoneFile("home.arpa")); string(b) != "zone data" {
		t.Errorf("zone not restored: %q", b)
	}
	if st, err := os.Stat(paths.CredentialsFile()); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("credentials not restored privately: %v", err)
	}
}

func TestRestoreRefusesForeignPaths(t *testing.T) {
	t.Setenv("MINIDNS_PREFIX", t.TempDir())
	for _, name := range []string{"etc/passwd", "etc/minidns/../shadow", "/etc/minidns/config.yaml", "var/lib/minidns/backups/x.tar.gz", "etc/cron.d/evil"} {
		archive := filepath.Join(t.TempDir(), "evil.tar.gz")
		f, _ := os.Create(archive)
		gz := gzip.NewWriter(f)
		tw := tar.NewWriter(gz)
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
		tw.Write([]byte("x"))
		tw.Close()
		gz.Close()
		f.Close()
		if _, err := restoreBackup(archive); err == nil {
			t.Errorf("archive member %q was accepted", name)
		}
	}
}

func TestBackupRetention(t *testing.T) {
	t.Setenv("MINIDNS_PREFIX", t.TempDir())
	os.MkdirAll(backupDir(), 0o700)
	for i := 0; i < keepBackups+5; i++ {
		os.WriteFile(filepath.Join(backupDir(), "minidns-20260101-0000"+string(rune('a'+i))+".tar.gz"), []byte("x"), 0o600)
	}
	pruneBackups()
	if got := len(listBackups()); got != keepBackups {
		t.Errorf("%d backups kept, want %d", got, keepBackups)
	}
}
