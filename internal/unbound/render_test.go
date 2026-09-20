package unbound

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awkto/minidns/internal/config"
	"github.com/awkto/minidns/internal/paths"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// sandbox points every minidns path at a temp dir and makes the
// host-dependent inputs (CPU count, CA bundle) fixed.
func sandbox(t *testing.T) (*config.Config, string) {
	t.Helper()
	prefix := t.TempDir()
	t.Setenv("MINIDNS_PREFIX", prefix)
	for _, d := range []string{paths.RPZDir(), paths.ZoneDir(), paths.UnboundConfD()} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	bundle := filepath.Join(prefix, "ca.crt")
	os.WriteFile(bundle, nil, 0o644)
	old := caBundlePaths
	caBundlePaths = []string{bundle}
	t.Cleanup(func() { caBundlePaths = old })

	cfg := config.Default()
	cfg.Threads = 4
	return cfg, prefix
}

func touch(t *testing.T, p string) {
	t.Helper()
	if err := os.WriteFile(p, []byte("; test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func golden(t *testing.T, name, prefix, got string) {
	t.Helper()
	got = strings.ReplaceAll(got, prefix, "{PREFIX}")
	path := filepath.Join("testdata", name+".conf")
	if *update {
		os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run `go test ./internal/unbound -update`)", err)
	}
	if got != string(want) {
		t.Errorf("%s differs from golden file %s\n--- got ---\n%s", name, path, got)
	}
}

func TestRenderFreshInstall(t *testing.T) {
	cfg, prefix := sandbox(t)
	golden(t, "fresh", prefix, Render(cfg))
}

func TestRenderFullForwarder(t *testing.T) {
	cfg, prefix := sandbox(t)
	cfg.UpstreamTLS = true
	cfg.Upstreams = []string{"1.1.1.1", "9.9.9.9", "10.0.0.1", "10.0.0.2@5353"}
	cfg.Adblock.Lists = append(cfg.Adblock.Lists,
		config.BlockList{Name: "oisd", Format: "rpz"},
		config.BlockList{Name: "missing", Format: "hosts"}) // no file on disk → not rendered
	cfg.Zones = []config.Zone{{Name: "dnsif.ca", Provider: "digitalocean"}, {Name: "unsynced.example", Provider: "digitalocean"}}
	for _, f := range []string{paths.AllowRPZ(), paths.BlockRPZ(), paths.AdblockRPZ("stevenblack"), paths.AdblockRPZ("oisd"), paths.ZoneFile("dnsif.ca")} {
		touch(t, f)
	}
	golden(t, "full-forwarder", prefix, Render(cfg))
}

func TestRenderRecursionNoBlocking(t *testing.T) {
	cfg, prefix := sandbox(t)
	cfg.Recursion = true
	cfg.Firewall.Enabled = false
	cfg.Adblock.Enabled = false
	cfg.Logging.Queries = false
	for _, f := range []string{paths.AllowRPZ(), paths.BlockRPZ(), paths.AdblockRPZ("stevenblack")} {
		touch(t, f)
	}
	out := Render(cfg)
	golden(t, "recursion-no-blocking", prefix, out)
	if strings.Contains(out, "forward-zone") {
		t.Error("recursion mode must not render a forward-zone")
	}
}

func TestRenderSkipsRemoteControlWhenDistroProvidesIt(t *testing.T) {
	cfg, _ := sandbox(t)
	if !strings.Contains(Render(cfg), "remote-control:") {
		t.Fatal("expected a remote-control block on a bare system")
	}
	os.WriteFile(filepath.Join(paths.UnboundConfD(), "remote-control.conf"),
		[]byte("remote-control:\n  control-enable: yes\n"), 0o644)
	if strings.Contains(Render(cfg), "remote-control:") {
		t.Error("must not duplicate the distro's remote-control block")
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	cfg, _ := sandbox(t)
	if Render(cfg) != Render(cfg) {
		t.Error("two renders of the same config differ")
	}
}

func TestRPZOrderAllowFirst(t *testing.T) {
	cfg, _ := sandbox(t)
	for _, f := range []string{paths.AllowRPZ(), paths.BlockRPZ(), paths.AdblockRPZ("stevenblack")} {
		touch(t, f)
	}
	out := Render(cfg)
	a, b, c := strings.Index(out, "allow.rpz.minidns."), strings.Index(out, "block.rpz.minidns."), strings.Index(out, "adblock-stevenblack.rpz.minidns.")
	if !(a >= 0 && a < b && b < c) {
		t.Errorf("RPZ order must be allow < block < adblock, got %d %d %d", a, b, c)
	}
}
