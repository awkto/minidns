package unbound

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/awkto/minidns/internal/paths"
)

// Control runs unbound-control with the given arguments.
func Control(args ...string) (string, error) {
	out, err := exec.Command("unbound-control", args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("unbound-control %s: %v: %s",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// Reload asks the daemon to re-read its config; falls back to a systemd
// restart if the control channel isn't up.
func Reload() error {
	if _, err := Control("reload"); err == nil {
		return nil
	}
	out, err := exec.Command("systemctl", "restart", "unbound").CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl restart unbound: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Restart fully restarts the daemon. Needed for settings unbound only reads
// at startup (e.g. tls-cert-bundle); reload doesn't pick those up. Without
// systemd (containers) the best we can do is a reload.
func Restart() error {
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		out, err := exec.Command("systemctl", "restart", "unbound").CombinedOutput()
		if err != nil {
			return fmt.Errorf("systemctl restart unbound: %v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	_, err := Control("reload")
	return err
}

// ReloadZone reloads one auth/RPZ zone from its zonefile without dropping
// the cache; falls back to a full reload.
func ReloadZone(name string) error {
	if _, err := Control("auth_zone_reload", name); err == nil {
		return nil
	}
	return Reload()
}

// Stats returns unbound-control stats_noreset as a key→value map.
func Stats() (map[string]string, error) {
	out, err := Control("stats_noreset")
	if err != nil {
		return nil, err
	}
	m := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			m[k] = v
		}
	}
	return m, nil
}

// CheckConf validates the full unbound configuration. If unbound isn't
// installed yet (dev environments) validation is skipped.
func CheckConf() error {
	if _, err := exec.LookPath("unbound-checkconf"); err != nil {
		return nil
	}
	out, err := exec.Command("unbound-checkconf").CombinedOutput()
	if err != nil {
		return fmt.Errorf("unbound-checkconf: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// WriteConf renders the config and installs it atomically, validating with
// unbound-checkconf and rolling back on failure.
func WriteConf(content string) error {
	target := paths.UnboundConfFile()
	if err := os.MkdirAll(paths.UnboundConfD(), 0o755); err != nil {
		return err
	}
	old, hadOld := os.ReadFile(target)
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		return err
	}
	os.Chmod(target, 0o644) // readable by the unbound user whatever root's umask is
	if err := CheckConf(); err != nil {
		if hadOld == nil {
			os.WriteFile(target, old, 0o644)
		} else {
			os.Remove(target)
		}
		return err
	}
	return nil
}

// Active reports whether an unbound daemon is reachable. Asks the daemon
// itself first (works without systemd, e.g. in containers), then systemd.
func Active() bool {
	if exec.Command("unbound-control", "status").Run() == nil {
		return true
	}
	return exec.Command("systemctl", "is-active", "--quiet", "unbound").Run() == nil
}
