package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/awkto/minidns/internal/config"
)

const (
	resolvedDropIn   = "/etc/systemd/resolved.conf.d/minidns.conf"
	resolvedStubConf = "/run/systemd/resolve/stub-resolv.conf"
	resolvedUplink   = "/run/systemd/resolve/resolv.conf"
	resolvConf       = "/etc/resolv.conf"
)

// freePort53 deals with systemd-resolved, whose stub listener owns
// 127.0.0.53:53 on stock Ubuntu and makes unbound's wildcard bind fail with
// "address already in use". The stub is switched off with a drop-in (undone
// by the package's postrm) and the host's own /etc/resolv.conf is pointed at
// resolved's uplink file so the host keeps resolving exactly as before.
func freePort53(cfg *config.Config) {
	if !listenConflictsWithStub(cfg) || !stubListening() {
		return
	}
	fmt.Println("==> systemd-resolved is holding port 53 — turning off its stub listener")

	// if resolved knows no uplink servers the host would be left without
	// DNS once the stub is gone; point it at unbound instead
	body := "# written by minidns setup; removed when the package is removed\n[Resolve]\nDNSStubListener=no\n"
	if !hasNameserver(resolvedUplink) {
		body += "DNS=127.0.0.1\n"
	}
	if err := os.MkdirAll("/etc/systemd/resolved.conf.d", 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "    warning:", err)
		return
	}
	if err := os.WriteFile(resolvedDropIn, []byte(body), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "    warning:", err)
		return
	}
	fmt.Println("    wrote", resolvedDropIn)

	if target, err := os.Readlink(resolvConf); err == nil && strings.HasSuffix(target, "stub-resolv.conf") {
		tmp := resolvConf + ".minidns"
		os.Remove(tmp)
		if err := os.Symlink(resolvedUplink, tmp); err == nil {
			if err := os.Rename(tmp, resolvConf); err == nil {
				fmt.Printf("    %s -> %s (was %s)\n", resolvConf, resolvedUplink, target)
			}
		}
	}
	if out, err := exec.Command("systemctl", "restart", "systemd-resolved").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "    warning: restart systemd-resolved: %s\n", strings.TrimSpace(string(out)))
	}
}

// listenConflictsWithStub reports whether any configured listen address
// overlaps 127.0.0.53 (a wildcard or loopback-range bind does; a specific
// LAN address does not).
func listenConflictsWithStub(cfg *config.Config) bool {
	if cfg.Port != 53 {
		return false
	}
	for _, l := range cfg.Listen {
		addr, _, _ := strings.Cut(l, "@")
		if addr == "0.0.0.0" || strings.HasPrefix(addr, "127.0.0.53") {
			return true
		}
	}
	return false
}

func stubListening() bool {
	c, err := net.DialTimeout("tcp", "127.0.0.53:53", 500*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func hasNameserver(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "nameserver ") {
			return true
		}
	}
	return false
}
