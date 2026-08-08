// Package paths centralizes every filesystem location minidns touches.
// Set MINIDNS_PREFIX to relocate everything under a prefix (dev/testing).
package paths

import (
	"os"
	"path/filepath"
)

func prefix() string { return os.Getenv("MINIDNS_PREFIX") }

func ConfigDir() string  { return prefix() + "/etc/minidns" }
func ConfigFile() string { return filepath.Join(ConfigDir(), "config.yaml") }

func StateDir() string { return prefix() + "/var/lib/minidns" }
func RPZDir() string   { return filepath.Join(StateDir(), "rpz") }
func ZoneDir() string  { return filepath.Join(StateDir(), "zones") }

func LogDir() string   { return prefix() + "/var/log/minidns" }
func QueryLog() string { return filepath.Join(LogDir(), "unbound.log") }

func UnboundConfD() string    { return prefix() + "/etc/unbound/unbound.conf.d" }
func UnboundConfFile() string { return filepath.Join(UnboundConfD(), "minidns.conf") }

// RPZ zone files. Manual firewall entries and the allowlist each get their
// own zone; every adblock list gets adblock-<name>.rpz.
func AllowRPZ() string { return filepath.Join(RPZDir(), "allow.rpz") }
func BlockRPZ() string { return filepath.Join(RPZDir(), "block.rpz") }
func AdblockRPZ(list string) string {
	return filepath.Join(RPZDir(), "adblock-"+list+".rpz")
}

func ZoneFile(zone string) string { return filepath.Join(ZoneDir(), zone+".zone") }
