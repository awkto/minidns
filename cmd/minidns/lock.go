package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/awkto/minidns/internal/paths"
)

// readOnly lists the commands that never write state, so they don't queue
// behind a running list update or zone sync.
var readOnly = map[string]bool{
	"status": true, "test": true, "blocklist": true, "logs": true, "top": true,
	"stats": true, "exporter": true, "version": true,
}

// lockState takes an exclusive lock for the life of the process so the
// adblock/zonesync timers and an interactive command can't rewrite the same
// files (or render the unbound config) at the same moment. The kernel drops
// the lock when the process exits.
func lockState() error {
	if err := os.MkdirAll(paths.StateDir(), 0o755); err != nil {
		return nil // not root: the command will fail on its own terms
	}
	f, err := os.OpenFile(filepath.Join(paths.StateDir(), ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil
	}
	deadline := time.Now().Add(2 * time.Minute)
	for announced := false; ; {
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			return nil // keep f open: closing it would release the lock
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("another minidns command has been running for over 2 minutes (lock: %s)", f.Name())
		}
		if !announced {
			fmt.Fprintln(os.Stderr, "waiting for another minidns command to finish...")
			announced = true
		}
		time.Sleep(250 * time.Millisecond)
	}
}
