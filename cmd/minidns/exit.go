package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/awkto/minidns/internal/zones"
)

// Exit codes are part of the CLI contract (scripts and other tools such as
// minidhcp branch on them); never renumber, only append.
const (
	exitOK         = 0
	exitError      = 1 // anything not covered below
	exitUsage      = 2 // bad command line
	exitInvalid    = 3 // input failed validation
	exitNotFound   = 4 // the named object does not exist
	exitConflict   = 5 // already exists / would break an invariant
	exitApply      = 6 // the engine rejected the change; previous state restored
	exitConnection = 7 // could not reach the target
	exitPermission = 8 // needs root
)

// applyError marks a failure to activate a change in unbound.
type applyError struct{ err error }

func (e applyError) Error() string { return e.err.Error() }
func (e applyError) Unwrap() error { return e.err }

// usageError marks a bad command line.
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func usagef(format string, a ...any) error { return usageError{fmt.Sprintf(format, a...)} }

func exitCodeFor(err error) int {
	var ae applyError
	var ue usageError
	var ce connError
	switch {
	case err == nil:
		return exitOK
	case errors.As(err, &ce):
		return exitConnection
	case errors.As(err, &ue):
		return exitUsage
	case errors.As(err, &ae):
		return exitApply
	case errors.Is(err, zones.ErrInvalid):
		return exitInvalid
	case errors.Is(err, zones.ErrNotFound):
		return exitNotFound
	case errors.Is(err, zones.ErrConflict):
		return exitConflict
	case errors.Is(err, os.ErrPermission):
		return exitPermission
	}
	return exitError
}

// jsonOut is set by the global --json flag.
var jsonOut bool

// dryRun is set by the global --dry-run flag. A command may only run under
// it when it is annotated as supporting it (see supportsDryRun): the change
// is validated and described, but nothing is written or activated.
var dryRun bool

// emit prints v as JSON when --json is set, otherwise runs the human
// renderer. Structured output goes to stdout only; messages for people that
// accompany a JSON result go to stderr so stdout stays parseable.
func emit(v any, human func()) error {
	if dryRun {
		if m, ok := v.(map[string]any); ok {
			m["dry_run"] = true
		}
	}
	if !jsonOut {
		if dryRun {
			fmt.Println("DRY RUN — nothing was changed. This is what would have happened:")
		}
		human()
		return nil
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// note prints a line meant for a person: stdout normally, stderr under --json.
func note(format string, a ...any) {
	if jsonOut {
		fmt.Fprintf(os.Stderr, format+"\n", a...)
		return
	}
	fmt.Printf(format+"\n", a...)
}
