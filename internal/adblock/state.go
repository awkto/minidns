package adblock

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/awkto/minidns/internal/paths"
)

// ListState is what the last refresh of one list did.
type ListState struct {
	LastAttempt time.Time `json:"last_attempt"`
	LastSuccess time.Time `json:"last_success,omitempty"`
	Entries     int       `json:"entries"`
	Error       string    `json:"error,omitempty"` // empty after a successful refresh
}

func stateFile() string { return filepath.Join(paths.StateDir(), "blocklists.json") }

// LoadState reads the refresh state of all lists (empty if none yet).
func LoadState() map[string]ListState {
	out := map[string]ListState{}
	if b, err := os.ReadFile(stateFile()); err == nil {
		json.Unmarshal(b, &out)
	}
	return out
}

// Record stores the outcome of one refresh attempt.
func Record(name string, entries int, refreshErr error) {
	all := LoadState()
	st := all[name]
	st.LastAttempt = time.Now().UTC().Truncate(time.Second)
	if refreshErr != nil {
		st.Error = refreshErr.Error()
	} else {
		st.Error, st.Entries, st.LastSuccess = "", entries, st.LastAttempt
	}
	all[name] = st
	saveState(all)
}

// Forget drops a removed list from the state.
func Forget(name string) {
	all := LoadState()
	delete(all, name)
	saveState(all)
}

func saveState(all map[string]ListState) {
	b, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return
	}
	tmp := stateFile() + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		os.Rename(tmp, stateFile())
	}
}
