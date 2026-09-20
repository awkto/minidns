package main

import "flag"

// parseArgs parses args allowing flags before, between and after positional
// arguments (the standard library stops at the first positional, which made
// `minidns zone add example.com --provider x` a usage error). It returns the
// positionals in order. A literal "--" ends flag parsing as usual.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		// everything after an explicit "--" is positional
		if n := len(args) - len(rest); n > 0 && args[n-1] == "--" {
			return append(pos, rest...), nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}
