package main

import (
	"flag"
	"io"
	"reflect"
	"testing"
)

func TestParseArgsInterspersed(t *testing.T) {
	cases := []struct {
		args []string
		pos  []string
		name string
		q    bool
	}{
		{[]string{"https://x/l", "--name", "oisd", "--quiet"}, []string{"https://x/l"}, "oisd", true},
		{[]string{"--name", "oisd", "https://x/l"}, []string{"https://x/l"}, "oisd", false},
		{[]string{"a", "--quiet", "b", "--name=n"}, []string{"a", "b"}, "n", true},
		{[]string{"a", "--", "--name", "b"}, []string{"a", "--name", "b"}, "", false},
		{nil, nil, "", false},
	}
	for _, c := range cases {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		name := fs.String("name", "", "")
		quiet := fs.Bool("quiet", false, "")
		pos, err := parseArgs(fs, c.args)
		if err != nil {
			t.Fatalf("%v: %v", c.args, err)
		}
		if !reflect.DeepEqual(pos, c.pos) || *name != c.name || *quiet != c.q {
			t.Errorf("%v: pos=%v name=%q quiet=%v", c.args, pos, *name, *quiet)
		}
	}
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if _, err := parseArgs(fs, []string{"a", "--nope"}); err == nil {
		t.Error("unknown flag after positional should error")
	}
}
