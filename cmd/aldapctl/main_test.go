package main

import (
	"slices"
	"strings"
	"testing"
)

func TestVersionLine_UsesLdflags(t *testing.T) {
	version, commit, date = "1.2.3", "abc1234", "2026-01-02T03:04:05Z"
	t.Cleanup(func() { version, commit, date = "dev", "none", "unknown" })
	got := versionLine()
	for _, want := range []string{"aldapctl 1.2.3", "commit abc1234", "built 2026-01-02T03:04:05Z"} {
		if !strings.Contains(got, want) {
			t.Errorf("versionLine() = %q, want substring %q", got, want)
		}
	}
}

func TestParseArgs_Interleaved(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		pos  []string
		set  []string
	}{
		{"flags_first", []string{"--socket", "/s", "unlock", "1.2.3.4"}, []string{"unlock", "1.2.3.4"}, []string{"socket"}},
		{"flags_last", []string{"lock", "1.2.3.4", "--for", "1h", "-y"}, []string{"lock", "1.2.3.4"}, []string{"for", "yes"}},
		{"double_dash", []string{"unlock", "--yes", "--", "-odd-account"}, []string{"unlock", "-odd-account"}, []string{"yes"}},
		{"short_follow", []string{"events", "-f"}, []string{"events"}, []string{"follow"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := &opts{}
			pos, set, err := parseArgs(newFlagSet(o), tc.args)
			if err != nil {
				t.Fatal(err)
			}
			slices.Sort(set)
			if !slices.Equal(pos, tc.pos) || !slices.Equal(set, tc.set) {
				t.Errorf("pos %v set %v; want %v %v", pos, set, tc.pos, tc.set)
			}
		})
	}
	if _, _, err := parseArgs(newFlagSet(&opts{}), []string{"lock", "--for", "soon"}); err == nil {
		t.Error("bad duration accepted")
	}
}

func TestTargetOf(t *testing.T) {
	for key, want := range map[string]string{"192.0.2.1": "ip", "2001:db8::1": "ip", "jdoe": "account", "jdoe@corp.example": "account", "CORP\\jdoe": "account"} {
		if got := targetOf(key, false); got != want {
			t.Errorf("%s: %s, want %s", key, got, want)
		}
	}
	if targetOf("192.0.2.1", true) != "account" {
		t.Error("--account ignored")
	}
}
