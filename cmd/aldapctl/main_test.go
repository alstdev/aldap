package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun_Commands(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "version", args: []string{"version"}, wantCode: 0, wantStdout: "aldapctl dev (commit none, built unknown, go"},
		{name: "help", args: []string{"help"}, wantCode: 0, wantStdout: "Usage: aldapctl"},
		{name: "help_flag", args: []string{"--help"}, wantCode: 0, wantStdout: "Usage: aldapctl"},
		{name: "no_args", args: nil, wantCode: 2, wantStderr: "Usage: aldapctl"},
		{name: "unknown", args: []string{"bogus"}, wantCode: 2, wantStderr: `unknown command "bogus"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if got := run(tt.args, &stdout, &stderr); got != tt.wantCode {
				t.Fatalf("exit code = %d, want %d (stderr: %s)", got, tt.wantCode, stderr.String())
			}
			if !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want substring %q", stdout.String(), tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want substring %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

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
