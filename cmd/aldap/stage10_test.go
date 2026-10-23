//go:build integration

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// buildAldapctl compiles the control client for the end-to-end tests.
func buildAldapctl(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "aldapctl")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "go", "build", "-o", bin, "../aldapctl").CombinedOutput()
	if err != nil {
		t.Fatalf("build aldapctl: %v\n%s", err, out)
	}
	return bin
}

type ctlResult struct {
	code           int
	stdout, stderr string
}

// ctl runs the aldapctl binary without a terminal (scripts).
func ctl(t *testing.T, bin string, args ...string) ctlResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = strings.NewReader("")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return ctlResult{code, out.String(), errb.String()}
}

func untar(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	out := map[string]string{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		out[strings.TrimPrefix(h.Name, "aldap-bundle/")] = string(b)
	}
}

// TestStage10_Aldapctl drives the aldapctl binary against a running daemon
// over the IPC socket (no token) and over TCP (token file): reads,
// confirmed and unconfirmed changes, config get/validate and the bundle.
func TestStage10_Aldapctl(t *testing.T) {
	s := startServed(t, "")
	bin := buildAldapctl(t)
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte(tAdminToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conns := map[string][]string{"tcp": {"--url", s.base, "--token-file", tok}}
	if runtime.GOOS != "windows" {
		conns["ipc"] = []string{"--socket", s.ipc}
	}
	for name, conn := range conns {
		t.Run(name, func(t *testing.T) {
			run := func(want int, args ...string) ctlResult {
				t.Helper()
				r := ctl(t, bin, append(append([]string{}, conn...), args...)...)
				if r.code != want {
					t.Fatalf("aldapctl %v: exit %d (want %d)\nstdout %s\nstderr %s", args, r.code, want, r.stdout, r.stderr)
				}
				return r
			}
			if r := run(0, "status"); !strings.Contains(r.stdout, "profiles: ") || !strings.Contains(r.stdout, "up") {
				t.Errorf("status:\n%s", r.stdout)
			}
			run(0, "upstreams")
			if r := run(0, "profiles"); !strings.Contains(r.stdout, "virola") {
				t.Errorf("profiles:\n%s", r.stdout)
			}
			// A change without --yes and without a terminal is refused.
			if r := run(3, "lock", "198.51.100.77", "--for", "10m"); !strings.Contains(r.stderr, "--yes") {
				t.Errorf("unconfirmed lock: %s", r.stderr)
			}
			if r := run(0, "locks"); strings.Contains(r.stdout, "198.51.100.77") {
				t.Error("unconfirmed lock applied")
			}
			run(0, "lock", "198.51.100.77", "--for", "10m", "--reason", "stage10", "--yes")
			if r := run(0, "locks", "--json"); !strings.Contains(r.stdout, `"key": "198.51.100.77"`) || !strings.Contains(r.stdout, "stage10") {
				t.Errorf("locks:\n%s", r.stdout)
			}
			run(0, "unlock", "198.51.100.77", "--yes")
			run(0, "lockdown", "on", "--yes")
			if r := run(0, "status"); !strings.Contains(r.stdout, "lockdown ON") {
				t.Errorf("lockdown:\n%s", r.stdout)
			}
			run(0, "lockdown", "off", "--yes")
			if r := run(0, "events", "--types", "lock,unlock,lockdown"); !strings.Contains(r.stdout, " unlock ") || !strings.Contains(r.stdout, " lockdown ") {
				t.Errorf("events:\n%s", r.stdout)
			}
			if r := run(0, "test", "virola", "--filter", "(uid=jdoe)"); !strings.Contains(r.stdout, "result: Success (0)") {
				t.Errorf("test:\n%s", r.stdout)
			}
			conf := run(0, "config", "get")
			if !strings.Contains(conf.stdout, "[profile.virola]") || strings.Contains(conf.stdout, tAdminToken) {
				t.Errorf("config get leaks or misses:\n%s", conf.stdout)
			}
			// The file of the daemon validates; the rendering with the
			// inline token masked as *** is refused (the token must be given).
			run(0, "config", "validate", s.path)
			rendered := filepath.Join(t.TempDir(), "rendered.toml")
			if err := os.WriteFile(rendered, []byte(conf.stdout), 0o600); err != nil {
				t.Fatal(err)
			}
			if r := run(1, "config", "validate", rendered); !strings.Contains(r.stderr, "masked placeholder") {
				t.Errorf("masked rendering: %s", r.stderr)
			}
			if r := run(1, "record", "start", "virola", "--yes"); !strings.Contains(r.stderr, "HTTP 501") {
				t.Errorf("record: %s", r.stderr)
			}
			out := filepath.Join(t.TempDir(), "aldap-bundle.tgz")
			r := run(0, "bundle", "--out", out)
			files := untar(t, out)
			for _, want := range []string{"manifest.json", "version.json", "health.json", "status.json", "config.toml", "events.jsonl", "metrics.txt"} {
				if files[want] == "" {
					t.Errorf("bundle: %s missing or empty", want)
				}
			}
			all := r.stdout + r.stderr
			for _, data := range files {
				all += data
			}
			for _, secret := range []string{tAdminToken, tEventsToken, clientPassword, tSvcPW} {
				if strings.Contains(all, secret) {
					t.Errorf("bundle carries a secret (%d bytes)", len(secret))
				}
			}
			if !strings.Contains(files["version.json"], runtime.Version()) || !strings.Contains(files["events.jsonl"], `"event":"lockdown"`) {
				t.Errorf("bundle content:\n%s\n%s", files["version.json"], files["events.jsonl"])
			}
		})
	}
	if strings.Contains(s.logs.String(), tAdminToken) {
		t.Error("token in the daemon log")
	}
}
