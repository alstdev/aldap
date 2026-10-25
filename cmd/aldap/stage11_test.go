//go:build integration

package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/secret"
	"github.com/alstdev/aldap/internal/testdir"
)

// startServedVirola runs serve() with the API and extra keys in
// [profile.virola]; it returns the served daemon and an ldaps client.
func startServedVirola(t *testing.T, virolaExtra string) (*served, *ldap.Conn) {
	t.Helper()
	t.Setenv("ALDAP_TEST_API_EVENTS", tEventsToken)
	dc := testdir.StartFixture(t)
	caDir := filepath.Join(t.TempDir(), "ca")
	port := freePort(t)
	path, lp, _ := daemonConfigVirola(t, dc, caDir, apiTOML(port, ""), virolaExtra)
	s := &served{path: path, base: fmt.Sprintf("http://127.0.0.1:%d", port), ca: caDir, logs: &safeBuffer{}, stdout: &safeBuffer{}, done: make(chan int, 1), client: &http.Client{Timeout: 10 * time.Second}}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		if v, ok := strings.CutPrefix(line, "ipc_socket = "); ok {
			s.ipc, _ = strconv.Unquote(v)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	opts := daemonOptions{LogOut: s.logs, EventsOut: io.Discard, Secrets: secret.Default, Argon2: fastArgon, NoPersistCerts: true, Hostname: "aldap-test"}
	go func() { s.done <- serve(ctx, path, true, opts, make(chan os.Signal), s.stdout) }()
	waitFor(t, func() bool { return strings.Contains(s.stdout.String(), "listening") || len(s.done) > 0 })
	if len(s.done) > 0 {
		t.Fatalf("serve exited early:\n%s", s.logs.String())
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-s.done:
		case <-time.After(10 * time.Second):
			t.Error("serve did not stop")
		}
	})
	c, err := ldap.DialURL(fmt.Sprintf("ldaps://127.0.0.1:%d", lp), ldap.DialWithTLSConfig((&running{caDir: caDir}).tlsConfig(t)))
	if err != nil {
		t.Fatal(err)
	}
	c.SetTimeout(5 * time.Second)
	t.Cleanup(func() { _ = c.Close() })
	return s, c
}

// TestStage11_AldapctlRecordReplay: aldapctl record start/stop around
// client searches, replay of the recording through the API with no
// difference, then after a filter change (config set) with differences
// (exit 1).
func TestStage11_AldapctlRecordReplay(t *testing.T) {
	recFile := filepath.Join(t.TempDir(), "virola.jsonl")
	s, c := startServedVirola(t, fmt.Sprintf("[profile.virola.record]\nfile = %q\nmax_size_mb = 1\nmax_files = 2\n", recFile))
	bin := buildAldapctl(t)
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte(tAdminToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conn := []string{"--url", s.base, "--token-file", tok}
	if runtime.GOOS != "windows" {
		conn = []string{"--socket", s.ipc}
	}
	run := func(want int, args ...string) ctlResult {
		t.Helper()
		r := ctl(t, bin, append(append([]string{}, conn...), args...)...)
		if r.code != want {
			t.Fatalf("aldapctl %v: exit %d (want %d)\nstdout %s\nstderr %s", args, r.code, want, r.stdout, r.stderr)
		}
		return r
	}
	if err := c.Bind(tClientDN, clientPassword); err != nil {
		t.Fatal(err)
	}
	search(t, c, tUsersDN, "(sAMAccountName=before.start)")
	if r := run(0, "record", "start", "virola", "--yes"); !strings.Contains(r.stdout, "recording of virola: on") {
		t.Fatalf("record start: %s", r.stdout)
	}
	for _, f := range []string{"(sAMAccountName=alice.adams)", "(objectClass=*)", "(mail=*)", "(userPassword=S3CR3T-int-6666)"} {
		search(t, c, tUsersDN, f, "mail")
	}
	run(0, "record", "stop", "virola", "--yes")
	search(t, c, tUsersDN, "(sAMAccountName=after.stop)")
	raw, err := os.ReadFile(recFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(raw), "\n") != 4 || strings.Contains(string(raw), "before.start") || strings.Contains(string(raw), "after.stop") ||
		strings.Contains(string(raw), "S3CR3T") || strings.Contains(string(raw), clientPassword) {
		t.Fatalf("recording:\n%s", raw)
	}
	if r := run(0, "replay", recFile, "--profile", "virola"); !strings.Contains(r.stdout, "replayed 4 searches against virola: 4 same, 0 different") {
		t.Errorf("replay before the change:\n%s", r.stdout)
	}
	// Change the filter through the API (config set reloads).
	body, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	changed := filepath.Join(t.TempDir(), "changed.toml")
	text := strings.Replace(string(body), "rdn_attr = \"sAMAccountName\"\n", "rdn_attr = \"sAMAccountName\"\nfilter = \"(&"+config.DefaultADFilter+"(!(sAMAccountName=alice.adams)))\"\n", 1)
	if err := os.WriteFile(changed, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	run(0, "config", "set", changed, "--yes")
	r := run(1, "replay", recFile, "--profile", "virola")
	if !strings.Contains(r.stdout, "replayed 4 searches against virola: 1 same, 3 different") || !strings.Contains(r.stdout, "missing: cn=alice.adams,") {
		t.Errorf("replay after the filter change:\n%s", r.stdout)
	}
	if r := run(1, "replay", recFile, "--profile", "virola", "--json"); !strings.Contains(r.stdout, `"missing"`) {
		t.Errorf("replay --json:\n%s", r.stdout)
	}
}
