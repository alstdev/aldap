package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/golden")

// fixedNow is the clock of every CLI test.
var fixedNow = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

const testToken = "S3CR3T-aldapctl-token-0123456789abcdef"

// fakeAPI serves canned answers shaped like docs/openapi.yaml and records
// every request.
type fakeAPI struct {
	t   *testing.T
	srv *httptest.Server

	mu   sync.Mutex
	reqs []recorded
	// status overrides the answer of a path ("METHOD /path" → code).
	status map[string]int
}

type recorded struct {
	method, path, query, auth, body string
}

func (f *fakeAPI) calls(prefix string) []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []recorded
	for _, r := range f.reqs {
		if strings.HasPrefix(r.method+" "+r.path, prefix) {
			out = append(out, r)
		}
	}
	return out
}

const fixtureEvents = `[
{"schema":"aldap.event.v1","ts":"2026-10-23T11:58:00.000Z","id":"01J0000000000000000000001","seq":41,"event":"bind_fail","level":"medium","host":"dc-proxy","profile":"virola","client_ip":"192.0.2.10","account":"jdoe","reason":"invalid_credentials","data":{"attempt":3}},
{"schema":"aldap.event.v1","ts":"2026-10-23T11:59:00.000Z","id":"01J0000000000000000000002","seq":42,"event":"lock","level":"high","host":"dc-proxy","profile":"virola","client_ip":"192.0.2.10","data":{"target":"ip","key":"192.0.2.10","until":"2026-10-23T12:15:00Z"}}
]`

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{t: t, status: map[string]int{}}
	answers := map[string]string{
		"GET /v1/status": `{"version":"1.4.0","go_version":"go1.26.10","uptime_s":3725,"lockdown":false,"learning":true,"profiles":["virola","app"],
			"upstreams":{"ad":[{"url":"ldaps://dc1.corp.example:636","state":"up","consecutive_failures":0,"latency_p50_ms":2.1,"latency_p95_ms":5.4},
			{"url":"ldaps://dc2.corp.example:636","state":"down","consecutive_failures":4,"last_error":"dial tcp: i/o timeout","latency_p50_ms":0,"latency_p95_ms":0}]},
			"locks_active":2,"attacks_active":1,"events_seq":42}`,
		"GET /v1/upstreams": `{"ad":[{"url":"ldaps://dc1.corp.example:636","state":"up","consecutive_ok":120,"consecutive_fail":0,"last_check":"2026-10-23T11:59:58Z","p50":2100000,"p95":5400000,"idle_conns":2,"active_conns":1},
			{"url":"ldaps://dc2.corp.example:636","state":"down","consecutive_ok":0,"consecutive_fail":4,"last_error":"dial tcp: i/o timeout","last_check":"2026-10-23T11:59:50Z","p50":0,"p95":0,"idle_conns":0,"active_conns":0}]}`,
		"GET /v1/profiles": `[{"name":"virola","mode":"proxy","transport":"ldaps","listen":[":636"],"upstream":"ad","virtual_base":"dc=aldap","bases":["OU=Staff,DC=corp,DC=example"],"cache":"ttl"},
			{"name":"app","mode":"mock","transport":"ldap+starttls","listen":["127.0.0.1:1389"],"virtual_base":"dc=app","bases":[],"cache":"none"}]`,
		"GET /v1/locks": `[{"target":"ip","key":"192.0.2.10","until":"2026-10-23T12:15:00Z","failures":5,"source":"ratelimit","profile":"virola"},
			{"target":"account","key":"jdoe","until":"2026-10-23T13:00:00Z","failures":0,"source":"api","reason":"helpdesk ticket 42"}]`,
		"POST /v1/locks":     `{"target":"ip","key":"198.51.100.7","until":"2026-10-23T13:00:00Z","failures":0,"source":"api","reason":"scan"}`,
		"DELETE /v1/locks/":  ``,
		"POST /v1/lockdown":  `{"lockdown":true,"source":"api"}`,
		"GET /v1/indicators": `[{"target":"ip","key":"192.0.2.10","score":7.5,"reasons":["bind_fail","spray"],"hits":{"bind_fail":12,"spray":1},"first_seen":"2026-10-23T11:00:00Z","last_seen":"2026-10-23T11:59:00Z","locked":true}]`,
		"GET /v1/events":     fixtureEvents,
		"POST /v1/reload":    `{"ok":true}`,
		"GET /v1/config":     "[server]\nlog_level = \"info\"\n\n[upstream.ad]\nservers = [\"ldaps://dc1.corp.example:636\"]\nbind_dn = \"CN=svc,DC=corp,DC=example\"\nbind_password = \"***\"\n",
		"PUT /v1/config":     `{"ok":true,"backup":"/etc/aldap/aldap.toml.bak.20261023T120000Z"}`,
		"POST /v1/profiles/": `{"status":"sync started"}`,
		"POST /v1/baseline/": `{"learning":true,"until":"2026-10-24T12:00:00Z","scope":"process"}`,
		"GET /healthz":       `{"status":"ok"}`,
		"GET /readyz":        `{"status":"ready"}`,
		"GET /metrics":       "# HELP aldap_up 1\naldap_up 1\n",
		"POST /v1/profiles/test": `{"result_code":0,"entries":[{"dn":"uid=jdoe,ou=users,dc=aldap","attrs":{"mail":["jdoe@corp.example"],"cn":["John Doe"]}}],
			"denied_attrs":["telephoneNumber"],"denied_terms":[],"upstream_queries":1,"effective_filter":"(&(objectClass=user)(sAMAccountName=jdoe))","duration_ms":3.2}`,
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.reqs = append(f.reqs, recorded{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"), string(body)})
		code, override := f.status[r.Method+" "+r.URL.Path]
		f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"a valid bearer token is required","code":"unauthorized"}`)
			return
		}
		if override {
			w.WriteHeader(code)
			_, _ = io.WriteString(w, `{"error":"request recording: not implemented","code":"not_implemented"}`)
			return
		}
		key := r.Method + " " + r.URL.Path
		if strings.HasSuffix(r.URL.Path, "/test") {
			key = "POST /v1/profiles/test"
		}
		ans, ok := answers[key]
		if !ok {
			for k, v := range answers {
				if strings.HasSuffix(k, "/") && strings.HasPrefix(key, k) {
					ans, ok = v, true
				}
			}
		}
		switch {
		case !ok:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":"no such endpoint","code":"not_found"}`)
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/sync") || strings.HasPrefix(r.URL.Path, "/v1/baseline/"):
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, ans)
		default:
			if strings.HasPrefix(ans, "[") || strings.HasPrefix(ans, "{") {
				w.Header().Set("Content-Type", "application/json")
			}
			_, _ = io.WriteString(w, ans)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// tokenFile writes the test token with owner-only permissions.
func tokenFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// cliResult is one aldapctl invocation.
type cliResult struct {
	code           int
	stdout, stderr string
}

// runCLI runs aldapctl against the fake API (the connection flags are added).
func (f *fakeAPI) run(t *testing.T, stdin string, interactive bool, args ...string) cliResult {
	t.Helper()
	full := append([]string{"--url", f.srv.URL, "--token-file", tokenFile(t)}, args...)
	return runApp(t, stdin, interactive, full...)
}

func runApp(t *testing.T, stdin string, interactive bool, args ...string) cliResult {
	t.Helper()
	var out, errb bytes.Buffer
	a := &app{stdin: strings.NewReader(stdin), stdout: &out, stderr: &errb, interactive: interactive, now: func() time.Time { return fixedNow },
		runTUI: func(context.Context, tuiAPI, io.Writer) error { return nil }}
	code := a.run(context.Background(), args)
	return cliResult{code, out.String(), errb.String()}
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", "golden", name+".golden")
	if *update {
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run go test -update)", err)
	}
	if string(want) != got {
		t.Errorf("%s differs from %s (go test -update rewrites it)\n--- got\n%s\n--- want\n%s", name, p, got, want)
	}
}

// TestCLI_Golden checks the human output of the read commands.
func TestCLI_Golden(t *testing.T) {
	f := newFakeAPI(t)
	replay := filepath.Join(t.TempDir(), "rec.jsonl")
	if err := os.WriteFile(replay, []byte(`# recorded 2026-10-23
{"profile":"virola","base":"ou=users,dc=aldap","scope":"sub","filter":"(uid=jdoe)","attrs":["mail"],"result_code":0,"entries":1,"dns":["UID=jdoe,ou=users,dc=aldap"]}
{"filter":"(uid=*)","result_code":0,"dns":["uid=jdoe,ou=users,dc=aldap","uid=asmith,ou=users,dc=aldap"]}
{"filter":"(cn=x)","entries":1}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
		code int
	}{
		{"status", []string{"status"}, 0},
		{"upstreams", []string{"upstreams"}, 0},
		{"profiles", []string{"profiles"}, 0},
		{"locks", []string{"locks"}, 0},
		{"events", []string{"events"}, 0},
		{"events_json", []string{"events", "--json", "--types", "lock"}, 0},
		{"indicators", []string{"indicators"}, 0},
		{"test", []string{"test", "virola", "--filter", "(uid=jdoe)", "--attrs", "mail,cn"}, 0},
		{"config_get", []string{"config", "get"}, 0},
		{"replay", []string{"replay", replay, "--profile", "virola"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := f.run(t, "", false, tc.args...)
			if r.code != tc.code {
				t.Fatalf("exit %d, want %d; stderr %s", r.code, tc.code, r.stderr)
			}
			golden(t, "cli_"+tc.name, r.stdout)
		})
	}
	if q := f.calls("GET /v1/events"); len(q) < 2 || q[1].query != "since=0&types=lock" {
		t.Errorf("events query: %+v", q)
	}
	if b := f.calls("POST /v1/profiles/virola/test"); len(b) == 0 || !strings.Contains(b[0].body, `"attrs":["mail","cn"]`) {
		t.Errorf("test body: %+v", b)
	}
}

// TestCLI_Help is the full aldapctl --help (golden) and the help of each command.
func TestCLI_Help(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the help names the platform's default IPC path")
	}
	if r := runApp(t, "", false, "version"); r.code != 0 || !strings.HasPrefix(r.stdout, "aldapctl dev (commit none") {
		t.Errorf("version: %+v", r)
	}
	r := runApp(t, "", false, "--help")
	if r.code != 0 {
		t.Fatal(r.stderr)
	}
	golden(t, "help", r.stdout)
	for _, c := range commands {
		if c.name == "help" {
			continue
		}
		if !strings.Contains(r.stdout, "  "+c.name) {
			t.Errorf("--help lacks %q", c.name)
		}
		h := runApp(t, "", false, append(strings.Fields(c.name), "--help")...)
		if h.code != 0 || !strings.Contains(h.stdout, "Usage: aldapctl "+c.name) {
			t.Errorf("%s --help: %d %q", c.name, h.code, h.stdout)
		}
		for _, fl := range c.flags {
			if !strings.Contains(h.stdout, "--"+fl) {
				t.Errorf("%s --help lacks --%s", c.name, fl)
			}
		}
		if c.mutating && !strings.Contains(h.stdout, "--yes") {
			t.Errorf("%s --help lacks --yes", c.name)
		}
	}
	golden(t, "help_lock", runApp(t, "", false, "help", "lock").stdout)
	if r := runApp(t, "", false, "help", "config"); r.code != 0 || !strings.Contains(r.stdout, "config set") || !strings.Contains(r.stdout, "config validate") {
		t.Errorf("help config: %+v", r)
	}
}

// TestCLI_Mutating checks y/n and --yes for every state-changing command:
// no request leaves before the confirmation.
func TestCLI_Mutating(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "aldap.toml")
	if err := os.WriteFile(cfg, []byte("[server]\nlog_level = \"warn\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		args   []string
		call   string
		body   string
		stdout string
	}{
		{"unlock_ip", []string{"unlock", "192.0.2.10"}, "DELETE /v1/locks/ip/192.0.2.10", "", "unlocked ip 192.0.2.10"},
		{"unlock_account", []string{"unlock", "jdoe"}, "DELETE /v1/locks/account/jdoe", "", "unlocked account jdoe"},
		{"unlock_forced", []string{"unlock", "--account", "10.0.0.1"}, "DELETE /v1/locks/account/10.0.0.1", "", "unlocked account"},
		{"lock", []string{"lock", "198.51.100.7", "--for", "1h", "--reason", "scan"}, "POST /v1/locks", `{"duration":"1h0m0s","key":"198.51.100.7","reason":"scan","target":"ip"}`, "locked ip 198.51.100.7 until 2026-10-23T13:00:00Z"},
		{"lockdown", []string{"lockdown", "on"}, "POST /v1/lockdown", `{"state":"on"}`, "lockdown on"},
		{"reload", []string{"reload"}, "POST /v1/reload", "", "reloaded"},
		{"config_set", []string{"config", "set", cfg}, "PUT /v1/config", "[server]\nlog_level = \"warn\"\n", "previous file saved as /etc/aldap/aldap.toml.bak.20261023T120000Z"},
		{"sync", []string{"sync", "virola"}, "POST /v1/profiles/virola/sync", "", "sync of virola started"},
		{"learn", []string{"baseline", "learn", "virola", "--for", "2h"}, "POST /v1/baseline/virola/learn", `{"duration":"2h0m0s"}`, "learning until 2026-10-24T12:00:00Z"},
		{"record", []string{"record", "start", "virola"}, "POST /v1/profiles/virola/record", `{"state":"on"}`, "recording of virola: on"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t)
			// Script without --yes: refused, nothing sent.
			r := f.run(t, "", false, tc.args...)
			if r.code != exitAborted || !strings.Contains(r.stderr, "pass --yes") || len(f.calls(tc.call)) != 0 {
				t.Fatalf("without --yes: %+v calls %v", r, f.calls(tc.call))
			}
			// Terminal, answered n: aborted, nothing sent.
			r = f.run(t, "n\n", true, tc.args...)
			if r.code != exitAborted || !strings.Contains(r.stderr, "[y/N]") || len(f.calls(tc.call)) != 0 {
				t.Fatalf("answered n: %+v", r)
			}
			// Terminal, answered y.
			r = f.run(t, "y\n", true, tc.args...)
			if r.code != 0 || !strings.Contains(r.stdout, tc.stdout) || len(f.calls(tc.call)) != 1 {
				t.Fatalf("answered y: %+v calls %v", r, f.calls(tc.call))
			}
			if got := f.calls(tc.call)[0].body; tc.body != "" && got != tc.body {
				t.Errorf("body %q, want %q", got, tc.body)
			}
			// Script with --yes (and -y).
			for _, yes := range []string{"--yes", "-y"} {
				if r := f.run(t, "", false, append(tc.args, yes)...); r.code != 0 {
					t.Errorf("%s: %+v", yes, r)
				}
			}
			if n := len(f.calls(tc.call)); n != 3 {
				t.Errorf("calls %d, want 3", n)
			}
		})
	}
}

func TestCLI_ErrorsAndUsage(t *testing.T) {
	f := newFakeAPI(t)
	f.status["POST /v1/profiles/virola/record"] = http.StatusNotImplemented
	for _, tc := range []struct {
		name   string
		args   []string
		code   int
		stderr string
	}{
		{"unknown", []string{"bogus"}, exitUsage, `unknown command "bogus"`},
		{"group", []string{"config"}, exitUsage, "config: want one of: get, set, validate"},
		{"flag_not_applicable", []string{"status", "--for", "1h"}, exitUsage, "flag --for does not apply"},
		{"yes_not_applicable", []string{"status", "--yes"}, exitUsage, "flag --yes does not apply"},
		{"missing_arg", []string{"unlock"}, exitUsage, "usage: aldapctl unlock <ip|account>"},
		{"extra_arg", []string{"status", "x"}, exitUsage, "usage: aldapctl status"},
		{"lock_no_for", []string{"lock", "192.0.2.1", "--yes"}, exitUsage, "--for DURATION is required"},
		{"lockdown_bad", []string{"lockdown", "maybe", "--yes"}, exitUsage, "want on or off"},
		{"test_no_filter", []string{"test", "virola"}, exitUsage, "--filter is required"},
		{"replay_no_profile", []string{"replay", "x.jsonl"}, exitUsage, "--profile is required"},
		{"bad_flag", []string{"status", "--nope"}, exitUsage, "flag provided but not defined"},
		{"indicators_conflict", []string{"indicators", "--json", "--format", "plain"}, exitUsage, "conflict"},
		{"not_implemented", []string{"record", "stop", "virola", "--yes"}, exitError, "not implemented (not_implemented, HTTP 501)"},
		{"tui_needs_terminal", []string{"tui"}, exitUsage, "needs a terminal"},
		{"no_command_no_terminal", nil, exitUsage, "needs a terminal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := f.run(t, "", false, tc.args...)
			if r.code != tc.code || !strings.Contains(r.stderr, tc.stderr) {
				t.Errorf("exit %d stderr %q; want %d %q", r.code, r.stderr, tc.code, tc.stderr)
			}
			if strings.Contains(r.stdout+r.stderr, testToken) {
				t.Error("token in output")
			}
		})
	}
	// A wrong token: the API error is reported, the token is not.
	bad := filepath.Join(t.TempDir(), "bad")
	_ = os.WriteFile(bad, []byte("wrong-token-0123456789abcdef0123456789\n"), 0o600)
	r := runApp(t, "", false, "--url", f.srv.URL, "--token-file", bad, "status")
	if r.code != exitError || !strings.Contains(r.stderr, "unauthorized") || strings.Contains(r.stderr, "wrong-token") {
		t.Errorf("bad token: %+v", r)
	}
	// Unreachable IPC socket.
	r = runApp(t, "", false, "--socket", filepath.Join(t.TempDir(), "none.sock"), "status")
	if r.code != exitError || !strings.Contains(r.stderr, "cannot reach aldap at IPC socket") {
		t.Errorf("no daemon: %+v", r)
	}
}

func TestCLI_ConfigGetOut(t *testing.T) {
	f := newFakeAPI(t)
	out := filepath.Join(t.TempDir(), "running.toml")
	if r := f.run(t, "", false, "config", "get", "--out", out); r.code != 0 || !strings.Contains(r.stderr, "secrets masked") {
		t.Fatalf("%+v", r)
	}
	if fi, err := os.Stat(out); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("mode: %v %v", fi, err)
	}
	if r := f.run(t, "", false, "config", "get", "--out", out); r.code != exitError || !strings.Contains(r.stderr, "--force") {
		t.Errorf("overwrite without --force: %+v", r)
	}
	if r := f.run(t, "", false, "config", "get", "--out", out, "--force"); r.code != 0 {
		t.Errorf("--force: %+v", r)
	}
	if r := f.run(t, "", false, "config", "validate", out); r.code != 0 || !strings.Contains(r.stdout, "valid") {
		t.Errorf("validate: %+v", r)
	}
	if q := f.calls("PUT /v1/config"); len(q) != 1 || q[0].query != "dry_run=true" {
		t.Errorf("validate query: %+v", q)
	}
}

func TestCLI_JSONOutput(t *testing.T) {
	f := newFakeAPI(t)
	for _, args := range [][]string{{"status", "--json"}, {"upstreams", "--json"}, {"profiles", "--json"}, {"locks", "--json"},
		{"indicators", "--json"}, {"test", "virola", "--filter", "(uid=a)", "--json"}} {
		r := f.run(t, "", false, args...)
		if r.code != 0 || !json.Valid([]byte(r.stdout)) {
			t.Errorf("%v: %d %q", args, r.code, r.stdout)
		}
	}
	for _, format := range []string{"plain", "stix-lite"} {
		if r := f.run(t, "", false, "indicators", "--format", format); r.code != 0 {
			t.Errorf("format %s: %+v", format, r)
		}
		if q := f.calls("GET /v1/indicators"); q[len(q)-1].query != "format="+format {
			t.Errorf("query %q", q[len(q)-1].query)
		}
	}
}
