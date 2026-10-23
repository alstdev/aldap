//go:build integration

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/events/schematest"
	"github.com/alstdev/aldap/internal/secret"
	"github.com/alstdev/aldap/internal/testdir"
)

const (
	tAdminToken  = "S3CR3T-api-admin-0123456789abcdef012345"
	tEventsToken = "S3CR3T-api-events-0123456789abcdef01234"
)

// apiTOML enables the API on a runtime port with an admin token (inline,
// to check masking) and an events:read token (environment).
func apiTOML(port int, extra string) string {
	return fmt.Sprintf(`
[api]
enabled = true
listen = "127.0.0.1:%d"
rate_limit_rps = 0
%s
[[api.token]]
name = "ops"
token = %q
scopes = ["admin"]
[[api.token]]
name = "siem"
token_env = "ALDAP_TEST_API_EVENTS"
scopes = ["events:read"]
`, port, extra, tAdminToken)
}

type served struct {
	path   string
	base   string
	ipc    string
	ca     string
	logs   *safeBuffer
	stdout *safeBuffer
	done   chan int
	cancel context.CancelFunc
	client *http.Client
}

// startServed runs serve() like `aldap run` with the API enabled.
func startServed(t *testing.T, apiExtra string) *served {
	t.Helper()
	t.Setenv("ALDAP_TEST_API_EVENTS", tEventsToken)
	dc := testdir.StartFixture(t)
	caDir := filepath.Join(t.TempDir(), "ca")
	port := freePort(t)
	path, _, _ := daemonConfig(t, dc, caDir, apiTOML(port, apiExtra))
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
	return s
}

func (s *served) do(t *testing.T, method, path, token, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, s.base+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func (s *served) events(t *testing.T, kind string) []events.Record {
	t.Helper()
	code, b := s.do(t, http.MethodGet, "/v1/events?limit=10000", tEventsToken, "")
	if code != http.StatusOK {
		t.Fatalf("events: %d %s", code, b)
	}
	var all []events.Record
	if err := json.Unmarshal(b, &all); err != nil {
		t.Fatal(err)
	}
	schematest.Check(t, all...)
	var out []events.Record
	for _, r := range all {
		if kind == "" || r.Event == kind {
			out = append(out, r)
		}
	}
	return out
}

// sseIDs reads n event ids from an SSE response.
func sseIDs(t *testing.T, resp *http.Response, n int) []uint64 {
	t.Helper()
	ids := make(chan uint64, n)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if v, ok := strings.CutPrefix(sc.Text(), "id: "); ok {
				id, _ := strconv.ParseUint(v, 10, 64)
				ids <- id
			}
		}
		close(ids)
	}()
	var out []uint64
	for len(out) < n {
		select {
		case id, ok := <-ids:
			if !ok {
				t.Fatalf("stream ended after %v", out)
			}
			out = append(out, id)
		case <-time.After(5 * time.Second):
			t.Fatalf("stream stalled after %v", out)
		}
	}
	return out
}

func (s *served) stream(t *testing.T, lastID string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, s.base+"/v1/events/stream?types=lock", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tEventsToken)
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream: %d", resp.StatusCode)
	}
	return resp
}

// TestStage7_SSEResume is TESTING.md 36 end to end: the client drops at
// seq N and reconnects with Last-Event-ID: N; it gets N+1… only.
func TestStage7_SSEResume(t *testing.T) {
	s := startServed(t, "")
	lock := func(ip string) {
		if code, b := s.do(t, http.MethodPost, "/v1/locks", tAdminToken, `{"target":"ip","key":"`+ip+`","duration":"1h"}`); code != http.StatusCreated {
			t.Fatalf("lock %s: %d %s", ip, code, b)
		}
	}
	lock("192.0.2.1")
	lock("192.0.2.2")
	resp := s.stream(t, "")
	first := sseIDs(t, resp, 2)
	_ = resp.Body.Close()
	lock("192.0.2.3") // while disconnected
	resp = s.stream(t, strconv.FormatUint(first[1], 10))
	defer resp.Body.Close()
	lock("192.0.2.4") // live
	next := sseIDs(t, resp, 2)
	locks := s.events(t, events.Lock)
	if len(locks) != 4 || next[0] != locks[2].Seq || next[1] != locks[3].Seq || first[0] != locks[0].Seq || next[0] <= first[1] {
		t.Fatalf("first %v, next %v, lock seqs %v", first, next, []uint64{locks[0].Seq, locks[1].Seq, locks[2].Seq, locks[3].Seq})
	}
}

// TestStage7_ScopesAndAudit is TESTING.md 37 end to end.
func TestStage7_ScopesAndAudit(t *testing.T) {
	s := startServed(t, "")
	if code, _ := s.do(t, http.MethodPost, "/v1/locks", tEventsToken, `{"target":"account","key":"jdoe"}`); code != http.StatusForbidden {
		t.Errorf("events:read on POST /v1/locks: %d", code)
	}
	if code, b := s.do(t, http.MethodPost, "/v1/locks", tAdminToken, `{"target":"account","key":"jdoe","reason":"test"}`); code != http.StatusCreated {
		t.Fatalf("admin: %d %s", code, b)
	}
	calls := s.events(t, events.APICall)
	if len(calls) != 2 || calls[0].Data["token_name"] != "siem" || calls[0].Data["status"] != float64(403) ||
		calls[1].Data["token_name"] != "ops" || calls[1].Data["status"] != float64(201) || calls[1].Data["client_ip"] != "127.0.0.1" {
		t.Errorf("api_call = %+v", calls)
	}
	// Status, readiness, metrics and the masked configuration.
	if code, b := s.do(t, http.MethodGet, "/v1/status", tAdminToken, ""); code != http.StatusOK || !strings.Contains(string(b), `"locks_active":1`) {
		t.Errorf("status: %d %s", code, b)
	}
	waitFor(t, func() bool { code, _ := s.do(t, http.MethodGet, "/readyz", "", ""); return code == http.StatusOK })
	if code, b := s.do(t, http.MethodGet, "/metrics", tAdminToken, ""); code != http.StatusOK || !strings.Contains(string(b), "aldap_build_info") {
		t.Errorf("metrics: %d", code)
	}
	if code, _ := s.do(t, http.MethodGet, "/metrics", tEventsToken, ""); code != http.StatusForbidden {
		t.Errorf("metrics with events:read: %d", code)
	}
	code, b := s.do(t, http.MethodGet, "/v1/config", tAdminToken, "")
	if code != http.StatusOK || !strings.Contains(string(b), `token = "***"`) || strings.Contains(string(b), "S3CR3T") {
		t.Errorf("config get: %d\n%s", code, b)
	}
	code, b = s.do(t, http.MethodPost, "/v1/profiles/virola/test", tAdminToken, `{"base":"ou=users,ou=virola,dc=aldap","filter":"(sAMAccountName=alice.adams)","attrs":["mail"]}`)
	if code != http.StatusOK || !strings.Contains(string(b), "cn=alice.adams,ou=users,ou=virola,dc=aldap") {
		t.Errorf("profile test: %d %s", code, b)
	}
	if code, _ := s.do(t, http.MethodPost, "/v1/profiles/virola/sync", tAdminToken, ""); code != http.StatusConflict {
		t.Errorf("sync of a non-replica: %d", code)
	}
	if code, _ := s.do(t, http.MethodPost, "/v1/baseline/plain/learn", tAdminToken, `{"duration":"1s"}`); code != http.StatusAccepted {
		t.Errorf("learn: %d", code)
	}
	if code, b := s.do(t, http.MethodGet, "/v1/profiles", tAdminToken, ""); code != http.StatusOK || !strings.Contains(string(b), `"name":"plain"`) || strings.Contains(string(b), "S3CR3T") {
		t.Errorf("profiles: %d %s", code, b)
	}
	if code, _ := s.do(t, http.MethodGet, "/v1/upstreams", tAdminToken, ""); code != http.StatusOK {
		t.Errorf("upstreams: %d", code)
	}
	if strings.Contains(s.logs.String(), "S3CR3T") || strings.Contains(s.stdout.String(), "S3CR3T") {
		t.Fatal("secret in daemon output")
	}
}

func backups(t *testing.T, path string) []string {
	t.Helper()
	m, err := filepath.Glob(path + ".bak.*")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestStage7_PutConfig is TESTING.md 38: an invalid configuration is
// refused with the file untouched; a valid one is backed up, written and
// reloaded; a configuration that fails to start is rolled back.
func TestStage7_PutConfig(t *testing.T) {
	s := startServed(t, "")
	orig, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"[server\nlog_level = ", "[server]\nlog_level = \"loud\"\n", "[server]\nlog_levl = \"info\"\n"} {
		code, b := s.do(t, http.MethodPut, "/v1/config", tAdminToken, bad)
		if code != http.StatusBadRequest || !strings.Contains(string(b), "invalid_config") {
			t.Errorf("invalid %q: %d %s", bad, code, b)
		}
	}
	if now, _ := os.ReadFile(s.path); !bytes.Equal(now, orig) || len(backups(t, s.path)) != 0 {
		t.Fatal("invalid configuration touched the file")
	}
	if n := len(s.events(t, events.ConfigReload)); n != 0 {
		t.Errorf("reload attempted for an invalid body: %d", n)
	}
	// Valid: log level changes, everything else is kept.
	valid := strings.Replace(string(orig), `log_level = "debug"`, `log_level = "info"`, 1)
	code, b := s.do(t, http.MethodPut, "/v1/config", tAdminToken, valid)
	if code != http.StatusOK {
		t.Fatalf("valid: %d %s\n%s", code, b, s.logs.String())
	}
	var res struct {
		OK     bool   `json:"ok"`
		Backup string `json:"backup"`
	}
	if err := json.Unmarshal(b, &res); err != nil || !res.OK {
		t.Fatalf("result %s: %v", b, err)
	}
	if bak, err := os.ReadFile(res.Backup); err != nil || !bytes.Equal(bak, orig) {
		t.Errorf("backup %s: %v", res.Backup, err)
	}
	if fi, err := os.Stat(res.Backup); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("backup mode: %v %v", fi.Mode(), err)
	}
	if now, _ := os.ReadFile(s.path); string(now) != valid {
		t.Error("new configuration not written")
	}
	if rel := s.events(t, events.ConfigReload); len(rel) != 1 || rel[0].Data["ok"] != true {
		t.Errorf("config_reload = %+v", rel)
	}
	// Valid but cannot start (listen port busy): restored, old one serving.
	busy, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	_, busyPort, _ := net.SplitHostPort(busy.Addr().String())
	conflict := valid + fmt.Sprintf("\n[profile.extra]\nlisten = [\"127.0.0.1:%s\"]\ntransport = \"ldap\"\nmode = \"honeypot\"\nvirtual_base = \"dc=extra\"\n", busyPort)
	code, b = s.do(t, http.MethodPut, "/v1/config", tAdminToken, conflict)
	if code != http.StatusInternalServerError || !strings.Contains(string(b), "previous file restored") {
		t.Errorf("start failure: %d %s", code, b)
	}
	if now, _ := os.ReadFile(s.path); string(now) != valid {
		t.Errorf("file not rolled back:\n%s", now)
	}
	if n := len(backups(t, s.path)); n != 2 {
		t.Errorf("backups: %d", n)
	}
	if code, _ := s.do(t, http.MethodGet, "/v1/profiles", tAdminToken, ""); code != http.StatusOK {
		t.Errorf("api after rollback: %d", code)
	}
	if code, b := s.do(t, http.MethodGet, "/v1/profiles", tAdminToken, ""); code != http.StatusOK || strings.Contains(string(b), `"extra"`) {
		t.Errorf("failed profile is served: %s", b)
	}
	// POST /v1/reload with the restored file succeeds.
	if code, b := s.do(t, http.MethodPost, "/v1/reload", tAdminToken, ""); code != http.StatusOK {
		t.Errorf("reload: %d %s", code, b)
	}
}

// TestStage7_IPCAndTCPWithoutToken is TESTING.md 40 (aldapctl uses the
// same HTTP calls): unlock over the IPC socket needs no token; the same
// call over TCP without a token is 401.
func TestStage7_IPCAndTCPWithoutToken(t *testing.T) {
	s := startServed(t, "")
	if code, b := s.do(t, http.MethodPost, "/v1/locks", tAdminToken, `{"target":"account","key":"jdoe"}`); code != http.StatusCreated {
		t.Fatalf("lock: %d %s", code, b)
	}
	if code, _ := s.do(t, http.MethodDelete, "/v1/locks/account/jdoe", "", ""); code != http.StatusUnauthorized {
		t.Errorf("tcp without token: %d", code)
	}
	if fi, err := os.Stat(s.ipc); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("ipc socket: %v %v", fi, err)
	}
	ipc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", s.ipc)
	}}}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodDelete, "http://aldap/v1/locks/account/jdoe", nil)
	resp, err := ipc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("ipc unlock: %d", resp.StatusCode)
	}
	unlocks := s.events(t, events.Unlock)
	if len(unlocks) != 1 || unlocks[0].Data["source"] != "api" {
		t.Errorf("unlock = %+v", unlocks)
	}
	calls := s.events(t, events.APICall)
	if last := calls[len(calls)-1]; last.Data["token_name"] != "ipc" || last.Data["client_ip"] != "local" {
		t.Errorf("ipc audit = %+v", last)
	}
}

// TestStage7_TLS covers the API transport rule: beyond loopback without TLS
// the daemon refuses to start; with tls.builtin the API serves HTTPS from
// the built-in CA.
func TestStage7_TLS(t *testing.T) {
	t.Setenv("ALDAP_TEST_API_EVENTS", tEventsToken)
	dc := testdir.StartFixture(t)
	caDir := filepath.Join(t.TempDir(), "ca")
	path, _, _ := daemonConfig(t, dc, caDir, strings.Replace(apiTOML(freePort(t), ""), `listen = "127.0.0.1:`, `listen = "0.0.0.0:`, 1))
	logs := &safeBuffer{}
	opts := daemonOptions{LogOut: logs, EventsOut: io.Discard, Secrets: secret.Default, Argon2: fastArgon, NoPersistCerts: true}
	if code := serve(context.Background(), path, true, opts, make(chan os.Signal), &safeBuffer{}); code != 1 || !strings.Contains(logs.String(), "TLS is mandatory") {
		t.Fatalf("plain API on 0.0.0.0: exit %d\n%s", code, logs.String())
	}
	s := startServed(t, "[api.tls]\nbuiltin = true\n")
	pem, err := os.ReadFile(filepath.Join(s.ca, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	s.client = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	s.base = strings.Replace(s.base, "http://", "https://", 1)
	if code, b := s.do(t, http.MethodGet, "/v1/status", tAdminToken, ""); code != http.StatusOK {
		t.Errorf("https status: %d %s", code, b)
	}
}
