package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alstdev/aldap/internal/api"
	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/ids"
	"github.com/alstdev/aldap/internal/listener"
	"github.com/alstdev/aldap/internal/metrics"
	"github.com/alstdev/aldap/internal/ratelimit"
	"github.com/alstdev/aldap/internal/secret"
	"github.com/alstdev/aldap/internal/upstream"
	"github.com/alstdev/aldap/internal/vdir"
)

// Secrets the backend leaks on purpose: the bundle must not carry them.
const (
	leakBindPW     = "S3CR3T-bind-password-ad"
	leakWebhookKey = "S3CR3T-webhook-hmac"
	leakHeader     = "S3CR3T-header-bearer"
	leakHash       = "$argon2id$v=19$m=65536,t=3,p=2$S3CR3T"
	leakFilterPW   = "S3CR3T-in-filter"
)

// realBackend implements api.Backend for the contract tests.
type realBackend struct {
	mu      sync.Mutex
	config  string
	applied []string
	dry     []string
	synced  []string
}

func (b *realBackend) Profiles() []api.ProfileInfo {
	return []api.ProfileInfo{{Name: "virola", Mode: "proxy", Transport: "ldaps", Listen: []string{":636"}, Upstream: "ad", VirtualBase: "dc=aldap", Bases: []string{"DC=corp"}, Cache: "replica"}}
}

func (b *realBackend) Upstreams() map[string][]upstream.ServerStatus {
	return map[string][]upstream.ServerStatus{"ad": {{URL: "ldaps://dc1:636", State: upstream.StateUp, P50: 2 * time.Millisecond, P95: 4 * time.Millisecond, IdleConns: 1}}}
}

func (b *realBackend) Ready() bool { return true }

func (b *realBackend) Test(_ context.Context, profile string, req vdir.TestRequest) (vdir.TestResult, error) {
	if profile != "virola" {
		return vdir.TestResult{}, fmt.Errorf("profile %q: %w", profile, api.ErrNotFound)
	}
	return vdir.TestResult{Entries: []listener.Entry{{DN: "uid=jdoe,dc=aldap"}}, UpstreamFilter: req.Filter, UpstreamQueries: 1}, nil
}

func (b *realBackend) ConfigTOML() ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return []byte(b.config), nil
}

func (b *realBackend) ApplyConfig(_ context.Context, body []byte) (api.ApplyResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if strings.Contains(string(body), "loud") {
		return api.ApplyResult{}, fmt.Errorf("%w:\nserver.log_level: not one of", api.ErrInvalidConfig)
	}
	b.applied = append(b.applied, string(body))
	return api.ApplyResult{Backup: "/etc/aldap/aldap.toml.bak.1"}, nil
}

func (b *realBackend) ValidateConfig(_ context.Context, body []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if strings.Contains(string(body), "loud") {
		return fmt.Errorf("%w:\nserver.log_level: not one of", api.ErrInvalidConfig)
	}
	b.dry = append(b.dry, string(body))
	return nil
}

func (b *realBackend) Reload(context.Context) error { return nil }

func (b *realBackend) Sync(_ context.Context, profile string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.synced = append(b.synced, profile)
	return nil
}

func (b *realBackend) Record(context.Context, string, bool) error {
	return fmt.Errorf("request recording: %w", api.ErrNotImplemented)
}

// realAPI is internal/api serving the IPC socket and a loopback TCP port.
type realAPI struct {
	srv    *api.Server
	bus    *events.Bus
	lim    *ratelimit.Limiter
	be     *realBackend
	socket string
	url    string
}

func newRealAPI(t *testing.T) *realAPI {
	t.Helper()
	log := slog.New(slog.DiscardHandler)
	bus := events.NewBus(events.Options{Host: "h", BufferSize: 20000, Logger: log})
	lim := ratelimit.New(ratelimit.Options{Events: bus, Logger: log, Salt: []byte("s")})
	eng := ids.New(config.Default().Intrusion, ids.Options{Events: bus, Logger: log})
	be := &realBackend{config: "[server]\nlog_level = \"info\"\n\n[upstream.ad]\nservers = [\"ldaps://dc1:636\"]\nbind_password = \"" + leakBindPW + "\"\n\n" +
		"[profile.virola.client_bind]\ndn = \"cn=app\"\npassword_hash = \"" + leakHash + "\"\n\n" +
		"[[notify.channel]]\nname = \"hook\"\ntype = \"webhook\"\nhmac_secret = \"" + leakWebhookKey + "\"\nhmac_secret_file = \"/etc/aldap/hmac\"\n" +
		"[notify.channel.headers]\nAuthorization = \"Bearer " + leakHeader + "\"\n"}
	srv := api.New(api.Options{Backend: be, Bus: bus, Limiter: lim, IDs: eng, Metrics: metrics.New("v1.4.0", "c", "d"), Logger: log, Version: "v1.4.0", Heartbeat: 50 * time.Millisecond})
	a := config.Default().API
	a.Enabled, a.RateLimitRPS = true, 0
	a.Metrics.Enabled = true
	a.Tokens = []config.APIToken{{Name: "ops", Token: secret.Inline(testToken), Scopes: []string{"admin"}}}
	if err := srv.Configure(a, secret.Default); err != nil {
		t.Fatal(err)
	}
	r := &realAPI{srv: srv, bus: bus, lim: lim, be: be}
	if runtime.GOOS != "windows" {
		dir, err := os.MkdirTemp("", "actl")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		r.socket = filepath.Join(dir, "aldap.sock")
		ln, err := api.ListenIPC(r.socket)
		if err != nil {
			t.Fatal(err)
		}
		if err := srv.ServeIPC(ln); err != nil {
			t.Fatal(err)
		}
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.ServeAPI(ln, nil); err != nil {
		t.Fatal(err)
	}
	r.url = "http://" + ln.Addr().String()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	})
	return r
}

func (r *realAPI) emitSample() {
	r.bus.Emit(events.Event{Event: events.BindFail, Level: events.LevelMedium, Profile: "virola", ClientIP: "192.0.2.10", Account: "jdoe", Reason: "invalid_credentials"})
	r.bus.Emit(events.Event{Event: events.Search, Level: events.LevelLow, Profile: "virola", ClientIP: "192.0.2.10",
		Data: map[string]any{"filter": "(&(uid=jdoe)(userPassword=" + leakFilterPW + "))", "entries": 0}})
	r.bus.Flush()
}

// conns are the two transports of every contract test.
func (r *realAPI) conns(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{"tcp": {"--url", r.url, "--token-file", tokenFile(t)}}
	if r.socket != "" {
		out["ipc"] = []string{"--socket", r.socket}
	}
	return out
}

// TestContract_RealAPI runs the CLI against internal/api over IPC (no
// token) and TCP (token file): the views decode what the API sends.
func TestContract_RealAPI(t *testing.T) {
	r := newRealAPI(t)
	r.emitSample()
	cfg := filepath.Join(t.TempDir(), "new.toml")
	if err := os.WriteFile(cfg, []byte("[server]\nlog_level = \"warn\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(t.TempDir(), "bad.toml")
	if err := os.WriteFile(bad, []byte("[server]\nlog_level = \"loud\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, conn := range r.conns(t) {
		t.Run(name, func(t *testing.T) {
			run := func(want int, args ...string) string {
				t.Helper()
				res := runApp(t, "", false, append(append([]string{}, conn...), args...)...)
				if res.code != want {
					t.Fatalf("%v: exit %d (want %d) stderr %s", args, res.code, want, res.stderr)
				}
				return res.stdout + res.stderr
			}
			for _, want := range []string{"aldap v1.4.0 (go1.", "profiles: virola", "ldaps://dc1:636"} {
				if out := run(0, "status"); !strings.Contains(out, want) {
					t.Errorf("status lacks %q:\n%s", want, out)
				}
			}
			if out := run(0, "upstreams"); !strings.Contains(out, "2ms") {
				t.Errorf("upstreams: %s", out)
			}
			if out := run(0, "profiles"); !strings.Contains(out, "replica") {
				t.Errorf("profiles: %s", out)
			}
			run(0, "lock", "198.51.100.7", "--for", "1h", "--reason", "contract", "--yes")
			if out := run(0, "locks"); !strings.Contains(out, "198.51.100.7") || !strings.Contains(out, "contract") {
				t.Errorf("locks: %s", out)
			}
			run(0, "unlock", "198.51.100.7", "--yes")
			if out := run(exitError, "unlock", "198.51.100.7", "--yes"); !strings.Contains(out, "no active lock") {
				t.Errorf("second unlock: %s", out)
			}
			run(0, "lockdown", "on", "--yes")
			if on, _ := r.lim.Lockdown(); !on {
				t.Error("lockdown not on")
			}
			run(0, "lockdown", "off", "--yes")
			if out := run(0, "events", "--types", "bind_fail"); !strings.Contains(out, "bind_fail") || strings.Contains(out, " search ") {
				t.Errorf("events: %s", out)
			}
			run(0, "indicators")
			run(0, "indicators", "--format", "stix-lite")
			if out := run(0, "config", "get"); !strings.Contains(out, "[server]") {
				t.Errorf("config get: %s", out)
			}
			run(0, "config", "validate", cfg)
			if out := run(exitError, "config", "validate", bad); !strings.Contains(out, "invalid_config") {
				t.Errorf("invalid config: %s", out)
			}
			run(0, "config", "set", cfg, "--yes")
			run(0, "reload", "--yes")
			run(0, "sync", "virola", "--yes")
			run(0, "baseline", "learn", "virola", "--for", "1h", "--yes")
			if out := run(0, "test", "virola", "--filter", "(uid=jdoe)"); !strings.Contains(out, "uid=jdoe,dc=aldap") {
				t.Errorf("test: %s", out)
			}
			if out := run(exitError, "test", "nope", "--filter", "(uid=jdoe)"); !strings.Contains(out, "not_found") {
				t.Errorf("test unknown profile: %s", out)
			}
			if out := run(exitError, "record", "start", "virola", "--yes"); !strings.Contains(out, "HTTP 501") {
				t.Errorf("record: %s", out)
			}
		})
	}
	if len(r.be.applied) != len(r.conns(t)) || len(r.be.synced) != len(r.conns(t)) {
		t.Errorf("applied %d synced %d", len(r.be.applied), len(r.be.synced))
	}
	// api_call audits name the IPC caller "ipc" and the TCP token "ops".
	var names []string
	for _, rec := range r.bus.Since(0, 0) {
		if rec.Event == events.APICall {
			names = append(names, fmt.Sprint(rec.Data["token_name"]))
		}
	}
	if !strings.Contains(strings.Join(names, ","), "ops") {
		t.Errorf("api_call token names: %v", names)
	}
}

func TestContract_FollowEvents(t *testing.T) {
	r := newRealAPI(t)
	r.emitSample()
	c, err := newClient(connOpts{url: r.url, tokenFile: tokenFile(t)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var got []events.Record
	done := errors.New("done")
	go func() {
		time.Sleep(100 * time.Millisecond)
		r.bus.Emit(events.Event{Event: events.Lockdown, Level: events.LevelHigh, Data: map[string]any{"state": "on"}})
	}()
	err = c.Stream(ctx, 1, nil, func(rec events.Record) error {
		got = append(got, rec)
		if rec.Event == events.Lockdown {
			return done
		}
		return nil
	}, nil)
	if !errors.Is(err, done) || len(got) != 2 || got[0].Seq != 2 {
		t.Fatalf("stream: %v %+v", err, got)
	}
}

// readBundle returns the members of a bundle archive.
func readBundle(t *testing.T, path string) map[string]string {
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
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Mode != 0o600 {
			t.Errorf("%s mode %o", h.Name, h.Mode)
		}
		b, _ := io.ReadAll(tr)
		out[strings.TrimPrefix(h.Name, "aldap-bundle/")] = string(b)
	}
	return out
}

// TestNoSecretsInOutput_Bundle: the bundle carries the configuration,
// events, versions, health and metrics, but no secret — even when the
// daemon's rendering leaks one, and never the token aldapctl used.
func TestNoSecretsInOutput_Bundle(t *testing.T) {
	r := newRealAPI(t)
	r.emitSample()
	for name, conn := range r.conns(t) {
		t.Run(name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "aldap-bundle.tgz")
			res := runApp(t, "", false, append(append([]string{}, conn...), "bundle", "--out", out)...)
			if res.code != 0 {
				t.Fatalf("bundle: %+v", res)
			}
			files := readBundle(t, out)
			for _, want := range []string{"manifest.json", "version.json", "health.json", "status.json", "upstreams.json", "profiles.json", "config.toml", "events.jsonl", "metrics.txt"} {
				if _, ok := files[want]; !ok {
					t.Errorf("bundle lacks %s (has %v)", want, files["manifest.json"])
				}
			}
			all := res.stdout + res.stderr
			for _, data := range files {
				all += data
			}
			for _, s := range []string{leakBindPW, leakWebhookKey, leakHeader, leakHash, leakFilterPW, testToken} {
				if strings.Contains(all, s) {
					t.Errorf("secret %q in the bundle or the output", s)
				}
			}
			for file, want := range map[string]string{
				"config.toml":  "/etc/aldap/hmac",
				"events.jsonl": "bind_fail",
				"version.json": "aldap_go",
				"health.json":  "ready",
				"metrics.txt":  "aldap_",
			} {
				if !strings.Contains(files[file], want) {
					t.Errorf("%s lacks %q:\n%s", file, want, files[file])
				}
			}
			if strings.Count(files["config.toml"], secret.Redacted) < 4 {
				t.Errorf("config.toml not masked:\n%s", files["config.toml"])
			}
			if res := runApp(t, "", false, append(append([]string{}, conn...), "bundle", "--out", out)...); res.code != exitError || !strings.Contains(res.stderr, "--force") {
				t.Errorf("overwrite: %+v", res)
			}
		})
	}
}

func TestBundle_Redact(t *testing.T) {
	for _, k := range []string{"bind_password", "password", "token", "bot_token", "hmac_secret", "password_hash", "Authorization_token"} {
		if !isSecretKey(k) {
			t.Errorf("%s not secret", k)
		}
	}
	for _, k := range []string{"bind_password_file", "token_env", "token_name", "account_hash", "same_password_hash_file", "key"} {
		if isSecretKey(k) {
			t.Errorf("%s secret", k)
		}
	}
	if _, err := redactTOML("[server"); err == nil {
		t.Error("broken TOML accepted")
	}
	got, err := redactJSON([]byte(`{"data":{"password":"x","list":[{"token":"y"}],"n":1}}`))
	if err != nil || strings.Contains(string(got), `"x"`) || strings.Contains(string(got), `"y"`) {
		t.Errorf("%s %v", got, err)
	}
	if string(scrub([]byte("a "+testToken), testToken)) != "a ***" {
		t.Error("scrub")
	}
}

func TestClient_Transport(t *testing.T) {
	tok := tokenFile(t)
	for _, tc := range []struct {
		name string
		o    connOpts
		msg  string
	}{
		{"http_remote", connOpts{url: "http://192.0.2.1:8636", tokenFile: tok}, "plain http is allowed on loopback only"},
		{"scheme", connOpts{url: "ftp://127.0.0.1", tokenFile: tok}, "scheme must be https"},
		{"path", connOpts{url: "https://h:8636/v1", tokenFile: tok}, "without path"},
		{"userinfo", connOpts{url: "https://u:p@h:8636", tokenFile: tok}, "without path, query or credentials"},
		{"no_token", connOpts{url: "https://h:8636"}, "--url requires --token-file"},
		{"both", connOpts{url: "https://h:8636", socket: "/s", tokenFile: tok}, "mutually exclusive"},
		{"token_without_url", connOpts{socket: "/s", tokenFile: tok}, "need --url"},
		{"missing_token", connOpts{url: "https://h:8636", tokenFile: filepath.Join(t.TempDir(), "none")}, "--token-file"},
		{"bad_ca", connOpts{url: "https://h:8636", tokenFile: tok, caFile: tok}, "no PEM certificate"},
		{"cert_without_key", connOpts{url: "https://h:8636", tokenFile: tok, clientCert: tok}, "go together"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newClient(tc.o); err == nil || !strings.Contains(err.Error(), tc.msg) {
				t.Errorf("err %v, want %q", err, tc.msg)
			}
		})
	}
	if runtime.GOOS != "windows" {
		loose := filepath.Join(t.TempDir(), "loose")
		_ = os.WriteFile(loose, []byte(testToken), 0o644)
		var warned []string
		if _, err := newClient(connOpts{url: "https://h:8636", tokenFile: loose, warn: func(m string) { warned = append(warned, m) }}); err != nil || len(warned) != 1 || strings.Contains(warned[0], testToken) {
			t.Errorf("loose token file: %v %v", err, warned)
		}
	}
	empty := filepath.Join(t.TempDir(), "empty")
	_ = os.WriteFile(empty, []byte("\n"), 0o600)
	if _, err := newClient(connOpts{url: "https://h:8636", tokenFile: empty}); err == nil {
		t.Error("empty token accepted")
	}
	for _, u := range []string{"http://127.0.0.1:8636", "http://[::1]:8636", "http://localhost:8636", "https://aldap.corp.example:8636"} {
		if _, err := newClient(connOpts{url: u, tokenFile: tok}); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
}

// TestClient_NoRedirect keeps the token from following a redirect.
func TestClient_NoRedirect(t *testing.T) {
	var leaked bool
	target := http.NewServeMux()
	target.HandleFunc("/", func(_ http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") != "" })
	ln2, _ := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	go func() { _ = http.Serve(ln2, target) }()
	defer ln2.Close()
	ln, _ := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	go func() {
		_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://"+ln2.Addr().String()+"/v1/status", http.StatusFound)
		}))
	}()
	defer ln.Close()
	c, err := newClient(connOpts{url: "http://" + ln.Addr().String(), tokenFile: tokenFile(t)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Status(context.Background()); err == nil {
		t.Error("redirect answer accepted")
	}
	if leaked {
		t.Error("token sent to the redirect target")
	}
}
