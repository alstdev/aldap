package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/events/schematest"
	"github.com/alstdev/aldap/internal/ids"
	"github.com/alstdev/aldap/internal/listener"
	"github.com/alstdev/aldap/internal/metrics"
	"github.com/alstdev/aldap/internal/ratelimit"
	"github.com/alstdev/aldap/internal/secret"
	"github.com/alstdev/aldap/internal/upstream"
	"github.com/alstdev/aldap/internal/vdir"
)

// Test tokens: 32+ bytes, one per scope plus admin.
const (
	tokAdmin   = "S3CR3T-admin-0123456789abcdef0123456789"
	tokEvents  = "S3CR3T-events-0123456789abcdef012345678"
	tokLocksR  = "S3CR3T-locksr-0123456789abcdef012345678"
	tokLocksW  = "S3CR3T-locksw-0123456789abcdef012345678"
	tokStatus  = "S3CR3T-status-0123456789abcdef012345678"
	tokNetOnly = "S3CR3T-netonly-0123456789abcdef01234567"
)

var tokenOf = map[string]string{
	ScopeAdmin: tokAdmin, ScopeEventsRead: tokEvents, ScopeLocksRead: tokLocksR, ScopeLocksWrite: tokLocksW, ScopeStatusRead: tokStatus,
}

type fakeBackend struct {
	mu        sync.Mutex
	ready     bool
	applied   [][]byte
	applyErr  error
	reloadErr error
	reloads   int
	syncErr   error
	validated [][]byte
	recordErr error
	records   []string
	testErr   error
	testReq   vdir.TestRequest
}

func (f *fakeBackend) Profiles() []ProfileInfo {
	return []ProfileInfo{{Name: "virola", Mode: "proxy", Transport: "ldaps", Listen: []string{":636"}, Upstream: "ad", VirtualBase: "dc=aldap", Bases: []string{"DC=x"}, Cache: "none"}}
}

func (f *fakeBackend) Upstreams() map[string][]upstream.ServerStatus {
	return map[string][]upstream.ServerStatus{"ad": {{URL: "ldaps://dc1:636", State: upstream.StateUp, P50: 2 * time.Millisecond, P95: 5 * time.Millisecond}}}
}

func (f *fakeBackend) Ready() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ready
}

func (f *fakeBackend) Test(_ context.Context, profile string, req vdir.TestRequest) (vdir.TestResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.testReq = req
	if profile != "virola" {
		return vdir.TestResult{}, fmt.Errorf("profile %q: %w", profile, ErrNotFound)
	}
	if f.testErr != nil {
		return vdir.TestResult{}, f.testErr
	}
	return vdir.TestResult{Entries: []listener.Entry{{DN: "cn=a,dc=aldap", Attrs: []listener.Attribute{{Name: "mail", Values: []string{"a@x"}}}}},
		DeniedTerms: []string{"telephoneNumber"}, UpstreamFilter: "(sAMAccountName=a)", UpstreamQueries: 1, Duration: time.Millisecond}, nil
}

func (f *fakeBackend) ConfigTOML() ([]byte, error) { return []byte("[api]\nenabled = true\n"), nil }

func (f *fakeBackend) ApplyConfig(_ context.Context, body []byte) (ApplyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.applyErr != nil {
		return ApplyResult{}, f.applyErr
	}
	f.applied = append(f.applied, body)
	return ApplyResult{Backup: "/etc/aldap/aldap.toml.bak.1"}, nil
}

func (f *fakeBackend) ValidateConfig(_ context.Context, body []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.applyErr != nil {
		return f.applyErr
	}
	f.validated = append(f.validated, body)
	return nil
}

func (f *fakeBackend) Record(_ context.Context, profile string, on bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if profile != "virola" {
		return fmt.Errorf("profile %q: %w", profile, ErrNotFound)
	}
	if f.recordErr != nil {
		return f.recordErr
	}
	f.records = append(f.records, fmt.Sprintf("%s:%v", profile, on))
	return nil
}

func (f *fakeBackend) Reload(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reloads++
	return f.reloadErr
}

func (f *fakeBackend) Sync(_ context.Context, profile string) error {
	if profile != "virola" {
		return ErrNotFound
	}
	return f.syncErr
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type env struct {
	s   *Server
	bus *events.Bus
	lim *ratelimit.Limiter
	ids *ids.Engine
	be  *fakeBackend
	clk *clock
	api http.Handler
	ipc http.Handler
}

func apiConfig() config.API {
	a := config.Default().API
	a.Enabled = true
	a.RateLimitRPS = 0
	for _, sc := range []string{ScopeAdmin, ScopeEventsRead, ScopeLocksRead, ScopeLocksWrite, ScopeStatusRead} {
		a.Tokens = append(a.Tokens, config.APIToken{Name: "t-" + sc, Token: secret.Inline(tokenOf[sc]), Scopes: []string{sc}})
	}
	a.Tokens = append(a.Tokens, config.APIToken{Name: "netonly", Token: secret.Inline(tokNetOnly), Scopes: []string{ScopeAdmin}, AllowCIDRs: []string{"10.9.0.0/16"}})
	return a
}

func newEnv(t *testing.T, mod func(*config.API)) *env {
	t.Helper()
	return newEnvOpts(t, mod, 0)
}

func newEnvQueue(t *testing.T, queue int) *env {
	t.Helper()
	return newEnvOpts(t, nil, queue)
}

func newEnvOpts(t *testing.T, mod func(*config.API), queue int) *env {
	t.Helper()
	clk := &clock{t: time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)}
	log := slog.New(slog.DiscardHandler)
	bus := events.NewBus(events.Options{Host: "h", BufferSize: 1000, Now: clk.now, Logger: log})
	e := &env{bus: bus, be: &fakeBackend{ready: true}, clk: clk}
	e.lim = ratelimit.New(ratelimit.Options{Events: bus, Logger: log, Now: clk.now, Salt: []byte("s")})
	e.ids = ids.New(config.Default().Intrusion, ids.Options{Events: bus, Logger: log, Now: clk.now})
	e.s = New(Options{Backend: e.be, Bus: bus, Limiter: e.lim, IDs: e.ids, Metrics: metrics.New("v", "c", "d"), Logger: log, Version: "v1.2.3", Now: clk.now, Heartbeat: 20 * time.Millisecond, StreamQueue: queue})
	a := apiConfig()
	if mod != nil {
		mod(&a)
	}
	if err := e.s.Configure(a, secret.Default); err != nil {
		t.Fatal(err)
	}
	e.api, e.ipc = e.s.Handler(), e.s.IPCHandler()
	t.Cleanup(func() { e.s.Shutdown(context.Background()) })
	return e
}

func request(method, path, token, body string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	r.RemoteAddr = "192.0.2.10:40000"
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func (e *env) do(method, path, token, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	e.api.ServeHTTP(w, request(method, path, token, body))
	return w
}

func decode[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	return v
}

func (e *env) records(kind string) []events.Record {
	var out []events.Record
	for _, r := range e.bus.Since(0, 0) {
		if r.Event == kind {
			out = append(out, r)
		}
	}
	return out
}

// routeCall is a request that satisfies the validation of each route.
func routeCall(rt Route) (path, body string) {
	path = strings.NewReplacer("{target}", "ip", "{key}", "192.0.2.99", "{name}", "virola", "{profile}", "virola").Replace(rt.Path)
	switch rt.Path {
	case "/v1/locks":
		body = `{"target":"ip","key":"192.0.2.99"}`
	case "/v1/lockdown", "/v1/profiles/{name}/record":
		body = `{"state":"off"}`
	case "/v1/config":
		body = "[server]\n"
	case "/v1/profiles/{name}/test":
		body = `{"base":"dc=aldap","filter":"(cn=a)"}`
	}
	return path, body
}

// TestScopes_EveryRoute is TESTING.md 37 for every endpoint: a token
// without the scope gets 403, the scope itself and admin pass, no token 401.
func TestScopes_EveryRoute(t *testing.T) {
	e := newEnv(t, nil)
	e.be.ready = true
	for _, rt := range Routes() {
		t.Run(rt.Method+" "+rt.Path, func(t *testing.T) {
			path, body := routeCall(rt)
			if rt.Path == "/v1/events/stream" {
				return // covered by TestStream_*
			}
			if rt.Scope == ScopePublic {
				if w := e.do(rt.Method, path, "", body); w.Code >= 400 {
					t.Fatalf("public route: %d %s", w.Code, w.Body.String())
				}
				return
			}
			if w := e.do(rt.Method, path, "", body); w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") == "" {
				t.Errorf("no token: %d", w.Code)
			}
			if w := e.do(rt.Method, path, "S3CR3T-wrong-0123456789abcdef0123456789", body); w.Code != http.StatusUnauthorized {
				t.Errorf("wrong token: %d", w.Code)
			}
			want := rt.Scope
			if want == ScopeMetrics {
				want = ScopeStatusRead
			}
			for sc, tok := range tokenOf {
				w := e.do(rt.Method, path, tok, body)
				allowed := sc == want || sc == ScopeAdmin
				if allowed && (w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden) {
					t.Errorf("scope %s refused: %d %s", sc, w.Code, w.Body.String())
				}
				if !allowed {
					if w.Code != http.StatusForbidden {
						t.Errorf("scope %s: %d, want 403", sc, w.Code)
					} else if er := decode[apiError](t, w); er.Code != "insufficient_scope" {
						t.Errorf("scope %s: error %+v", sc, er)
					}
				}
				if sc == want && rt.Method != http.MethodGet {
					// Undo the lock so the next call creates it again.
					e.lim.Unlock("ip", "192.0.2.99", "api")
				}
			}
		})
	}
	schematest.Check(t, e.bus.Since(0, 0)...)
}

// TestAudit_APICall is the second half of TESTING.md 37: locks:write with
// an events:read token → 403 and an audit event; admin → 201 and api_call.
func TestAudit_APICall(t *testing.T) {
	e := newEnv(t, nil)
	if w := e.do("POST", "/v1/locks", tokEvents, `{"target":"ip","key":"192.0.2.7"}`); w.Code != http.StatusForbidden {
		t.Fatalf("events:read on POST /v1/locks: %d", w.Code)
	}
	if len(e.lim.Locks()) != 0 {
		t.Fatal("refused call locked anyway")
	}
	w := e.do("POST", "/v1/locks", tokAdmin, `{"target":"ip","key":"::ffff:192.0.2.7","duration":"1h","reason":"ticket 7"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("admin POST /v1/locks: %d %s", w.Code, w.Body.String())
	}
	l := decode[lock](t, w)
	if l.Key != "192.0.2.7" || l.Source != "api" || l.Reason != "ticket 7" || !l.Until.Equal(e.clk.now().Add(time.Hour)) {
		t.Errorf("lock = %+v", l)
	}
	calls := e.records(events.APICall)
	if len(calls) != 2 {
		t.Fatalf("api_call events: %d", len(calls))
	}
	if d := calls[0].Data; d["token_name"] != "t-events:read" || d["status"] != http.StatusForbidden || calls[0].Level != events.LevelMedium {
		t.Errorf("refused call audit: %+v", calls[0])
	}
	if d := calls[1].Data; d["method"] != "POST" || d["path"] != "/v1/locks" || d["token_name"] != "t-admin" || d["client_ip"] != "192.0.2.10" || d["status"] != http.StatusCreated {
		t.Errorf("api_call data = %v", d)
	}
	// Reads are not audited.
	e.do("GET", "/v1/locks", tokAdmin, "")
	if n := len(e.records(events.APICall)); n != 2 {
		t.Errorf("GET audited: %d", n)
	}
	for _, r := range e.bus.Since(0, 0) {
		if strings.Contains(string(r.JSON()), "S3CR3T") {
			t.Fatalf("token in event: %s", r.JSON())
		}
	}
	schematest.Check(t, e.bus.Since(0, 0)...)
}

func TestAuth_CIDRsRateLimitAndConfigure(t *testing.T) {
	e := newEnv(t, func(a *config.API) { a.RateLimitRPS = 2 })
	if w := e.do("GET", "/v1/status", tokNetOnly, ""); w.Code != http.StatusForbidden || decode[apiError](t, w).Code != "forbidden_source" {
		t.Errorf("allow_cidrs: %d %s", w.Code, w.Body.String())
	}
	r := request("GET", "/v1/status", tokNetOnly, "")
	r.RemoteAddr = "10.9.1.2:5000"
	w := httptest.NewRecorder()
	e.api.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("allowed source: %d", w.Code)
	}
	// 2 rps per client: the third request within the same instant is refused.
	e.do("GET", "/healthz", "", "")
	if w := e.do("GET", "/healthz", "", ""); w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Errorf("rate limit: %d", w.Code)
	}
	e.clk.add(time.Second)
	if w := e.do("GET", "/healthz", "", ""); w.Code != http.StatusOK {
		t.Errorf("after refill: %d", w.Code)
	}
	// Lower-case scheme, missing scheme.
	r = request("GET", "/v1/status", "", "")
	r.Header.Set("Authorization", "bearer "+tokStatus)
	w = httptest.NewRecorder()
	e.clk.add(time.Second)
	e.api.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("lower-case bearer: %d", w.Code)
	}
	r.Header.Set("Authorization", tokStatus)
	w = httptest.NewRecorder()
	e.api.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("token without scheme: %d", w.Code)
	}
	// Configure errors keep the previous tokens.
	short := apiConfig()
	short.Tokens = []config.APIToken{{Name: "s", Token: "short", Scopes: []string{ScopeAdmin}}}
	if err := e.s.Configure(short, secret.Default); err == nil || !strings.Contains(err.Error(), "at least 32 bytes") {
		t.Errorf("short token: %v", err)
	}
	missing := apiConfig()
	missing.Tokens = []config.APIToken{{Name: "m", TokenEnv: "ALDAP_TEST_API_TOKEN_UNSET", Scopes: []string{ScopeAdmin}}}
	if err := e.s.Configure(missing, secret.Default); err == nil {
		t.Error("missing token source accepted")
	}
	badNet := apiConfig()
	badNet.Tokens[0].AllowCIDRs = []string{"nope"}
	if err := e.s.Configure(badNet, secret.Default); err == nil {
		t.Error("bad CIDR accepted")
	}
	e.clk.add(time.Second)
	if w := e.do("GET", "/v1/status", tokStatus, ""); w.Code != http.StatusOK {
		t.Errorf("tokens lost after failed Configure: %d", w.Code)
	}
	// Tokens from a file are resolved too.
	t.Setenv("ALDAP_TEST_API_TOKEN", tokAdmin+"-env")
	env := apiConfig()
	env.Tokens = []config.APIToken{{Name: "env", TokenEnv: "ALDAP_TEST_API_TOKEN", Scopes: []string{ScopeStatusRead}}}
	if err := e.s.Configure(env, secret.Default); err != nil {
		t.Fatal(err)
	}
	if w := e.do("GET", "/v1/status", tokAdmin+"-env", ""); w.Code != http.StatusOK {
		t.Errorf("env token: %d", w.Code)
	}
	if w := e.do("GET", "/v1/status", tokAdmin, ""); w.Code != http.StatusUnauthorized {
		t.Errorf("removed token still accepted: %d", w.Code)
	}
}

func TestBuckets_Bounded(t *testing.T) {
	b := newBuckets(1)
	now := time.Now()
	for i := range maxBuckets + 5 {
		b.take(fmt.Sprintf("10.0.%d.%d", i/256, i%256), now)
	}
	if len(b.m) > maxBuckets {
		t.Errorf("table grew to %d", len(b.m))
	}
	b.take("x", now.Add(2*time.Second))
	b.mu.Lock()
	b.prune(now.Add(4 * time.Second))
	n := len(b.m)
	b.mu.Unlock()
	if n != 0 {
		t.Errorf("prune left %d", n)
	}
}

func TestEndpoints_StatusProfilesUpstreamsHealth(t *testing.T) {
	e := newEnv(t, nil)
	e.lim.LockIP("192.0.2.5", e.clk.now().Add(time.Minute), "ids")
	e.lim.SetLockdown(true, "api")
	e.clk.add(90 * time.Second)
	st := decode[status](t, e.do("GET", "/v1/status", tokStatus, ""))
	if st.Version != "v1.2.3" || st.UptimeS != 90 || !st.Lockdown || st.LocksActive != 0 || len(st.Profiles) != 1 || st.Upstreams["ad"][0].State != "up" ||
		st.Upstreams["ad"][0].LatencyP95MS != 5 || st.EventsSeq == 0 || !st.Learning {
		t.Errorf("status = %+v", st)
	}
	if ps := decode[[]ProfileInfo](t, e.do("GET", "/v1/profiles", tokStatus, "")); len(ps) != 1 || ps[0].Name != "virola" {
		t.Errorf("profiles = %+v", ps)
	}
	if us := decode[map[string][]map[string]any](t, e.do("GET", "/v1/upstreams", tokStatus, "")); us["ad"][0]["url"] != "ldaps://dc1:636" || us["ad"][0]["state"] != "up" {
		t.Errorf("upstreams = %+v", us)
	}
	if w := e.do("GET", "/healthz", "", ""); w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/json" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("healthz: %d %v", w.Code, w.Header())
	}
	if w := e.do("GET", "/readyz", "", ""); w.Code != http.StatusOK {
		t.Errorf("readyz: %d", w.Code)
	}
	e.be.mu.Lock()
	e.be.ready = false
	e.be.mu.Unlock()
	if w := e.do("GET", "/readyz", "", ""); w.Code != http.StatusServiceUnavailable || decode[apiError](t, w).Code != "not_ready" {
		t.Errorf("readyz not ready: %d", w.Code)
	}
	// Unknown path and wrong method are JSON errors.
	if w := e.do("GET", "/v2/nope", tokAdmin, ""); w.Code != http.StatusNotFound || decode[apiError](t, w).Code != "not_found" {
		t.Errorf("404: %d", w.Code)
	}
	if w := e.do("PATCH", "/v1/locks", tokAdmin, ""); w.Code != http.StatusMethodNotAllowed || !strings.Contains(w.Header().Get("Allow"), "POST") {
		t.Errorf("405: %d %v", w.Code, w.Header())
	}
	if w := e.do("PUT", "/v1/locks/ip/1.2.3.4", tokAdmin, ""); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("405 with params: %d", w.Code)
	}
}

func TestMetrics_ScopeAndPublic(t *testing.T) {
	e := newEnv(t, nil)
	if w := e.do("GET", "/metrics", "", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("metrics without token: %d", w.Code)
	}
	w := e.do("GET", "/metrics", tokStatus, "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "aldap_build_info") {
		t.Errorf("metrics: %d %s", w.Code, w.Body.String())
	}
	pub := newEnv(t, func(a *config.API) { a.Metrics.Public = true })
	if w := pub.do("GET", "/metrics", "", ""); w.Code != http.StatusOK {
		t.Errorf("public metrics: %d", w.Code)
	}
	off := newEnv(t, func(a *config.API) { a.Metrics.Enabled = false })
	if w := off.do("GET", "/metrics", tokAdmin, ""); w.Code != http.StatusNotFound {
		t.Errorf("disabled metrics: %d", w.Code)
	}
	none := New(Options{Backend: &fakeBackend{}, Logger: slog.New(slog.DiscardHandler)})
	if err := none.Configure(apiConfig(), secret.Default); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	none.Handler().ServeHTTP(w, request("GET", "/metrics", tokAdmin, ""))
	if w.Code != http.StatusNotFound {
		t.Errorf("nil registry: %d", w.Code)
	}
	// The metrics-only handler serves /metrics and health, nothing else.
	mh := e.s.MetricsHandler()
	for path, want := range map[string]int{"/metrics": http.StatusOK, "/healthz": http.StatusOK, "/v1/status": http.StatusNotFound} {
		w := httptest.NewRecorder()
		mh.ServeHTTP(w, request("GET", path, tokAdmin, ""))
		if w.Code != want {
			t.Errorf("metrics listener %s: %d", path, w.Code)
		}
	}
}

func TestLocks_CreateListDeleteLockdown(t *testing.T) {
	e := newEnv(t, nil)
	for _, body := range []string{
		`{"target":"host","key":"x"}`, `{"target":"ip","key":"not-an-ip"}`, `{"target":"account","key":""}`,
		`{"target":"ip","key":"192.0.2.1","duration":"-1m"}`, `{"target":"ip","key":"192.0.2.1","duration":"9000h"}`,
		`{"target":"ip","key":"192.0.2.1","extra":1}`, `not json`, `{"target":"account","key":"a","reason":"` + strings.Repeat("r", 600) + `"}`,
	} {
		if w := e.do("POST", "/v1/locks", tokLocksW, body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", body, w.Code)
		}
	}
	if w := e.do("POST", "/v1/locks", tokLocksW, `{"target":"account","key":"TEST\\JDoe"}`); w.Code != http.StatusCreated {
		t.Fatalf("account lock: %d %s", w.Code, w.Body.String())
	}
	ls := decode[[]lock](t, e.do("GET", "/v1/locks", tokLocksR, ""))
	if len(ls) != 1 || ls[0].Key != `test\jdoe` || !ls[0].Until.Equal(e.clk.now().Add(DefaultLockDuration)) {
		t.Fatalf("locks = %+v", ls)
	}
	if w := e.do("DELETE", "/v1/locks/account/TEST%5CJDoe", tokLocksW, ""); w.Code != http.StatusNoContent {
		t.Errorf("delete: %d %s", w.Code, w.Body.String())
	}
	if w := e.do("DELETE", "/v1/locks/account/TEST%5CJDoe", tokLocksW, ""); w.Code != http.StatusNotFound {
		t.Errorf("delete again: %d", w.Code)
	}
	if w := e.do("DELETE", "/v1/locks/host/x", tokLocksW, ""); w.Code != http.StatusBadRequest {
		t.Errorf("delete bad target: %d", w.Code)
	}
	// Full lock table → 503.
	full := ratelimit.New(ratelimit.Options{Events: e.bus, Logger: slog.New(slog.DiscardHandler), Now: e.clk.now, MaxEntries: 1})
	full.LockIP("192.0.2.200", e.clk.now().Add(time.Hour), "ids")
	e.s.o.Limiter = full
	if w := e.do("POST", "/v1/locks", tokLocksW, `{"target":"ip","key":"192.0.2.201"}`); w.Code != http.StatusServiceUnavailable {
		t.Errorf("full table: %d", w.Code)
	}
	e.s.o.Limiter = e.lim
	// Lockdown.
	for _, body := range []string{`{"state":"maybe"}`, `{}`, ``} {
		if w := e.do("POST", "/v1/lockdown", tokLocksW, body); w.Code != http.StatusBadRequest {
			t.Errorf("lockdown %q: %d", body, w.Code)
		}
	}
	w := e.do("POST", "/v1/lockdown", tokLocksW, `{"state":"on"}`)
	if got := decode[map[string]any](t, w); w.Code != http.StatusOK || got["lockdown"] != true || got["source"] != "api" {
		t.Errorf("lockdown on: %d %v", w.Code, got)
	}
	if on, _ := e.lim.Lockdown(); !on {
		t.Error("limiter not in lockdown")
	}
	e.do("POST", "/v1/lockdown", tokLocksW, `{"state":"off"}`)
	if on, _ := e.lim.Lockdown(); on {
		t.Error("lockdown not lifted")
	}
	if len(e.records(events.Lockdown)) != 2 || len(e.records(events.Unlock)) != 1 {
		t.Errorf("events: %d lockdown, %d unlock", len(e.records(events.Lockdown)), len(e.records(events.Unlock)))
	}
	schematest.Check(t, e.bus.Since(0, 0)...)
}

func TestIndicators_Formats(t *testing.T) {
	e := newEnv(t, nil)
	e.ids.Note(events.Event{Event: events.Honeytoken, ClientIP: "192.0.2.66", Account: "h.trap"})
	e.ids.Note(events.Event{Event: events.OpDenied, ClientIP: "2001:db8::1"})
	e.lim.LockIP("192.0.2.66", e.clk.now().Add(time.Hour), "honeytoken")
	list := decode[[]indicator](t, e.do("GET", "/v1/indicators", tokLocksR, ""))
	if len(list) != 3 || list[0].Key != "h.trap" || list[0].Locked || list[1].Key != "192.0.2.66" || list[1].Score != 100 || !list[1].Locked ||
		list[1].Reasons[0] != "honeytoken" || list[2].Target != "ip" || list[2].Score != 2 || list[2].Locked {
		t.Fatalf("json = %+v", list)
	}
	if l := decode[[]indicator](t, e.do("GET", "/v1/indicators?format=json&min_score=50", tokLocksR, "")); len(l) != 2 {
		t.Errorf("min_score: %+v", l)
	}
	w := e.do("GET", "/v1/indicators?format=plain", tokLocksR, "")
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") ||
		!strings.Contains(w.Body.String(), "ip\t192.0.2.66\t100.00\thoneytoken\ttrue\n") || !strings.Contains(w.Body.String(), "account\th.trap\t") {
		t.Errorf("plain: %s", w.Body.String())
	}
	b := decode[map[string]any](t, e.do("GET", "/v1/indicators?format=stix-lite", tokLocksR, ""))
	objs, _ := b["objects"].([]any)
	if b["type"] != "bundle" || len(objs) != 3 {
		t.Fatalf("stix = %v", b)
	}
	patterns := map[string]bool{}
	for _, o := range objs {
		m := o.(map[string]any)
		patterns[m["pattern"].(string)] = true
		if m["type"] != "indicator" || m["spec_version"] != "2.1" || !strings.HasPrefix(m["id"].(string), "indicator--") || m["pattern_type"] != "stix" {
			t.Errorf("stix object = %v", m)
		}
	}
	for _, p := range []string{"[ipv4-addr:value = '192.0.2.66']", "[ipv6-addr:value = '2001:db8::1']", "[user-account:account_login = 'h.trap']"} {
		if !patterns[p] {
			t.Errorf("pattern %s missing: %v", p, patterns)
		}
	}
	// Stable ids across exports.
	b2 := decode[map[string]any](t, e.do("GET", "/v1/indicators?format=stix-lite", tokLocksR, ""))
	if b2["objects"].([]any)[0].(map[string]any)["id"] != objs[0].(map[string]any)["id"] {
		t.Error("indicator id not stable")
	}
	for _, q := range []string{"?format=xml", "?min_score=-1", "?min_score=x", "?min_score=NaN"} {
		if w := e.do("GET", "/v1/indicators"+q, tokLocksR, ""); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", q, w.Code)
		}
	}
	if got := stixPattern("account", `a'b\c`); got != `[user-account:account_login = 'a\'b\\c']` {
		t.Errorf("escape: %s", got)
	}
	if got := sanitize("a\tb\nc"); got != "a b c" {
		t.Errorf("sanitize: %q", got)
	}
}

func TestEvents_SinceLimitTypes(t *testing.T) {
	e := newEnv(t, nil)
	for i := range 5 {
		e.bus.Emit(events.Event{Event: events.BindFail, Reason: "invalid_password", ClientIP: fmt.Sprintf("192.0.2.%d", i)})
		e.bus.Emit(events.Event{Event: events.Search, Data: map[string]any{"base": "dc=x", "scope": "sub", "filter_norm": "(cn=*)", "results": 0}})
	}
	all := decode[[]events.Record](t, e.do("GET", "/v1/events", tokEvents, ""))
	if len(all) != 10 || all[0].Seq != 1 {
		t.Fatalf("all: %d", len(all))
	}
	got := decode[[]events.Record](t, e.do("GET", "/v1/events?since=4&limit=2&types=bind_fail,%20lock", tokEvents, ""))
	if len(got) != 2 || got[0].Seq != 5 || got[1].Seq != 7 || got[0].Event != events.BindFail {
		t.Errorf("filtered: %+v", got)
	}
	if got := decode[[]events.Record](t, e.do("GET", "/v1/events?since=100", tokEvents, "")); len(got) != 0 {
		t.Errorf("beyond: %d", len(got))
	}
	for _, q := range []string{"?since=-1", "?limit=0", "?limit=10001", "?limit=x"} {
		if w := e.do("GET", "/v1/events"+q, tokEvents, ""); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", q, w.Code)
		}
	}
}

func TestAdmin_ConfigReloadSyncTestLearn(t *testing.T) {
	e := newEnv(t, nil)
	w := e.do("GET", "/v1/config", tokAdmin, "")
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/toml" || !strings.Contains(w.Body.String(), "[api]") {
		t.Errorf("config get: %d %v", w.Code, w.Header())
	}
	w = e.do("PUT", "/v1/config", tokAdmin, "[server]\nlog_level = \"info\"\n")
	if res := decode[ApplyResult](t, w); w.Code != http.StatusOK || !res.OK || res.Backup == "" || len(e.be.applied) != 1 {
		t.Errorf("config put: %d %+v", w.Code, res)
	}
	// Dry run: validated only, nothing applied.
	w = e.do("PUT", "/v1/config?dry_run=true", tokAdmin, "[server]\n")
	if res := decode[ApplyResult](t, w); w.Code != http.StatusOK || !res.OK || !res.DryRun || res.Backup != "" || len(e.be.applied) != 1 || len(e.be.validated) != 1 {
		t.Errorf("config dry run: %d %+v", w.Code, res)
	}
	if w := e.do("PUT", "/v1/config?dry_run=maybe", tokAdmin, "[server]\n"); w.Code != http.StatusBadRequest {
		t.Errorf("dry_run=maybe: %d", w.Code)
	}
	e.be.applyErr = fmt.Errorf("%w:\nserver.log_level: bad", ErrInvalidConfig)
	if w := e.do("PUT", "/v1/config?dry_run=1", tokAdmin, "x"); w.Code != http.StatusBadRequest || decode[apiError](t, w).Code != "invalid_config" {
		t.Errorf("invalid config dry run: %d", w.Code)
	}
	if w := e.do("PUT", "/v1/config", tokAdmin, "x"); w.Code != http.StatusBadRequest || decode[apiError](t, w).Code != "invalid_config" {
		t.Errorf("invalid config: %d", w.Code)
	}
	e.be.applyErr = ErrNoConfigFile
	if w := e.do("PUT", "/v1/config", tokAdmin, "x"); w.Code != http.StatusConflict {
		t.Errorf("no file: %d", w.Code)
	}
	if w := e.do("PUT", "/v1/config", tokAdmin, strings.Repeat("#", maxConfigBody+1)); w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("too large: %d", w.Code)
	}
	if w := e.do("POST", "/v1/reload", tokAdmin, ""); w.Code != http.StatusOK || e.be.reloads != 1 {
		t.Errorf("reload: %d", w.Code)
	}
	e.be.reloadErr = errors.New("listen 127.0.0.1:1: address in use")
	if w := e.do("POST", "/v1/reload", tokAdmin, ""); w.Code != http.StatusInternalServerError {
		t.Errorf("reload failure: %d", w.Code)
	}
	e.be.reloadErr = context.DeadlineExceeded
	if w := e.do("POST", "/v1/reload", tokAdmin, ""); w.Code != http.StatusServiceUnavailable {
		t.Errorf("reload timeout: %d", w.Code)
	}
	for name, tc := range map[string]struct {
		err  error
		path string
		want int
	}{
		"ok": {nil, "virola", http.StatusAccepted}, "unknown": {nil, "nope", http.StatusNotFound},
		"not_replica": {ErrNotReplica, "virola", http.StatusConflict}, "not_implemented": {ErrNotImplemented, "virola", http.StatusNotImplemented},
	} {
		e.be.syncErr = tc.err
		if w := e.do("POST", "/v1/profiles/"+tc.path+"/sync", tokAdmin, ""); w.Code != tc.want {
			t.Errorf("sync %s: %d", name, w.Code)
		}
	}
	// Record on/off.
	for name, tc := range map[string]struct {
		err  error
		path string
		body string
		want int
	}{
		"on": {nil, "virola", `{"state":"on"}`, http.StatusOK}, "unknown": {nil, "nope", `{"state":"on"}`, http.StatusNotFound},
		"bad_state": {nil, "virola", `{"state":"maybe"}`, http.StatusBadRequest}, "no_record_file": {ErrNoRecordFile, "virola", `{"state":"off"}`, http.StatusConflict},
	} {
		e.be.recordErr = tc.err
		if w := e.do("POST", "/v1/profiles/"+tc.path+"/record", tokAdmin, tc.body); w.Code != tc.want {
			t.Errorf("record %s: %d", name, w.Code)
		}
	}
	if len(e.be.records) != 1 || e.be.records[0] != "virola:true" {
		t.Errorf("records: %v", e.be.records)
	}
	// Profile test.
	w = e.do("POST", "/v1/profiles/virola/test", tokAdmin, `{"base":"ou=users,dc=aldap","scope":"one","filter":"(uid=a)","attrs":["mail"],"size_limit":3}`)
	tr := decode[testResponse](t, w)
	if w.Code != http.StatusOK || len(tr.Entries) != 1 || tr.Entries[0].Attrs["mail"][0] != "a@x" || tr.DeniedTerms[0] != "telephoneNumber" || tr.EffectiveFilter != "(sAMAccountName=a)" ||
		tr.UpstreamQueries != 1 || tr.DeniedAttrs == nil || e.be.testReq.Scope != listener.ScopeOne || e.be.testReq.SizeLimit != 3 {
		t.Errorf("test: %d %+v %+v", w.Code, tr, e.be.testReq)
	}
	for _, body := range []string{`{"base":"x"}`, `{"filter":"(a=b)","scope":"deep"}`, `{"filter":"(a=b)","size_limit":-1}`} {
		if w := e.do("POST", "/v1/profiles/virola/test", tokAdmin, body); w.Code != http.StatusBadRequest {
			t.Errorf("test %s: %d", body, w.Code)
		}
	}
	if w := e.do("POST", "/v1/profiles/nope/test", tokAdmin, `{"filter":"(a=b)"}`); w.Code != http.StatusNotFound {
		t.Errorf("test unknown profile: %d", w.Code)
	}
	e.be.testErr = errors.New("upstream down")
	if w := e.do("POST", "/v1/profiles/virola/test", tokAdmin, `{"filter":"(a=b)","scope":"base"}`); w.Code != http.StatusInternalServerError {
		t.Errorf("test error: %d", w.Code)
	}
	// Baseline learning.
	w = e.do("POST", "/v1/baseline/virola/learn", tokAdmin, `{"duration":"2h"}`)
	if got := decode[map[string]any](t, w); w.Code != http.StatusAccepted || got["until"] != "2026-10-23T14:00:00Z" {
		t.Errorf("learn: %d %v", w.Code, got)
	}
	e.clk.add(90 * time.Minute)
	if !e.ids.Learning() {
		t.Error("learning not started")
	}
	if w := e.do("POST", "/v1/baseline/virola/learn", tokAdmin, ""); w.Code != http.StatusAccepted {
		t.Errorf("learn default: %d", w.Code)
	}
	for path, body := range map[string]string{"/v1/baseline/nope/learn": "", "/v1/baseline/virola/learn": `{"duration":"1000h"}`} {
		if w := e.do("POST", path, tokAdmin, body); w.Code < 400 {
			t.Errorf("learn %s %s: %d", path, body, w.Code)
		}
	}
	if w := e.do("POST", "/v1/baseline/virola/learn", tokAdmin, `{"duration":"x"}`); w.Code != http.StatusBadRequest {
		t.Errorf("learn bad duration: %d", w.Code)
	}
}

func TestBackendError_Mapping(t *testing.T) {
	for err, want := range map[error]int{ErrNotFound: 404, ErrInvalidConfig: 400, ErrNoConfigFile: 409, ErrNotReplica: 409, ErrNotImplemented: 501, ErrNoRecordFile: 409,
		context.Canceled: 503, io.ErrUnexpectedEOF: 500} {
		w := httptest.NewRecorder()
		backendError(w, err)
		if w.Code != want {
			t.Errorf("%v: %d", err, w.Code)
		}
	}
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, func() {})
	if w.Code != http.StatusInternalServerError {
		t.Errorf("unencodable: %d", w.Code)
	}
	if !pathMatches("/v1/locks/{target}/{key}", "/v1/locks/ip/1") || pathMatches("/v1/locks/{target}/{key}", "/v1/locks/ip/") || pathMatches("/v1/locks", "/v1/lock") {
		t.Error("pathMatches")
	}
}

// TestIPC_NoTokenAdmin is the IPC half of TESTING.md 40 at handler level:
// the IPC socket needs no token and acts with scope admin.
func TestIPC_NoTokenAdmin(t *testing.T) {
	e := newEnv(t, nil)
	e.lim.LockAccount("jdoe", e.clk.now().Add(time.Hour), "ratelimit")
	w := httptest.NewRecorder()
	e.ipc.ServeHTTP(w, request("DELETE", "/v1/locks/account/jdoe", "", ""))
	if w.Code != http.StatusNoContent || len(e.lim.Locks()) != 0 {
		t.Fatalf("ipc unlock: %d", w.Code)
	}
	calls := e.records(events.APICall)
	if len(calls) != 1 || calls[0].Data["token_name"] != "ipc" || calls[0].Data["client_ip"] != "local" || calls[0].ClientIP != "" {
		t.Errorf("ipc audit: %+v", calls)
	}
	// Over TCP the same call without a token is 401.
	e.lim.LockAccount("jdoe", e.clk.now().Add(time.Hour), "ratelimit")
	if w := e.do("DELETE", "/v1/locks/account/jdoe", "", ""); w.Code != http.StatusUnauthorized || len(e.lim.Locks()) != 1 {
		t.Errorf("tcp without token: %d", w.Code)
	}
	schematest.Check(t, e.bus.Since(0, 0)...)
}

func TestNoSecretsInOutput_API(t *testing.T) {
	e := newEnv(t, nil)
	for _, rt := range Routes() {
		if rt.Path == "/v1/events/stream" {
			continue
		}
		path, body := routeCall(rt)
		for _, tok := range []string{tokAdmin, tokEvents, "S3CR3T-wrong-0123456789abcdef0123456789"} {
			w := e.do(rt.Method, path, tok, body)
			if strings.Contains(w.Body.String(), "S3CR3T") || strings.Contains(fmt.Sprint(w.Header()), "S3CR3T") {
				t.Fatalf("%s %s leaks a token: %s", rt.Method, path, w.Body.String())
			}
		}
	}
	for _, r := range e.bus.Since(0, 0) {
		if strings.Contains(string(r.JSON()), "S3CR3T") {
			t.Fatalf("token in event: %s", r.JSON())
		}
	}
}
