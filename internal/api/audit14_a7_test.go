package api

// Audit 14, area A.7 (management API). These tests document the observed
// authorization matrix and probe the transport, token handling, SSE and
// event endpoints as an attacker holding a low-privilege token would.
// Tests named *_Finding* are expected to FAIL on the current code; the
// others are evidence of checks that passed.

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/ids"
	"github.com/alstdev/aldap/internal/metrics"
	"github.com/alstdev/aldap/internal/ratelimit"
	"github.com/alstdev/aldap/internal/secret"
)

const (
	a7TokOld     = "S3CR3T-old-removed-0123456789abcdef01234"
	a7TokInvalid = "S3CR3T-invalid-0123456789abcdef012345678"
)

// a7Principals are the columns of the matrix: no token, an unknown token,
// a token that was configured once and then removed, and one token per scope.
var a7Principals = []struct{ name, token string }{
	{"none", ""},
	{"invalid", a7TokInvalid},
	{"removed", a7TokOld},
	{ScopeEventsRead, tokEvents},
	{ScopeLocksRead, tokLocksR},
	{ScopeLocksWrite, tokLocksW},
	{ScopeStatusRead, tokStatus},
	{ScopeAdmin, tokAdmin},
}

// a7Do runs one request against h; the SSE route gets a context that ends
// after a short while so the handler returns.
func a7Do(h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	r := request(method, path, token, body)
	if strings.HasPrefix(path, "/v1/events/stream") {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		r = r.WithContext(ctx)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// a7Expect is the expected answer class of principal p on a route with scope sc.
func a7Expect(sc, p string) string {
	if sc == ScopePublic {
		return "2xx"
	}
	switch p {
	case "none", "invalid", "removed":
		return "401"
	}
	if sc == ScopeMetrics {
		sc = ScopeStatusRead
	}
	if p == ScopeAdmin || p == sc {
		return "ok" // anything but 401/403
	}
	return "403"
}

func a7Class(code int) string {
	switch {
	case code == 401:
		return "401"
	case code == 403:
		return "403"
	case code >= 200 && code < 300:
		return "2xx"
	}
	return fmt.Sprint(code)
}

// TestAudit14_A7_Matrix asserts the full route × principal matrix on the
// TCP handler, then the IPC handler (every route, no token) and the
// separate metrics handler (only /metrics and the public routes exist).
func TestAudit14_A7_Matrix(t *testing.T) {
	e := newEnv(t, nil)
	// Configure a token, then remove it again: it must stop working.
	a := apiConfig()
	a.Tokens = append(a.Tokens, config.APIToken{Name: "old", Token: secret.Inline(a7TokOld), Scopes: []string{ScopeAdmin}})
	if err := e.s.Configure(a, secret.Default); err != nil {
		t.Fatal(err)
	}
	if w := e.do("GET", "/v1/config", a7TokOld, ""); w.Code != 200 {
		t.Fatalf("configured token refused: %d", w.Code)
	}
	if err := e.s.Configure(apiConfig(), secret.Default); err != nil {
		t.Fatal(err)
	}

	var table strings.Builder
	fmt.Fprintf(&table, "%-45s", "route")
	for _, p := range a7Principals {
		fmt.Fprintf(&table, " %-12s", p.name)
	}
	table.WriteString(" | ipc\n")
	for _, rt := range Routes() {
		path, body := routeCall(rt)
		fmt.Fprintf(&table, "%-45s", rt.Method+" "+rt.Path)
		for _, p := range a7Principals {
			w := a7Do(e.api, rt.Method, path, p.token, body)
			got := a7Class(w.Code)
			want := a7Expect(rt.Scope, p.name)
			switch want {
			case "ok":
				if got == "401" || got == "403" {
					t.Errorf("%s %s as %s: %d, want success class: %s", rt.Method, rt.Path, p.name, w.Code, w.Body.String())
				}
			case "2xx":
				if got != "2xx" {
					t.Errorf("%s %s as %s: %d, want 2xx", rt.Method, rt.Path, p.name, w.Code)
				}
			default:
				if got != want {
					t.Errorf("%s %s as %s: %d, want %s: %s", rt.Method, rt.Path, p.name, w.Code, want, w.Body.String())
				}
				if er := decode[apiError](t, w); er.Code == "" || er.Error == "" {
					t.Errorf("%s %s as %s: error body %q lacks {error, code}", rt.Method, rt.Path, p.name, w.Body.String())
				}
			}
			if w.Code == 401 && w.Header().Get("WWW-Authenticate") == "" {
				t.Errorf("%s %s as %s: 401 without WWW-Authenticate", rt.Method, rt.Path, p.name)
			}
			fmt.Fprintf(&table, " %-12d", w.Code)
			e.lim.Unlock("ip", "192.0.2.99", "api")
		}
		// IPC: no token, scope admin.
		w := a7Do(e.ipc, rt.Method, path, "", body)
		if w.Code == 401 || w.Code == 403 {
			t.Errorf("IPC %s %s: %d", rt.Method, rt.Path, w.Code)
		}
		fmt.Fprintf(&table, " | %d\n", w.Code)
		e.lim.Unlock("ip", "192.0.2.99", "api")
	}
	t.Logf("matrix (TCP handler; columns = principal):\n%s", table.String())

	// Separate metrics listener: only /metrics, /healthz, /readyz exist.
	mh := e.s.MetricsHandler()
	for _, rt := range Routes() {
		path, body := routeCall(rt)
		w := a7Do(mh, rt.Method, path, tokAdmin, body)
		if rt.Path == "/metrics" || rt.Scope == ScopePublic {
			if w.Code != 200 {
				t.Errorf("metrics handler %s: %d", rt.Path, w.Code)
			}
			continue
		}
		if w.Code != 404 {
			t.Errorf("metrics handler serves %s %s: %d", rt.Method, rt.Path, w.Code)
		}
	}
	if w := a7Do(mh, "GET", "/metrics", "", ""); w.Code != 401 {
		t.Errorf("metrics handler /metrics without token: %d", w.Code)
	}
	if w := a7Do(mh, "GET", "/metrics", tokEvents, ""); w.Code != 403 {
		t.Errorf("metrics handler /metrics with events:read: %d", w.Code)
	}

	// metrics.public: /metrics without a token; metrics.enabled=false: 404 even for admin.
	pub := newEnv(t, func(a *config.API) { a.Metrics.Public = true })
	if w := pub.do("GET", "/metrics", "", ""); w.Code != 200 {
		t.Errorf("metrics.public without token: %d", w.Code)
	}
	off := newEnv(t, func(a *config.API) { a.Metrics.Enabled = false })
	if w := off.do("GET", "/metrics", tokAdmin, ""); w.Code != 404 {
		t.Errorf("metrics disabled, admin: %d", w.Code)
	}
}

// TestAudit14_A7_MethodAndPathConfusion: every method that is not a route
// on a protected path, and every path spelling that normalizes to a
// protected route, must not be served without a token.
func TestAudit14_A7_MethodAndPathConfusion(t *testing.T) {
	e := newEnv(t, nil)
	routes := map[string]bool{}
	paths := map[string]string{}
	for _, rt := range Routes() {
		routes[rt.Method+" "+rt.Path] = true
		p, _ := routeCall(rt)
		paths[rt.Path] = p
	}
	var table strings.Builder
	keys := make([]string, 0, len(paths))
	for k := range paths {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, pattern := range keys {
		for _, m := range []string{"HEAD", "OPTIONS", "PATCH", "TRACE", "GET", "POST", "PUT", "DELETE", "CONNECT"} {
			if routes[m+" "+pattern] {
				continue
			}
			w := a7Do(e.api, m, paths[pattern], "", "")
			fmt.Fprintf(&table, "%-8s %-38s -> %d allow=%q\n", m, paths[pattern], w.Code, w.Header().Get("Allow"))
			if w.Code >= 200 && w.Code < 300 && pattern != "/healthz" && pattern != "/readyz" {
				t.Errorf("%s %s served without a token: %d", m, paths[pattern], w.Code)
			}
			if m == "HEAD" && routes["GET "+pattern] && pattern != "/healthz" && pattern != "/readyz" && w.Code != 401 {
				t.Errorf("HEAD %s without token: %d, want 401 (HEAD is GET)", paths[pattern], w.Code)
			}
		}
	}
	t.Logf("method confusion (no token):\n%s", table.String())

	variants := []struct{ method, path string }{
		{"GET", "/v1//config"}, {"GET", "/v1/config/"}, {"GET", "/v1/./config"}, {"GET", "/V1/config"}, {"GET", "/v1/CONFIG"},
		{"GET", "/v1/%63onfig"}, {"GET", "//v1/config"}, {"GET", "/v1/config?dry_run=../"}, {"GET", "/v1/config%00"},
		{"GET", "/v1/locks/ip/..%2f..%2fconfig"}, {"DELETE", "/v1/locks/ip/..%2f..%2fconfig"}, {"DELETE", "/v1/locks/ip/../../config"},
		{"DELETE", "/v1/locks/account/.."}, {"DELETE", "/v1/locks/account/a%2Fb"}, {"DELETE", "/v1/locks/account/%2e%2e%2f%2e%2e%2fconfig"},
		{"GET", "/v1/events/../config"}, {"GET", "/v1/status/../config"}, {"POST", "/v1/reload/"}, {"GET", "/v1/reload"},
	}
	table.Reset()
	for _, v := range variants {
		none := a7Do(e.api, v.method, v.path, "", "")
		adm := a7Do(e.api, v.method, v.path, tokAdmin, "")
		low := a7Do(e.api, v.method, v.path, tokEvents, "")
		fmt.Fprintf(&table, "%-7s %-45s none=%d loc=%-12q events:read=%d admin=%d\n", v.method, v.path, none.Code, none.Header().Get("Location"), low.Code, adm.Code)
		if none.Code >= 200 && none.Code < 300 {
			t.Errorf("%s %s served without a token", v.method, v.path)
		}
		if low.Code >= 200 && low.Code < 300 {
			t.Errorf("%s %s served to events:read", v.method, v.path)
		}
		if loc := none.Header().Get("Location"); loc != "" && !strings.HasPrefix(loc, "/") {
			t.Errorf("%s %s redirects off-site: %q", v.method, v.path, loc)
		}
	}
	t.Logf("path normalization:\n%s", table.String())
}

// TestAudit14_A7_TokenOnlyInBearerHeader: query string, cookie, X-API-Key
// and Basic are not accepted; an empty bearer and a bearer that is a prefix
// or extension of a real token are refused.
func TestAudit14_A7_TokenOnlyInBearerHeader(t *testing.T) {
	e := newEnv(t, nil)
	cases := []struct {
		name string
		mod  func(r *http.Request)
	}{
		{"query token", func(r *http.Request) { r.URL.RawQuery = "token=" + tokAdmin }},
		{"query access_token", func(r *http.Request) { r.URL.RawQuery = "access_token=" + tokAdmin }},
		{"cookie", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "token", Value: tokAdmin}) }},
		{"x-api-key", func(r *http.Request) { r.Header.Set("X-API-Key", tokAdmin) }},
		{"basic", func(r *http.Request) { r.SetBasicAuth("admin", tokAdmin) }},
		{"bearer empty", func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") }},
		{"token scheme", func(r *http.Request) { r.Header.Set("Authorization", "Token "+tokAdmin) }},
		{"prefix", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tokAdmin[:len(tokAdmin)-1]) }},
		{"extension", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tokAdmin+"x") }},
		{"bearer of sha256", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64)) }},
	}
	for _, c := range cases {
		r := request("GET", "/v1/config", "", "")
		c.mod(r)
		w := httptest.NewRecorder()
		e.api.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Errorf("%s: %d, want 401", c.name, w.Code)
		}
	}
	// Case-insensitive scheme and surrounding spaces are accepted (RFC 9110).
	r := request("GET", "/v1/config", "", "")
	r.Header.Set("Authorization", "BEARER   "+tokAdmin+"  ")
	w := httptest.NewRecorder()
	e.api.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Errorf("BEARER with spaces: %d", w.Code)
	}
}

// TestAudit14_A7_ForwardedHeadersIgnored: allow_cidrs is checked on the
// TCP peer, not on X-Forwarded-For / X-Real-IP / Forwarded; an IPv4-mapped
// IPv6 peer matches its IPv4 prefix.
func TestAudit14_A7_ForwardedHeadersIgnored(t *testing.T) {
	e := newEnv(t, nil)
	for _, h := range [][2]string{{"X-Forwarded-For", "10.9.1.1"}, {"X-Real-IP", "10.9.1.1"}, {"Forwarded", "for=10.9.1.1"}, {"X-Client-IP", "10.9.1.1"}, {"True-Client-IP", "10.9.1.1"}} {
		r := request("GET", "/v1/config", tokNetOnly, "")
		r.Header.Set(h[0], h[1])
		w := httptest.NewRecorder()
		e.api.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Errorf("%s trusted: %d", h[0], w.Code)
		}
	}
	for _, addr := range []string{"10.9.1.1:5", "[::ffff:10.9.1.1]:5"} {
		r := request("GET", "/v1/config", tokNetOnly, "")
		r.RemoteAddr = addr
		w := httptest.NewRecorder()
		e.api.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Errorf("peer %s: %d", addr, w.Code)
		}
	}
	// IPv6-mapped prefix in allow_cidrs is normalized (Masked) and never widens.
	r := request("GET", "/v1/config", tokNetOnly, "")
	r.RemoteAddr = "[fe80::1%25eth0]:5"
	w := httptest.NewRecorder()
	e.api.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Errorf("zoned link-local peer: %d", w.Code)
	}
}

// TestAudit14_A7_RateLimitBeforeAuth: the per-IP bucket is taken before the
// token is looked at, so an unauthenticated flood is limited too; source
// ports do not matter; the limit is per peer address.
func TestAudit14_A7_RateLimitBeforeAuth(t *testing.T) {
	e := newEnv(t, func(a *config.API) { a.RateLimitRPS = 2 })
	codes := []int{}
	for i := 0; i < 5; i++ {
		r := request("GET", "/v1/status", "", "")
		r.RemoteAddr = fmt.Sprintf("192.0.2.10:%d", 40000+i)
		w := httptest.NewRecorder()
		e.api.ServeHTTP(w, r)
		codes = append(codes, w.Code)
	}
	if codes[0] != 401 || codes[1] != 401 || codes[2] != 429 || codes[4] != 429 {
		t.Errorf("unauthenticated flood: %v", codes)
	}
	// Another address has its own bucket.
	r := request("GET", "/v1/status", tokStatus, "")
	r.RemoteAddr = "192.0.2.11:1"
	w := httptest.NewRecorder()
	e.api.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Errorf("other peer limited: %d", w.Code)
	}
	// Public routes are limited too; the IPC handler is not.
	w = httptest.NewRecorder()
	e.api.ServeHTTP(w, request("GET", "/healthz", "", ""))
	if w.Code != 429 {
		t.Errorf("healthz after flood: %d", w.Code)
	}
	for i := 0; i < 10; i++ {
		w = httptest.NewRecorder()
		e.ipc.ServeHTTP(w, request("GET", "/v1/status", "", ""))
	}
	if w.Code != 200 {
		t.Errorf("ipc limited: %d", w.Code)
	}
}

// TestAudit14_A7_NoCORSContentTypeErrorShape: no Access-Control-* header on
// any answer, JSON content type on every JSON route, {error, code} bodies.
func TestAudit14_A7_NoCORSContentTypeErrorShape(t *testing.T) {
	e := newEnv(t, nil)
	for _, rt := range Routes() {
		path, body := routeCall(rt)
		for _, tok := range []string{"", tokEvents, tokAdmin} {
			r := request(rt.Method, path, tok, body)
			r.Header.Set("Origin", "https://evil.example")
			r.Header.Set("Access-Control-Request-Method", rt.Method)
			if rt.Path == "/v1/events/stream" {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
				defer cancel()
				r = r.WithContext(ctx)
			}
			w := httptest.NewRecorder()
			e.api.ServeHTTP(w, r)
			for k := range w.Header() {
				if strings.HasPrefix(strings.ToLower(k), "access-control-") {
					t.Errorf("%s %s: CORS header %s", rt.Method, rt.Path, k)
				}
			}
			ct := w.Header().Get("Content-Type")
			switch {
			case w.Code >= 400:
				if ct != "application/json" {
					t.Errorf("%s %s %d: content type %q", rt.Method, rt.Path, w.Code, ct)
				}
				er := decode[apiError](t, w)
				if er.Code == "" || er.Error == "" {
					t.Errorf("%s %s %d: body %q", rt.Method, rt.Path, w.Code, w.Body.String())
				}
				if strings.Contains(er.Error, "/home/") || strings.Contains(er.Error, "goroutine ") || strings.Contains(er.Error, ".go:") {
					t.Errorf("%s %s: error discloses internals: %q", rt.Method, rt.Path, er.Error)
				}
			case rt.Path == "/v1/config" && rt.Method == http.MethodGet:
				if ct != "application/toml" {
					t.Errorf("GET /v1/config content type %q", ct)
				}
			case rt.Path == "/v1/events/stream":
				if ct != "text/event-stream" {
					t.Errorf("stream content type %q", ct)
				}
			case rt.Path == "/metrics":
			case w.Code != 204 && ct != "application/json":
				t.Errorf("%s %s %d: content type %q", rt.Method, rt.Path, w.Code, ct)
			}
			if w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("%s %s: hardening headers %v", rt.Method, rt.Path, w.Header())
			}
			e.lim.Unlock("ip", "192.0.2.99", "api")
		}
	}
	// OPTIONS preflight gets no CORS answer either.
	r := request("OPTIONS", "/v1/config", "", "")
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	e.api.ServeHTTP(w, r)
	if w.Code != 405 || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("OPTIONS preflight: %d %v", w.Code, w.Header())
	}
}

// TestAudit14_A7_Finding_StreamNoCap: an events:read token opens as many
// SSE streams as it likes; every one keeps a goroutine and a pre-allocated
// queue of StreamQueue records for as long as the TCP connection lives
// (no maximum duration, no maximum subscriber count).
func TestAudit14_A7_Finding_StreamNoCap(t *testing.T) {
	e := newEnvQueue(t, 1024)
	base := serveTCP(t, e)
	const n = 300
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	g0 := runtime.NumGoroutine()
	accepted, refused := 0, 0
	for i := 0; i < n; i++ {
		c := openStream(t, base+"/v1/events/stream", tokEvents, nil)
		defer c.close()
		if c.resp.StatusCode == http.StatusOK {
			accepted++
		} else {
			refused++
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	perStream := int(unsafe.Sizeof(events.Record{})) * 1024
	t.Logf("streams accepted=%d refused=%d; goroutines %d -> %d; heap %d -> %d bytes (client side included); sizeof(Record)=%d, queue 1024 => >= %d bytes pinned per stream server side",
		accepted, refused, g0, runtime.NumGoroutine(), before.HeapAlloc, after.HeapAlloc, unsafe.Sizeof(events.Record{}), perStream)
	if refused == 0 {
		t.Errorf("FINDING: %d concurrent SSE streams from one events:read token all accepted; no cap on concurrent streams (each pins >= %d bytes + a goroutine indefinitely)", n, perStream)
	}
}

// a7BigEnv builds a server over a bus holding ringSize records.
func a7BigEnv(t *testing.T, ringSize int) (*Server, *events.Bus) {
	t.Helper()
	log := slog.New(slog.DiscardHandler)
	bus := events.NewBus(events.Options{Host: "h", BufferSize: ringSize, Logger: log})
	lim := ratelimit.New(ratelimit.Options{Events: bus, Logger: log, Salt: []byte("s")})
	eng := ids.New(config.Default().Intrusion, ids.Options{Events: bus, Logger: log})
	s := New(Options{Backend: &fakeBackend{ready: true}, Bus: bus, Limiter: lim, IDs: eng, Metrics: metrics.New("v", "c", "d"), Logger: log, Heartbeat: 20 * time.Millisecond})
	if err := s.Configure(apiConfig(), secret.Default); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	for i := 0; i < ringSize; i++ {
		bus.Emit(events.Event{Event: events.BindFail, Profile: "virola", Reason: "invalid_password", ClientIP: "192.0.2.1", Account: "jdoe@test.aldap", Data: map[string]any{"attempt": i}})
	}
	return s, bus
}

// TestAudit14_A7_Finding_EventsFullRingCopy: GET /v1/events copies the whole
// ring buffer (Bus.Since(since, 0)) on every request before applying limit,
// and GET /v1/events/stream?since=0 replays and JSON-encodes the whole ring
// to a client that can reconnect as often as the rate limit allows.
func TestAudit14_A7_Finding_EventsFullRingCopy(t *testing.T) {
	const ring = 100000
	s, bus := a7BigEnv(t, ring)
	h := s.Handler()
	if bus.Seq() < ring {
		t.Fatalf("ring not filled: %d", bus.Seq())
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request("GET", "/v1/events?limit=1", tokEvents, ""))
	dur := time.Since(start)
	runtime.ReadMemStats(&after)
	alloc := after.TotalAlloc - before.TotalAlloc
	if w.Code != 200 {
		t.Fatalf("events: %d %s", w.Code, w.Body.String())
	}
	t.Logf("GET /v1/events?limit=1 over a %d-record ring: %d bytes allocated, %s, %d bytes answered", ring, alloc, dur, w.Body.Len())
	if alloc > 4<<20 {
		t.Errorf("FINDING: a 1-record answer allocates %d bytes (whole ring copied; %d records x %d bytes); at rate_limit_rps=50 one events:read client forces ~%d MB/s of allocation", alloc, ring, unsafe.Sizeof(events.Record{}), alloc*50>>20)
	}

	// SSE replay from seq 0: bytes written before the first heartbeat.
	ln := a7Listen(t, s)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ln+"/v1/events/stream?since=0", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokEvents)
	start = time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var bytesOut, ids int
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		bytesOut += len(line) + 1
		if strings.HasPrefix(line, "id: ") {
			ids++
		}
		if line == ": ping" {
			break
		}
	}
	t.Logf("GET /v1/events/stream?since=0: %d records, %d bytes replayed in %s per connection (reconnect allowed %d/s)", ids, bytesOut, time.Since(start), 50)
	if ids != ring {
		t.Errorf("replay returned %d of %d", ids, ring)
	}
}

func a7Listen(t *testing.T, s *Server) string {
	t.Helper()
	e := &env{s: s}
	return serveTCP(t, e)
}

// TestAudit14_A7_Info_DuplicateTokenValues: two [[api.token]] entries with
// the same value and different scopes are accepted; the last one wins
// silently (match keeps the last index), so a reused value escalates.
func TestAudit14_A7_Info_DuplicateTokenValues(t *testing.T) {
	a := apiConfig()
	a.Tokens = []config.APIToken{
		{Name: "reader", Token: secret.Inline(tokEvents), Scopes: []string{ScopeEventsRead}},
		{Name: "root", Token: secret.Inline(tokEvents), Scopes: []string{ScopeAdmin}},
	}
	s := New(Options{Backend: &fakeBackend{}, Bus: events.NewBus(events.Options{BufferSize: 16, Logger: slog.New(slog.DiscardHandler)}), Logger: slog.New(slog.DiscardHandler)})
	if err := s.Configure(a, secret.Default); err == nil {
		t.Error("the same token value configured twice was accepted (the last entry's scopes would win)")
	}
}

// TestAudit14_A7_Info_IPCIgnoresMetricsDisabled: over the IPC socket the
// metrics.enabled switch is not consulted (admin, local only).
func TestAudit14_A7_Info_IPCIgnoresMetricsDisabled(t *testing.T) {
	e := newEnv(t, func(a *config.API) { a.Metrics.Enabled = false })
	w := httptest.NewRecorder()
	e.ipc.ServeHTTP(w, request("GET", "/metrics", "", ""))
	if w.Code != 404 {
		t.Errorf("INFO: /metrics over IPC with metrics.enabled=false: %d", w.Code)
	}
}

// TestAudit14_A7_LocksAndStreamInputs: lock body bounds, Last-Event-ID
// edge values and the limit cap of /v1/events.
func TestAudit14_A7_LocksAndStreamInputs(t *testing.T) {
	e := newEnv(t, nil)
	for _, c := range []struct {
		body string
		want int
	}{
		{`{"target":"ip","key":"0.0.0.0/0"}`, 400},
		{`{"target":"ip","key":"0.0.0.0"}`, 201},
		{`{"target":"account","key":"` + strings.Repeat("a", 513) + `"}`, 400},
		{`{"target":"account","key":"` + strings.Repeat("a", 512) + `"}`, 201},
		{`{"target":"account","key":"x","duration":"8761h"}`, 400},
		{`{"target":"account","key":"x","duration":"-1h"}`, 400},
		{`{"target":"account","key":"x","reason":"` + strings.Repeat("r", 513) + `"}`, 400},
		{`{"target":"account","key":"x","extra":1}`, 400},
		{`{"target":"account","key":"` + strings.Repeat("a", 70000) + `"}`, 400},
	} {
		if w := e.do("POST", "/v1/locks", tokLocksW, c.body); w.Code != c.want {
			t.Errorf("POST /v1/locks %.60s: %d, want %d: %s", c.body, w.Code, c.want, w.Body.String())
		}
	}
	for _, q := range []string{"limit=0", "limit=10001", "limit=-1", "since=-1", "since=x", "since=18446744073709551616"} {
		if w := e.do("GET", "/v1/events?"+q, tokEvents, ""); w.Code != 400 {
			t.Errorf("GET /v1/events?%s: %d", q, w.Code)
		}
	}
	if w := e.do("GET", "/v1/events?since=18446744073709551615&limit=10000", tokEvents, ""); w.Code != 200 {
		t.Errorf("max since: %d", w.Code)
	}
	for _, h := range []string{"-1", "abc", "18446744073709551616", "1e3"} {
		r := request("GET", "/v1/events/stream", tokEvents, "")
		r.Header.Set("Last-Event-ID", h)
		w := httptest.NewRecorder()
		e.api.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Errorf("Last-Event-ID %q: %d", h, w.Code)
		}
	}
	// CRLF/TAB in an account key cannot break the plain (TSV) indicator format.
	plain := plainIndicators([]indicator{{Target: "account", Key: "a\r\nb\tc", Reasons: []string{"x"}}})
	if strings.Count(plain, "\n") != 2 || strings.Contains(plain, "a\r") || strings.Count(plain, "\t") != 8 {
		t.Errorf("plain indicators not sanitized: %q", plain)
	}
	if w := e.do("GET", "/v1/indicators?format=plain", tokLocksR, ""); w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("plain indicators: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
}
