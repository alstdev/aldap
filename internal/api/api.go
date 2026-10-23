package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/ids"
	"github.com/alstdev/aldap/internal/metrics"
	"github.com/alstdev/aldap/internal/ratelimit"
	"github.com/alstdev/aldap/internal/upstream"
	"github.com/alstdev/aldap/internal/vdir"
)

// Scopes of [[api.token]] (SPEC §3.4). admin implies every other scope.
const (
	ScopeEventsRead = "events:read"
	ScopeLocksRead  = "locks:read"
	ScopeLocksWrite = "locks:write"
	ScopeStatusRead = "status:read"
	ScopeAdmin      = "admin"
	// ScopePublic marks routes served without a token.
	ScopePublic = ""
	// ScopeMetrics is status:read, or public with [api.metrics].public.
	ScopeMetrics = "metrics"
)

// Sentinel errors a Backend wraps; they select the HTTP status.
var (
	ErrNotFound       = errors.New("not found")
	ErrInvalidConfig  = errors.New("configuration invalid")
	ErrNoConfigFile   = errors.New("the configuration does not come from a file")
	ErrNotReplica     = errors.New("profile is not a replica (cache.mode)")
	ErrNotImplemented = errors.New("not implemented")
	// ErrInsecureListen refuses a non-loopback listener without TLS.
	ErrInsecureListen = errors.New("TLS is mandatory when the API listens beyond loopback")
)

// Backend is what the daemon provides for the configuration-dependent
// endpoints. It follows the current configuration across reloads.
type Backend interface {
	Profiles() []ProfileInfo
	Upstreams() map[string][]upstream.ServerStatus
	// Ready reports whether every proxy profile has an upstream server up.
	Ready() bool
	Test(ctx context.Context, profile string, req vdir.TestRequest) (vdir.TestResult, error)
	// ConfigTOML renders the running configuration with secrets masked.
	ConfigTOML() ([]byte, error)
	// ApplyConfig validates body, writes it atomically with a backup of the
	// previous file and reloads; on a failed reload the previous file is restored.
	ApplyConfig(ctx context.Context, body []byte) (ApplyResult, error)
	// ValidateConfig checks body like ApplyConfig without writing or
	// reloading (PUT /v1/config?dry_run=true).
	ValidateConfig(ctx context.Context, body []byte) error
	Reload(ctx context.Context) error
	Sync(ctx context.Context, profile string) error
	// Record starts or stops request recording of a profile.
	Record(ctx context.Context, profile string, on bool) error
}

// ProfileInfo describes a profile without secrets (/v1/profiles).
type ProfileInfo struct {
	Name        string   `json:"name"`
	Mode        string   `json:"mode"`
	Transport   string   `json:"transport"`
	Listen      []string `json:"listen"`
	Upstream    string   `json:"upstream,omitempty"`
	VirtualBase string   `json:"virtual_base"`
	Bases       []string `json:"bases"`
	Cache       string   `json:"cache"`
}

// ApplyResult is the answer of PUT /v1/config.
type ApplyResult struct {
	OK     bool   `json:"ok"`
	DryRun bool   `json:"dry_run,omitempty"`
	Backup string `json:"backup,omitempty"`
}

// Options wire a Server to the process-wide models.
type Options struct {
	Backend Backend
	Bus     *events.Bus
	Limiter *ratelimit.Limiter
	IDs     *ids.Engine
	// Metrics serves /metrics (nil = 404).
	Metrics *metrics.Metrics
	// Events receives api_call (default Bus).
	Events  events.Sink
	Logger  *slog.Logger
	Version string
	Now     func() time.Time
	// Heartbeat is the SSE keep-alive interval (default 15s).
	Heartbeat time.Duration
	// StreamQueue is the subscription queue of one SSE client (default
	// 1024); a lagging client is backfilled from the ring buffer by seq.
	StreamQueue int
}

// Route is one endpoint of the API (docs/openapi.yaml).
type Route struct {
	Method string
	Path   string
	Scope  string
}

type handlerFunc func(s *Server, w http.ResponseWriter, r *http.Request, c *call)

type route struct {
	Route
	h handlerFunc
}

var routeTable = []route{
	{Route{"GET", "/healthz", ScopePublic}, (*Server).handleHealthz},
	{Route{"GET", "/readyz", ScopePublic}, (*Server).handleReadyz},
	{Route{"GET", "/metrics", ScopeMetrics}, (*Server).handleMetrics},
	{Route{"GET", "/v1/status", ScopeStatusRead}, (*Server).handleStatus},
	{Route{"GET", "/v1/upstreams", ScopeStatusRead}, (*Server).handleUpstreams},
	{Route{"GET", "/v1/profiles", ScopeStatusRead}, (*Server).handleProfiles},
	{Route{"GET", "/v1/locks", ScopeLocksRead}, (*Server).handleLocks},
	{Route{"POST", "/v1/locks", ScopeLocksWrite}, (*Server).handleLockCreate},
	{Route{"DELETE", "/v1/locks/{target}/{key}", ScopeLocksWrite}, (*Server).handleLockDelete},
	{Route{"GET", "/v1/indicators", ScopeLocksRead}, (*Server).handleIndicators},
	{Route{"GET", "/v1/events", ScopeEventsRead}, (*Server).handleEvents},
	{Route{"GET", "/v1/events/stream", ScopeEventsRead}, (*Server).handleStream},
	{Route{"POST", "/v1/lockdown", ScopeLocksWrite}, (*Server).handleLockdown},
	{Route{"GET", "/v1/config", ScopeAdmin}, (*Server).handleConfigGet},
	{Route{"PUT", "/v1/config", ScopeAdmin}, (*Server).handleConfigPut},
	{Route{"POST", "/v1/reload", ScopeAdmin}, (*Server).handleReload},
	{Route{"POST", "/v1/profiles/{name}/sync", ScopeAdmin}, (*Server).handleSync},
	{Route{"POST", "/v1/profiles/{name}/test", ScopeAdmin}, (*Server).handleTest},
	{Route{"POST", "/v1/profiles/{name}/record", ScopeAdmin}, (*Server).handleRecord},
	{Route{"POST", "/v1/baseline/{profile}/learn", ScopeAdmin}, (*Server).handleLearn},
}

// Routes lists every endpoint with its scope.
func Routes() []Route {
	out := make([]Route, len(routeTable))
	for i, r := range routeTable {
		out[i] = r.Route
	}
	return out
}

// Listener kinds: the API, the separate metrics address and the IPC socket.
type kind int

const (
	kindAPI kind = iota
	kindMetrics
	kindIPC
)

// Server serves the API on any number of listeners.
type Server struct {
	o       Options
	log     *slog.Logger
	started time.Time
	auth    atomic.Pointer[authState]

	// ctx ends the SSE streams on Shutdown.
	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	servers []*http.Server
	wg      sync.WaitGroup
}

// New creates a server without tokens; Configure installs them.
func New(o Options) *Server {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Events == nil {
		if o.Bus != nil {
			o.Events = o.Bus
		} else {
			o.Events = events.Discard
		}
	}
	if o.Heartbeat <= 0 {
		o.Heartbeat = 15 * time.Second
	}
	if o.StreamQueue <= 0 {
		o.StreamQueue = 1024
	}
	s := &Server{o: o, log: o.Logger, started: o.Now()}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.auth.Store(&authState{buckets: newBuckets(0)})
	return s
}

// Handler returns the API handler for a TCP listener (tokens required).
func (s *Server) Handler() http.Handler { return s.handler(kindAPI) }

// IPCHandler returns the handler of the IPC socket: no token, scope admin.
func (s *Server) IPCHandler() http.Handler { return s.handler(kindIPC) }

// MetricsHandler returns the handler of a separate metrics listener.
func (s *Server) MetricsHandler() http.Handler { return s.handler(kindMetrics) }

func (s *Server) handler(k kind) http.Handler {
	mux := http.NewServeMux()
	for _, rt := range routeTable {
		if k == kindMetrics && rt.Path != "/metrics" && rt.Scope != ScopePublic {
			continue
		}
		mux.Handle(rt.Method+" "+rt.Path, s.wrap(k, rt))
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { s.noRoute(k, w, r) })
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

// noRoute answers 405 for a known path with another method, else 404.
func (s *Server) noRoute(k kind, w http.ResponseWriter, r *http.Request) {
	var allow []string
	for _, rt := range routeTable {
		if (k != kindMetrics || rt.Path == "/metrics" || rt.Scope == ScopePublic) && pathMatches(rt.Path, r.URL.Path) {
			allow = append(allow, rt.Method)
		}
	}
	if len(allow) > 0 {
		w.Header().Set("Allow", strings.Join(allow, ", "))
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method "+r.Method+" is not allowed")
		return
	}
	writeError(w, http.StatusNotFound, "not_found", "no such endpoint")
}

// pathMatches reports whether path fits the pattern with {param} segments.
func pathMatches(pattern, path string) bool {
	ps, xs := strings.Split(pattern, "/"), strings.Split(path, "/")
	if len(ps) != len(xs) {
		return false
	}
	for i, p := range ps {
		if strings.HasPrefix(p, "{") {
			if xs[i] == "" {
				return false
			}
			continue
		}
		if p != xs[i] {
			return false
		}
	}
	return true
}

// call is the authenticated context of one request.
type call struct {
	kind  kind
	ip    string
	token string
}

// wrap applies the rate limit, authentication, scope and audit to a route.
func (s *Server) wrap(k kind, rt route) http.Handler {
	audited := rt.Scope == ScopeLocksWrite || rt.Scope == ScopeAdmin
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := &call{kind: k, ip: remoteIP(r)}
		rec := &recorder{ResponseWriter: w, status: http.StatusOK}
		if audited {
			defer func() { s.audit(r, c, rec.status) }()
		}
		if s.authorize(rec, r, c, rt.Scope) {
			rt.h(s, rec, r, c)
		}
	})
}

// authorize decides a request; it writes the refusal and returns false.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, c *call, scope string) bool {
	st := s.auth.Load()
	if c.kind == kindIPC {
		c.token = "ipc"
		return true
	}
	if !st.buckets.take(c.ip, s.o.Now()) {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
		return false
	}
	if scope == ScopeMetrics {
		if !st.metricsEnabled {
			writeError(w, http.StatusNotFound, "not_found", "metrics are disabled")
			return false
		}
		scope = ScopeStatusRead
		if st.metricsPublic {
			scope = ScopePublic
		}
	}
	if scope == ScopePublic {
		return true
	}
	t := st.match(bearer(r))
	if t == nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="aldap"`)
		writeError(w, http.StatusUnauthorized, "unauthorized", "a valid bearer token is required")
		return false
	}
	c.token = t.name
	if !t.allowedFrom(c.ip) {
		writeError(w, http.StatusForbidden, "forbidden_source", "the token is not allowed from this address")
		return false
	}
	if !t.has(scope) {
		writeError(w, http.StatusForbidden, "insufficient_scope", "the token lacks scope "+scope)
		return false
	}
	return true
}

// audit emits api_call for locks:write and admin endpoints (SPEC §7),
// refused attempts included.
func (s *Server) audit(r *http.Request, c *call, status int) {
	ip := c.ip
	if c.kind == kindIPC {
		ip = "local"
	}
	lvl := events.LevelLow
	if status >= 400 {
		lvl = events.LevelMedium
	}
	ev := events.Event{Event: events.APICall, Level: lvl,
		Data: map[string]any{"method": r.Method, "path": r.URL.Path, "token_name": c.token, "client_ip": ip, "status": status}}
	if c.kind != kindIPC {
		ev.ClientIP = c.ip
	}
	s.o.Events.Emit(ev)
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// recorder keeps the status for the audit event; Unwrap lets
// http.ResponseController reach Flush and the write deadline.
type recorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (r *recorder) WriteHeader(code int) {
	if !r.wrote {
		r.status, r.wrote = code, true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	r.wrote = true
	return r.ResponseWriter.Write(b)
}

func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// apiError is the error body of every endpoint (SPEC §7).
type apiError struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "response encoding failed")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n')) //nolint:errcheck // the client may be gone
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	b, _ := json.Marshal(apiError{Error: msg, Code: code}) //nolint:errcheck // two strings always encode
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n')) //nolint:errcheck // the client may be gone
}

// backendError maps the Backend sentinels to HTTP answers.
func backendError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, ErrInvalidConfig):
		writeError(w, http.StatusBadRequest, "invalid_config", err.Error())
	case errors.Is(err, ErrNoConfigFile):
		writeError(w, http.StatusConflict, "no_config_file", err.Error())
	case errors.Is(err, ErrNotReplica):
		writeError(w, http.StatusConflict, "not_replica", err.Error())
	case errors.Is(err, ErrNotImplemented):
		writeError(w, http.StatusNotImplemented, "not_implemented", err.Error())
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		writeError(w, http.StatusServiceUnavailable, "timeout", err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
	}
}

// CheckTransport refuses a listener that is not on loopback when TLS is
// off (SPEC §3.4 [api].tls). It looks at the bound address, so a host
// name or a wildcard address cannot slip through.
func CheckTransport(addr net.Addr, withTLS bool) error {
	if withTLS {
		return nil
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		if a.IP.IsLoopback() {
			return nil
		}
	case *net.UnixAddr:
		return nil
	}
	if isPipe(addr) {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrInsecureListen, addr)
}

// ServeAPI serves the API on ln (TLS when tlsCfg is set). A non-loopback
// listener without TLS is refused and closed.
func (s *Server) ServeAPI(ln net.Listener, tlsCfg *tls.Config) error {
	return s.serve(ln, tlsCfg, kindAPI)
}

// ServeMetrics serves /metrics (and the health endpoints) on a separate listener.
func (s *Server) ServeMetrics(ln net.Listener, tlsCfg *tls.Config) error {
	return s.serve(ln, tlsCfg, kindMetrics)
}

// isPipe reports a Windows named pipe listener (go-winio reports the
// network "pipe"); it is local only and restricted by its ACL.
func isPipe(addr net.Addr) bool { return addr.Network() == "pipe" }

// ServeIPC serves the IPC socket or named pipe (no token, scope admin).
func (s *Server) ServeIPC(ln net.Listener) error {
	if _, ok := ln.Addr().(*net.UnixAddr); !ok && !isPipe(ln.Addr()) {
		_ = ln.Close() //nolint:errcheck // refused listener
		return fmt.Errorf("ipc: %s is not a unix socket or a named pipe", ln.Addr())
	}
	return s.serve(ln, nil, kindIPC)
}

func (s *Server) serve(ln net.Listener, tlsCfg *tls.Config, k kind) error {
	if err := CheckTransport(ln.Addr(), tlsCfg != nil); err != nil {
		_ = ln.Close() //nolint:errcheck // refused listener
		return err
	}
	if tlsCfg != nil {
		ln = tls.NewListener(ln, tlsCfg)
	}
	hs := &http.Server{
		Handler:           s.handler(k),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		BaseContext:       func(net.Listener) context.Context { return s.ctx },
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
	}
	s.mu.Lock()
	s.servers = append(s.servers, hs)
	s.mu.Unlock()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("api listener stopped", "addr", ln.Addr().String(), "err", err)
		}
	}()
	s.log.Info("api listening", "addr", ln.Addr().String(), "tls", tlsCfg != nil, "kind", kindName(k))
	return nil
}

func kindName(k kind) string {
	switch k {
	case kindIPC:
		return "ipc"
	case kindMetrics:
		return "metrics"
	case kindAPI:
	}
	return "api"
}

// Shutdown ends the SSE streams and stops every listener within ctx.
func (s *Server) Shutdown(ctx context.Context) {
	s.cancel()
	s.mu.Lock()
	servers := s.servers
	s.servers = nil
	s.mu.Unlock()
	for _, hs := range servers {
		if err := hs.Shutdown(ctx); err != nil {
			_ = hs.Close() //nolint:errcheck // forced close after the timeout
		}
	}
	s.wg.Wait()
}
