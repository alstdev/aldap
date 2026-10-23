package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/listener"
	"github.com/alstdev/aldap/internal/ratelimit"
	"github.com/alstdev/aldap/internal/upstream"
	"github.com/alstdev/aldap/internal/vdir"
)

// Request limits.
const (
	maxJSONBody   = 64 << 10
	maxConfigBody = 4 << 20
	// DefaultLockDuration applies when POST /v1/locks has no duration.
	DefaultLockDuration = 15 * time.Minute
	// MaxLockDuration bounds manual locks.
	MaxLockDuration = 365 * 24 * time.Hour
	// DefaultLearn applies when POST /v1/baseline/{profile}/learn has no duration.
	DefaultLearn = 24 * time.Hour
	// MaxLearn bounds a learning period.
	MaxLearn          = 30 * 24 * time.Hour
	defaultEventLimit = 1000
	maxEventLimit     = 10000
)

// decodeJSON reads a bounded JSON body and rejects unknown fields; an empty
// body is accepted when optional.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any, optional bool) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if optional && errors.Is(err, io.EOF) {
			return true
		}
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request, _ *call) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request, _ *call) {
	if !s.o.Backend.Ready() {
		writeError(w, http.StatusServiceUnavailable, "not_ready", "a proxy profile has no upstream server up")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request, _ *call) {
	if s.o.Metrics == nil {
		writeError(w, http.StatusNotFound, "not_found", "metrics are disabled")
		return
	}
	s.o.Metrics.Handler().ServeHTTP(w, r)
}

// upstreamServer is the Status view of one server (docs/openapi.yaml UpstreamServer).
type upstreamServer struct {
	URL                 string  `json:"url"`
	State               string  `json:"state"`
	ConsecutiveFailures int     `json:"consecutive_failures"`
	LastError           string  `json:"last_error,omitempty"`
	LatencyP50MS        float64 `json:"latency_p50_ms"`
	LatencyP95MS        float64 `json:"latency_p95_ms"`
}

type status struct {
	Version       string                      `json:"version"`
	UptimeS       int64                       `json:"uptime_s"`
	Lockdown      bool                        `json:"lockdown"`
	Learning      bool                        `json:"learning"`
	Profiles      []string                    `json:"profiles"`
	Upstreams     map[string][]upstreamServer `json:"upstreams"`
	LocksActive   int                         `json:"locks_active"`
	AttacksActive int                         `json:"attacks_active"`
	EventsSeq     uint64                      `json:"events_seq"`
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request, _ *call) {
	st := status{Version: s.o.Version, UptimeS: int64(s.o.Now().Sub(s.started) / time.Second), Profiles: []string{}, Upstreams: map[string][]upstreamServer{}}
	for _, p := range s.o.Backend.Profiles() {
		st.Profiles = append(st.Profiles, p.Name)
	}
	for name, servers := range s.o.Backend.Upstreams() {
		list := make([]upstreamServer, 0, len(servers))
		for _, ss := range servers {
			list = append(list, upstreamServer{URL: ss.URL, State: ss.State.String(), ConsecutiveFailures: ss.ConsecutiveFail, LastError: ss.LastError,
				LatencyP50MS: ms(ss.P50), LatencyP95MS: ms(ss.P95)})
		}
		st.Upstreams[name] = list
	}
	if s.o.Limiter != nil {
		st.Lockdown, _ = s.o.Limiter.Lockdown()
		st.LocksActive = len(s.o.Limiter.Locks())
	}
	if s.o.IDs != nil {
		st.AttacksActive = len(s.o.IDs.Attacks())
		st.Learning = s.o.IDs.Learning()
	}
	if s.o.Bus != nil {
		st.EventsSeq = s.o.Bus.Seq()
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleUpstreams(w http.ResponseWriter, _ *http.Request, _ *call) {
	out := s.o.Backend.Upstreams()
	if out == nil {
		out = map[string][]upstream.ServerStatus{}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleProfiles(w http.ResponseWriter, _ *http.Request, _ *call) {
	out := s.o.Backend.Profiles()
	if out == nil {
		out = []ProfileInfo{}
	}
	writeJSON(w, http.StatusOK, out)
}

// lock is the API view of a lock (docs/openapi.yaml Lock).
type lock struct {
	Target   string    `json:"target"`
	Key      string    `json:"key"`
	Until    time.Time `json:"until"`
	Failures int       `json:"failures"`
	Source   string    `json:"source"`
	Reason   string    `json:"reason,omitempty"`
	Profile  string    `json:"profile,omitempty"`
}

func lockOf(l ratelimit.LockInfo) lock {
	return lock{Target: l.Target, Key: l.Key, Until: l.Until.UTC(), Failures: l.Failures, Source: l.Source, Reason: l.Reason, Profile: l.Profile}
}

func (s *Server) handleLocks(w http.ResponseWriter, _ *http.Request, _ *call) {
	locks := s.o.Limiter.Locks()
	out := make([]lock, 0, len(locks))
	for _, l := range locks {
		out = append(out, lockOf(l))
	}
	writeJSON(w, http.StatusOK, out)
}

// lockKey validates a target and normalizes the key (IP addresses in
// canonical form, accounts as the limiter stores them).
func lockKey(target, key string) (string, error) {
	key = strings.TrimSpace(key)
	switch target {
	case ratelimit.TargetIP:
		a, err := netip.ParseAddr(key)
		if err != nil {
			return "", fmt.Errorf("key %q is not an IP address", key)
		}
		return a.Unmap().String(), nil
	case ratelimit.TargetAccount:
		if key == "" || len(key) > 512 {
			return "", errors.New("key must be 1–512 characters")
		}
		return strings.ToLower(key), nil
	}
	return "", fmt.Errorf("target %q: use ip or account", target)
}

type lockRequest struct {
	Target   string `json:"target"`
	Key      string `json:"key"`
	Duration string `json:"duration"`
	Reason   string `json:"reason"`
}

func (s *Server) handleLockCreate(w http.ResponseWriter, r *http.Request, _ *call) {
	var req lockRequest
	if !decodeJSON(w, r, &req, false) {
		return
	}
	key, err := lockKey(req.Target, req.Key)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	d := DefaultLockDuration
	if req.Duration != "" {
		if d, err = time.ParseDuration(req.Duration); err != nil || d <= 0 || d > MaxLockDuration {
			writeError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf("duration %q: a positive Go duration up to %s", req.Duration, MaxLockDuration))
			return
		}
	}
	if len(req.Reason) > 512 {
		writeError(w, http.StatusBadRequest, "bad_request", "reason is longer than 512 bytes")
		return
	}
	source := ratelimit.SourceAPI
	s.o.Limiter.Lock(req.Target, key, s.o.Now().Add(d), source, req.Reason)
	for _, l := range s.o.Limiter.Locks() {
		if l.Target == req.Target && l.Key == key {
			writeJSON(w, http.StatusCreated, lockOf(l))
			return
		}
	}
	// The lock table is full (the limiter logged it).
	writeError(w, http.StatusServiceUnavailable, "lock_table_full", "the lock could not be recorded")
}

func (s *Server) handleLockDelete(w http.ResponseWriter, r *http.Request, _ *call) {
	target := r.PathValue("target")
	key, err := lockKey(target, r.PathValue("key"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if !s.o.Limiter.Unlock(target, key, ratelimit.SourceAPI) {
		writeError(w, http.StatusNotFound, "not_found", "no active lock for "+target+" "+key)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleLockdown(w http.ResponseWriter, r *http.Request, _ *call) {
	var req struct {
		State string `json:"state"`
	}
	if !decodeJSON(w, r, &req, false) {
		return
	}
	if req.State != "on" && req.State != "off" {
		writeError(w, http.StatusBadRequest, "bad_request", "state must be on or off")
		return
	}
	s.o.Limiter.SetLockdown(req.State == "on", ratelimit.SourceAPI)
	on, src := s.o.Limiter.Lockdown()
	writeJSON(w, http.StatusOK, map[string]any{"lockdown": on, "source": src})
}

// eventFilter parses types=a,b (empty = all kinds).
func eventFilter(r *http.Request) map[string]bool {
	v := strings.TrimSpace(r.URL.Query().Get("types"))
	if v == "" {
		return nil
	}
	m := map[string]bool{}
	for _, t := range strings.Split(v, ",") {
		if t = strings.TrimSpace(t); t != "" {
			m[t] = true
		}
	}
	return m
}

func keep(types map[string]bool, r events.Record) bool { return types == nil || types[r.Event] }

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request, _ *call) {
	q := r.URL.Query()
	var since uint64
	if v := q.Get("since"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "since must be a sequence number")
			return
		}
		since = n
	}
	limit := defaultEventLimit
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxEventLimit {
			writeError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf("limit must be 1–%d", maxEventLimit))
			return
		}
		limit = n
	}
	types := eventFilter(r)
	out := []events.Record{}
	for _, rec := range s.o.Bus.Since(since, 0) {
		if keep(types, rec) {
			out = append(out, rec)
			if len(out) == limit {
				break
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleConfigGet(w http.ResponseWriter, _ *http.Request, _ *call) {
	b, err := s.o.Backend.ConfigTOML()
	if err != nil {
		backendError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/toml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b) //nolint:errcheck // the client may be gone
}

func (s *Server) handleConfigPut(w http.ResponseWriter, r *http.Request, _ *call) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxConfigBody))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", fmt.Sprintf("the configuration exceeds %d bytes", maxConfigBody))
		return
	}
	res, err := s.o.Backend.ApplyConfig(r.Context(), body)
	if err != nil {
		backendError(w, err)
		return
	}
	res.OK = true
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request, _ *call) {
	if err := s.o.Backend.Reload(r.Context()); err != nil {
		backendError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleSync(w http.ResponseWriter, r *http.Request, _ *call) {
	if err := s.o.Backend.Sync(r.Context(), r.PathValue("name")); err != nil {
		backendError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "sync started"})
}

type testRequest struct {
	Base      string   `json:"base"`
	Scope     string   `json:"scope"`
	Filter    string   `json:"filter"`
	Attrs     []string `json:"attrs"`
	SizeLimit int      `json:"size_limit"`
}

type testEntry struct {
	DN    string              `json:"dn"`
	Attrs map[string][]string `json:"attrs"`
}

type testResponse struct {
	ResultCode      int         `json:"result_code"`
	Entries         []testEntry `json:"entries"`
	DeniedAttrs     []string    `json:"denied_attrs"`
	DeniedTerms     []string    `json:"denied_terms"`
	UpstreamQueries int         `json:"upstream_queries"`
	EffectiveFilter string      `json:"effective_filter"`
	PostFilter      string      `json:"post_filter,omitempty"`
	Honeytoken      string      `json:"honeytoken,omitempty"`
	DurationMS      float64     `json:"duration_ms"`
}

func parseScope(s string) (listener.Scope, bool) {
	switch strings.ToLower(s) {
	case "base":
		return listener.ScopeBase, true
	case "one", "onelevel":
		return listener.ScopeOne, true
	case "", "sub", "subtree":
		return listener.ScopeSub, true
	}
	return 0, false
}

func (s *Server) handleTest(w http.ResponseWriter, r *http.Request, _ *call) {
	var req testRequest
	if !decodeJSON(w, r, &req, false) {
		return
	}
	scope, ok := parseScope(req.Scope)
	if !ok || req.Filter == "" || req.SizeLimit < 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "filter is required, scope is base, one or sub, size_limit is not negative")
		return
	}
	res, err := s.o.Backend.Test(r.Context(), r.PathValue("name"), vdir.TestRequest{Base: req.Base, Scope: scope, Filter: req.Filter, Attrs: req.Attrs, SizeLimit: req.SizeLimit})
	if err != nil {
		backendError(w, err)
		return
	}
	out := testResponse{ResultCode: res.Result.Code, Entries: []testEntry{}, DeniedAttrs: nonNil(res.DeniedAttrs), DeniedTerms: nonNil(res.DeniedTerms),
		UpstreamQueries: res.UpstreamQueries, EffectiveFilter: res.UpstreamFilter, PostFilter: res.PostFilter, Honeytoken: res.Honeytoken, DurationMS: ms(res.Duration)}
	for _, e := range res.Entries {
		te := testEntry{DN: e.DN, Attrs: map[string][]string{}}
		for _, a := range e.Attrs {
			te.Attrs[a.Name] = append(te.Attrs[a.Name], a.Values...)
		}
		out.Entries = append(out.Entries, te)
	}
	writeJSON(w, http.StatusOK, out)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (s *Server) hasProfile(name string) bool {
	for _, p := range s.o.Backend.Profiles() {
		if p.Name == name {
			return true
		}
	}
	return false
}

func (s *Server) handleLearn(w http.ResponseWriter, r *http.Request, _ *call) {
	var req struct {
		Duration string `json:"duration"`
	}
	if !decodeJSON(w, r, &req, true) {
		return
	}
	name := r.PathValue("profile")
	if !s.hasProfile(name) {
		writeError(w, http.StatusNotFound, "not_found", "unknown profile "+name)
		return
	}
	d := DefaultLearn
	if req.Duration != "" {
		var err error
		if d, err = time.ParseDuration(req.Duration); err != nil || d <= 0 || d > MaxLearn {
			writeError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf("duration %q: a positive Go duration up to %s", req.Duration, MaxLearn))
			return
		}
	}
	s.o.IDs.Learn(d)
	writeJSON(w, http.StatusAccepted, map[string]any{"learning": true, "until": s.o.Now().Add(d).UTC(), "scope": "process"})
}

// sortedReasons lists the hit kinds of an indicator.
func sortedReasons(hits map[string]int) []string {
	out := make([]string, 0, len(hits))
	for k := range hits {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
