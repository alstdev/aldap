package upstream

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/ldapfilter"
	"github.com/alstdev/aldap/internal/metrics"
)

// Options tune an Upstream. All fields are optional.
type Options struct {
	// Logger defaults to slog.Default().
	Logger *slog.Logger
	// Events receives upstream_down/upstream_up/insecure_config.
	Events EventSink
	// Now is the clock (tests).
	Now func() time.Time
	// Metrics receives upstream counters (nil = none).
	Metrics *metrics.Metrics

	dial dialFunc
}

// Upstream is one [upstream.<name>] with its servers, pools and health loops.
type Upstream struct {
	name     string
	cfg      config.Upstream
	password string
	servers  []*server
	dial     dialFunc
	log      *slog.Logger
	events   EventSink
	now      func() time.Time
	metrics  *metrics.Metrics

	rr      atomic.Uint32
	current atomic.Int64
	closed  atomic.Bool

	mu     sync.Mutex
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New builds an Upstream from a validated configuration. bindPassword is the
// resolved service account password ("" for anonymous service access).
func New(name string, cfg *config.Upstream, bindPassword string, opts Options) (*Upstream, error) {
	if cfg == nil {
		return nil, errors.New("upstream: nil config")
	}
	if len(cfg.Servers) == 0 {
		return nil, fmt.Errorf("upstream %s: no servers", name)
	}
	u := &Upstream{name: name, cfg: *cfg, password: bindPassword, log: opts.Logger, events: opts.Events, now: opts.Now, dial: opts.dial, metrics: opts.Metrics}
	if u.log == nil {
		u.log = slog.Default()
	}
	u.log = u.log.With("upstream", name)
	if u.now == nil {
		u.now = time.Now
	}
	if u.dial == nil {
		tc, err := buildTLSConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("upstream %s: %w", name, err)
		}
		d := &dialer{cfg: &u.cfg, tls: tc, log: u.log}
		u.dial = d.dial
	}
	for i, raw := range cfg.Servers {
		su, err := ParseServerURL(raw)
		if err != nil {
			return nil, fmt.Errorf("upstream %s: %w", name, err)
		}
		s := &server{url: su, index: i, kick: make(chan struct{}, 1)}
		s.svc = newPool(cfg.Pool.Size, time.Duration(cfg.Pool.MaxIdle), u.now, u.log, u.serviceDialer(s))
		s.bind = newPool(cfg.Pool.Size, time.Duration(cfg.Pool.MaxIdle), u.now, u.log, u.plainDialer(s))
		u.servers = append(u.servers, s)
	}
	return u, nil
}

// Name returns the upstream name.
func (u *Upstream) Name() string { return u.name }

// Config returns a copy of the configuration.
func (u *Upstream) Config() config.Upstream { return u.cfg }

// serviceDialer opens a connection and binds the service account.
func (u *Upstream) serviceDialer(s *server) func(ctx context.Context) (ldapConn, error) {
	return func(ctx context.Context) (ldapConn, error) {
		c, err := u.dial(ctx, s.url)
		if err != nil {
			return nil, err
		}
		if u.cfg.BindDN != "" {
			c.SetTimeout(time.Duration(u.cfg.Timeouts.Bind))
			if err := c.Bind(u.cfg.BindDN, u.password); err != nil {
				closeQuietly(c, u.log)
				return nil, fmt.Errorf("service bind %s: %w", s.url, err)
			}
		}
		c.SetTimeout(time.Duration(u.cfg.Timeouts.Search))
		return c, nil
	}
}

// plainDialer opens an unbound connection for the bind-only pool.
func (u *Upstream) plainDialer(s *server) func(ctx context.Context) (ldapConn, error) {
	return func(ctx context.Context) (ldapConn, error) {
		c, err := u.dial(ctx, s.url)
		if err != nil {
			return nil, err
		}
		c.SetTimeout(time.Duration(u.cfg.Timeouts.Bind))
		return c, nil
	}
}

// Start launches the health loops and the service-account audit. It returns
// immediately; servers stay "unknown" until their first check.
func (u *Upstream) Start(ctx context.Context) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.cancel != nil || u.closed.Load() {
		return
	}
	ctx, u.cancel = context.WithCancel(ctx)
	for _, s := range u.servers {
		u.wg.Add(1)
		go func(s *server) {
			defer u.wg.Done()
			u.healthLoop(ctx, s)
		}(s)
	}
	if u.cfg.TLSInsecureSkipVerify {
		u.log.Warn("tls_insecure_skip_verify is enabled: upstream certificates are not verified")
		u.emit(Event{Kind: EventInsecureConfig, Level: "medium", Upstream: u.name, Data: map[string]any{"what": "tls_insecure_skip_verify"}})
	}
	if !u.cfg.StartTLS {
		for _, s := range u.servers {
			if !s.url.TLS() {
				// SPEC §9: ldap:// without StartTLS sends the service password and
				// every user password to the directory in clear text.
				u.log.Warn("plain ldap:// to upstream without StartTLS: credentials cross the network unencrypted", "server", s.url.String())
				u.emit(Event{Kind: EventInsecureConfig, Level: "medium", Upstream: u.name, Server: s.url.String(),
					Data: map[string]any{"what": "plaintext_upstream", "server": s.url.String()}})
			}
		}
	}
	if u.cfg.AuditServiceAccount && u.cfg.BindDN != "" {
		u.wg.Add(1)
		go func() {
			defer u.wg.Done()
			u.runAudit(ctx)
		}()
	}
}

// Close stops the loops and closes every pooled connection.
func (u *Upstream) Close() {
	if u.closed.Swap(true) {
		return
	}
	u.mu.Lock()
	cancel := u.cancel
	u.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	u.wg.Wait()
	for _, s := range u.servers {
		s.svc.close()
		s.bind.close()
	}
}

// Status returns a snapshot of every server in list order.
func (u *Upstream) Status() []ServerStatus {
	out := make([]ServerStatus, len(u.servers))
	for i, s := range u.servers {
		out[i] = s.status()
	}
	return out
}

// Healthy reports whether at least one server is up.
func (u *Upstream) Healthy() bool {
	for _, s := range u.servers {
		if s.getState() == StateUp {
			return true
		}
	}
	return false
}

// candidates returns the servers to try, in order (SPEC §5.2): down servers
// are skipped; "primary" with prefer_primary uses list order, without it the
// server that served the last request stays first; "roundrobin" rotates
// the up servers. Unknown servers come after up ones.
func (u *Upstream) candidates() []*server {
	var up, unknown []*server
	for _, s := range u.servers {
		switch s.getState() {
		case StateUp:
			up = append(up, s)
		case StateUnknown:
			unknown = append(unknown, s)
		case StateDown:
		}
	}
	switch {
	case u.cfg.Failover.Strategy == "roundrobin" && len(up) > 1:
		n := int(u.rr.Add(1)-1) % len(up)
		up = append(append([]*server(nil), up[n:]...), up[:n]...)
	case !u.cfg.Failover.PreferPrimary && len(up) > 1:
		cur := int(u.current.Load())
		for i, s := range up {
			if s.index == cur {
				up = append(append([]*server{s}, up[:i]...), up[i+1:]...)
				break
			}
		}
	}
	return append(up, unknown...)
}

// do runs fn against the candidate servers until one answers. A server
// failure (connection error) is recorded against the server and, when retry
// is set, the next candidate is tried; any other error is returned as is.
func (u *Upstream) do(ctx context.Context, op string, retry bool, fn func(ctx context.Context, s *server) error) error {
	if u.closed.Load() {
		return ErrClosed
	}
	cands := u.candidates()
	if len(cands) == 0 {
		return fmt.Errorf("%w: all servers down", ErrUnavailable)
	}
	var last error
	for _, s := range cands {
		start := u.now()
		err := fn(ctx, s)
		d := u.now().Sub(start)
		if err == nil {
			u.metrics.Upstream(u.name, s.url.String(), op, "ok", d)
			u.observe(s, true, nil, d)
			u.current.Store(int64(s.index))
			return nil
		}
		if !isConnError(err) {
			// The server answered; the request itself failed.
			u.metrics.Upstream(u.name, s.url.String(), op, "error", d)
			u.observe(s, true, nil, d)
			return err
		}
		u.metrics.Upstream(u.name, s.url.String(), op, "conn_error", d)
		u.observe(s, false, err, d)
		last = err
		if ctx.Err() != nil || !retry {
			break
		}
	}
	return fmt.Errorf("%w: %w", ErrUnavailable, last)
}

// observe records an operation or health result and emits transitions.
func (u *Upstream) observe(s *server, ok bool, err error, d time.Duration) {
	now := u.now()
	tr, changed := s.record(ok, err, d, u.cfg.Failover, now)
	if !ok {
		s.requestCheck()
	}
	if !changed {
		return
	}
	u.metrics.SetUpstreamUp(u.name, s.url.String(), tr.to == StateUp)
	switch tr.to {
	case StateUp:
		u.log.Info("upstream server up", "server", s.url.String(), "consecutive", tr.consecutive)
		if tr.from == StateDown {
			u.emit(Event{Kind: EventUpstreamUp, Level: "medium", Upstream: u.name, Server: s.url.String(),
				Data: map[string]any{"server": s.url.String(), "reason": "recovered", "consecutive": tr.consecutive}})
		}
	case StateDown:
		u.log.Warn("upstream server down", "server", s.url.String(), "reason", tr.reason, "consecutive", tr.consecutive)
		s.svc.drain()
		s.bind.drain()
		u.emit(Event{Kind: EventUpstreamDown, Level: "high", Upstream: u.name, Server: s.url.String(),
			Data: map[string]any{"server": s.url.String(), "reason": tr.reason, "consecutive": tr.consecutive}})
	case StateUnknown:
	}
}

func (u *Upstream) emit(e Event) {
	if u.events != nil {
		u.events.Emit(e)
	}
}

// Scope of a search.
type Scope int

// Search scopes.
const (
	ScopeBase Scope = iota
	ScopeOne
	ScopeSub
)

func (s Scope) ldap() int {
	switch s {
	case ScopeOne:
		return ldap.ScopeSingleLevel
	case ScopeSub:
		return ldap.ScopeWholeSubtree
	default:
		return ldap.ScopeBaseObject
	}
}

// SearchRequest is a read-only search against the upstream.
type SearchRequest struct {
	Base  string
	Scope Scope
	// Filter is serialized with SerializeFilter; nil means (objectClass=*).
	Filter *ldapfilter.Filter
	// Attrs are the attributes to return; empty means all user attributes.
	Attrs []string
	// SizeLimit caps the number of entries (0 = unlimited).
	SizeLimit int
	// TimeLimit is sent to the server (0 = none).
	TimeLimit time.Duration
}

// Entry is one result entry. Attribute names are lower-cased keys.
type Entry struct {
	DN    string
	Attrs map[string][]string
}

// Get returns the values of an attribute (case-insensitive).
func (e Entry) Get(name string) []string { return e.Attrs[strings.ToLower(name)] }

// First returns the first value of an attribute or "".
func (e Entry) First(name string) string {
	if v := e.Get(name); len(v) > 0 {
		return v[0]
	}
	return ""
}

// Result is the outcome of a Search.
type Result struct {
	Entries []Entry
	// Pages is the number of pages fetched (0 when no query was sent).
	Pages int
	// Server is the URL that answered ("" when no query was sent).
	Server string
	// Referrals counts ignored search references.
	Referrals int
	// Truncated is set when SizeLimit or the server size limit cut the result.
	Truncated bool
	// Cached is set by internal/cache when the result came from memory
	// (no query was sent); Stale when it had outlived the cache ttl and was
	// served because every server was down; Age is its age then.
	Cached, Stale bool
	Age           time.Duration
}

// Search runs a paged search with failover. An absolute false filter yields
// an empty result without touching the upstream.
func (u *Upstream) Search(ctx context.Context, req SearchRequest) (*Result, error) {
	filter, err := SerializeFilter(req.Filter)
	if errors.Is(err, ErrAbsoluteFalse) {
		return &Result{}, nil
	}
	if err != nil {
		return nil, err
	}
	var res *Result
	err = u.do(ctx, "search", true, func(ctx context.Context, s *server) error {
		r, err := u.searchOn(ctx, s, req, filter)
		if err != nil {
			return err
		}
		res = r
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (u *Upstream) searchOn(ctx context.Context, s *server, req SearchRequest, filter string) (*Result, error) {
	c, err := s.svc.get(ctx)
	if err != nil {
		return nil, err
	}
	healthy := true
	defer func() { s.svc.put(c, healthy) }()
	res := &Result{Server: s.url.String()}
	pageSize := uint32(500)
	if n := u.cfg.PageSize; n > 0 && n <= math.MaxUint32 {
		pageSize = uint32(n)
	}
	paging := ldap.NewControlPaging(pageSize)
	timeLimit := int(req.TimeLimit / time.Second)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lr := ldap.NewSearchRequest(req.Base, req.Scope.ldap(), ldap.NeverDerefAliases, req.SizeLimit, timeLimit, false, filter, req.Attrs, []ldap.Control{paging})
		sr, err := c.Search(lr)
		if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
			if ldap.IsErrorWithCode(err, ldap.LDAPResultReferral) {
				return nil, fmt.Errorf("%w: %w", ErrReferral, err)
			}
			if isConnError(err) {
				healthy = false
			}
			return nil, err
		}
		if err != nil {
			res.Truncated = true
		}
		res.Pages++
		if sr != nil {
			res.Referrals += len(sr.Referrals)
			for _, e := range sr.Entries {
				res.Entries = append(res.Entries, convertEntry(e))
			}
		}
		if req.SizeLimit > 0 && len(res.Entries) >= req.SizeLimit {
			res.Truncated = res.Truncated || len(res.Entries) > req.SizeLimit
			res.Entries = res.Entries[:req.SizeLimit]
			u.abandonPaging(c, lr, sr)
			return res, nil
		}
		if res.Truncated || sr == nil {
			return res, nil
		}
		ctl := pagingControl(sr.Controls)
		if ctl == nil || len(ctl.Cookie) == 0 {
			return res, nil
		}
		paging.SetCookie(ctl.Cookie)
	}
}

// abandonPaging tells the server to drop the paging cursor (page size 0).
func (u *Upstream) abandonPaging(c ldapConn, lr *ldap.SearchRequest, sr *ldap.SearchResult) {
	if sr == nil {
		return
	}
	ctl := pagingControl(sr.Controls)
	if ctl == nil || len(ctl.Cookie) == 0 {
		return
	}
	stop := ldap.NewControlPaging(0)
	stop.SetCookie(ctl.Cookie)
	lr.Controls = []ldap.Control{stop}
	if _, err := c.Search(lr); err != nil {
		u.log.Debug("abandon paging", "err", err)
	}
}

// pagingControl extracts the paged results control, if any.
func pagingControl(controls []ldap.Control) *ldap.ControlPaging {
	ctl, ok := ldap.FindControl(controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
	if !ok {
		return nil
	}
	return ctl
}

func convertEntry(e *ldap.Entry) Entry {
	out := Entry{DN: e.DN, Attrs: make(map[string][]string, len(e.Attributes))}
	for _, a := range e.Attributes {
		out.Attrs[strings.ToLower(a.Name)] = append(out.Attrs[strings.ToLower(a.Name)], a.Values...)
	}
	return out
}

// RootDSE reads the root DSE of the first available server.
func (u *Upstream) RootDSE(ctx context.Context, attrs ...string) (*Entry, error) {
	res, err := u.Search(ctx, SearchRequest{Base: "", Scope: ScopeBase, Attrs: attrs})
	if err != nil {
		return nil, err
	}
	if len(res.Entries) == 0 {
		return nil, errors.New("rootdse: empty response")
	}
	e := res.Entries[0]
	return &e, nil
}

// UserBind authenticates a user on a bind-only connection (SPEC §4.3). A
// credential failure returns *BindError (never retried on another server);
// a server failure is retried on the next up server and finally reported as
// ErrUnavailable. An empty password is refused locally.
func (u *Upstream) UserBind(ctx context.Context, dn, password string) error {
	if password == "" {
		return &BindError{Reason: ReasonAnonymous, Err: ErrEmptyPassword}
	}
	if dn == "" {
		return &BindError{Reason: ReasonUnknownAccount, Err: errors.New("empty bind name")}
	}
	return u.do(ctx, "bind", true, func(ctx context.Context, s *server) error {
		c, err := s.bind.get(ctx)
		if err != nil {
			return err
		}
		err = c.Bind(dn, password)
		switch {
		case err == nil:
			s.bind.put(c, true)
			return nil
		case ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials):
			s.bind.put(c, true)
			reason, data := ClassifyBindError(err)
			return &BindError{Reason: reason, Data: data, Err: err}
		case isConnError(err) || c.IsClosing():
			s.bind.put(c, false)
			return fmt.Errorf("%w: %w", ErrConnect, err)
		default:
			s.bind.put(c, true)
			return &BindError{Reason: ReasonUpstreamError, Err: err}
		}
	})
}
