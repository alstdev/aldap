package listener

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/metrics"
)

// Transports of [profile.<name>].transport.
const (
	TransportLDAP          = "ldap"
	TransportLDAPS         = "ldaps"
	TransportStartTLS      = "starttls"
	TransportLDAPStartTLS  = "ldap+starttls"
	readBufferSize         = 4096
	defaultFirstPacket     = 5 * time.Second
	defaultWriteTimeout    = 30 * time.Second
	defaultHandshake       = 10 * time.Second
	defaultMaxRequestBytes = 1 << 20
)

// Config describes one listener (one profile, one or more addresses).
type Config struct {
	// Profile is the profile name used in events and logs.
	Profile string
	// Transport is ldap, ldaps, starttls or ldap+starttls.
	Transport string
	// StartTLSRequired refuses binds and searches (except the root DSE)
	// before StartTLS on ldap+starttls listeners. transport = starttls
	// implies it.
	StartTLSRequired bool
	// TLS is the server configuration; required unless Transport is ldap.
	TLS *tls.Config
	// Handler serves Bind and Search.
	Handler Handler

	// MaxRequestBytes closes a connection that sends a longer message (0 = 1 MiB).
	MaxRequestBytes int64
	// IdleTimeout closes a connection without requests for this long (0 = none).
	IdleTimeout time.Duration
	// FirstPacketTimeout bounds the wait for the first request (0 = 5 s).
	FirstPacketTimeout time.Duration
	// WriteTimeout bounds every response write (0 = 30 s).
	WriteTimeout time.Duration
	// HandshakeTimeout bounds TLS handshakes (0 = 10 s).
	HandshakeTimeout time.Duration
	// PerIP limits concurrent connections per client IP; shared between
	// the listeners of one profile. nil = unlimited.
	PerIP *IPLimiter
	// Global limits concurrent connections of the whole process. nil = unlimited.
	Global *Limiter

	Logger *slog.Logger
	Events events.Sink
	// Fingerprints receives the client fingerprint of every connection
	// (TLS ClientHello hash and LDAP first packet); nil disables it.
	Fingerprints Fingerprinter
	// Metrics receives connection gauges (nil = none).
	Metrics *metrics.Metrics
}

// Server serves one profile on one or more addresses. Its configuration
// can be replaced while it runs (Reconfigure): every request runs under the
// configuration that was current when the request started.
type Server struct {
	gen atomic.Pointer[generation]

	ctx    context.Context
	cancel context.CancelFunc
	nextID atomic.Uint64

	mu        sync.Mutex
	listeners map[net.Listener]struct{}
	conns     map[*Conn]struct{}
	closed    bool
	wg        sync.WaitGroup
}

// generation is one configuration of a Server. Requests hold it (acquire)
// while they run; a retired generation takes no new requests, so waiting
// for its active count to drop to zero waits for the requests that still
// use it (and the handler resources behind it).
type generation struct {
	cfg            Config
	log            *slog.Logger
	events         events.Sink
	requireTLS     bool
	offersStartTLS bool
	ldaps          bool

	mu      sync.Mutex
	retired bool
	active  sync.WaitGroup
}

// newGeneration validates cfg and fills the defaults.
func newGeneration(cfg Config) (*generation, error) {
	if cfg.Handler == nil {
		return nil, errors.New("listener: handler is required")
	}
	g := &generation{cfg: cfg, log: cfg.Logger, events: cfg.Events}
	if g.log == nil {
		g.log = slog.Default()
	}
	g.log = g.log.With("profile", cfg.Profile)
	if g.events == nil {
		g.events = events.Discard
	}
	switch cfg.Transport {
	case TransportLDAP:
	case TransportLDAPS:
		g.ldaps = true
	case TransportStartTLS:
		g.offersStartTLS, g.requireTLS = true, true
	case TransportLDAPStartTLS:
		g.offersStartTLS, g.requireTLS = true, cfg.StartTLSRequired
	default:
		return nil, fmt.Errorf("listener: unknown transport %q", cfg.Transport)
	}
	if cfg.Transport != TransportLDAP && cfg.TLS == nil {
		return nil, fmt.Errorf("listener: transport %s needs a TLS configuration", cfg.Transport)
	}
	if g.cfg.MaxRequestBytes <= 0 {
		g.cfg.MaxRequestBytes = defaultMaxRequestBytes
	}
	if g.cfg.FirstPacketTimeout <= 0 {
		g.cfg.FirstPacketTimeout = defaultFirstPacket
	}
	if g.cfg.WriteTimeout <= 0 {
		g.cfg.WriteTimeout = defaultWriteTimeout
	}
	if g.cfg.HandshakeTimeout <= 0 {
		g.cfg.HandshakeTimeout = defaultHandshake
	}
	return g, nil
}

// done ends one request started with Server.acquire.
func (g *generation) done() { g.active.Done() }

// retire stops new requests from using g; the caller has already made
// another generation current.
func (g *generation) retire() {
	g.mu.Lock()
	g.retired = true
	g.mu.Unlock()
}

// wait blocks until the requests running under g have finished or ctx ends.
func (g *generation) wait(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		g.active.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Check validates cfg as New and Reconfigure would, without a Server.
func Check(cfg Config) error {
	_, err := newGeneration(cfg)
	return err
}

// New validates cfg and prepares a Server; call Serve or ListenAndServe.
func New(cfg Config) (*Server, error) {
	g, err := newGeneration(cfg)
	if err != nil {
		return nil, err
	}
	s := &Server{listeners: map[net.Listener]struct{}{}, conns: map[*Conn]struct{}{}}
	s.gen.Store(g)
	s.ctx, s.cancel = context.WithCancel(context.Background())
	return s, nil
}

// current returns the configuration new connections and checks use.
func (s *Server) current() *generation { return s.gen.Load() }

// acquire returns the current generation with one more active request;
// the caller ends it with done.
func (s *Server) acquire() *generation {
	for {
		g := s.gen.Load()
		g.mu.Lock()
		if !g.retired {
			g.active.Add(1)
			g.mu.Unlock()
			return g
		}
		// Retired generations are swapped out before they retire: the next
		// load returns the newer one.
		g.mu.Unlock()
	}
}

// Reconfigure atomically replaces the configuration (SPEC §3.6): requests
// already running finish under the old one, every later request and new
// connection uses cfg. Connections accepted for another profile or
// transport than cfg names are ended with a Notice of Disconnection once
// their current request is answered — a plain connection is never kept on
// a listener that became ldaps, and vice versa. The returned wait blocks
// until the requests of the replaced configuration have finished (or its
// ctx ends), so their handler resources can be released afterwards.
func (s *Server) Reconfigure(cfg Config) (wait func(context.Context) error, err error) {
	g, err := newGeneration(cfg)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrServerClosed
	}
	old := s.gen.Swap(g)
	var stale []*Conn
	for c := range s.conns {
		if c.profile != cfg.Profile || c.transport != cfg.Transport {
			stale = append(stale, c)
		}
	}
	s.mu.Unlock()
	old.retire()
	for _, c := range stale {
		c.kick(reasonReconfigured)
	}
	if len(stale) > 0 {
		g.log.Info("listener reconfigured, connections of the previous profile or transport closed", "conns", len(stale))
	}
	return old.wait, nil
}

// Notice of Disconnection texts (RFC 4511 §4.4.1, resultCode unavailable).
const (
	reasonShutdown     = "server shutting down"
	reasonReconfigured = "listener reconfigured"
)

// OffersStartTLS reports whether the listener advertises StartTLS.
func (s *Server) OffersStartTLS() bool { return s.current().offersStartTLS }

// RequiresTLS reports whether binds and searches need an encrypted connection.
func (s *Server) RequiresTLS() bool {
	g := s.current()
	return g.requireTLS || g.ldaps
}

// ListenAndServe listens on addr and serves until Shutdown.
func (s *Server) ListenAndServe(addr string) error {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(s.ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("listener: %w", err)
	}
	return s.Serve(ln)
}

// Serve accepts connections on ln until it is closed by Shutdown. For ldaps
// the TLS handshake happens on the first read; the listener itself stays
// plain so that limits are applied before any handshake work.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		closeQuietly(ln, s.current().log)
		return ErrServerClosed
	}
	s.listeners[ln] = struct{}{}
	s.mu.Unlock()
	g := s.current()
	g.log.Info("listening", "addr", ln.Addr().String(), "transport", g.cfg.Transport)
	for {
		nc, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			delete(s.listeners, ln)
			s.mu.Unlock()
			if closed || errors.Is(err, net.ErrClosed) {
				return ErrServerClosed
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return fmt.Errorf("listener: accept: %w", err)
		}
		s.accept(nc)
	}
}

// ErrServerClosed is returned by Serve after Shutdown.
var ErrServerClosed = errors.New("listener: server closed")

// accept applies the connection limits and starts the per-connection loop.
// The connection keeps the limiters it was counted against, so a reload
// that replaces them releases into the right ones.
func (s *Server) accept(nc net.Conn) {
	g := s.current()
	ip, _ := splitHostPort(nc.RemoteAddr())
	global, perIP := g.cfg.Global, g.cfg.PerIP
	if global != nil && !global.Acquire() {
		g.rejected(nc, ip, "conn_limit_global", global.Limit())
		return
	}
	if perIP != nil && !perIP.Acquire(ip) {
		if global != nil {
			global.Release()
		}
		g.rejected(nc, ip, "conn_limit_ip", perIP.Limit())
		return
	}
	release := func() {
		if perIP != nil {
			perIP.Release(ip)
		}
		if global != nil {
			global.Release()
		}
	}
	c := &Conn{id: fmt.Sprintf("c-%08x", s.nextID.Add(1)), remote: nc.RemoteAddr(), profile: g.cfg.Profile, transport: g.cfg.Transport, opened: time.Now(), nc: nc}
	if g.ldaps {
		tc := tls.Server(nc, g.tlsFor(c))
		c.nc = tc
		c.tls.Store(true)
	}
	c.rd = bufio.NewReaderSize(c.nc, readBufferSize)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		release()
		closeQuietly(nc, g.log)
		return
	}
	s.conns[c] = struct{}{}
	s.wg.Add(1)
	s.mu.Unlock()
	g.log.Debug("connection accepted", "conn_id", c.id, "client_ip", ip, "client_port", c.ClientPort())
	m := g.cfg.Metrics
	m.Connection(c.profile, 1)
	go func() {
		defer s.wg.Done()
		defer release()
		defer func() {
			s.mu.Lock()
			delete(s.conns, c)
			s.mu.Unlock()
			m.Connection(c.profile, -1)
			cur := s.current()
			cur.log.Debug("connection closed", "conn_id", c.id, "client_ip", ip, "duration_ms", time.Since(c.opened).Milliseconds())
			cur.sessionSummary(c)
		}()
		s.serve(s.ctx, c)
	}()
}

// sessionSummary reports the counters of a finished connection (SPEC §6).
func (g *generation) sessionSummary(c *Conn) {
	ev := c.Event(events.SessionSummary, events.LevelLow)
	ev.Duration = time.Since(c.opened)
	ev.Data = map[string]any{
		"binds_ok": c.bindsOK.Load(), "binds_fail": c.bindsFail.Load(), "searches": c.searches.Load(), "results_total": c.results.Load(),
		"denied": c.denied.Load(), "duration_ms": ev.Duration.Milliseconds(), "bytes_in": c.bytesIn.Load(), "bytes_out": c.bytesOut.Load(),
		"fingerprint": c.Fingerprint(),
	}
	g.events.Emit(ev)
}

// tlsFor returns the TLS configuration for one connection: the shared one,
// or a clone that records the ClientHello fingerprint when a Fingerprinter
// is configured.
func (g *generation) tlsFor(c *Conn) *tls.Config {
	if g.cfg.Fingerprints == nil {
		return g.cfg.TLS
	}
	cfg := g.cfg.TLS.Clone()
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		c.setTLSFingerprint(HelloFingerprint(hello))
		return nil, nil
	}
	return cfg
}

// rejected closes a connection over the limit and reports rate_limited.
func (g *generation) rejected(nc net.Conn, ip, reason string, limit int) {
	g.log.Warn("connection rejected", "client_ip", ip, "reason", reason, "limit", limit)
	g.events.Emit(events.Event{Event: events.RateLimited, Level: events.LevelLow, Profile: g.cfg.Profile, ClientIP: ip,
		Reason: reason, Data: map[string]any{"target": "conn", "key": ip, "limit": limit}})
	closeQuietly(nc, g.log)
}

// closeQuietly closes c and logs a failure at debug level.
func closeQuietly(c io.Closer, log *slog.Logger) {
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Debug("close failed", "err", err)
	}
}

// Shutdown drains the server (SPEC §5.3): it stops accepting, lets every
// connection finish the request it is serving, then ends it with a Notice
// of Disconnection (unavailable) — idle connections at once. Connections
// still busy when ctx ends get the notice, are closed and their requests
// canceled; Shutdown then returns ctx's error.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	g := s.current()
	for ln := range s.listeners {
		closeQuietly(ln, g.log)
	}
	conns := make([]*Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		c.kick(reasonShutdown)
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	var err error
	select {
	case <-done:
	case <-ctx.Done():
		err = ctx.Err()
		s.mu.Lock()
		conns = conns[:0]
		for c := range s.conns {
			conns = append(conns, c)
		}
		s.mu.Unlock()
		notice := encodeNotice(ldap.LDAPResultUnavailable, reasonShutdown)
		for _, c := range conns {
			c.writeQuietly(g.log, notice, time.Second)
			c.close()
		}
		s.cancel()
		<-done
	}
	s.cancel()
	return err
}

// Close is Shutdown with an already-expired context: connections are cut at once.
func (s *Server) Close() {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// The only error Shutdown returns is the expired context.
	if err := s.Shutdown(ctx); err != nil && !errors.Is(err, context.Canceled) {
		s.current().log.Debug("close", "err", err)
	}
}

// ConnCount returns the number of open connections.
func (s *Server) ConnCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

// Limiter counts concurrent connections against a global limit. It keeps
// counting while unlimited, so a reload can set a limit (SetLimit) without
// losing the connections already open.
type Limiter struct {
	limit atomic.Int64
	n     atomic.Int64
}

// NewLimiter returns a limiter of at most n concurrent connections (n <= 0 = unlimited).
func NewLimiter(n int) *Limiter {
	l := &Limiter{}
	l.limit.Store(int64(n))
	return l
}

// SetLimit changes the maximum (reload); open connections stay counted and
// are never cut by a lower limit.
func (l *Limiter) SetLimit(n int) { l.limit.Store(int64(n)) }

// Acquire takes a slot; false when the limit is reached.
func (l *Limiter) Acquire() bool {
	n := l.n.Add(1)
	if lim := l.limit.Load(); lim > 0 && n > lim {
		l.n.Add(-1)
		return false
	}
	return true
}

// Release frees a slot.
func (l *Limiter) Release() { l.n.Add(-1) }

// Limit returns the configured maximum.
func (l *Limiter) Limit() int { return int(l.limit.Load()) }

// Count returns the current number of connections.
func (l *Limiter) Count() int { return int(l.n.Load()) }

// IPLimiter counts concurrent connections per client IP; like Limiter it
// counts while unlimited.
type IPLimiter struct {
	mu    sync.Mutex
	limit int
	n     map[string]int
}

// NewIPLimiter returns a limiter of at most n connections per IP (n <= 0 = unlimited).
func NewIPLimiter(n int) *IPLimiter { return &IPLimiter{limit: n, n: map[string]int{}} }

// SetLimit changes the maximum per IP (reload).
func (l *IPLimiter) SetLimit(n int) {
	l.mu.Lock()
	l.limit = n
	l.mu.Unlock()
}

// Acquire takes a slot for ip; false when the limit is reached.
func (l *IPLimiter) Acquire(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.limit > 0 && l.n[ip] >= l.limit {
		return false
	}
	l.n[ip]++
	return true
}

// Release frees a slot of ip.
func (l *IPLimiter) Release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.n[ip] <= 1 {
		delete(l.n, ip)
	} else {
		l.n[ip]--
	}
}

// Limit returns the configured maximum per IP.
func (l *IPLimiter) Limit() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.limit
}

// Count returns the current number of connections of ip.
func (l *IPLimiter) Count(ip string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.n[ip]
}
