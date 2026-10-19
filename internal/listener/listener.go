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
}

// Server serves one profile on one or more addresses.
type Server struct {
	cfg            Config
	log            *slog.Logger
	events         events.Sink
	requireTLS     bool
	offersStartTLS bool
	ldaps          bool

	ctx    context.Context
	cancel context.CancelFunc
	nextID atomic.Uint64

	mu        sync.Mutex
	listeners map[net.Listener]struct{}
	conns     map[*Conn]struct{}
	closed    bool
	wg        sync.WaitGroup
}

// New validates cfg and prepares a Server; call Serve or ListenAndServe.
func New(cfg Config) (*Server, error) {
	if cfg.Handler == nil {
		return nil, errors.New("listener: handler is required")
	}
	s := &Server{cfg: cfg, log: cfg.Logger, events: cfg.Events, listeners: map[net.Listener]struct{}{}, conns: map[*Conn]struct{}{}}
	if s.log == nil {
		s.log = slog.Default()
	}
	s.log = s.log.With("profile", cfg.Profile)
	if s.events == nil {
		s.events = events.Discard
	}
	switch cfg.Transport {
	case TransportLDAP:
	case TransportLDAPS:
		s.ldaps = true
	case TransportStartTLS:
		s.offersStartTLS, s.requireTLS = true, true
	case TransportLDAPStartTLS:
		s.offersStartTLS, s.requireTLS = true, cfg.StartTLSRequired
	default:
		return nil, fmt.Errorf("listener: unknown transport %q", cfg.Transport)
	}
	if cfg.Transport != TransportLDAP && cfg.TLS == nil {
		return nil, fmt.Errorf("listener: transport %s needs a TLS configuration", cfg.Transport)
	}
	if s.cfg.MaxRequestBytes <= 0 {
		s.cfg.MaxRequestBytes = defaultMaxRequestBytes
	}
	if s.cfg.FirstPacketTimeout <= 0 {
		s.cfg.FirstPacketTimeout = defaultFirstPacket
	}
	if s.cfg.WriteTimeout <= 0 {
		s.cfg.WriteTimeout = defaultWriteTimeout
	}
	if s.cfg.HandshakeTimeout <= 0 {
		s.cfg.HandshakeTimeout = defaultHandshake
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	return s, nil
}

// OffersStartTLS reports whether the listener advertises StartTLS.
func (s *Server) OffersStartTLS() bool { return s.offersStartTLS }

// RequiresTLS reports whether binds and searches need an encrypted connection.
func (s *Server) RequiresTLS() bool { return s.requireTLS || s.ldaps }

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
		closeQuietly(ln, s.log)
		return ErrServerClosed
	}
	s.listeners[ln] = struct{}{}
	s.mu.Unlock()
	s.log.Info("listening", "addr", ln.Addr().String(), "transport", s.cfg.Transport)
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
func (s *Server) accept(nc net.Conn) {
	ip, _ := splitHostPort(nc.RemoteAddr())
	if s.cfg.Global != nil && !s.cfg.Global.Acquire() {
		s.rejected(nc, ip, "conn_limit_global", s.cfg.Global.Limit())
		return
	}
	if s.cfg.PerIP != nil && !s.cfg.PerIP.Acquire(ip) {
		if s.cfg.Global != nil {
			s.cfg.Global.Release()
		}
		s.rejected(nc, ip, "conn_limit_ip", s.cfg.PerIP.Limit())
		return
	}
	c := &Conn{id: fmt.Sprintf("c-%08x", s.nextID.Add(1)), remote: nc.RemoteAddr(), profile: s.cfg.Profile, opened: time.Now(), nc: nc}
	if s.ldaps {
		tc := tls.Server(nc, s.cfg.TLS)
		c.nc = tc
		c.tls.Store(true)
	}
	c.rd = bufio.NewReaderSize(c.nc, readBufferSize)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.release(ip)
		closeQuietly(nc, s.log)
		return
	}
	s.conns[c] = struct{}{}
	s.wg.Add(1)
	s.mu.Unlock()
	s.log.Debug("connection accepted", "conn_id", c.id, "client_ip", ip, "client_port", c.ClientPort())
	go func() {
		defer s.wg.Done()
		defer s.release(ip)
		defer func() {
			s.mu.Lock()
			delete(s.conns, c)
			s.mu.Unlock()
			s.log.Debug("connection closed", "conn_id", c.id, "client_ip", ip, "duration_ms", time.Since(c.opened).Milliseconds())
		}()
		s.serve(s.ctx, c)
	}()
}

func (s *Server) release(ip string) {
	if s.cfg.PerIP != nil {
		s.cfg.PerIP.Release(ip)
	}
	if s.cfg.Global != nil {
		s.cfg.Global.Release()
	}
}

// rejected closes a connection over the limit and reports rate_limited.
func (s *Server) rejected(nc net.Conn, ip, reason string, limit int) {
	s.log.Warn("connection rejected", "client_ip", ip, "reason", reason, "limit", limit)
	s.events.Emit(events.Event{Event: events.RateLimited, Level: events.LevelLow, Profile: s.cfg.Profile, ClientIP: ip,
		Reason: reason, Data: map[string]any{"target": "conn", "key": ip, "limit": limit}})
	closeQuietly(nc, s.log)
}

// closeQuietly closes c and logs a failure at debug level.
func closeQuietly(c io.Closer, log *slog.Logger) {
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Debug("close failed", "err", err)
	}
}

// Shutdown stops accepting, waits for connections to finish until ctx is
// done, then disconnects the rest with a Notice of Disconnection
// (unavailable) and closes them (SPEC §5.3).
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	for ln := range s.listeners {
		closeQuietly(ln, s.log)
	}
	s.mu.Unlock()
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
		conns := make([]*Conn, 0, len(s.conns))
		for c := range s.conns {
			conns = append(conns, c)
		}
		s.mu.Unlock()
		notice := encodeNotice(ldap.LDAPResultUnavailable, "server shutting down")
		for _, c := range conns {
			c.writeQuietly(s.log, notice, time.Second)
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
		s.log.Debug("close", "err", err)
	}
}

// ConnCount returns the number of open connections.
func (s *Server) ConnCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

// Limiter counts concurrent connections against a global limit.
type Limiter struct {
	limit int64
	n     atomic.Int64
}

// NewLimiter returns a limiter of at most n concurrent connections (n <= 0 = unlimited).
func NewLimiter(n int) *Limiter { return &Limiter{limit: int64(n)} }

// Acquire takes a slot; false when the limit is reached.
func (l *Limiter) Acquire() bool {
	if l.limit <= 0 {
		return true
	}
	if l.n.Add(1) > l.limit {
		l.n.Add(-1)
		return false
	}
	return true
}

// Release frees a slot.
func (l *Limiter) Release() {
	if l.limit > 0 {
		l.n.Add(-1)
	}
}

// Limit returns the configured maximum.
func (l *Limiter) Limit() int { return int(l.limit) }

// Count returns the current number of connections.
func (l *Limiter) Count() int { return int(l.n.Load()) }

// IPLimiter counts concurrent connections per client IP.
type IPLimiter struct {
	limit int
	mu    sync.Mutex
	n     map[string]int
}

// NewIPLimiter returns a limiter of at most n connections per IP (n <= 0 = unlimited).
func NewIPLimiter(n int) *IPLimiter { return &IPLimiter{limit: n, n: map[string]int{}} }

// Acquire takes a slot for ip; false when the limit is reached.
func (l *IPLimiter) Acquire(ip string) bool {
	if l.limit <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.n[ip] >= l.limit {
		return false
	}
	l.n[ip]++
	return true
}

// Release frees a slot of ip.
func (l *IPLimiter) Release(ip string) {
	if l.limit <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.n[ip] <= 1 {
		delete(l.n, ip)
	} else {
		l.n[ip]--
	}
}

// Limit returns the configured maximum per IP.
func (l *IPLimiter) Limit() int { return l.limit }

// Count returns the current number of connections of ip.
func (l *IPLimiter) Count(ip string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.n[ip]
}
