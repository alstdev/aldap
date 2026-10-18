package testdir

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/jimlambrt/gldap"
)

// Sentinel errors.
var (
	// ErrNoSuchObject reports a search base that does not exist.
	ErrNoSuchObject = errors.New("no such object")
	// ErrKilled reports an operation on a killed server.
	ErrKilled = errors.New("server killed")
)

// Counts are the call counters of a server.
type Counts struct {
	// Conns is the number of accepted client connections.
	Conns int64
	// Binds is the number of bind requests handled.
	Binds int64
	// Searches is the number of search requests handled (RootDSE included).
	Searches int64
	// RootDSE is the number of RootDSE reads.
	RootDSE int64
}

// Option configures Start.
type Option func(*options)

type options struct {
	entries     []*Entry
	dir         *Directory
	ldifPath    string
	tls         bool
	maxPageSize int
	adBindCodes bool
	anonSearch  bool
	noStartTLS  bool
	hostName    string
}

// WithEntries seeds the directory with entries.
func WithEntries(entries ...*Entry) Option {
	return func(o *options) { o.entries = append(o.entries, entries...) }
}

// WithLDIF seeds the directory from an LDIF file.
func WithLDIF(path string) Option { return func(o *options) { o.ldifPath = path } }

// WithDirectory shares an existing store (for a two-server failover pair).
func WithDirectory(d *Directory) Option { return func(o *options) { o.dir = d } }

// WithTLS serves ldaps:// instead of ldap:// (StartTLS is always offered on
// plain connections).
func WithTLS() Option { return func(o *options) { o.tls = true } }

// WithMaxPageSize caps the paged results page size (AD MaxPageSize, 1000).
func WithMaxPageSize(n int) Option { return func(o *options) { o.maxPageSize = n } }

// WithADBindCodes toggles AD diagnostics on failed binds (default on).
func WithADBindCodes(on bool) Option { return func(o *options) { o.adBindCodes = on } }

// WithAnonymousSearch allows searches on unbound connections (AD denies them).
func WithAnonymousSearch() Option { return func(o *options) { o.anonSearch = true } }

// WithoutStartTLS makes the server refuse the StartTLS extended operation
// (unavailableCriticalExtension), like a directory without TLS configured.
func WithoutStartTLS() Option { return func(o *options) { o.noStartTLS = true } }

// WithHostName sets dnsHostName in the RootDSE.
func WithHostName(h string) Option { return func(o *options) { o.hostName = h } }

// Server is one in-memory LDAP server with test hooks. Clients connect to a
// front listener that proxies bytes to the gldap backend; Kill closes the
// front listener and every client connection while the backend keeps
// serving, so Restart brings the same server back on the same port.
type Server struct {
	Dir *Directory

	opts     options
	certs    *certBundle
	backend  *gldap.Server
	backAddr string
	frontAdr string
	scheme   string

	mu     sync.Mutex
	front  net.Listener
	conns  map[net.Conn]net.Conn
	killed bool
	wg     sync.WaitGroup

	bound   map[int]string
	boundMu sync.Mutex

	conns64   atomic.Int64
	binds     atomic.Int64
	searches  atomic.Int64
	rootDSE   atomic.Int64
	delayNano atomic.Int64
	stopped   atomic.Bool
}

// Start runs a server and registers Stop with t.Cleanup.
func Start(tb testing.TB, opts ...Option) *Server {
	tb.Helper()
	s, err := New(opts...)
	if err != nil {
		tb.Fatalf("testdir: %v", err)
	}
	tb.Cleanup(s.Stop)
	return s
}

// New runs a server without a testing.TB; call Stop when done.
func New(opts ...Option) (*Server, error) {
	o := options{maxPageSize: 1000, adBindCodes: true, hostName: "dc.test.aldap"}
	for _, f := range opts {
		f(&o)
	}
	if o.ldifPath != "" {
		es, err := LoadLDIF(o.ldifPath)
		if err != nil {
			return nil, err
		}
		o.entries = append(es, o.entries...)
	}
	dir := o.dir
	if dir == nil {
		var err error
		if dir, err = NewDirectory(o.entries...); err != nil {
			return nil, err
		}
	} else {
		for _, e := range o.entries {
			if err := dir.Upsert(e); err != nil {
				return nil, err
			}
		}
	}
	certs, err := newCertBundle()
	if err != nil {
		return nil, err
	}
	s := &Server{Dir: dir, opts: o, certs: certs, conns: map[net.Conn]net.Conn{}, bound: map[int]string{}, scheme: "ldap"}
	if o.tls {
		s.scheme = "ldaps"
	}
	if err := s.startBackend(); err != nil {
		return nil, err
	}
	ln, err := listen("127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("testdir: listen: %w", err)
	}
	s.frontAdr = ln.Addr().String()
	s.serveFront(ln)
	return s, nil
}

func (s *Server) startBackend() error {
	srv, err := gldap.NewServer(gldap.WithLogger(hclog.NewNullLogger()), gldap.WithOnClose(s.onClose))
	if err != nil {
		return fmt.Errorf("testdir: backend: %w", err)
	}
	mux, err := gldap.NewMux()
	if err != nil {
		return fmt.Errorf("testdir: mux: %w", err)
	}
	for _, step := range []error{
		mux.Bind(s.handleBind),
		mux.Search(s.handleSearch),
		mux.ExtendedOperation(s.handleStartTLS, gldap.ExtendedOperationStartTLS),
		mux.Add(s.handleReadOnly),
		mux.Modify(s.handleReadOnly),
		mux.Delete(s.handleReadOnly),
		mux.DefaultRoute(s.handleDefault),
	} {
		if step != nil {
			return fmt.Errorf("testdir: routes: %w", step)
		}
	}
	if err := srv.Router(mux); err != nil {
		return fmt.Errorf("testdir: router: %w", err)
	}
	// Reserve a port for the backend, then hand it to gldap.
	probe, err := listen("127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("testdir: backend port: %w", err)
	}
	s.backAddr = probe.Addr().String()
	_ = probe.Close()
	var runOpts []gldap.Option
	if s.opts.tls {
		runOpts = append(runOpts, gldap.WithTLSConfig(s.certs.serverConfig()))
	}
	s.backend = srv
	go func() { _ = srv.Run(s.backAddr, runOpts...) }()
	for i := 0; i < 200; i++ {
		if srv.Ready() {
			c, err := dialTimeout(s.backAddr, 50*time.Millisecond)
			if err == nil {
				_ = c.Close()
				return nil
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	return errors.New("testdir: backend did not start")
}

func (s *Server) serveFront(ln net.Listener) {
	s.mu.Lock()
	s.front = ln
	s.killed = false
	s.mu.Unlock()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.conns64.Add(1)
			s.wg.Add(1)
			go s.pipe(c)
		}
	}()
}

func (s *Server) pipe(front net.Conn) {
	defer s.wg.Done()
	back, err := dialTimeout(s.backAddr, 2*time.Second)
	if err != nil {
		_ = front.Close()
		return
	}
	s.mu.Lock()
	if s.killed {
		s.mu.Unlock()
		_ = front.Close()
		_ = back.Close()
		return
	}
	s.conns[front] = back
	s.mu.Unlock()
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(back, front)
	go cp(front, back)
	<-done
	_ = front.Close()
	_ = back.Close()
	<-done
	s.mu.Lock()
	delete(s.conns, front)
	s.mu.Unlock()
}

// Kill closes the listener and every client connection; the port stays
// reserved for Restart. Calling it twice is harmless.
func (s *Server) Kill() {
	s.mu.Lock()
	if s.killed {
		s.mu.Unlock()
		return
	}
	s.killed = true
	ln := s.front
	s.front = nil
	conns := make([]net.Conn, 0, len(s.conns)*2)
	for f, b := range s.conns {
		conns = append(conns, f, b)
	}
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	for _, c := range conns {
		_ = c.Close()
	}
}

// Restart listens again on the same address after Kill.
func (s *Server) Restart() error {
	s.mu.Lock()
	killed := s.killed
	s.mu.Unlock()
	if !killed {
		return nil
	}
	if s.stopped.Load() {
		return ErrKilled
	}
	var (
		ln  net.Listener
		err error
	)
	for i := 0; i < 50; i++ {
		if ln, err = listen(s.frontAdr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		return fmt.Errorf("testdir: restart: %w", err)
	}
	s.serveFront(ln)
	return nil
}

// Stop kills the server and shuts the backend down.
func (s *Server) Stop() {
	if s.stopped.Swap(true) {
		return
	}
	s.Kill()
	s.wg.Wait()
	_ = s.backend.Stop()
}

// Alive reports whether the server accepts connections.
func (s *Server) Alive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.killed
}

// Addr is the host:port clients connect to.
func (s *Server) Addr() string { return s.frontAdr }

// URL is the ldap:// or ldaps:// URL of the server.
func (s *Server) URL() string { return s.scheme + "://" + s.frontAdr }

// CAPEM is the PEM of the CA that signed the server certificate.
func (s *Server) CAPEM() []byte { return s.certs.caPEM }

// CAFile writes the CA PEM into a temporary directory and returns its path.
func (s *Server) CAFile(tb testing.TB) string {
	tb.Helper()
	p := filepath.Join(tb.TempDir(), "ca.pem")
	if err := os.WriteFile(p, s.certs.caPEM, 0o600); err != nil {
		tb.Fatalf("testdir: ca file: %v", err)
	}
	return p
}

// ClientTLS is a client TLS config trusting the server certificate.
func (s *Server) ClientTLS() *tls.Config { return s.certs.clientConfig() }

// SetDelay makes every bind and search wait d before answering.
func (s *Server) SetDelay(d time.Duration) { s.delayNano.Store(int64(d)) }

// Calls returns a snapshot of the call counters.
func (s *Server) Calls() Counts {
	return Counts{Conns: s.conns64.Load(), Binds: s.binds.Load(), Searches: s.searches.Load(), RootDSE: s.rootDSE.Load()}
}

// ResetCalls zeroes the call counters.
func (s *Server) ResetCalls() {
	s.conns64.Store(0)
	s.binds.Store(0)
	s.searches.Store(0)
	s.rootDSE.Store(0)
}

// OpenConns is the number of live client connections.
func (s *Server) OpenConns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

func (s *Server) sleep() {
	if d := s.delayNano.Load(); d > 0 {
		time.Sleep(time.Duration(d))
	}
}

func (s *Server) onClose(connID int) {
	s.boundMu.Lock()
	delete(s.bound, connID)
	s.boundMu.Unlock()
}

func (s *Server) setBound(connID int, dn string) {
	s.boundMu.Lock()
	s.bound[connID] = dn
	s.boundMu.Unlock()
}

func (s *Server) boundDN(connID int) (string, bool) {
	s.boundMu.Lock()
	defer s.boundMu.Unlock()
	dn, ok := s.bound[connID]
	return dn, ok
}

func listen(addr string) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(context.Background(), "tcp", addr)
}

func dialTimeout(addr string, d time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	var nd net.Dialer
	return nd.DialContext(ctx, "tcp", addr)
}

// FixturePath returns the path of testdata/ad.ldif in the repository.
func FixturePath() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return filepath.Join("testdata", "ad.ldif")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", "ad.ldif")
}

// StartFixture starts a server seeded with testdata/ad.ldif.
func StartFixture(tb testing.TB, opts ...Option) *Server {
	tb.Helper()
	return Start(tb, append([]Option{WithLDIF(FixturePath())}, opts...)...)
}
