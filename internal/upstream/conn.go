package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/config"
)

// ldapConn is the subset of *ldap.Conn the package uses; tests substitute fakes.
type ldapConn interface {
	Bind(username, password string) error
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
	StartTLS(*tls.Config) error
	SetTimeout(time.Duration)
	IsClosing() bool
	Close() error
}

var _ ldapConn = (*ldap.Conn)(nil)

// dialFunc opens a connection to one server (transport only, no bind).
type dialFunc func(ctx context.Context, srv ServerURL) (ldapConn, error)

// buildTLSConfig builds the client TLS configuration of an upstream.
func buildTLSConfig(cfg *config.Upstream) (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.TLSServerName}
	if cfg.TLSCAFile != "" {
		pem, err := os.ReadFile(cfg.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("tls_ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tls_ca_file %q: no certificates found", cfg.TLSCAFile)
		}
		tc.RootCAs = pool
	}
	if cfg.TLSInsecureSkipVerify {
		// Explicit operator choice; config validation warns and the daemon
		// emits insecure_config on every start.
		tc.InsecureSkipVerify = true
	}
	return tc, nil
}

// dialer opens real connections honoring the connect timeout, ldaps and
// StartTLS settings.
type dialer struct {
	cfg *config.Upstream
	tls *tls.Config
	log *slog.Logger
}

func (d *dialer) dial(ctx context.Context, srv ServerURL) (ldapConn, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(d.cfg.Timeouts.Connect))
	defer cancel()
	nd := net.Dialer{}
	nc, err := nd.DialContext(ctx, "tcp", srv.Addr())
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", srv, err)
	}
	tc := d.tlsConfigFor(srv)
	if srv.TLS() {
		tlsConn := tls.Client(nc, tc)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			closeQuietly(nc, nil)
			return nil, fmt.Errorf("tls %s: %w", srv, err)
		}
		nc = tlsConn
	}
	c := ldap.NewConn(nc, srv.TLS())
	c.Start()
	c.SetTimeout(time.Duration(d.cfg.Timeouts.Connect))
	if !srv.TLS() && d.cfg.StartTLS {
		// Any StartTLS failure is fatal for the connection: go-ldap leaves it
		// unusable after a refused or failed negotiation, and re-dialing in
		// clear text would be a silent downgrade (docs/DECISIONS.md).
		if err := c.StartTLS(tc); err != nil {
			closeQuietly(c, d.log)
			return nil, fmt.Errorf("starttls %s: %w", srv, err)
		}
	}
	return c, nil
}

func (d *dialer) tlsConfigFor(srv ServerURL) *tls.Config {
	tc := d.tls.Clone()
	if tc.ServerName == "" {
		tc.ServerName = srv.Host
	}
	return tc
}

// closeQuietly closes c and logs a failure at debug level: a close error on
// a connection that is being discarded is not actionable.
func closeQuietly(c io.Closer, log *slog.Logger) {
	if err := c.Close(); err != nil && log != nil {
		log.Debug("close", "err", err)
	}
}

// isConnError reports whether err means the server (not the request) failed:
// network errors, timeouts, serverDown/unavailable/busy results and closed
// connections. A context canceled by the caller is not a server failure.
func isConnError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	if ldap.IsErrorAnyOf(err, ldap.ErrorNetwork, ldap.ErrorUnexpectedResponse, ldap.LDAPResultServerDown,
		ldap.LDAPResultUnavailable, ldap.LDAPResultBusy, ldap.LDAPResultConnectError, ldap.LDAPResultTimeLimitExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	// go-ldap reports a broken read with a plain, unwrapped error.
	if strings.Contains(err.Error(), "unable to read LDAP response packet") {
		return true
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrPoolExhausted) || errors.Is(err, ErrConnect)
}
