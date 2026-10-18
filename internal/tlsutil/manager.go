package tlsutil

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/alstdev/aldap/internal/events"
)

// Modes of [tls].
const (
	ModeBuiltinCA = "builtin-ca"
	ModeExternal  = "external"
)

// Options configure a Manager; they mirror the effective [tls] table of one
// profile (profile overrides already merged).
type Options struct {
	// Profile is used in events and log lines.
	Profile string
	// Mode is builtin-ca or external.
	Mode string
	// CADir holds ca.crt/ca.key and the persisted server certificate.
	CADir string
	// AutoInit creates the CA when it is missing.
	AutoInit bool
	// Cert and Key are the external certificate chain and private key.
	Cert, Key string
	// KeyType is the key algorithm of issued certificates.
	KeyType KeyType
	// SANs are the names the server certificate must cover.
	SANs SANs
	// AutoRenewBefore reissues the built-in certificate this long before expiry.
	AutoRenewBefore time.Duration
	// ExpiryAlertBefore emits cert_expiring this long before expiry.
	ExpiryAlertBefore time.Duration
	// MinVersion is "1.2" or "1.3".
	MinVersion string
	// ClientAuth is none, request or require; ClientCA verifies client certificates.
	ClientAuth string
	ClientCA   string
	// Persist writes the built-in server certificate into CADir (default true
	// when CADir is writable; a failure is logged, not fatal).
	NoPersist bool

	Logger *slog.Logger
	Events events.Sink
	Now    func() time.Time
}

// Manager owns the server certificate of one profile: loads or issues it,
// renews it and reports expiry.
type Manager struct {
	o    Options
	ca   *CA
	log  *slog.Logger
	ev   events.Sink
	now  func() time.Time
	base *tls.Config

	mu      sync.RWMutex
	cert    *tls.Certificate
	alerted bool
}

// New loads or creates everything the listeners need. For builtin-ca it
// loads (or with AutoInit creates) the CA and a server certificate covering
// SANs; for external it loads cert/key.
func New(o Options) (*Manager, error) {
	m := &Manager{o: o, log: o.Logger, ev: o.Events, now: o.Now}
	if m.log == nil {
		m.log = slog.Default()
	}
	m.log = m.log.With("profile", o.Profile)
	if m.ev == nil {
		m.ev = events.Discard
	}
	if m.now == nil {
		m.now = time.Now
	}
	kt, err := ParseKeyType(string(o.KeyType))
	if err != nil {
		return nil, err
	}
	m.o.KeyType = kt
	base, err := baseConfig(o)
	if err != nil {
		return nil, err
	}
	m.base = base
	switch o.Mode {
	case ModeBuiltinCA, "":
		if err := m.initBuiltin(); err != nil {
			return nil, err
		}
	case ModeExternal:
		c, err := LoadServerCert(o.Cert, o.Key)
		if err != nil {
			return nil, err
		}
		m.cert = &c
	default:
		return nil, fmt.Errorf("unknown tls mode %q", o.Mode)
	}
	return m, nil
}

func baseConfig(o Options) (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	switch o.MinVersion {
	case "", "1.2":
	case "1.3":
		tc.MinVersion = tls.VersionTLS13
	default:
		return nil, fmt.Errorf("unknown min_version %q", o.MinVersion)
	}
	switch o.ClientAuth {
	case "", "none":
		tc.ClientAuth = tls.NoClientCert
	case "request":
		tc.ClientAuth = tls.VerifyClientCertIfGiven
	case "require":
		tc.ClientAuth = tls.RequireAndVerifyClientCert
	default:
		return nil, fmt.Errorf("unknown client_auth %q", o.ClientAuth)
	}
	if tc.ClientAuth != tls.NoClientCert {
		if o.ClientCA == "" {
			return nil, errors.New("client_ca is required for client_auth")
		}
		pool, err := LoadCertPool(o.ClientCA)
		if err != nil {
			return nil, err
		}
		tc.ClientCAs = pool
	}
	return tc, nil
}

func (m *Manager) initBuiltin() error {
	ca, created, err := EnsureCA(m.o.CADir, m.o.AutoInit, m.o.KeyType, m.now())
	if err != nil {
		return err
	}
	m.ca = ca
	if created {
		m.log.Info("built-in CA created", "dir", m.o.CADir, "not_after", ca.Cert.NotAfter.Format(time.RFC3339))
	}
	if c, ok := m.loadPersisted(); ok {
		m.cert = &c
		return nil
	}
	return m.reissue("issu")
}

// loadPersisted returns the server certificate stored in CADir when it was
// issued by the CA, covers the SANs and is not yet due for renewal.
func (m *Manager) loadPersisted() (tls.Certificate, bool) {
	certPath, keyPath := filepath.Join(m.o.CADir, ServerCertFile), filepath.Join(m.o.CADir, ServerKeyFile)
	c, err := LoadServerCert(certPath, keyPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			m.log.Warn("stored server certificate unusable, reissuing", "err", err)
		}
		return tls.Certificate{}, false
	}
	roots := x509.NewCertPool()
	roots.AddCert(m.ca.Cert)
	if _, err := c.Leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: m.now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		m.log.Info("stored server certificate not issued by the current CA, reissuing", "err", err)
		return tls.Certificate{}, false
	}
	if !m.o.SANs.Covers(c.Leaf) {
		m.log.Info("stored server certificate does not cover the listen names, reissuing")
		return tls.Certificate{}, false
	}
	if m.dueForRenewal(c.Leaf) {
		return tls.Certificate{}, false
	}
	return c, true
}

func (m *Manager) dueForRenewal(leaf *x509.Certificate) bool {
	return m.o.AutoRenewBefore > 0 && m.now().Add(m.o.AutoRenewBefore).After(leaf.NotAfter)
}

// reissue issues a new server certificate, persists it and installs it.
func (m *Manager) reissue(why string) error {
	c, err := m.ca.Issue(m.o.SANs, m.o.KeyType, m.now(), ServerValidity)
	if err != nil {
		return err
	}
	if !m.o.NoPersist {
		if key, ok := c.PrivateKey.(crypto.Signer); !ok {
			m.log.Warn("server certificate kept in memory only", "err", fmt.Sprintf("unsupported key type %T", c.PrivateKey))
		} else if err := WriteKeyPair(filepath.Join(m.o.CADir, ServerCertFile), filepath.Join(m.o.CADir, ServerKeyFile), ChainPEM(c), key); err != nil {
			m.log.Warn("server certificate kept in memory only", "err", err)
		}
	}
	m.mu.Lock()
	m.cert = &c
	m.alerted = false
	m.mu.Unlock()
	data := certData(c.Leaf, m.now())
	m.log.Info("server certificate "+why+"ed", "subject", data["subject"], "not_after", data["not_after"], "dns", c.Leaf.DNSNames, "ips", c.Leaf.IPAddresses)
	if why == "renew" {
		m.ev.Emit(events.Event{Event: events.CertRenewed, Level: events.LevelLow, Profile: m.o.Profile, Data: data})
	}
	return nil
}

// Certificate returns the current server certificate.
func (m *Manager) Certificate() *tls.Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cert
}

// Leaf returns the parsed current server certificate.
func (m *Manager) Leaf() *x509.Certificate { return m.Certificate().Leaf }

// CAPEM returns the built-in CA certificate (nil for external mode).
func (m *Manager) CAPEM() []byte {
	if m.ca == nil {
		return nil
	}
	return m.ca.PEM
}

// CA returns the built-in CA (nil for external mode).
func (m *Manager) CA() *CA { return m.ca }

// Config returns the listener tls.Config. The certificate is looked up per
// handshake so renewals apply without restarting listeners.
func (m *Manager) Config() *tls.Config {
	tc := m.base.Clone()
	tc.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return m.Certificate(), nil
	}
	return tc
}

// Check renews a built-in certificate that is within AutoRenewBefore of
// its expiry and emits cert_expiring (once per certificate) when the
// current one is within ExpiryAlertBefore. Call it periodically.
func (m *Manager) Check() {
	leaf := m.Leaf()
	now := m.now()
	if m.ca != nil && m.dueForRenewal(leaf) {
		if err := m.reissue("renew"); err != nil {
			m.log.Error("server certificate renewal failed", "err", err)
		} else {
			return
		}
	}
	if m.o.ExpiryAlertBefore > 0 && now.Add(m.o.ExpiryAlertBefore).After(leaf.NotAfter) {
		m.mu.Lock()
		first := !m.alerted
		m.alerted = true
		m.mu.Unlock()
		if first {
			data := certData(leaf, now)
			m.log.Warn("server certificate expires soon", "subject", data["subject"], "not_after", data["not_after"], "days_left", data["days_left"])
			m.ev.Emit(events.Event{Event: events.CertExpiring, Level: events.LevelMedium, Profile: m.o.Profile, Data: data})
		}
	}
}

func certData(leaf *x509.Certificate, now time.Time) map[string]any {
	return map[string]any{
		"subject":   leaf.Subject.String(),
		"not_after": leaf.NotAfter.UTC().Format(time.RFC3339),
		"days_left": int(leaf.NotAfter.Sub(now).Hours() / 24),
	}
}

// ChainPEM renders the certificate chain of c as PEM.
func ChainPEM(c tls.Certificate) []byte {
	out := make([]byte, 0, 4096)
	for _, der := range c.Certificate {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return out
}
