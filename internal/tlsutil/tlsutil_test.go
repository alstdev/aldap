package tlsutil

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/alstdev/aldap/internal/events"
)

var t0 = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

type recorder struct {
	mu sync.Mutex
	ev []events.Event
}

func (r *recorder) Emit(e events.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ev = append(r.ev, e)
}

func (r *recorder) kinds() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.ev))
	for _, e := range r.ev {
		out = append(out, e.Event)
	}
	return out
}

func TestParseKeyType_Cases(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want KeyType
		err  bool
	}{{"", ECDSAP256, false}, {"ecdsa-p256", ECDSAP256, false}, {"rsa-2048", RSA2048, false}, {"ed25519", "", true}} {
		got, err := ParseKeyType(tc.in)
		if (err != nil) != tc.err || got != tc.want {
			t.Errorf("ParseKeyType(%q) = %q, %v", tc.in, got, err)
		}
	}
	if _, err := GenerateKey("dsa"); err == nil {
		t.Error("GenerateKey(dsa) should fail")
	}
	k, err := GenerateKey(RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := k.(*rsa.PrivateKey); !ok {
		t.Errorf("rsa-2048 produced %T", k)
	}
}

func TestCA_GenerateLoad(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	if _, err := LoadCA(dir); !errors.Is(err, ErrNoCA) {
		t.Fatalf("LoadCA on empty dir: %v", err)
	}
	if _, _, err := EnsureCA(dir, false, ECDSAP256, t0); !errors.Is(err, ErrNoCA) {
		t.Fatalf("EnsureCA without auto_init: %v", err)
	}
	ca, created, err := EnsureCA(dir, true, ECDSAP256, t0)
	if err != nil || !created {
		t.Fatalf("EnsureCA: created=%v err=%v", created, err)
	}
	if !ca.Cert.IsCA || ca.Cert.NotAfter.Sub(t0) != CAValidity {
		t.Errorf("CA cert: isCA=%v notAfter=%v", ca.Cert.IsCA, ca.Cert.NotAfter)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(filepath.Join(dir, CAKeyFile))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("ca.key mode = %v, err %v", st.Mode(), err)
		}
	}
	if _, err := GenerateCA(dir, ECDSAP256, t0); !errors.Is(err, ErrCAExists) {
		t.Errorf("second GenerateCA: %v", err)
	}
	loaded, created, err := EnsureCA(dir, false, ECDSAP256, t0)
	if err != nil || created {
		t.Fatalf("EnsureCA load: created=%v err=%v", created, err)
	}
	if !loaded.Cert.Equal(ca.Cert) {
		t.Error("loaded CA differs from generated")
	}
	if _, ok := loaded.Key.(*ecdsa.PrivateKey); !ok {
		t.Errorf("loaded key %T", loaded.Key)
	}
	// Key that does not match the certificate.
	other, err := GenerateKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	pemKey, _ := MarshalKeyPEM(other)
	if err := os.WriteFile(filepath.Join(dir, CAKeyFile), pemKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCA(dir); err == nil {
		t.Error("LoadCA with mismatched key should fail")
	}
	// Non-CA certificate in ca.crt.
	leaf, err := ca.Issue(ParseSANs("x"), ECDSAP256, t0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, CACertFile), ChainPEM(leaf)[:len(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]}))], 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteKeyPair(filepath.Join(dir, "x.crt"), filepath.Join(dir, CAKeyFile), ChainPEM(leaf), leaf.PrivateKey.(*ecdsa.PrivateKey)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCA(dir); err == nil {
		t.Error("LoadCA with a leaf certificate should fail")
	}
}

func TestParseSANs_Covers(t *testing.T) {
	s := ParseSANs("", "0.0.0.0", "::", "ldap.corp.local", "LDAP.corp.local", "10.0.0.5", "[::1]", "localhost")
	if len(s.DNS) != 2 || s.DNS[0] != "ldap.corp.local" || s.DNS[1] != "localhost" {
		t.Errorf("DNS = %v", s.DNS)
	}
	if len(s.IPs) != 2 || !s.IPs[0].Equal(net.ParseIP("10.0.0.5")) || !s.IPs[1].Equal(net.ParseIP("::1")) {
		t.Errorf("IPs = %v", s.IPs)
	}
	ca, err := NewCA(ECDSAP256, t0)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ca.Issue(s, RSA2048, t0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.PrivateKey.(*rsa.PrivateKey); !ok {
		t.Errorf("rsa key type ignored: %T", c.PrivateKey)
	}
	if !s.Covers(c.Leaf) || ParseSANs("other.host").Covers(c.Leaf) || ParseSANs("10.0.0.6").Covers(c.Leaf) {
		t.Error("Covers mismatch")
	}
	if c.Leaf.Subject.CommonName != "ldap.corp.local" || c.Leaf.NotAfter.Sub(t0) != ServerValidity {
		t.Errorf("leaf: cn=%s notAfter=%v", c.Leaf.Subject.CommonName, c.Leaf.NotAfter)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := c.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "ldap.corp.local", CurrentTime: t0}); err != nil {
		t.Errorf("verify: %v", err)
	}
	// Validity never exceeds the CA.
	late := ca.Cert.NotAfter.Add(-24 * time.Hour)
	c2, err := ca.Issue(ParseSANs("10.0.0.5"), ECDSAP256, late, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !c2.Leaf.NotAfter.Equal(ca.Cert.NotAfter) || c2.Leaf.Subject.CommonName != "10.0.0.5" {
		t.Errorf("capped leaf: notAfter=%v cn=%s", c2.Leaf.NotAfter, c2.Leaf.Subject.CommonName)
	}
	c3, _ := ca.Issue(SANs{}, ECDSAP256, t0, time.Hour)
	if c3.Leaf.Subject.CommonName != "aldap" || c3.Leaf.NotAfter.Sub(t0) != time.Hour {
		t.Errorf("default cn/validity: %s %v", c3.Leaf.Subject.CommonName, c3.Leaf.NotAfter)
	}
}

func TestParseKeyPEM_Forms(t *testing.T) {
	ec, _ := GenerateKey(ECDSAP256)
	rs, _ := GenerateKey(RSA2048)
	ecDER, _ := x509.MarshalECPrivateKey(ec.(*ecdsa.PrivateKey))
	cases := map[string][]byte{
		"pkcs8-ec": must(MarshalKeyPEM(ec)),
		"sec1":     pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}),
		"pkcs1":    pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rs.(*rsa.PrivateKey))}),
	}
	for name, b := range cases {
		if _, err := ParseKeyPEM(append([]byte("# comment\n"), b...)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, b := range map[string][]byte{
		"empty": nil,
		"cert":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}),
		"junk":  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}),
		"ecbad": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}}),
		"rsabd": pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1}}),
	} {
		if _, err := ParseKeyPEM(b); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := parseCertPEM(nil); err == nil {
		t.Error("parseCertPEM(nil) should fail")
	}
	if _, err := parseCertPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})); err == nil {
		t.Error("parseCertPEM(junk) should fail")
	}
	if _, err := LoadCertPool(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Error("LoadCertPool(missing) should fail")
	}
	empty := filepath.Join(t.TempDir(), "empty.pem")
	_ = os.WriteFile(empty, []byte("nothing"), 0o600)
	if _, err := LoadCertPool(empty); err == nil {
		t.Error("LoadCertPool(empty) should fail")
	}
	if _, err := LoadServerCert(empty, empty); err == nil {
		t.Error("LoadServerCert(junk) should fail")
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func newManager(t *testing.T, o Options) (*Manager, *recorder) {
	t.Helper()
	rec := &recorder{}
	o.Events = rec
	o.Logger = slog.New(slog.DiscardHandler)
	if o.Now == nil {
		o.Now = func() time.Time { return t0 }
	}
	m, err := New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m, rec
}

func TestManager_BuiltinLifecycle(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	opts := Options{Profile: "p", Mode: ModeBuiltinCA, CADir: dir, AutoInit: true, SANs: ParseSANs("ldap.test", "127.0.0.1"),
		AutoRenewBefore: 30 * 24 * time.Hour, ExpiryAlertBefore: 14 * 24 * time.Hour}
	m1, _ := newManager(t, opts)
	if m1.CA() == nil || len(m1.CAPEM()) == 0 {
		t.Fatal("builtin manager must expose the CA")
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(filepath.Join(dir, ServerKeyFile))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("server.key: %v %v", st, err)
		}
	}
	// Second start reuses the persisted certificate.
	m2, _ := newManager(t, opts)
	if m2.Leaf().SerialNumber.Cmp(m1.Leaf().SerialNumber) != 0 {
		t.Error("persisted certificate not reused")
	}
	// New SAN → reissue.
	o3 := opts
	o3.SANs = ParseSANs("ldap.test", "127.0.0.1", "ldap2.test")
	m3, _ := newManager(t, o3)
	if m3.Leaf().SerialNumber.Cmp(m1.Leaf().SerialNumber) == 0 {
		t.Error("certificate with missing SAN must be reissued")
	}
	// Renewal window → reissue at start, and at Check later.
	o4 := opts
	o4.Now = func() time.Time { return t0.Add(ServerValidity - 29*24*time.Hour) }
	m4, rec4 := newManager(t, o4)
	if m4.Leaf().SerialNumber.Cmp(m3.Leaf().SerialNumber) == 0 {
		t.Error("certificate due for renewal must be reissued at start")
	}
	var now time.Time
	m4.now = func() time.Time { return now }
	now = m4.Leaf().NotAfter.Add(-29 * 24 * time.Hour)
	before := m4.Leaf().SerialNumber
	m4.Check()
	if m4.Leaf().SerialNumber.Cmp(before) == 0 {
		t.Error("Check must renew within auto_renew_before")
	}
	if k := rec4.kinds(); len(k) != 1 || k[0] != events.CertRenewed {
		t.Errorf("events = %v", k)
	}
	// Handshake with the issued certificate and the CA as root.
	handshake(t, m4.Config(), m4.CAPEM(), "ldap.test", nil, true, now)
	// Corrupt stored certificate → reissued, not fatal.
	_ = os.WriteFile(filepath.Join(dir, ServerCertFile), []byte("garbage"), 0o644)
	m5, _ := newManager(t, opts)
	if m5.Leaf() == nil {
		t.Error("manager without certificate")
	}
	// Stored certificate from another CA → reissued.
	otherCA, _ := NewCA(ECDSAP256, t0)
	foreign, _ := otherCA.Issue(opts.SANs, ECDSAP256, t0, 0)
	_ = WriteKeyPair(filepath.Join(dir, ServerCertFile), filepath.Join(dir, ServerKeyFile), ChainPEM(foreign), foreign.PrivateKey.(*ecdsa.PrivateKey))
	m6, _ := newManager(t, opts)
	if m6.Leaf().SerialNumber.Cmp(foreign.Leaf.SerialNumber) == 0 {
		t.Error("certificate from a foreign CA must be replaced")
	}
	// Read-only directory: certificate kept in memory.
	ro := Options{Mode: ModeBuiltinCA, CADir: dir, SANs: opts.SANs, NoPersist: true}
	if _, err := New(ro); err != nil {
		t.Errorf("NoPersist: %v", err)
	}
}

func TestManager_Errors(t *testing.T) {
	dir := t.TempDir()
	for name, o := range map[string]Options{
		"no-ca":       {Mode: ModeBuiltinCA, CADir: filepath.Join(dir, "none"), AutoInit: false},
		"bad-mode":    {Mode: "pkcs11", CADir: dir},
		"bad-keytype": {Mode: ModeBuiltinCA, CADir: dir, AutoInit: true, KeyType: "dsa"},
		"bad-minver":  {Mode: ModeBuiltinCA, CADir: dir, AutoInit: true, MinVersion: "1.1"},
		"bad-auth":    {Mode: ModeBuiltinCA, CADir: dir, AutoInit: true, ClientAuth: "maybe"},
		"no-clientca": {Mode: ModeBuiltinCA, CADir: dir, AutoInit: true, ClientAuth: "require"},
		"bad-clientca": {Mode: ModeBuiltinCA, CADir: dir, AutoInit: true, ClientAuth: "require",
			ClientCA: filepath.Join(dir, "missing.pem")},
		"ext-missing": {Mode: ModeExternal, Cert: filepath.Join(dir, "a.crt"), Key: filepath.Join(dir, "a.key")},
	} {
		if _, err := New(o); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestManager_ExternalExpiring(t *testing.T) {
	dir := t.TempDir()
	ca, _ := NewCA(ECDSAP256, t0)
	c, _ := ca.Issue(ParseSANs("ext.test"), ECDSAP256, t0, 10*24*time.Hour)
	certPath, keyPath := filepath.Join(dir, "s.crt"), filepath.Join(dir, "s.key")
	if err := WriteKeyPair(certPath, keyPath, ChainPEM(c), c.PrivateKey.(*ecdsa.PrivateKey)); err != nil {
		t.Fatal(err)
	}
	m, rec := newManager(t, Options{Profile: "ext", Mode: ModeExternal, Cert: certPath, Key: keyPath,
		ExpiryAlertBefore: 14 * 24 * time.Hour, AutoRenewBefore: 30 * 24 * time.Hour, MinVersion: "1.3"})
	if m.CA() != nil || m.CAPEM() != nil {
		t.Error("external mode has no CA")
	}
	m.Check()
	m.Check()
	if k := rec.kinds(); len(k) != 1 || k[0] != events.CertExpiring {
		t.Errorf("events = %v (cert_expiring once)", k)
	}
	rec.mu.Lock()
	d := rec.ev[0].Data
	rec.mu.Unlock()
	if d["days_left"] != 10 || d["subject"] == "" || d["not_after"] == "" {
		t.Errorf("data = %v", d)
	}
	cfg := m.Config()
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("min version = %x", cfg.MinVersion)
	}
	handshake(t, cfg, ca.PEM, "ext.test", nil, true, t0)
}

func TestManager_ClientAuth(t *testing.T) {
	dir := t.TempDir()
	clientCA, _ := NewCA(ECDSAP256, t0)
	caPath := filepath.Join(dir, "clients.pem")
	_ = os.WriteFile(caPath, clientCA.PEM, 0o600)
	m, _ := newManager(t, Options{Mode: ModeBuiltinCA, CADir: filepath.Join(dir, "ca"), AutoInit: true,
		SANs: ParseSANs("mtls.test"), ClientAuth: "require", ClientCA: caPath})
	handshake(t, m.Config(), m.CAPEM(), "mtls.test", nil, false, t0)
	// Client certificates need the clientAuth EKU; issue one by hand.
	clientCert := clientCertificate(t, clientCA)
	handshake(t, m.Config(), m.CAPEM(), "mtls.test", &clientCert, true, t0)
	m2, _ := newManager(t, Options{Mode: ModeBuiltinCA, CADir: filepath.Join(dir, "ca"), SANs: ParseSANs("mtls.test"),
		ClientAuth: "request", ClientCA: caPath})
	handshake(t, m2.Config(), m2.CAPEM(), "mtls.test", nil, true, t0)
}

func clientCertificate(t *testing.T, ca *CA) tls.Certificate {
	t.Helper()
	key, _ := GenerateKey(ECDSAP256)
	sn, _ := serial()
	tpl := &x509.Certificate{SerialNumber: sn, NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	tpl.Subject.CommonName = "client"
	der, err := x509.CreateCertificate(nil, tpl, ca.Cert, key.Public(), ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// handshake runs a TLS handshake over a pipe and asserts the outcome.
func handshake(t *testing.T, srvCfg *tls.Config, caPEM []byte, serverName string, clientCert *tls.Certificate, wantOK bool, at time.Time) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	ccfg := &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12, Time: func() time.Time { return at }}
	if clientCert != nil {
		ccfg.Certificates = []tls.Certificate{*clientCert}
	}
	srvCfg = srvCfg.Clone()
	srvCfg.Time = func() time.Time { return at }
	a, b := net.Pipe()
	errc := make(chan error, 1)
	go func() {
		s := tls.Server(a, srvCfg)
		err := s.HandshakeContext(context.Background())
		_ = a.Close() // close the pipe, not the TLS layer: close_notify would block for 5 s
		errc <- err
	}()
	c := tls.Client(b, ccfg)
	cerr := c.HandshakeContext(context.Background())
	_ = b.Close()
	serr := <-errc
	ok := cerr == nil && serr == nil
	if ok != wantOK {
		t.Errorf("handshake ok=%v (client %v, server %v), want %v", ok, cerr, serr, wantOK)
	}
}
