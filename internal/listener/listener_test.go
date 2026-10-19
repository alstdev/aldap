package listener

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/events/schematest"
	"github.com/alstdev/aldap/internal/tlsutil"
)

// fakeHandler records calls and answers from a script.
type fakeHandler struct {
	mu       sync.Mutex
	binds    []string
	pws      []string
	searches []*SearchRequest
	// bindCode is returned for every bind; the name "ok" always succeeds.
	bindCode int
	// entries are streamed for every search.
	entries []Entry
	// block, when set, makes Search wait for ctx or the channel.
	block  chan struct{}
	ctxErr error
}

func (h *fakeHandler) Bind(_ context.Context, c *Conn, name string, password []byte) Result {
	h.mu.Lock()
	h.binds = append(h.binds, name)
	h.pws = append(h.pws, string(password))
	h.mu.Unlock()
	if name == "ok" || h.bindCode == 0 {
		c.SetBound(Bound{Kind: BindUser, Name: name})
		return Success
	}
	return Result{Code: h.bindCode}
}

func (h *fakeHandler) Search(ctx context.Context, c *Conn, req *SearchRequest, w EntryWriter) Result {
	h.mu.Lock()
	h.searches = append(h.searches, req)
	h.mu.Unlock()
	if h.block != nil {
		select {
		case <-ctx.Done():
			h.mu.Lock()
			h.ctxErr = ctx.Err()
			h.mu.Unlock()
			return Result{Code: ldap.LDAPResultUnavailable}
		case <-h.block:
		}
	}
	for _, e := range h.entries {
		if err := w.Entry(e); err != nil {
			return Result{Code: ldap.LDAPResultOther}
		}
	}
	res := Success
	for _, ctl := range req.Controls {
		if p, ok := ctl.(*ldap.ControlPaging); ok {
			// Echo a cookie once so the client asks for a second page.
			if len(p.Cookie) == 0 && p.PagingSize > 0 {
				res.Controls = []ldap.Control{&ldap.ControlPaging{PagingSize: p.PagingSize, Cookie: []byte("next")}}
			} else {
				res.Controls = []ldap.Control{&ldap.ControlPaging{PagingSize: p.PagingSize}}
			}
		}
	}
	if v, ok := c.Load("hits"); ok {
		c.Store("hits", v.(int)+1)
	} else {
		c.Store("hits", 1)
	}
	return res
}

type sink struct {
	mu sync.Mutex
	ev []events.Event
}

func (s *sink) Emit(e events.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ev = append(s.ev, e)
}

func (s *sink) find(kind string) []events.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []events.Event
	for _, e := range s.ev {
		if e.Event == kind {
			out = append(out, e)
		}
	}
	return out
}

var (
	testCA     *tlsutil.CA
	testCert   tls.Certificate
	testCAOnce sync.Once
)

func serverTLS(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	testCAOnce.Do(func() {
		var err error
		testCA, err = tlsutil.NewCA(tlsutil.ECDSAP256, time.Now())
		if err != nil {
			panic(err)
		}
		testCert, err = testCA.Issue(tlsutil.ParseSANs("127.0.0.1", "localhost"), tlsutil.ECDSAP256, time.Now(), 0)
		if err != nil {
			panic(err)
		}
	})
	pool := x509.NewCertPool()
	pool.AddCert(testCA.Cert)
	return &tls.Config{Certificates: []tls.Certificate{testCert}, MinVersion: tls.VersionTLS12}, pool
}

type testServer struct {
	*Server
	addr string
	h    *fakeHandler
	ev   *sink
	pool *x509.CertPool
	done chan error
}

func start(t *testing.T, cfg Config) *testServer {
	t.Helper()
	ts := &testServer{h: &fakeHandler{}, ev: &sink{}}
	// Every event the listener emitted must be valid against the schema (TESTING.md 34).
	t.Cleanup(func() {
		ts.ev.mu.Lock()
		defer ts.ev.mu.Unlock()
		schematest.CheckEvents(t, ts.ev.ev...)
	})
	if cfg.Handler == nil {
		cfg.Handler = ts.h
	} else if h, ok := cfg.Handler.(*fakeHandler); ok {
		ts.h = h
	}
	cfg.Events = ts.ev
	cfg.Logger = slog.New(slog.DiscardHandler)
	if cfg.Transport == "" {
		cfg.Transport = TransportLDAP
	}
	if cfg.Transport != TransportLDAP && cfg.TLS == nil {
		cfg.TLS, ts.pool = serverTLS(t)
	} else {
		_, ts.pool = serverTLS(t)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts.Server = s
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ts.addr = ln.Addr().String()
	ts.done = make(chan error, 1)
	go func() { ts.done <- s.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	return ts
}

func (ts *testServer) clientTLS() *tls.Config {
	return &tls.Config{RootCAs: ts.pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}
}

func (ts *testServer) dial(t *testing.T) *ldap.Conn {
	t.Helper()
	var c *ldap.Conn
	var err error
	if ts.ldaps {
		c, err = ldap.DialURL("ldaps://"+ts.addr, ldap.DialWithTLSConfig(ts.clientTLS()))
	} else {
		c, err = ldap.DialURL("ldap://" + ts.addr)
	}
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.SetTimeout(5 * time.Second)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestNew_Errors(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("handler required")
	}
	if _, err := New(Config{Handler: &fakeHandler{}, Transport: "udp"}); err == nil {
		t.Error("unknown transport")
	}
	if _, err := New(Config{Handler: &fakeHandler{}, Transport: TransportLDAPS}); err == nil {
		t.Error("ldaps needs TLS")
	}
	s, err := New(Config{Handler: &fakeHandler{}, Transport: TransportLDAP})
	if err != nil {
		t.Fatal(err)
	}
	if s.OffersStartTLS() || s.RequiresTLS() || s.cfg.MaxRequestBytes != defaultMaxRequestBytes {
		t.Error("ldap defaults")
	}
	s.Close()
	if err := s.ListenAndServe("127.0.0.1:0"); !errors.Is(err, ErrServerClosed) {
		t.Errorf("serve after close: %v", err)
	}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Errorf("second shutdown: %v", err)
	}
	if _, err := New(Config{Handler: &fakeHandler{}, Transport: TransportLDAP}); err != nil {
		t.Fatal(err)
	}
	bad, _ := New(Config{Handler: &fakeHandler{}, Transport: TransportLDAP})
	if err := bad.ListenAndServe("256.0.0.1:1"); err == nil {
		t.Error("bad address")
	}
}

func TestBindSearch_Plain(t *testing.T) {
	ts := start(t, Config{Profile: "p"})
	ts.h.entries = []Entry{{DN: "cn=a,ou=users,dc=x", Attrs: []Attribute{{Name: "cn", Values: []string{"a"}}, {Name: "mail", Values: []string{"a@x", "b@x"}}}}}
	c := ts.dial(t)
	if err := c.Bind("ok", "S3CR3T-pw"); err != nil {
		t.Fatalf("bind: %v", err)
	}
	res, err := c.Search(ldap.NewSearchRequest("ou=users,dc=x", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 7, 3, false,
		"(&(objectClass=user)(cn=a*))", []string{"cn", "mail"}, nil))
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res.Entries) != 1 || res.Entries[0].DN != "cn=a,ou=users,dc=x" || len(res.Entries[0].GetAttributeValues("mail")) != 2 {
		t.Errorf("entries = %+v", res.Entries)
	}
	ts.h.mu.Lock()
	req := ts.h.searches[0]
	ts.h.mu.Unlock()
	if req.Base != "ou=users,dc=x" || req.Scope != ScopeSub || req.SizeLimit != 7 || req.TimeLimit != 3*time.Second ||
		req.Filter != "(&(objectClass=user)(cn=a*))" || strings.Join(req.Attrs, ",") != "cn,mail" || req.TypesOnly {
		t.Errorf("request = %+v", req)
	}
	if ts.h.pws[0] != "S3CR3T-pw" || ts.h.binds[0] != "ok" {
		t.Errorf("bind seen as %q", ts.h.binds)
	}
	// typesOnly: values omitted.
	res, err = c.Search(ldap.NewSearchRequest("ou=users,dc=x", ldap.ScopeBaseObject, 0, 0, 0, true, "(cn=*)", nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != 1 || len(res.Entries[0].GetAttributeValues("mail")) != 0 || len(res.Entries[0].Attributes) != 2 {
		t.Errorf("typesOnly entries = %+v", res.Entries[0].Attributes)
	}
	// Paging round trip: the control reaches the handler and the cookie the client.
	pres, err := c.SearchWithPaging(ldap.NewSearchRequest("ou=users,dc=x", ldap.ScopeWholeSubtree, 0, 0, 0, false, "(cn=*)", nil, nil), 50)
	if err != nil {
		t.Fatalf("paged: %v", err)
	}
	if len(pres.Entries) != 2 {
		t.Errorf("paged entries = %d, want 2 (two pages)", len(pres.Entries))
	}
	if ts.ConnCount() != 1 {
		t.Errorf("conns = %d", ts.ConnCount())
	}
	// Bind failure is passed through and resets the bound state.
	ts.h.bindCode = ldap.LDAPResultInvalidCredentials
	if err := c.Bind("bad", "x"); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Errorf("bad bind: %v", err)
	}
	_ = c.Close()
	waitFor(t, func() bool { return ts.ConnCount() == 0 })
}

func TestDenied_Operations(t *testing.T) {
	ts := start(t, Config{Profile: "p"})
	c := ts.dial(t)
	if err := c.Bind("ok", "pw"); err != nil {
		t.Fatal(err)
	}
	add := ldap.NewAddRequest("cn=x,dc=x", nil)
	add.Attribute("cn", []string{"x"})
	mod := ldap.NewModifyRequest("cn=x,dc=x", nil)
	mod.Replace("cn", []string{"y"})
	cases := []struct {
		op   string
		call func() error
		code uint16
	}{
		{"add", func() error { return c.Add(add) }, ldap.LDAPResultUnwillingToPerform},
		{"modify", func() error { return c.Modify(mod) }, ldap.LDAPResultUnwillingToPerform},
		{"delete", func() error { return c.Del(ldap.NewDelRequest("cn=x,dc=x", nil)) }, ldap.LDAPResultUnwillingToPerform},
		{"modrdn", func() error { return c.ModifyDN(ldap.NewModifyDNRequest("cn=x,dc=x", "cn=y", true, "")) }, ldap.LDAPResultUnwillingToPerform},
		{"compare", func() error {
			ok, err := c.Compare("cn=x,dc=x", "cn", "x")
			if err == nil && ok {
				return errors.New("compare returned true")
			}
			return err
		}, ldap.LDAPResultCompareFalse},
		{"extended", func() error { _, err := c.WhoAmI(nil); return err }, ldap.LDAPResultUnwillingToPerform},
		{"extended", func() error { _, err := c.PasswordModify(ldap.NewPasswordModifyRequest("", "old", "new")); return err }, ldap.LDAPResultUnwillingToPerform},
	}
	for i, tc := range cases {
		err := tc.call()
		if tc.op == "compare" {
			if err != nil {
				t.Errorf("compare: %v (want compareFalse without error)", err)
			}
		} else if !ldap.IsErrorWithCode(err, tc.code) {
			t.Errorf("%s: %v, want code %d", tc.op, err, tc.code)
		}
		evs := ts.ev.find(events.OpDenied)
		if len(evs) != i+1 {
			t.Fatalf("%s: %d op_denied events, want %d", tc.op, len(evs), i+1)
		}
		e := evs[i]
		if e.Data["op"] != tc.op || e.Level != events.LevelMedium || e.Account != "ok" || e.ClientIP != "127.0.0.1" || e.ConnID == "" || e.TLS == nil || *e.TLS {
			t.Errorf("%s event = %+v", tc.op, e)
		}
		if tc.op == "extended" && e.Data["oid"] == "" {
			t.Errorf("extended op_denied without oid: %+v", e.Data)
		}
	}
	// The connection is still usable afterwards.
	if _, err := c.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, 0, 0, 0, false, "(objectClass=*)", nil, nil)); err != nil {
		t.Errorf("search after denials: %v", err)
	}
}

func TestLDAPS(t *testing.T) {
	ts := start(t, Config{Profile: "p", Transport: TransportLDAPS})
	c := ts.dial(t)
	if err := c.Bind("ok", "pw"); err != nil {
		t.Fatalf("bind over ldaps: %v", err)
	}
	// op_denied carries tls=true.
	_, _ = c.Compare("cn=x", "cn", "x")
	if evs := ts.ev.find(events.OpDenied); len(evs) != 1 || evs[0].TLS == nil || !*evs[0].TLS {
		t.Errorf("tls flag in event: %+v", evs)
	}
	// StartTLS on an ldaps listener is refused.
	if err := c.StartTLS(ts.clientTLS()); err == nil {
		t.Error("StartTLS over ldaps should fail")
	}
	// A plain client on the ldaps port gets nothing but a closed connection.
	raw, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", ts.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_, _ = raw.Write(bindPacket(1, 3, "ok", "pw"))
	_ = raw.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	if n, err := raw.Read(buf); err == nil && n > 0 && buf[0] == 0x30 {
		t.Error("plain client on ldaps port received an LDAP response")
	}
}

func TestStartTLS_Flows(t *testing.T) {
	for _, tc := range []struct {
		name      string
		transport string
		required  bool
	}{{"optional", TransportLDAPStartTLS, false}, {"required-flag", TransportLDAPStartTLS, true}, {"starttls", TransportStartTLS, false}} {
		t.Run(tc.name, func(t *testing.T) {
			ts := start(t, Config{Profile: "p", Transport: tc.transport, StartTLSRequired: tc.required})
			requires := tc.required || tc.transport == TransportStartTLS
			if ts.RequiresTLS() != requires || !ts.OffersStartTLS() {
				t.Fatalf("RequiresTLS=%v OffersStartTLS=%v", ts.RequiresTLS(), ts.OffersStartTLS())
			}
			c := ts.dial(t)
			// Root DSE is always readable in clear text.
			if _, err := c.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, 0, 0, 0, false, "(objectClass=*)", []string{"supportedExtension"}, nil)); err != nil {
				t.Errorf("root DSE in clear: %v", err)
			}
			err := c.Bind("ok", "pw")
			_, serr := c.Search(ldap.NewSearchRequest("dc=x", ldap.ScopeBaseObject, 0, 0, 0, false, "(objectClass=*)", nil, nil))
			if requires {
				if !ldap.IsErrorWithCode(err, ldap.LDAPResultConfidentialityRequired) || !ldap.IsErrorWithCode(serr, ldap.LDAPResultConfidentialityRequired) {
					t.Errorf("plain bind/search with TLS required: %v / %v", err, serr)
				}
			} else if err != nil || serr != nil {
				t.Errorf("plain bind/search allowed: %v / %v", err, serr)
			}
			if err := c.StartTLS(ts.clientTLS()); err != nil {
				t.Fatalf("StartTLS: %v", err)
			}
			if err := c.Bind("ok", "pw"); err != nil {
				t.Errorf("bind after StartTLS: %v", err)
			}
			if err := c.StartTLS(ts.clientTLS()); err == nil {
				t.Error("second StartTLS should fail")
			}
		})
	}
	t.Run("not-offered", func(t *testing.T) {
		ts := start(t, Config{Profile: "p", Transport: TransportLDAP})
		c := ts.dial(t)
		if err := c.StartTLS(ts.clientTLS()); err == nil {
			t.Error("StartTLS on a plain listener should be refused")
		}
		if evs := ts.ev.find(events.OpDenied); len(evs) != 0 {
			t.Errorf("StartTLS must not be reported as op_denied: %+v", evs)
		}
	})
	t.Run("handshake-failure", func(t *testing.T) {
		ts := start(t, Config{Profile: "p", Transport: TransportLDAPStartTLS, HandshakeTimeout: 300 * time.Millisecond})
		raw, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", ts.addr)
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		if _, err := raw.Write(extendedPacket(1, oidStartTLS)); err != nil {
			t.Fatal(err)
		}
		rd := bufio.NewReader(raw)
		_ = raw.SetReadDeadline(time.Now().Add(2 * time.Second))
		msg := readRaw(t, rd)
		if msg.ID != 1 || msg.Op != ldap.ApplicationExtendedResponse {
			t.Fatalf("response = %+v", msg)
		}
		// Send junk instead of a ClientHello: the server closes.
		_, _ = raw.Write([]byte("not a hello"))
		if _, err := rd.ReadByte(); err == nil {
			t.Error("connection should be closed after a failed handshake")
		}
	})
}

// bindPacket encodes a simple bind.
func bindPacket(id int64, version int, name, pw string) []byte {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindRequest, nil, "Bind")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, version, "version"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "name"))
	op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, pw, "password"))
	return envelope(id, op, nil).Bytes()
}

func extendedPacket(id int64, oid string) []byte {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationExtendedRequest, nil, "Extended")
	op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, oid, "requestName"))
	return envelope(id, op, nil).Bytes()
}

func readRaw(t *testing.T, rd *bufio.Reader) *message {
	t.Helper()
	raw, err := readMessage(rd, 0)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	m, err := parseMessage(raw)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	return m
}

func resultCode(t *testing.T, m *message) int64 {
	t.Helper()
	if len(m.Body.Children) == 0 {
		t.Fatalf("no result in %+v", m)
	}
	code, _ := m.Body.Children[0].Value.(int64)
	return code
}

func rawConn(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	raw, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	return raw, bufio.NewReader(raw)
}

func TestProtocol_Edges(t *testing.T) {
	ts := start(t, Config{Profile: "p", MaxRequestBytes: 512})
	t.Run("sasl", func(t *testing.T) {
		raw, rd := rawConn(t, ts.addr)
		op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindRequest, nil, "Bind")
		op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "version"))
		op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "name"))
		sasl := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "sasl")
		sasl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "GSSAPI", "mechanism"))
		op.AppendChild(sasl)
		_, _ = raw.Write(envelope(5, op, nil).Bytes())
		m := readRaw(t, rd)
		if m.ID != 5 || resultCode(t, m) != ldap.LDAPResultAuthMethodNotSupported {
			t.Errorf("sasl bind → %d", resultCode(t, m))
		}
	})
	t.Run("version2", func(t *testing.T) {
		raw, rd := rawConn(t, ts.addr)
		_, _ = raw.Write(bindPacket(2, 2, "x", "y"))
		if m := readRaw(t, rd); resultCode(t, m) != ldap.LDAPResultProtocolError {
			t.Errorf("v2 bind → %d", resultCode(t, m))
		}
	})
	t.Run("abandon-ignored", func(t *testing.T) {
		raw, rd := rawConn(t, ts.addr)
		ab := ber.NewInteger(ber.ClassApplication, ber.TypePrimitive, ldap.ApplicationAbandonRequest, 1, "abandon")
		_, _ = raw.Write(envelope(2, ab, nil).Bytes())
		_, _ = raw.Write(bindPacket(3, 3, "ok", "pw"))
		if m := readRaw(t, rd); m.ID != 3 || resultCode(t, m) != 0 {
			t.Errorf("after abandon: id=%d code=%d", m.ID, resultCode(t, m))
		}
	})
	t.Run("unknown-op", func(t *testing.T) {
		raw, rd := rawConn(t, ts.addr)
		op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 30, nil, "bogus")
		op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "x", "x"))
		_, _ = raw.Write(envelope(1, op, nil).Bytes())
		m := readRaw(t, rd)
		if m.ID != 0 || resultCode(t, m) != ldap.LDAPResultProtocolError {
			t.Errorf("notice = %+v code %d", m, resultCode(t, m))
		}
		if err := closed(rd); err != nil {
			t.Errorf("connection should be closed: %v", err)
		}
	})
	t.Run("malformed-envelope", func(t *testing.T) {
		raw, rd := rawConn(t, ts.addr)
		p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
		p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "id?", "not an id"))
		p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "op?", "not an op"))
		_, _ = raw.Write(p.Bytes())
		m := readRaw(t, rd)
		if m.ID != 0 || resultCode(t, m) != ldap.LDAPResultProtocolError {
			t.Errorf("malformed → %d", resultCode(t, m))
		}
	})
	t.Run("malformed-bind", func(t *testing.T) {
		raw, rd := rawConn(t, ts.addr)
		op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindRequest, nil, "Bind")
		op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "version"))
		_, _ = raw.Write(envelope(1, op, nil).Bytes())
		if m := readRaw(t, rd); m.ID != 0 {
			t.Errorf("expected notice, got id %d", m.ID)
		}
	})
	t.Run("malformed-search", func(t *testing.T) {
		raw, rd := rawConn(t, ts.addr)
		op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchRequest, nil, "Search")
		op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "dc=x", "base"))
		_, _ = raw.Write(envelope(1, op, nil).Bytes())
		if m := readRaw(t, rd); m.ID != 0 {
			t.Errorf("expected notice, got id %d", m.ID)
		}
	})
	t.Run("malformed-extended", func(t *testing.T) {
		raw, rd := rawConn(t, ts.addr)
		op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationExtendedRequest, nil, "Extended")
		_, _ = raw.Write(envelope(1, op, nil).Bytes())
		if m := readRaw(t, rd); m.ID != 0 {
			t.Errorf("expected notice, got id %d", m.ID)
		}
	})
	t.Run("tls-hello-on-plain", func(t *testing.T) {
		raw, rd := rawConn(t, ts.addr)
		_, _ = raw.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5})
		if err := closed(rd); err != nil {
			t.Errorf("expected close, got %v", err)
		}
	})
	t.Run("oversize", func(t *testing.T) {
		raw, rd := rawConn(t, ts.addr)
		// SEQUENCE with a 2 MiB length.
		_, _ = raw.Write([]byte{0x30, 0x83, 0x20, 0x00, 0x00})
		m := readRaw(t, rd)
		if m.ID != 0 || resultCode(t, m) != ldap.LDAPResultProtocolError {
			t.Errorf("oversize → %+v", m)
		}
		evs := ts.ev.find(events.RateLimited)
		if len(evs) != 1 || evs[0].Reason != "oversize" || evs[0].Data["key"] != "127.0.0.1" {
			t.Errorf("rate_limited = %+v", evs)
		}
		// Indefinite length and too many length octets are refused too.
		raw2, rd2 := rawConn(t, ts.addr)
		_, _ = raw2.Write([]byte{0x30, 0x80})
		if err := closed(rd2); err != nil {
			t.Errorf("indefinite length: %v", err)
		}
		raw3, rd3 := rawConn(t, ts.addr)
		_, _ = raw3.Write([]byte{0x30, 0x85, 1, 1, 1, 1, 1})
		if m := readRaw(t, rd3); resultCode(t, m) != ldap.LDAPResultProtocolError {
			t.Errorf("5 length octets → %d", resultCode(t, m))
		}
	})
	t.Run("short", func(t *testing.T) {
		raw, rd := rawConn(t, ts.addr)
		_, _ = raw.Write([]byte{0x30, 0x02, 0x02, 0x01})
		if err := closed(rd); err != nil {
			t.Errorf("short message: %v", err)
		}
	})
}

func TestTimeouts(t *testing.T) {
	// The idle timeout leaves a wide margin over the pause below: under -race on
	// a loaded CI runner a sleep can overshoot by hundreds of milliseconds.
	ts := start(t, Config{Profile: "p", FirstPacketTimeout: 150 * time.Millisecond, IdleTimeout: 1500 * time.Millisecond})
	t.Run("first-packet", func(t *testing.T) {
		_, rd := rawConn(t, ts.addr)
		startT := time.Now()
		m := readRaw(t, rd)
		if m.ID != 0 || resultCode(t, m) != ldap.LDAPResultUnavailable || time.Since(startT) > 2*time.Second {
			t.Errorf("first packet timeout → %+v after %v", m, time.Since(startT))
		}
	})
	t.Run("idle", func(t *testing.T) {
		raw, rd := rawConn(t, ts.addr)
		_, _ = raw.Write(bindPacket(1, 3, "ok", "pw"))
		if m := readRaw(t, rd); resultCode(t, m) != 0 {
			t.Fatalf("bind → %d", resultCode(t, m))
		}
		time.Sleep(300 * time.Millisecond) // well inside the idle timeout
		_, _ = raw.Write(bindPacket(2, 3, "ok", "pw"))
		if m := readRaw(t, rd); m.ID != 2 {
			t.Fatalf("second bind within idle timeout → id %d", m.ID)
		}
		m := readRaw(t, rd)
		if m.ID != 0 || resultCode(t, m) != ldap.LDAPResultUnavailable {
			t.Errorf("idle → %+v", m)
		}
	})
}

func TestLimits(t *testing.T) {
	perIP := NewIPLimiter(2)
	global := NewLimiter(3)
	ts := start(t, Config{Profile: "p", PerIP: perIP, Global: global})
	ts2 := start(t, Config{Profile: "p", PerIP: perIP, Global: global})
	c1 := ts.dial(t)
	c2 := ts2.dial(t) // same profile limiter across listeners
	// Dial returns before the server's Accept has counted the connection.
	waitFor(t, func() bool { return perIP.Count("127.0.0.1") == 2 && global.Count() == 2 })
	raw, rd := rawConn(t, ts.addr)
	_, _ = raw.Write(bindPacket(1, 3, "ok", "pw"))
	if err := closed(rd); err != nil {
		t.Errorf("third connection from the same IP should be closed, got %v", err)
	}
	evs := ts.ev.find(events.RateLimited)
	if len(evs) != 1 || evs[0].Reason != "conn_limit_ip" || evs[0].Data["limit"] != 2 {
		t.Errorf("rate_limited = %+v", evs)
	}
	if global.Count() != 2 {
		t.Errorf("rejected connection must release the global slot: %d", global.Count())
	}
	_ = c1.Close()
	waitFor(t, func() bool { return perIP.Count("127.0.0.1") == 1 && global.Count() == 1 })
	_ = c2
	// Global limit.
	g := NewLimiter(1)
	ts3 := start(t, Config{Profile: "g", Global: g})
	ts3.dial(t)
	waitFor(t, func() bool { return g.Count() == 1 })
	raw2, rd2 := rawConn(t, ts3.addr)
	_, _ = raw2.Write(bindPacket(1, 3, "ok", "pw"))
	if err := closed(rd2); err != nil {
		t.Errorf("over the global limit: %v", err)
	}
	if evs := ts3.ev.find(events.RateLimited); len(evs) != 1 || evs[0].Reason != "conn_limit_global" {
		t.Errorf("rate_limited = %+v", evs)
	}
	// Unlimited limiters.
	u := NewLimiter(0)
	if !u.Acquire() || u.Limit() != 0 {
		t.Error("unlimited limiter")
	}
	u.Release()
	ui := NewIPLimiter(0)
	if !ui.Acquire("x") || ui.Count("x") != 0 {
		t.Error("unlimited ip limiter")
	}
	ui.Release("x")
	li := NewIPLimiter(1)
	li.Release("never") // no-op
	if li.Count("never") != 0 {
		t.Error("release of unknown ip")
	}
}

func TestShutdown_Graceful(t *testing.T) {
	h := &fakeHandler{block: make(chan struct{})}
	ts := start(t, Config{Profile: "p", Handler: h})
	// Idle connection: receives the notice of disconnection when the drain
	// deadline passes.
	idle, idleRd := rawConn(t, ts.addr)
	_, _ = idle.Write(bindPacket(1, 3, "ok", "pw"))
	readRaw(t, idleRd)
	// Busy connection: a search in flight.
	busy, busyRd := rawConn(t, ts.addr)
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchRequest, nil, "Search")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "dc=x", "base"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 2, "scope"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "deref"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "size"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "time"))
	op.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "typesOnly"))
	filter, _ := ldap.CompileFilter("(cn=*)")
	op.AppendChild(filter)
	op.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attrs"))
	_, _ = busy.Write(envelope(7, op, nil).Bytes())
	// Wait until the search is inside the handler (blocked on h.block).
	waitFor(t, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return len(h.searches) == 1
	})
	if ts.ConnCount() != 2 {
		t.Fatalf("conns = %d", ts.ConnCount())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	startT := time.Now()
	err := ts.Shutdown(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(startT) > 2*time.Second {
		t.Errorf("Shutdown = %v after %v", err, time.Since(startT))
	}
	if m := readRaw(t, idleRd); m.ID != 0 || resultCode(t, m) != ldap.LDAPResultUnavailable {
		t.Errorf("idle connection notice = %+v", m)
	}
	if err := closed(idleRd); err != nil {
		t.Errorf("idle connection should be closed: %v", err)
	}
	// The in-flight handler saw the canceled context.
	h.mu.Lock()
	ctxErr := h.ctxErr
	h.mu.Unlock()
	if ctxErr == nil {
		t.Error("in-flight search was not canceled")
	}
	_ = busyRd
	// New connections are refused.
	if _, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", ts.addr); err == nil {
		t.Error("listener should be closed")
	}
	if err := <-ts.done; !errors.Is(err, ErrServerClosed) {
		t.Errorf("Serve returned %v", err)
	}
}

func TestShutdown_WaitsForDrain(t *testing.T) {
	ts := start(t, Config{Profile: "p"})
	c := ts.dial(t)
	waitFor(t, func() bool { return ts.ConnCount() == 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res := make(chan error, 1)
	go func() { res <- ts.Shutdown(ctx) }()
	// Serve returns once Shutdown has closed the listener: the drain is on.
	if err := <-ts.done; !errors.Is(err, ErrServerClosed) {
		t.Fatalf("Serve returned %v", err)
	}
	_ = c.Close()
	if err := <-res; err != nil {
		t.Errorf("Shutdown after client unbind = %v", err)
	}
}

func TestConn_Helpers(t *testing.T) {
	c := &Conn{id: "c-1", profile: "p", remote: &net.TCPAddr{IP: net.ParseIP("10.1.2.3"), Port: 4444}}
	if c.ID() != "c-1" || c.Profile() != "p" || c.ClientIP() != "10.1.2.3" || c.ClientPort() != 4444 || c.RemoteAddr().String() != "10.1.2.3:4444" {
		t.Error("accessors")
	}
	c.SetBound(Bound{Kind: BindClient, Name: "cn=app"})
	if c.Bound().Kind != BindClient {
		t.Error("bound")
	}
	c.Store("k", 1)
	if v, ok := c.Load("k"); !ok || v != 1 {
		t.Error("store/load")
	}
	c.Store("k", nil)
	if _, ok := c.Load("k"); ok {
		t.Error("delete")
	}
	ev := c.Event(events.Search, events.LevelLow)
	if ev.Account != "cn=app" || ev.ClientIP != "10.1.2.3" || ev.ClientPort != 4444 || ev.ConnID != "c-1" || *ev.TLS {
		t.Errorf("event = %+v", ev)
	}
	if ip, port := splitHostPort(nil); ip != "" || port != 0 {
		t.Error("nil addr")
	}
	if ip, port := splitHostPort(&net.UnixAddr{Name: "/tmp/x", Net: "unix"}); ip != "/tmp/x" || port != 0 {
		t.Errorf("unix addr → %q %d", ip, port)
	}
	if ip, port := splitHostPort(stringAddr("[::1]:636")); ip != "::1" || port != 636 {
		t.Errorf("string addr → %q %d", ip, port)
	}
	for s, want := range map[Scope]string{ScopeBase: "base", ScopeOne: "one", ScopeSub: "sub", Scope(9): "scope(9)"} {
		if s.String() != want {
			t.Errorf("%d → %s", s, s.String())
		}
	}
	if tag, ok := responseTag(ldap.ApplicationUnbindRequest); ok || tag != 0 {
		t.Error("unbind has no response")
	}
	if deniedOp(ldap.ApplicationBindRequest) != "" {
		t.Error("bind is not denied")
	}
}

// waitFor polls cond for up to five seconds.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

// closed reports nil when the peer has closed the connection (EOF or reset).
func closed(rd *bufio.Reader) error {
	_, err := rd.ReadByte()
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return nil
	}
	var ne *net.OpError
	if errors.As(err, &ne) && strings.Contains(ne.Err.Error(), "reset") {
		return nil
	}
	if err == nil {
		return errors.New("connection still open")
	}
	return err
}

type stringAddr string

func (s stringAddr) Network() string { return "tcp" }
func (s stringAddr) String() string  { return string(s) }

func TestPanicRecovery(t *testing.T) {
	ts := start(t, Config{Profile: "p", Handler: panicHandler{}})
	c := ts.dial(t)
	if err := c.Bind("boom", "pw"); err == nil {
		t.Error("connection should drop on panic")
	}
	waitFor(t, func() bool { return ts.ConnCount() == 0 })
}

type panicHandler struct{}

func (panicHandler) Bind(context.Context, *Conn, string, []byte) Result { panic("handler bug") }
func (panicHandler) Search(context.Context, *Conn, *SearchRequest, EntryWriter) Result {
	return Success
}
