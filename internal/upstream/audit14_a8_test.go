package upstream

// Audit 14, area A.8 (upstream): referrals/SSRF, LDAP signing result codes,
// failover idempotency, pool hygiene. Tests named TestAudit14_A8_*; a test
// that fails on the current code documents a FINDING in the audit report.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/ldapfilter"
)

// AD diagnostics for the two "secure the channel" result codes.
const (
	diagStrongerAuth = `00002028: LdapErr: DSID-0C090259, comment: The server requires binds to turn on integrity checking if SSL\TLS are not already active on the connection, data 0, v4563`
	diagConfReq      = `00002028: LdapErr: DSID-0C090259, comment: The server requires binds to be over SSL/TLS, data 0, v4563`
)

// ---- raw wire server: referrals ----------------------------------------------

// rawLDAPServer speaks just enough LDAP (BER) to answer binds with success and
// searches with a SearchResultReference plus a SearchResultDone carrying the
// given result code and referral URL.
type rawLDAPServer struct {
	ln       net.Listener
	refURL   string
	doneCode int64
	wg       sync.WaitGroup
	searches atomic.Int32
}

func startRawLDAP(t *testing.T, refURL string, doneCode int64) *rawLDAPServer {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &rawLDAPServer{ln: ln, refURL: refURL, doneCode: doneCode}
	s.wg.Add(1)
	go s.serve()
	t.Cleanup(func() { _ = ln.Close(); s.wg.Wait() })
	return s
}

func (s *rawLDAPServer) serve() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer c.Close()
			for {
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				p, err := ber.ReadPacket(c)
				if err != nil || len(p.Children) < 2 {
					return
				}
				id, _ := p.Children[0].Value.(int64)
				op := p.Children[1]
				switch op.Tag {
				case ldap.ApplicationBindRequest:
					_, _ = c.Write(envelope(id, resultOp(ldap.ApplicationBindResponse, 0, "", nil)).Bytes())
				case ldap.ApplicationSearchRequest:
					s.searches.Add(1)
					ref := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultReference, nil, "SearchResultReference")
					ref.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, s.refURL, "uri"))
					_, _ = c.Write(envelope(id, ref).Bytes())
					var refs []string
					if s.doneCode == ldap.LDAPResultReferral {
						refs = []string{s.refURL}
					}
					_, _ = c.Write(envelope(id, resultOp(ldap.ApplicationSearchResultDone, s.doneCode, "", refs)).Bytes())
				case ldap.ApplicationUnbindRequest:
					return
				default:
					_, _ = c.Write(envelope(id, resultOp(ldap.ApplicationExtendedResponse, ldap.LDAPResultUnwillingToPerform, "", nil)).Bytes())
				}
			}
		}()
	}
}

func envelope(id int64, op *ber.Packet) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "MessageID"))
	p.AppendChild(op)
	return p
}

func resultOp(tag ber.Tag, code int64, diag string, referrals []string) *ber.Packet {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "op")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, "resultCode"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, diag, "diagnosticMessage"))
	if len(referrals) > 0 {
		r := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "referral")
		for _, u := range referrals {
			r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, u, "uri"))
		}
		op.AppendChild(r)
	}
	return op
}

// trapListener counts TCP connections: the referred-to "attacker" host.
func trapListener(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), &hits
}

func realConfig(url string) *config.Upstream {
	cfg := config.DefaultUpstream()
	cfg.Servers = []string{url}
	cfg.BindDN = "cn=svc,dc=x"
	cfg.BaseDN = "dc=x"
	cfg.AuditServiceAccount = false
	cfg.Timeouts = config.Timeouts{Connect: config.Duration(time.Second), Bind: config.Duration(time.Second), Search: config.Duration(2 * time.Second)}
	return cfg
}

// Check 1: a SearchResultReference and a referral(10) result pointing at an
// attacker host must never be dialed; the real go-ldap client is used.
func TestAudit14_A8_ReferralNotFollowed_Wire(t *testing.T) {
	trapAddr, hits := trapListener(t)
	refURL := "ldap://" + trapAddr + "/dc=evil,dc=x??sub?(objectClass=*)"
	for _, tc := range []struct {
		name string
		code int64
	}{{"reference_then_success", ldap.LDAPResultSuccess}, {"reference_then_referral", ldap.LDAPResultReferral}} {
		t.Run(tc.name, func(t *testing.T) {
			srv := startRawLDAP(t, refURL, tc.code)
			u, err := New("wire", realConfig("ldap://"+srv.ln.Addr().String()), "pw", Options{Logger: slog.New(slog.DiscardHandler)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(u.Close)
			res, err := u.Search(context.Background(), SearchRequest{Base: "dc=x", Scope: ScopeSub, Filter: ldapfilter.True(), Attrs: []string{"cn"}})
			switch tc.code {
			case ldap.LDAPResultSuccess:
				if err != nil || res == nil || res.Referrals != 1 || len(res.Entries) != 0 {
					t.Fatalf("reference ignored: res=%+v err=%v", res, err)
				}
			default:
				if !errors.Is(err, ErrReferral) {
					t.Fatalf("referral result → %v, want ErrReferral", err)
				}
				if errors.Is(err, ErrUnavailable) {
					t.Fatalf("referral must not count as a server failure: %v", err)
				}
			}
			time.Sleep(150 * time.Millisecond)
			if n := hits.Load(); n != 0 {
				t.Fatalf("referred host was dialed %d times", n)
			}
			if srv.searches.Load() != 1 {
				t.Fatalf("searches on the configured server = %d, want 1 (no retry)", srv.searches.Load())
			}
		})
	}
}

// Check 1: server URL parsing rejects userinfo, path, query, fragment and
// non-numeric ports; documents that out-of-range ports are accepted.
func TestAudit14_A8_ParseServerURL_Hostile(t *testing.T) {
	bad := []string{"ldap://user:pw@dc1", "ldap://dc1/dc=x", "ldap://dc1?x=1", "ldap://dc1#f", "ldap://dc1:abc", "ldap:///", "ldapi:///", "http://dc1", "ldap://user@dc1:389", "ldap://dc1:389/"}
	for _, s := range bad {
		if _, err := ParseServerURL(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	// Informational: numeric but out-of-range ports pass parsing (fail at dial).
	for _, s := range []string{"ldap://dc1:0", "ldap://dc1:99999"} {
		if _, err := ParseServerURL(s); err != nil {
			t.Logf("INFO %q rejected: %v", s, err)
		} else {
			t.Logf("INFO %q accepted by ParseServerURL (dial will fail at runtime)", s)
		}
	}
}

// ---- hook connections: observe per-connection operation order ----------------

type opLog struct {
	mu  sync.Mutex
	ops map[ldapConn][]string // conn → ops ("bind:<dn>", "search:<base>:<cookie>")
	srv map[ldapConn]string
}

type hookConn struct {
	ldapConn
	log      *opLog
	onSearch func(req *ldap.SearchRequest)
}

func (h *hookConn) Bind(dn, pw string) error {
	err := h.ldapConn.Bind(dn, pw)
	h.log.mu.Lock()
	h.log.ops[h] = append(h.log.ops[h], "bind:"+dn+":"+boolStr(err == nil))
	h.log.mu.Unlock()
	return err
}

func (h *hookConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	cookie := ""
	if ctl := pagingControl(req.Controls); ctl != nil {
		cookie = string(ctl.Cookie)
	}
	h.log.mu.Lock()
	h.log.ops[h] = append(h.log.ops[h], "search:"+req.BaseDN+":"+cookie)
	h.log.mu.Unlock()
	if h.onSearch != nil {
		h.onSearch(req)
	}
	return h.ldapConn.Search(req)
}

func boolStr(b bool) string {
	if b {
		return "ok"
	}
	return "fail"
}

// newHooked builds an Upstream over fake servers whose connections record
// every operation. onSearch runs before each search (server URL, request).
func newHooked(t *testing.T, cfg *config.Upstream, onSearch func(srv string, req *ldap.SearchRequest), sizes ...int) (*Upstream, []*fakeServer, *opLog, *eventLog) {
	t.Helper()
	n := &fakeNet{servers: map[string]*fakeServer{}}
	fss := make([]*fakeServer, 0, len(cfg.Servers))
	for i, raw := range cfg.Servers {
		su, err := ParseServerURL(raw)
		if err != nil {
			t.Fatal(err)
		}
		size := 0
		if i < len(sizes) {
			size = sizes[i]
		}
		fs := newFakeServer(size)
		n.servers[su.String()] = fs
		fss = append(fss, fs)
	}
	log := &opLog{ops: map[ldapConn][]string{}, srv: map[ldapConn]string{}}
	dial := func(ctx context.Context, srv ServerURL) (ldapConn, error) {
		c, err := n.dial(ctx, srv)
		if err != nil {
			return nil, err
		}
		h := &hookConn{ldapConn: c, log: log}
		if onSearch != nil {
			h.onSearch = func(req *ldap.SearchRequest) { onSearch(srv.String(), req) }
		}
		log.mu.Lock()
		log.srv[h] = srv.String()
		log.mu.Unlock()
		return h, nil
	}
	ev := &eventLog{}
	u, err := New("test", cfg, "svc-pw", Options{Events: ev, dial: dial, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(u.Close)
	return u, fss, log, ev
}

// Check 2: a connection that carried a user bind never carries a search, and
// a connection that carried the service bind never carries a user bind.
func TestAudit14_A8_BindPool_NeverSearches(t *testing.T) {
	u, _, log, _ := newHooked(t, testConfig("ldap://a"), nil, 6)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := u.UserBind(ctx, "cn=user,dc=x", "user-pw"); err != nil {
			t.Fatal(err)
		}
		if _, err := u.Search(ctx, SearchRequest{Base: "dc=x", Scope: ScopeSub, Filter: ldapfilter.True()}); err != nil {
			t.Fatal(err)
		}
		if err := u.UserBind(ctx, "cn=user,dc=x", "wrong"); !IsCredentialFailure(err) {
			t.Fatalf("wrong pw → %v", err)
		}
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	for c, ops := range log.ops {
		userBound, svcBound := false, false
		for _, op := range ops {
			switch {
			case strings.HasPrefix(op, "bind:cn=user,dc=x:"):
				userBound = true
				if svcBound {
					t.Errorf("service connection reused for a user bind: %v", ops)
				}
			case strings.HasPrefix(op, "bind:cn=svc,dc=x:"):
				svcBound = true
			case strings.HasPrefix(op, "search:"):
				if userBound {
					t.Errorf("connection bound as a user executed a search: %v", ops)
				}
			}
		}
		_ = c
	}
}

// Check 3: strongerAuthRequired(8)/confidentialityRequired(13) on a user bind
// map to upstream_error, are not retried on another server and are not a
// credential failure.
func TestAudit14_A8_UserBind_SigningRequired_Mapping(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"strongerAuthRequired", ldap.NewError(ldap.LDAPResultStrongAuthRequired, errors.New(diagStrongerAuth))},
		{"confidentialityRequired", ldap.NewError(ldap.LDAPResultConfidentialityRequired, errors.New(diagConfReq))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, fss, _ := newFake(t, testConfig("ldap://a", "ldap://b"))
			fss[0].bindErr, fss[1].bindErr = tc.err, tc.err
			err := u.UserBind(context.Background(), "cn=user,dc=x", "user-pw")
			var be *BindError
			if !errors.As(err, &be) {
				t.Fatalf("err = %v (%T), want *BindError", err, err)
			}
			if be.Reason != ReasonUpstreamError {
				t.Errorf("reason = %q, want upstream_error", be.Reason)
			}
			if be.Reason == ReasonInvalidPassword {
				t.Errorf("signing requirement reported as invalid_password")
			}
			_, b0, _ := fss[0].counts()
			_, b1, _ := fss[1].counts()
			if b0 != 1 || b1 != 0 {
				t.Errorf("binds a=%d b=%d, want 1/0 (no retry on another DC)", b0, b1)
			}
			if r, _ := ClassifyBindError(tc.err); r != ReasonUpstreamError {
				t.Errorf("ClassifyBindError = %q", r)
			}
			// BindError.Error() hides the cause entirely (see A8 finding on diagnostics).
			t.Logf("BindError.Error() = %q", be.Error())
		})
	}
}

// Check 3: `aldap check --online` must name the cause when the service bind
// is refused for a channel-security reason; "upstream_error" alone leaves the
// operator guessing between a dead DC, a typo and LDAP signing enforcement.
func TestAudit14_A8_Check_ServiceBindRefused_NamesCause(t *testing.T) {
	u, fss, _ := newFake(t, testConfig("ldap://a"))
	fss[0].bindErr = ldap.NewError(ldap.LDAPResultStrongAuthRequired, errors.New(diagStrongerAuth))
	out := u.Check(context.Background(), nil)
	var bind *Finding
	for i := range out {
		if out[i].Check == "bind" {
			bind = &out[i]
		}
	}
	if bind == nil || bind.OK {
		t.Fatalf("no failed bind finding: %+v", out)
	}
	msg := strings.ToLower(bind.Msg)
	if !strings.Contains(msg, "8") && !strings.Contains(msg, "strong") && !strings.Contains(msg, "sign") {
		t.Errorf("bind finding does not name the LDAP result: %q", bind.Msg)
	}
}

// Check 3: with health_check = rootdse (the default) an anonymous root DSE
// read succeeds on a DC that refuses the service bind, so the server is
// reported "up" although no search or user bind can ever succeed, and the
// request path flips it down/up (event storm).
func TestAudit14_A8_Health_RootDSE_MasksRefusedServiceBind(t *testing.T) {
	cfg := testConfig("ldap://a")
	cfg.HealthCheck = "rootdse"
	u, fss, ev := newFake(t, cfg, 3)
	fss[0].bindErr = ldap.NewError(ldap.LDAPResultStrongAuthRequired, errors.New(diagStrongerAuth))
	u.Start(context.Background())
	waitFor(t, "first health check", func() bool { return u.Status()[0].LastCheck != (time.Time{}) })
	// Every search fails because the service bind is refused.
	for i := 0; i < 6; i++ {
		if _, err := u.Search(context.Background(), SearchRequest{Base: "dc=x", Scope: ScopeSub, Filter: ldapfilter.True()}); err == nil {
			t.Fatalf("search %d succeeded although the service bind is refused", i)
		}
		time.Sleep(25 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	st := u.Status()[0]
	t.Logf("state=%s last_error=%q down=%d up=%d", st.State, st.LastError, ev.count(EventUpstreamDown), ev.count(EventUpstreamUp))
	if u.Healthy() {
		t.Errorf("upstream reported healthy while the service bind is refused with strongerAuthRequired")
	}
	if ev.count(EventUpstreamDown) > 1 {
		t.Errorf("server flapped: %d upstream_down events", ev.count(EventUpstreamDown))
	}
}

// Check 4: an invalidCredentials answer is final; only transport failures
// move a user bind to the next server.
func TestAudit14_A8_UserBind_RetryPolicy(t *testing.T) {
	u, fss, _ := newFake(t, testConfig("ldap://a", "ldap://b"))
	if err := u.UserBind(context.Background(), "cn=user,dc=x", "wrong"); !IsCredentialFailure(err) {
		t.Fatalf("wrong pw → %v", err)
	}
	_, b0, _ := fss[0].counts()
	_, b1, _ := fss[1].counts()
	if b0 != 1 || b1 != 0 {
		t.Errorf("invalidCredentials retried: binds a=%d b=%d", b0, b1)
	}
	// Transport failure: a is dead → b answers.
	fss[0].setAlive(false)
	if err := u.UserBind(context.Background(), "cn=user,dc=x", "user-pw"); err != nil {
		t.Fatalf("failover bind → %v", err)
	}
	_, b1, _ = fss[1].counts()
	if b1 != 1 {
		t.Errorf("binds on b = %d, want 1", b1)
	}
	// INFO: a bind that times out (ErrorNetwork / DeadlineExceeded) is a
	// transport failure and is retried — the DC may already have evaluated
	// the password (double badPwdCount). Documented, not asserted.
	fss[0].setAlive(true)
	fss[0].bindErr = ldap.NewError(ldap.ErrorNetwork, context.DeadlineExceeded)
	fss[1].bindErr = nil
	_ = u.UserBind(context.Background(), "cn=user,dc=x", "user-pw")
	_, b1after, _ := fss[1].counts()
	t.Logf("INFO timed-out bind retried on b: %v", b1after > b1)
}

// Check 4: a paged search that loses its server mid-way restarts on the next
// server with an empty cookie (never DC1's cookie on DC2) and the service
// bind is never retried with invalidCredentials... (fake: dead server).
func TestAudit14_A8_PagedFailover_FreshCookie(t *testing.T) {
	cfg := testConfig("ldap://a", "ldap://b")
	var fss []*fakeServer
	var once sync.Once
	u, servers, log, _ := newHooked(t, cfg, func(srv string, req *ldap.SearchRequest) {
		if srv == "ldap://a:389" {
			if ctl := pagingControl(req.Controls); ctl != nil && len(ctl.Cookie) > 0 {
				once.Do(func() { fss[0].setAlive(false) }) // dies when asked for page 2
			}
		}
	}, 10, 10)
	fss = servers
	res, err := u.Search(context.Background(), SearchRequest{Base: "dc=x", Scope: ScopeSub, Filter: ldapfilter.True()})
	if err != nil {
		t.Fatalf("search → %v", err)
	}
	if res.Server != "ldap://b:389" || len(res.Entries) != 10 {
		t.Fatalf("res = %+v", res)
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	for c, ops := range log.ops {
		if log.srv[c] != "ldap://b:389" {
			continue
		}
		for i, op := range ops {
			if strings.HasPrefix(op, "search:dc=x:") && i == firstSearchIdx(ops) && op != "search:dc=x:" {
				t.Errorf("first search on b carried a foreign cookie: %q", op)
			}
		}
	}
}

func firstSearchIdx(ops []string) int {
	for i, op := range ops {
		if strings.HasPrefix(op, "search:dc=x:") {
			return i
		}
	}
	return -1
}

// Check 4: fail_threshold applies to unknown servers too (unknown → down after
// fail_threshold, unknown → up on the first success).
func TestAudit14_A8_FailThreshold_Unknown(t *testing.T) {
	s := &server{}
	f := config.Failover{FailThreshold: 3, RecoverThreshold: 2}
	now := time.Now()
	for i := 0; i < 2; i++ {
		if _, ch := s.record(false, errNet, 0, f, now); ch {
			t.Fatalf("down after %d failures", i+1)
		}
	}
	if tr, ch := s.record(false, errNet, 0, f, now); !ch || tr.to != StateDown {
		t.Fatalf("not down after fail_threshold: %+v %v", tr, ch)
	}
	s2 := &server{}
	if tr, ch := s2.record(true, nil, 0, f, now); !ch || tr.to != StateUp {
		t.Fatalf("unknown → up on first success: %+v %v", tr, ch)
	}
}

// Check 5: tls_ca_file replaces the system roots (a public CA cannot MITM a
// DC name); without it the system roots are used; tls_server_name applies
// to every server; an IP host becomes the ServerName (IP SAN check).
func TestAudit14_A8_TLS_RootsAndServerName(t *testing.T) {
	cfg := config.DefaultUpstream()
	cfg.Servers = []string{"ldaps://10.0.0.5"}
	tc, err := buildTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tc.RootCAs != nil {
		t.Errorf("without tls_ca_file RootCAs must be nil (system roots)")
	}
	if tc.InsecureSkipVerify || tc.MinVersion < 0x0303 {
		t.Errorf("tls defaults: %+v", tc)
	}
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, selfSignedPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.TLSCAFile = ca
	tc, err = buildTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tc.RootCAs == nil {
		t.Errorf("tls_ca_file set but RootCAs nil (system roots would still be trusted)")
	}
	d := &dialer{cfg: cfg, tls: tc}
	su, _ := ParseServerURL("ldaps://10.0.0.5")
	if got := d.tlsConfigFor(su).ServerName; got != "10.0.0.5" {
		t.Errorf("ServerName for IP host = %q", got)
	}
	cfg.TLSServerName = "dc1.corp.local"
	tc, _ = buildTLSConfig(cfg)
	d = &dialer{cfg: cfg, tls: tc}
	su2, _ := ParseServerURL("ldaps://dc2.corp.local")
	if got := d.tlsConfigFor(su2).ServerName; got != "dc1.corp.local" {
		t.Errorf("tls_server_name not applied: %q", got)
	}
	t.Logf("INFO one tls_server_name applies to every server in `servers` (dc2 verified against %q)", "dc1.corp.local")
}

// Check 5: pool.size bounds concurrent connections; the service pool and the
// bind pool are separate bounds (2 × size per server).
func TestAudit14_A8_Pool_Bound(t *testing.T) {
	cfg := testConfig("ldap://a")
	cfg.Pool.Size = 2
	u, fss, _ := newFake(t, cfg, 50)
	fss[0].searchErr = nil
	// Hold both service slots; a third get must block until ctx ends.
	s := u.servers[0]
	ctx := context.Background()
	c1, err := s.svc.get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := s.svc.get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if _, err := s.svc.get(tctx); !errors.Is(err, ErrPoolExhausted) {
		t.Errorf("third get → %v, want ErrPoolExhausted", err)
	}
	// The bind pool is a separate bound: a user bind still works.
	if err := u.UserBind(ctx, "cn=user,dc=x", "user-pw"); err != nil {
		t.Errorf("bind pool blocked by service pool: %v", err)
	}
	s.svc.put(c1, true)
	s.svc.put(c2, true)
	fss[0].mu.Lock()
	open := fss[0].open
	fss[0].mu.Unlock()
	if open > 2*cfg.Pool.Size {
		t.Errorf("open connections %d > 2*pool.size", open)
	}
}

// selfSignedPEM returns a throw-away self-signed CA certificate in PEM.
func selfSignedPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "audit-a8-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
