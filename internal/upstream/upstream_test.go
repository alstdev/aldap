package upstream

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/ldapfilter"
)

func mustFilter(t *testing.T, s string) *ldapfilter.Filter {
	t.Helper()
	f, err := ldapfilter.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestParseServerURL_Cases(t *testing.T) {
	tests := []struct {
		in       string
		want     string
		addr     string
		tls      bool
		wantErr  bool
		errMatch string
	}{
		{in: "ldap://dc1", want: "ldap://dc1:389", addr: "dc1:389"},
		{in: "ldaps://dc1.corp.local", want: "ldaps://dc1.corp.local:636", addr: "dc1.corp.local:636", tls: true},
		{in: "ldap://10.0.0.1:3268", want: "ldap://10.0.0.1:3268", addr: "10.0.0.1:3268"},
		{in: "ldaps://[::1]:6636", want: "ldaps://[::1]:6636", addr: "[::1]:6636", tls: true},
		{in: "http://dc1", wantErr: true, errMatch: "scheme"},
		{in: "ldap://", wantErr: true, errMatch: "host"},
		{in: "ldap://dc1/dc=x", wantErr: true, errMatch: "scheme://host"},
		{in: "ldap://user@dc1", wantErr: true, errMatch: "scheme://host"},
		{in: "ldap://dc1?x=1", wantErr: true, errMatch: "scheme://host"},
		{in: "::bad", wantErr: true, errMatch: "server url"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseServerURL(tc.in)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), tc.errMatch) {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err != nil || got.String() != tc.want || got.Addr() != tc.addr || got.TLS() != tc.tls || got.Raw != tc.in {
				t.Fatalf("got %+v, %v", got, err)
			}
		})
	}
}

func TestSerializeFilter_Cases(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr error
	}{
		{name: "plain", in: "(cn=a)", want: "(cn=a)"},
		{name: "absolute_true", in: "(&)", want: PresentAll},
		{name: "absolute_false", in: "(|)", wantErr: ErrAbsoluteFalse},
		{name: "nested_true_in_and", in: "(&(cn=a)(&))", want: "(cn=a)"},
		{name: "nested_true_in_or", in: "(|(cn=a)(&))", want: PresentAll},
		{name: "nested_false_in_and", in: "(&(cn=a)(|))", wantErr: ErrAbsoluteFalse},
		{name: "nested_false_in_or", in: "(|(cn=a)(|))", want: "(cn=a)"},
		{name: "not_true", in: "(!(&))", wantErr: ErrAbsoluteFalse},
		{name: "not_false", in: "(!(|))", want: PresentAll},
		{name: "deep", in: "(&(|(cn=a)(&(|)(sn=b)))(!(|)))", want: "(cn=a)"},
		{name: "deep_false", in: "(&(objectClass=user)(|(&(|))(|)))", wantErr: ErrAbsoluteFalse},
		{name: "keeps_multi", in: "(&(cn=a)(sn=b)(&))", want: "(&(cn=a)(sn=b))"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SerializeFilter(mustFilter(t, tc.in))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
			if strings.Contains(got, "(&)") || strings.Contains(got, "(|)") {
				t.Fatalf("absolute filter leaked to upstream: %q", got)
			}
		})
	}
	if got, err := SerializeFilter(nil); err != nil || got != PresentAll {
		t.Fatalf("nil: %q %v", got, err)
	}
	if _, err := SerializeFilter(&ldapfilter.Filter{Kind: ldapfilter.Not}); err == nil {
		t.Fatal("malformed not accepted")
	}
	if _, err := SerializeFilter(&ldapfilter.Filter{Kind: ldapfilter.And, Children: []*ldapfilter.Filter{{Kind: ldapfilter.Not}, {Kind: ldapfilter.Equality, Attr: "a", Value: "b"}}}); err == nil {
		t.Fatal("malformed nested not accepted")
	}
}

func TestClassifyBindError_Cases(t *testing.T) {
	ad := func(data string) error {
		return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data "+data+", v4563"))
	}
	tests := []struct {
		name string
		err  error
		want Reason
		data string
	}{
		{name: "nil", err: nil, want: ReasonNone},
		{name: "52e", err: ad("52e"), want: ReasonInvalidPassword, data: "52e"},
		{name: "52E_upper", err: ad("52E"), want: ReasonInvalidPassword, data: "52e"},
		{name: "525", err: ad("525"), want: ReasonUnknownAccount, data: "525"},
		{name: "533", err: ad("533"), want: ReasonDisabled, data: "533"},
		{name: "775", err: ad("775"), want: ReasonLockedInAD, data: "775"},
		{name: "701", err: ad("701"), want: ReasonExpired, data: "701"},
		{name: "532", err: ad("532"), want: ReasonExpired, data: "532"},
		{name: "773", err: ad("773"), want: ReasonMustChange, data: "773"},
		{name: "530", err: ad("530"), want: ReasonDisabled, data: "530"},
		{name: "unknown_data", err: ad("999"), want: ReasonInvalidPassword, data: "999"},
		{name: "plain_49", err: ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("")), want: ReasonInvalidPassword},
		{name: "network", err: errNet, want: ReasonUpstreamError},
		{name: "other", err: errors.New("boom"), want: ReasonUpstreamError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, data := ClassifyBindError(tc.err)
			if r != tc.want || data != tc.data {
				t.Fatalf("got %s/%q, want %s/%q", r, data, tc.want, tc.data)
			}
		})
	}
	be := &BindError{Reason: ReasonLockedInAD, Data: "775", Err: ad("775")}
	if be.Level() != "medium" || !strings.Contains(be.Error(), "locked_in_ad (data 775)") || !errors.Is(be, be.Err) || !IsCredentialFailure(be) {
		t.Fatalf("bind error: %v level %s", be, be.Level())
	}
	if (&BindError{Reason: ReasonInvalidPassword}).Level() != "low" || (&BindError{Reason: ReasonInvalidPassword}).Error() != "bind failed: invalid_password" || IsCredentialFailure(errNet) {
		t.Fatal("bind error defaults")
	}
}

func TestPool_Lifecycle(t *testing.T) {
	fs := newFakeServer(0)
	now := time.Now()
	clock := func() time.Time { return now }
	p := newPool(2, time.Minute, clock, nil, func(context.Context) (ldapConn, error) {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		fs.dials++
		if !fs.alive {
			return nil, errNet
		}
		return &fakeConn{srv: fs}, nil
	})
	ctx := context.Background()
	c1, err := p.get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := p.get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if idle, active := p.stats(); idle != 0 || active != 2 {
		t.Fatalf("stats idle=%d active=%d", idle, active)
	}
	short, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if _, err := p.get(short); !errors.Is(err, ErrPoolExhausted) || !isConnError(err) {
		t.Fatalf("exhausted: %v", err)
	}
	p.put(c1, true)
	p.put(c2, false)
	if idle, active := p.stats(); idle != 1 || active != 0 || !c2.(*fakeConn).closed.Load() {
		t.Fatalf("after put idle=%d active=%d", idle, active)
	}
	c3, err := p.get(ctx)
	if err != nil || c3 != c1 {
		t.Fatalf("reuse: %v %v", c3, err)
	}
	p.put(c3, true)
	// Idle expiry on get and reap.
	now = now.Add(2 * time.Minute)
	p.reap()
	if idle, _ := p.stats(); idle != 0 || !c1.(*fakeConn).closed.Load() {
		t.Fatal("reap did not close expired idle")
	}
	c4, _ := p.get(ctx)
	p.put(c4, true)
	now = now.Add(2 * time.Minute)
	c5, _ := p.get(ctx)
	if c5 == c4 || !c4.(*fakeConn).closed.Load() {
		t.Fatal("expired idle reused")
	}
	p.put(c5, true)
	c5.(*fakeConn).closed.Store(true)
	c6, _ := p.get(ctx)
	if c6 == c5 {
		t.Fatal("closing idle reused")
	}
	p.put(c6, true)
	// Dial failure releases the slot.
	fs.setAlive(false)
	p.drain()
	if _, err := p.get(ctx); !errors.Is(err, errNet) {
		t.Fatalf("dial error: %v", err)
	}
	if _, active := p.stats(); active != 0 {
		t.Fatal("slot leaked after dial error")
	}
	fs.setAlive(true)
	c7, _ := p.get(ctx)
	p.close()
	p.put(c7, true)
	if !c7.(*fakeConn).closed.Load() {
		t.Fatal("put after close kept connection")
	}
	if _, err := p.get(ctx); !errors.Is(err, ErrClosed) {
		t.Fatalf("get after close: %v", err)
	}
	if np := newPool(0, 0, clock, nil, nil); np.size != 1 {
		t.Fatal("size floor")
	}
	np := newPool(1, 0, clock, nil, func(context.Context) (ldapConn, error) { return &fakeConn{srv: fs}, nil })
	c8, _ := np.get(ctx)
	np.put(c8, true)
	np.reap()
	if idle, _ := np.stats(); idle != 1 {
		t.Fatal("reap with maxIdle 0 dropped idle")
	}
}

func TestServer_Record(t *testing.T) {
	f := config.Failover{FailThreshold: 2, RecoverThreshold: 2}
	s := &server{url: ServerURL{Scheme: "ldap", Host: "h", Port: "389"}}
	now := time.Now()
	steps := []struct {
		ok     bool
		change bool
		to     State
	}{
		{ok: true, change: true, to: StateUp},   // unknown → up on first success
		{ok: true, change: false, to: StateUp},  // stays up
		{ok: false, change: false, to: StateUp}, // 1 failure < threshold
		{ok: false, change: true, to: StateDown},
		{ok: false, change: false, to: StateDown},
		{ok: true, change: false, to: StateDown}, // 1 success < recover
		{ok: true, change: true, to: StateUp},
		{ok: false, change: false, to: StateUp},
		{ok: true, change: false, to: StateUp}, // failure streak reset
		{ok: false, change: false, to: StateUp},
		{ok: false, change: true, to: StateDown},
	}
	for i, st := range steps {
		tr, changed := s.record(st.ok, errors.New("e"), time.Duration(i+1)*time.Millisecond, f, now)
		if changed != st.change || s.getState() != st.to || (changed && tr.to != st.to) {
			t.Fatalf("step %d: changed=%v state=%s tr=%+v", i, changed, s.getState(), tr)
		}
	}
	st := s.status()
	if st.State != StateDown || st.ConsecutiveFail != 2 || st.LastError != "e" || st.P50 == 0 || st.P95 < st.P50 || st.URL != "ldap://h:389" {
		t.Fatalf("status %+v", st)
	}
	if b, _ := StateDown.MarshalText(); string(b) != "down" || State(9).String() != "unknown" {
		t.Fatal("state text")
	}
	// Unknown → down after threshold without ever being up.
	s2 := &server{}
	s2.record(false, nil, 0, f, now)
	tr, changed := s2.record(false, nil, 0, f, now)
	if !changed || tr.from != StateUnknown || tr.to != StateDown || s2.status().P50 != 0 {
		t.Fatalf("unknown→down: %+v %v", tr, changed)
	}
	for i := 0; i < 2*latencyWindow; i++ {
		s2.record(true, nil, time.Duration(i+1)*time.Microsecond, f, now)
	}
	if p50, p95 := s2.percentiles(); p50 == 0 || p95 <= p50 {
		t.Fatalf("percentiles %v %v", p50, p95)
	}
}

func TestNew_Errors(t *testing.T) {
	if _, err := New("x", nil, "", Options{}); err == nil {
		t.Fatal("nil config accepted")
	}
	cfg := testConfig()
	if _, err := New("x", cfg, "", Options{}); err == nil {
		t.Fatal("no servers accepted")
	}
	cfg.Servers = []string{"http://x"}
	if _, err := New("x", cfg, "", Options{}); err == nil {
		t.Fatal("bad url accepted")
	}
	cfg.Servers = []string{"ldaps://x"}
	cfg.TLSCAFile = "/nonexistent/ca.pem"
	if _, err := New("x", cfg, "", Options{}); err == nil || !strings.Contains(err.Error(), "tls_ca_file") {
		t.Fatalf("missing ca: %v", err)
	}
	bad := t.TempDir() + "/ca.pem"
	if err := writeFile(bad, "not a pem"); err != nil {
		t.Fatal(err)
	}
	cfg.TLSCAFile = bad
	if _, err := New("x", cfg, "", Options{}); err == nil || !strings.Contains(err.Error(), "no certificates") {
		t.Fatalf("bad ca: %v", err)
	}
	cfg.TLSCAFile = ""
	cfg.TLSServerName = "dc.example"
	cfg.TLSInsecureSkipVerify = true
	u, err := New("x", cfg, "", Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if u.Name() != "x" || u.Config().TLSServerName != "dc.example" || len(u.Status()) != 1 || u.Healthy() {
		t.Fatalf("new state: %+v", u.Status())
	}
	tc, err := buildTLSConfig(cfg)
	if err != nil || !tc.InsecureSkipVerify || tc.ServerName != "dc.example" {
		t.Fatalf("tls config %+v %v", tc, err)
	}
	d := &dialer{cfg: cfg, tls: tc}
	if d.tlsConfigFor(ServerURL{Host: "h"}).ServerName != "dc.example" {
		t.Fatal("sni override lost")
	}
	tc.ServerName = ""
	if d.tlsConfigFor(ServerURL{Host: "h"}).ServerName != "h" {
		t.Fatal("sni default")
	}
}

func TestSearch_PagingAndFailover(t *testing.T) {
	cfg := testConfig("ldap://a", "ldap://b")
	u, fss, ev := newFake(t, cfg, 10, 10)
	ctx := context.Background()
	res, err := u.Search(ctx, SearchRequest{Base: "dc=x", Scope: ScopeSub, Filter: mustFilter(t, "(objectClass=user)"), Attrs: []string{"cn"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != 10 || res.Pages != 3 || res.Server != "ldap://a:389" || res.Entries[0].First("cn") != "e000" || res.Entries[0].Get("CN")[0] != "e000" {
		t.Fatalf("res %+v", res)
	}
	if _, binds, searches := fss[0].counts(); binds != 1 || searches != 3 {
		t.Fatalf("a binds=%d searches=%d", binds, searches)
	}
	if fss[0].lastReq.Filter != "(objectClass=user)" || fss[0].lastReq.Scope != ldap.ScopeWholeSubtree {
		t.Fatalf("request %+v", fss[0].lastReq)
	}
	if st := u.Status(); st[0].State != StateUp || st[1].State != StateUnknown || !u.Healthy() {
		t.Fatalf("status %+v", st)
	}
	// Absolute false: no query.
	res, err = u.Search(ctx, SearchRequest{Base: "dc=x", Filter: mustFilter(t, "(&(cn=a)(|))")})
	if err != nil || len(res.Entries) != 0 || res.Pages != 0 || res.Server != "" {
		t.Fatalf("absolute false: %+v %v", res, err)
	}
	if _, _, searches := fss[0].counts(); searches != 3 {
		t.Fatal("absolute false reached the upstream")
	}
	// Absolute true → (objectClass=*).
	if _, err := u.Search(ctx, SearchRequest{Base: "dc=x", Filter: mustFilter(t, "(|(cn=a)(&))")}); err != nil || fss[0].lastReq.Filter != PresentAll {
		t.Fatalf("absolute true: %v %q", err, fss[0].lastReq.Filter)
	}
	// Malformed AST.
	if _, err := u.Search(ctx, SearchRequest{Filter: &ldapfilter.Filter{Kind: ldapfilter.Not}}); err == nil {
		t.Fatal("malformed filter accepted")
	}
	// Size limit truncates and abandons the paging cursor.
	fss[0].reqs = nil
	res, err = u.Search(ctx, SearchRequest{Base: "dc=x", SizeLimit: 5})
	if err != nil || len(res.Entries) != 5 || !res.Truncated {
		t.Fatalf("size limit: %+v %v", res, err)
	}
	last := fss[0].reqs[len(fss[0].reqs)-1]
	if ctl, _ := ldap.FindControl(last.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging); ctl == nil || ctl.PagingSize != 0 {
		t.Fatalf("paging not abandoned: %+v", last.Controls)
	}
	// Size limit exceeded from the server.
	fss[0].noPaging = true
	res, err = u.Search(ctx, SearchRequest{Base: "dc=x", SizeLimit: 3})
	if err != nil || len(res.Entries) != 3 || !res.Truncated {
		t.Fatalf("server size limit: %+v %v", res, err)
	}
	fss[0].noPaging = false
	// Referrals are counted and ignored.
	fss[0].referrals = []string{"ldap://other/dc=y"}
	res, err = u.Search(ctx, SearchRequest{Base: "dc=x", SizeLimit: 2})
	if err != nil || res.Referrals != 1 {
		t.Fatalf("referrals: %+v %v", res, err)
	}
	fss[0].referrals = nil
	// Referral result code → ErrReferral, server stays up.
	fss[0].searchErr = ldap.NewError(ldap.LDAPResultReferral, errors.New("referral"))
	if _, err := u.Search(ctx, SearchRequest{Base: "dc=y"}); !errors.Is(err, ErrReferral) {
		t.Fatalf("referral: %v", err)
	}
	// Logical error is returned as is and does not count as a failure.
	fss[0].searchErr = ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object"))
	if _, err := u.Search(ctx, SearchRequest{Base: "dc=y"}); !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		t.Fatalf("noSuchObject: %v", err)
	}
	fss[0].searchErr = nil
	if st := u.Status(); st[0].State != StateUp || st[0].ConsecutiveFail != 0 {
		t.Fatalf("logical error counted: %+v", st[0])
	}
	// Server a dies: the request fails over to b; a goes down after the threshold.
	fss[0].setAlive(false)
	res, err = u.Search(ctx, SearchRequest{Base: "dc=x"})
	if err != nil || res.Server != "ldap://b:389" || len(res.Entries) != 10 {
		t.Fatalf("failover: %+v %v", res, err)
	}
	if st := u.Status(); st[0].State != StateUp || st[0].ConsecutiveFail != 1 || st[1].State != StateUp {
		t.Fatalf("after first failure: %+v", st)
	}
	if _, err := u.Search(ctx, SearchRequest{Base: "dc=x"}); err != nil {
		t.Fatal(err)
	}
	if st := u.Status(); st[0].State != StateDown || ev.count(EventUpstreamDown) != 1 {
		t.Fatalf("a not down: %+v events %v", st, ev.kinds())
	}
	if e := ev.events[0]; e.Server != "ldap://a:389" || e.Level != "high" || e.Data["consecutive"] != 2 || e.Data["reason"] == "" {
		t.Fatalf("down event %+v", e)
	}
	// Down server is skipped entirely.
	dials, _, _ := fss[0].counts()
	if _, err := u.Search(ctx, SearchRequest{Base: "dc=x"}); err != nil {
		t.Fatal(err)
	}
	if d2, _, _ := fss[0].counts(); d2 != dials {
		t.Fatal("down server was dialed")
	}
	// All down → ErrUnavailable without dialing.
	fss[1].setAlive(false)
	for i := 0; i < 2; i++ {
		_, _ = u.Search(ctx, SearchRequest{Base: "dc=x"})
	}
	if _, err := u.Search(ctx, SearchRequest{Base: "dc=x"}); !errors.Is(err, ErrUnavailable) || !u.Status()[1].State.isDown() {
		t.Fatalf("all down: %v %+v", err, u.Status())
	}
	if u.Healthy() {
		t.Fatal("healthy with all down")
	}
	// Recovery through the health loop: both come back, a is preferred again.
	u.Start(ctx)
	fss[0].setAlive(true)
	fss[1].setAlive(true)
	waitFor(t, "both up", func() bool { return ev.count(EventUpstreamUp) == 2 })
	if st := u.Status(); st[0].State != StateUp || st[1].State != StateUp {
		t.Fatalf("status %+v", st)
	}
	res, err = u.Search(ctx, SearchRequest{Base: "dc=x"})
	if err != nil || res.Server != "ldap://a:389" {
		t.Fatalf("prefer_primary: %+v %v", res, err)
	}
	u.Close()
	if _, err := u.Search(ctx, SearchRequest{Base: "dc=x"}); !errors.Is(err, ErrClosed) {
		t.Fatalf("after close: %v", err)
	}
	fss[0].mu.Lock()
	defer fss[0].mu.Unlock()
	if fss[0].open != 0 {
		t.Fatalf("connections left open: %d", fss[0].open)
	}
}

func (s State) isDown() bool { return s == StateDown }

func TestSearch_ContextAndPoolErrors(t *testing.T) {
	cfg := testConfig("ldap://a")
	cfg.Pool.Size = 1
	u, fss, _ := newFake(t, cfg, 3)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := u.Search(ctx, SearchRequest{Base: "dc=x"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v", err)
	}
	if st := u.Status()[0]; st.State == StateDown {
		t.Fatal("canceled context marked the server down")
	}
	// Service bind failure surfaces as a connection error and marks failures.
	fss[0].bindErr = ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("bad svc"))
	_, err := u.Search(context.Background(), SearchRequest{Base: "dc=x"})
	if err == nil || !strings.Contains(err.Error(), "service bind") {
		t.Fatalf("service bind: %v", err)
	}
}

func TestCandidates_Strategies(t *testing.T) {
	ctx := context.Background()
	t.Run("roundrobin", func(t *testing.T) {
		cfg := testConfig("ldap://a", "ldap://b", "ldap://c")
		cfg.Failover.Strategy = "roundrobin"
		u, fss, _ := newFake(t, cfg, 1, 1, 1)
		// Warm every server to "up".
		for i := range u.servers {
			u.observe(u.servers[i], true, nil, time.Millisecond)
		}
		var order []string
		for i := 0; i < 6; i++ {
			res, err := u.Search(ctx, SearchRequest{Base: "dc=x"})
			if err != nil {
				t.Fatal(err)
			}
			order = append(order, res.Server)
		}
		want := "ldap://a:389 ldap://b:389 ldap://c:389 ldap://a:389 ldap://b:389 ldap://c:389"
		if strings.Join(order, " ") != want {
			t.Fatalf("order %v", order)
		}
		fss[1].setAlive(false)
		seen := map[string]int{}
		for i := 0; i < 6; i++ {
			res, err := u.Search(ctx, SearchRequest{Base: "dc=x"})
			if err != nil {
				t.Fatal(err)
			}
			seen[res.Server]++
		}
		if seen["ldap://b:389"] != 0 || seen["ldap://a:389"] == 0 || seen["ldap://c:389"] == 0 {
			t.Fatalf("roundrobin with b dead: %v", seen)
		}
	})
	t.Run("sticky_without_prefer_primary", func(t *testing.T) {
		cfg := testConfig("ldap://a", "ldap://b")
		cfg.Failover.PreferPrimary = false
		cfg.Failover.FailThreshold = 1
		u, fss, _ := newFake(t, cfg, 1, 1)
		fss[0].setAlive(false)
		res, err := u.Search(ctx, SearchRequest{Base: "dc=x"})
		if err != nil || res.Server != "ldap://b:389" {
			t.Fatalf("failover: %+v %v", res, err)
		}
		fss[0].setAlive(true)
		u.observe(u.servers[0], true, nil, 0)
		u.observe(u.servers[0], true, nil, 0)
		if u.Status()[0].State != StateUp {
			t.Fatal("a not up")
		}
		res, err = u.Search(ctx, SearchRequest{Base: "dc=x"})
		if err != nil || res.Server != "ldap://b:389" {
			t.Fatalf("sticky lost: %+v %v", res, err)
		}
		fss[1].setAlive(false)
		res, err = u.Search(ctx, SearchRequest{Base: "dc=x"})
		if err != nil || res.Server != "ldap://a:389" {
			t.Fatalf("sticky failover: %+v %v", res, err)
		}
	})
	t.Run("unknown_after_up", func(t *testing.T) {
		cfg := testConfig("ldap://a", "ldap://b")
		u, _, _ := newFake(t, cfg, 1, 1)
		u.observe(u.servers[1], true, nil, 0)
		c := u.candidates()
		if len(c) != 2 || c[0].index != 1 || c[1].index != 0 {
			t.Fatalf("order %v", c)
		}
	})
}

func TestUserBind_Cases(t *testing.T) {
	cfg := testConfig("ldap://a", "ldap://b")
	u, fss, _ := newFake(t, cfg, 0, 0)
	ctx := context.Background()
	var be *BindError
	err := u.UserBind(ctx, "cn=user,dc=x", "")
	if !errors.As(err, &be) || be.Reason != ReasonAnonymous || !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("empty password: %v", err)
	}
	if err := u.UserBind(ctx, "", "x"); !errors.As(err, &be) || be.Reason != ReasonUnknownAccount {
		t.Fatalf("empty dn: %v", err)
	}
	if _, binds, _ := fss[0].counts(); binds != 0 {
		t.Fatal("local refusals reached the upstream")
	}
	if err := u.UserBind(ctx, "cn=user,dc=x", "user-pw"); err != nil {
		t.Fatalf("success: %v", err)
	}
	if _, binds, _ := fss[0].counts(); binds != 1 {
		t.Fatalf("bind-only pool bound the service account: %d", binds)
	}
	err = u.UserBind(ctx, "cn=user,dc=x", "wrong")
	if !errors.As(err, &be) || be.Reason != ReasonInvalidPassword || be.Data != "52e" || !IsCredentialFailure(err) {
		t.Fatalf("wrong password: %v", err)
	}
	if err := u.UserBind(ctx, "cn=nobody,dc=x", "x"); !errors.As(err, &be) || be.Reason != ReasonUnknownAccount {
		t.Fatalf("unknown: %v", err)
	}
	if _, binds, _ := fss[1].counts(); binds != 0 {
		t.Fatal("credential failure retried on the second server")
	}
	if st := u.Status()[0]; st.State != StateUp || st.ConsecutiveFail != 0 {
		t.Fatalf("credential failures counted against the server: %+v", st)
	}
	// Other LDAP error → upstream_error, not retried.
	fss[0].bindErr = ldap.NewError(ldap.LDAPResultUnwillingToPerform, errors.New("nope"))
	if err := u.UserBind(ctx, "cn=user,dc=x", "user-pw"); !errors.As(err, &be) || be.Reason != ReasonUpstreamError {
		t.Fatalf("unwilling: %v", err)
	}
	fss[0].bindErr = nil
	// Network failure → retried on b.
	fss[0].setAlive(false)
	if err := u.UserBind(ctx, "cn=user,dc=x", "user-pw"); err != nil {
		t.Fatalf("failover bind: %v", err)
	}
	if _, binds, _ := fss[1].counts(); binds != 1 {
		t.Fatal("failover did not reach b")
	}
	fss[1].setAlive(false)
	err = u.UserBind(ctx, "cn=user,dc=x", "user-pw")
	if !errors.Is(err, ErrUnavailable) || IsCredentialFailure(err) {
		t.Fatalf("all dead: %v", err)
	}
}

func TestHealth_KindsAndEvents(t *testing.T) {
	for _, kind := range []string{"rootdse", "bind", "search"} {
		t.Run(kind, func(t *testing.T) {
			cfg := testConfig("ldap://a")
			cfg.HealthCheck = kind
			u, fss, ev := newFake(t, cfg, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			u.Start(ctx)
			u.Start(ctx) // idempotent
			waitFor(t, "up", func() bool { return u.Healthy() })
			dials, binds, searches := fss[0].counts()
			if dials == 0 || (kind != "rootdse" && binds == 0) || (kind != "bind" && searches == 0) || (kind == "bind" && searches != 0) {
				t.Fatalf("probe %s: dials=%d binds=%d searches=%d", kind, dials, binds, searches)
			}
			if ev.count(EventUpstreamUp) != 0 {
				t.Fatal("initial up emitted an event")
			}
			fss[0].setAlive(false)
			waitFor(t, "down event", func() bool { return ev.count(EventUpstreamDown) == 1 })
			if u.Status()[0].State != StateDown {
				t.Fatalf("state %s", u.Status()[0].State)
			}
			fss[0].setAlive(true)
			waitFor(t, "up event", func() bool { return ev.count(EventUpstreamUp) == 1 })
			if u.Status()[0].State != StateUp || ev.events[1].Level != "medium" || ev.events[1].Data["reason"] != "recovered" {
				t.Fatalf("events %+v", ev.events)
			}
			cancel()
			u.Close()
		})
	}
	t.Run("bind_failure_and_rootdse_empty", func(t *testing.T) {
		cfg := testConfig("ldap://a")
		cfg.HealthCheck = "bind"
		cfg.Failover.FailThreshold = 1
		u, fss, _ := newFake(t, cfg, 0)
		fss[0].bindErr = errors.New("boom")
		u.healthCheck(context.Background(), u.servers[0])
		if st := u.Status()[0]; st.State != StateDown || !strings.Contains(st.LastError, "service bind") {
			t.Fatalf("status %+v", st)
		}
		cfg2 := testConfig("ldap://a")
		u2, fss2, _ := newFake(t, cfg2, 0)
		fss2[0].searchErr = ldap.NewError(ldap.LDAPResultUnavailable, errors.New("down"))
		if err := u2.probe(context.Background(), u2.servers[0].url, "rootdse"); err == nil || !strings.Contains(err.Error(), "rootdse") {
			t.Fatalf("probe: %v", err)
		}
		fss2[0].searchErr = nil
		fss2[0].setAlive(false)
		if err := u2.probe(context.Background(), u2.servers[0].url, "search"); err == nil {
			t.Fatal("probe of dead server succeeded")
		}
		fss2[0].setAlive(true)
		cfg2.HealthInterval = 0
		if err := u2.probe(context.Background(), u2.servers[0].url, "search"); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		u2.healthCheck(ctx, u2.servers[0])
		if u2.Status()[0].State != StateUnknown {
			t.Fatal("canceled health check recorded")
		}
	})
}

func TestAudit_Cases(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig("ldap://a")
	cfg.AuditServiceAccount = true
	u, fss, ev := newFake(t, cfg, 0)
	fss[0].entries = []*ldap.Entry{ldap.NewEntry("CN=Domain Admins,CN=Users,dc=x", map[string][]string{"cn": {"Domain Admins"}})}
	groups, err := u.AuditServiceAccount(ctx)
	if err != nil || len(groups) != 1 || groups[0] != "CN=Domain Admins,CN=Users,dc=x" {
		t.Fatalf("audit: %v %v", groups, err)
	}
	f := fss[0].lastReq.Filter
	if !strings.Contains(f, "(member:1.2.840.113556.1.4.1941:=cn=svc,dc=x)") || !strings.Contains(f, "(cn=Domain Admins)") || !strings.Contains(f, "(cn=Account Operators)") {
		t.Fatalf("filter %q", f)
	}
	u.Start(ctx)
	waitFor(t, "insecure_config", func() bool { return ev.count(EventInsecureConfig) == 1 })
	e := ev.events[0]
	if e.Data["what"] != "service_account_admin" || e.Level != "medium" {
		t.Fatalf("event %+v", e)
	}
	u.Close()
	// Generic kind uses direct membership; base from RootDSE when base_dn is empty.
	cfg2 := testConfig("ldap://a")
	cfg2.Kind = "generic"
	cfg2.BaseDN = ""
	u2, fss2, ev2 := newFake(t, cfg2, 0)
	groups, err = u2.AuditServiceAccount(ctx)
	if err != nil || len(groups) != 0 || !strings.Contains(fss2[0].lastReq.Filter, "(member=cn=svc,dc=x)") || fss2[0].lastReq.BaseDN != "dc=x" {
		t.Fatalf("generic audit: %v %v %+v", groups, err, fss2[0].lastReq)
	}
	cfg2.AuditServiceAccount = true
	u2.cfg.AuditServiceAccount = true
	u2.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	if ev2.count(EventInsecureConfig) != 0 {
		t.Fatal("clean account reported")
	}
	u2.Close()
	// No bind_dn → nothing to audit; dead server → error.
	cfg3 := testConfig("ldap://a")
	cfg3.BindDN = ""
	u3, _, _ := newFake(t, cfg3, 0)
	if g, err := u3.AuditServiceAccount(ctx); g != nil || err != nil {
		t.Fatalf("no bind dn: %v %v", g, err)
	}
	cfg4 := testConfig("ldap://a")
	u4, fss4, _ := newFake(t, cfg4, 0)
	fss4[0].setAlive(false)
	if _, err := u4.AuditServiceAccount(ctx); err == nil {
		t.Fatal("dead server audited")
	}
	u4.cfg.AuditServiceAccount = true
	actx, acancel := context.WithCancel(ctx)
	u4.Start(actx)
	time.Sleep(30 * time.Millisecond)
	acancel()
	u4.Close()
	// Insecure TLS emits insecure_config on Start.
	cfg5 := testConfig("ldap://a")
	cfg5.TLSInsecureSkipVerify = true
	u5, _, ev5 := newFake(t, cfg5, 0)
	u5.Start(ctx)
	u5.Close()
	if ev5.count(EventInsecureConfig) != 1 || ev5.events[0].Data["what"] != "tls_insecure_skip_verify" {
		t.Fatalf("events %+v", ev5.events)
	}
}

func TestCheck_Findings(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig("ldap://a", "ldap://b")
	cfg.AuditServiceAccount = true
	u, fss, _ := newFake(t, cfg, 0, 0)
	fss[1].setAlive(false)
	findings := u.Check(ctx, []string{"ou=users,dc=x"})
	byKey := map[string]Finding{}
	for _, f := range findings {
		byKey[f.Server+"|"+f.Check] = f
	}
	for key, ok := range map[string]bool{
		"ldap://a:389|connect": true, "ldap://a:389|bind": true, "ldap://a:389|rootdse": true, "ldap://a:389|base": true,
		"ldap://b:389|connect": false, "|audit": true,
	} {
		f, present := byKey[key]
		if !present || f.OK != ok {
			t.Errorf("%s: %+v (present=%v)", key, f, present)
		}
	}
	if _, present := byKey["ldap://b:389|bind"]; present {
		t.Error("checks continued after connect failure")
	}
	if s := byKey["ldap://a:389|base"].String(); s != "ldap://a:389 base: ou=users,dc=x ok" {
		t.Errorf("string %q", s)
	}
	if s := byKey["|audit"].String(); !strings.HasPrefix(s, "audit: ") {
		t.Errorf("string %q", s)
	}
	// Bind failure, base failure, base_dn mismatch, admin membership, audit error.
	cfg2 := testConfig("ldap://a")
	cfg2.AuditServiceAccount = true
	cfg2.BaseDN = "dc=other"
	u2, fss2, _ := newFake(t, cfg2, 0)
	fss2[0].entries = []*ldap.Entry{ldap.NewEntry("CN=Administrators,CN=Builtin,dc=x", nil)}
	var warns, errs int
	for _, f := range u2.Check(ctx, nil) {
		switch {
		case f.Warn:
			warns++
		case !f.OK:
			errs++
		}
	}
	if warns != 2 || errs != 0 { // base_dn mismatch + admin membership
		t.Fatalf("warns=%d errs=%d: %+v", warns, errs, u2.Check(ctx, nil))
	}
	fss2[0].passwords["cn=svc,dc=x"] = "other"
	fs := u2.Check(ctx, []string{"dc=x"})
	if len(fs) < 2 || fs[1].Check != "bind" || fs[1].OK || !strings.Contains(fs[1].Msg, "invalid_password") {
		t.Fatalf("bind failure: %+v", fs)
	}
	fss2[0].passwords["cn=svc,dc=x"] = "svc-pw"
	fss2[0].searchErr = ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("nope"))
	fs = u2.Check(ctx, []string{"dc=x"})
	var rootFail, baseFail, auditWarn bool
	for _, f := range fs {
		switch {
		case f.Check == "rootdse" && !f.OK:
			rootFail = true
		case f.Check == "base" && !f.OK:
			baseFail = true
		case f.Check == "audit" && f.Warn && strings.Contains(f.Msg, "failed"):
			auditWarn = true
		}
	}
	if !rootFail || !baseFail || !auditWarn {
		t.Fatalf("findings %+v", fs)
	}
	if !contains([]string{"a", "b"}, "b") || contains(nil, "x") {
		t.Fatal("contains")
	}
}

func TestIsConnError_Cases(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"canceled", context.Canceled, false},
		{"deadline", context.DeadlineExceeded, true},
		{"network", errNet, true},
		{"server_down", ldap.NewError(ldap.LDAPResultServerDown, errors.New("x")), true},
		{"busy", ldap.NewError(ldap.LDAPResultBusy, errors.New("x")), true},
		{"invalid_credentials", ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("x")), false},
		{"no_such_object", ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("x")), false},
		{"eof", io.EOF, true},
		{"closed", net.ErrClosed, true},
		{"wrapped_closed", fmt.Errorf("x: %w", net.ErrClosed), true},
		{"connect", fmt.Errorf("%w: x509 bad cert", ErrConnect), true},
		{"goldap_read", errors.New("unable to read LDAP response packet: EOF"), true},
		{"plain", errors.New("x"), false},
		{"net_error", &net.OpError{Op: "dial", Err: errors.New("refused")}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isConnError(tc.err); got != tc.want {
				t.Fatalf("isConnError(%v) = %v", tc.err, got)
			}
		})
	}
}

// TestNoSecretsInOutput_Upstream drives binds, failures and health checks
// through a logger and asserts the service and user passwords never reach
// logs, errors, events or status.
func TestNoSecretsInOutput_Upstream(t *testing.T) {
	const svcSecret, userSecret = "svc-pw", "user-pw"
	cfg := testConfig("ldap://a")
	cfg.AuditServiceAccount = true
	cfg.Failover.FailThreshold = 1
	n := &fakeNet{servers: map[string]*fakeServer{"ldap://a:389": newFakeServer(2)}}
	var logs bytes.Buffer
	ev := &eventLog{}
	u, err := New("secret-test", cfg, svcSecret, Options{Events: ev, dial: n.dial, Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	u.Start(ctx)
	out := make([]string, 0, 16)
	collect := func(err error) {
		if err != nil {
			out = append(out, err.Error())
		}
	}
	collect(u.UserBind(ctx, "cn=user,dc=x", userSecret))
	collect(u.UserBind(ctx, "cn=user,dc=x", "wrong-"+userSecret))
	n.servers["ldap://a:389"].passwords["cn=svc,dc=x"] = "rotated"
	n.servers["ldap://a:389"].mu.Lock()
	n.servers["ldap://a:389"].binds = 0
	n.servers["ldap://a:389"].mu.Unlock()
	u.servers[0].svc.drain()
	_, err = u.Search(ctx, SearchRequest{Base: "dc=x"})
	collect(err)
	n.servers["ldap://a:389"].setAlive(false)
	_, err = u.Search(ctx, SearchRequest{Base: "dc=x"})
	collect(err)
	waitFor(t, "down", func() bool { return u.Status()[0].State == StateDown })
	u.Close()
	for _, f := range u.Check(ctx, []string{"dc=x"}) {
		out = append(out, f.String())
	}
	for _, st := range u.Status() {
		out = append(out, fmt.Sprintf("%+v", st))
	}
	ev.mu.Lock()
	for _, e := range ev.events {
		out = append(out, fmt.Sprintf("%+v", e))
	}
	ev.mu.Unlock()
	out = append(out, logs.String())
	for _, s := range out {
		if strings.Contains(s, svcSecret) || strings.Contains(s, userSecret) {
			t.Fatalf("secret leaked: %q", s)
		}
	}
	if len(out) < 6 || logs.Len() == 0 {
		t.Fatalf("too little output to judge: %d items, %d log bytes", len(out), logs.Len())
	}
}
