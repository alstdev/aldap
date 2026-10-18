//go:build integration

package upstream_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/ldapfilter"
	"github.com/alstdev/aldap/internal/testdir"
	"github.com/alstdev/aldap/internal/upstream"
)

const (
	baseDN = "DC=test,DC=aldap"
	svcDN  = "CN=svc-aldap,CN=Users,DC=test,DC=aldap"
	svcPW  = "svc-aldap-pass"
)

type sink struct {
	mu     sync.Mutex
	events []upstream.Event
}

func (s *sink) Emit(e upstream.Event) {
	s.mu.Lock()
	s.events = append(s.events, e)
	s.mu.Unlock()
}

func (s *sink) count(kind, server string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, e := range s.events {
		if e.Kind == kind && (server == "" || e.Server == server) {
			n++
		}
	}
	return n
}

func cfgFor(servers ...*testdir.Server) *config.Upstream {
	cfg := config.DefaultUpstream()
	for _, s := range servers {
		cfg.Servers = append(cfg.Servers, s.URL())
	}
	cfg.BindDN = svcDN
	cfg.BaseDN = baseDN
	cfg.HealthInterval = config.Duration(30 * time.Millisecond)
	cfg.Timeouts = config.Timeouts{Connect: config.Duration(time.Second), Bind: config.Duration(2 * time.Second), Search: config.Duration(5 * time.Second)}
	cfg.Failover.FailThreshold = 2
	cfg.Failover.RecoverThreshold = 2
	cfg.AuditServiceAccount = false
	return cfg
}

func newUpstream(t *testing.T, cfg *config.Upstream) (*upstream.Upstream, *sink) {
	t.Helper()
	ev := &sink{}
	u, err := upstream.New("ad-test", cfg, svcPW, upstream.Options{Events: ev, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(u.Close)
	return u, ev
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func filter(t *testing.T, s string) *ldapfilter.Filter {
	t.Helper()
	f, err := ldapfilter.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// Scenario 20 (TESTING.md): two upstreams, stop the first → upstream_down and
// requests go to the second; start it again → upstream_up and back to primary.
func TestIntegration_FailoverAndReturnToPrimary(t *testing.T) {
	dc1 := testdir.StartFixture(t)
	dc2 := testdir.Start(t, testdir.WithDirectory(dc1.Dir))
	u, ev := newUpstream(t, cfgFor(dc1, dc2))
	ctx := context.Background()
	u.Start(ctx)
	waitFor(t, "both up", func() bool {
		st := u.Status()
		return st[0].State == upstream.StateUp && st[1].State == upstream.StateUp
	})
	req := upstream.SearchRequest{Base: baseDN, Scope: upstream.ScopeSub, Filter: filter(t, "(sAMAccountName=alice.adams)"), Attrs: []string{"mail"}}
	res, err := u.Search(ctx, req)
	if err != nil || res.Server != dc1.URL() || len(res.Entries) != 1 || res.Entries[0].First("mail") != "alice.adams@test.aldap" {
		t.Fatalf("primary search: %+v %v", res, err)
	}
	dc1.Kill()
	res, err = u.Search(ctx, req)
	if err != nil || res.Server != dc2.URL() || len(res.Entries) != 1 {
		t.Fatalf("failover search: %+v %v", res, err)
	}
	waitFor(t, "upstream_down", func() bool { return ev.count(upstream.EventUpstreamDown, dc1.URL()) == 1 })
	if st := u.Status(); st[0].State != upstream.StateDown || st[0].LastError == "" || st[1].State != upstream.StateUp {
		t.Fatalf("status after kill: %+v", st)
	}
	before := dc2.Calls().Searches
	for i := 0; i < 3; i++ {
		if res, err := u.Search(ctx, req); err != nil || res.Server != dc2.URL() {
			t.Fatalf("search while dc1 down: %+v %v", res, err)
		}
	}
	if dc2.Calls().Searches-before != 3 {
		t.Fatal("searches did not all go to dc2")
	}
	if err := dc1.Restart(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "upstream_up", func() bool { return ev.count(upstream.EventUpstreamUp, dc1.URL()) == 1 })
	res, err = u.Search(ctx, req)
	if err != nil || res.Server != dc1.URL() {
		t.Fatalf("return to primary: %+v %v", res, err)
	}
	if !u.Healthy() {
		t.Fatal("not healthy")
	}
	// Both down → unavailable; the client is not told which server failed.
	dc1.Kill()
	dc2.Kill()
	waitFor(t, "all down", func() bool { return !u.Healthy() })
	if _, err := u.Search(ctx, req); !errors.Is(err, upstream.ErrUnavailable) {
		t.Fatalf("all down: %v", err)
	}
	if err := dc1.Restart(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "dc1 back", func() bool { return u.Healthy() })
	if res, err := u.Search(ctx, req); err != nil || res.Server != dc1.URL() {
		t.Fatalf("after recovery: %+v %v", res, err)
	}
}

// Paged search: 25 persons with page_size 20 → exactly 2 pages, 2 upstream
// searches, entries de-duplicated across pages.
func TestIntegration_PagedSearch(t *testing.T) {
	dc := testdir.StartFixture(t)
	cfg := cfgFor(dc)
	cfg.PageSize = 20
	u, _ := newUpstream(t, cfg)
	ctx := context.Background()
	dc.ResetCalls()
	res, err := u.Search(ctx, upstream.SearchRequest{Base: baseDN, Scope: upstream.ScopeSub, Filter: filter(t, "(&(objectCategory=person)(objectClass=user))"), Attrs: []string{"sAMAccountName", "objectGUID"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != 25 || res.Pages != 2 || dc.Calls().Searches != 2 || dc.Calls().Binds != 1 {
		t.Fatalf("entries=%d pages=%d calls=%+v", len(res.Entries), res.Pages, dc.Calls())
	}
	seen := map[string]bool{}
	for _, e := range res.Entries {
		guid := e.First("objectGUID")
		if len(guid) != 16 || seen[guid] {
			t.Fatalf("bad or duplicate guid in %s", e.DN)
		}
		seen[guid] = true
	}
	// Size limit is enforced by the server (sizeLimitExceeded) and reported as truncation.
	dc.ResetCalls()
	res, err = u.Search(ctx, upstream.SearchRequest{Base: baseDN, Scope: upstream.ScopeSub, Filter: filter(t, "(objectClass=user)"), SizeLimit: 5})
	if err != nil || len(res.Entries) != 5 || !res.Truncated || res.Pages != 1 || dc.Calls().Searches != 1 {
		t.Fatalf("size limit: entries=%d truncated=%v pages=%d err=%v calls=%+v", len(res.Entries), res.Truncated, res.Pages, err, dc.Calls())
	}
	// Absolute filters never reach the server.
	dc.ResetCalls()
	res, err = u.Search(ctx, upstream.SearchRequest{Base: baseDN, Scope: upstream.ScopeSub, Filter: filter(t, "(&(objectClass=user)(|))")})
	if err != nil || len(res.Entries) != 0 || dc.Calls().Searches != 0 {
		t.Fatalf("absolute false: %+v %v calls=%+v", res, err, dc.Calls())
	}
	res, err = u.Search(ctx, upstream.SearchRequest{Base: "OU=Office," + baseDN, Scope: upstream.ScopeOne, Filter: filter(t, "(|(objectClass=user)(&))")})
	if err != nil || len(res.Entries) != 14 {
		t.Fatalf("absolute true: %d %v", len(res.Entries), err)
	}
	root, err := u.RootDSE(ctx, "defaultNamingContext")
	if err != nil || root.First("defaultNamingContext") != baseDN {
		t.Fatalf("rootdse: %+v %v", root, err)
	}
	// Pool reuse: one connection serves consecutive searches.
	if conns := dc.Calls().Conns; conns != 0 {
		t.Fatalf("new connections dialed: %d", conns)
	}
}

// Scenario (SPEC §4.3): AD bind diagnostics map to reasons; the server is
// never marked down by credential failures; user binds never bind the
// service account on the bind-only pool.
func TestIntegration_UserBindReasons(t *testing.T) {
	dc := testdir.StartFixture(t)
	u, _ := newUpstream(t, cfgFor(dc))
	ctx := context.Background()
	tests := []struct {
		name, dn, pw string
		reason       upstream.Reason
		data         string
	}{
		{name: "ok", dn: "CN=Alice Adams,OU=Office," + baseDN, pw: "alice.adams-pass"},
		{name: "ok_upn", dn: "alice.adams@test.aldap", pw: "alice.adams-pass"},
		{name: "bad_password", dn: "CN=Alice Adams,OU=Office," + baseDN, pw: "nope", reason: upstream.ReasonInvalidPassword, data: "52e"},
		{name: "unknown", dn: "CN=Nobody,OU=Office," + baseDN, pw: "x", reason: upstream.ReasonUnknownAccount, data: "525"},
		{name: "disabled", dn: "carol.clark@test.aldap", pw: "carol.clark-pass", reason: upstream.ReasonDisabled, data: "533"},
		{name: "locked", dn: "eve.evans@test.aldap", pw: "eve.evans-pass", reason: upstream.ReasonLockedInAD, data: "775"},
		{name: "must_change", dn: "leo.lewis@test.aldap", pw: "leo.lewis-pass", reason: upstream.ReasonMustChange, data: "773"},
		{name: "anonymous", dn: "alice.adams@test.aldap", pw: "", reason: upstream.ReasonAnonymous},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := u.UserBind(ctx, tc.dn, tc.pw)
			if tc.reason == "" {
				if err != nil {
					t.Fatalf("bind: %v", err)
				}
				return
			}
			var be *upstream.BindError
			if !errors.As(err, &be) || be.Reason != tc.reason || be.Data != tc.data {
				t.Fatalf("err = %v, want %s/%s", err, tc.reason, tc.data)
			}
			if strings.Contains(err.Error(), tc.pw) && tc.pw != "" {
				t.Fatal("password in error text")
			}
		})
	}
	if calls := dc.Calls(); calls.Binds != 7 || calls.Searches != 0 {
		t.Fatalf("calls %+v", calls)
	}
	if st := u.Status()[0]; st.State != upstream.StateUp || st.ConsecutiveFail != 0 {
		t.Fatalf("status %+v", st)
	}
	dc.Kill()
	if err := u.UserBind(ctx, "alice.adams@test.aldap", "alice.adams-pass"); !errors.Is(err, upstream.ErrUnavailable) || upstream.IsCredentialFailure(err) {
		t.Fatalf("dead server: %v", err)
	}
}

func TestIntegration_TLS(t *testing.T) {
	plain := testdir.StartFixture(t)
	secure := testdir.Start(t, testdir.WithDirectory(plain.Dir), testdir.WithTLS())
	ctx := context.Background()
	req := upstream.SearchRequest{Base: baseDN, Scope: upstream.ScopeBase}
	t.Run("ldaps_with_ca", func(t *testing.T) {
		cfg := cfgFor(secure)
		cfg.TLSCAFile = secure.CAFile(t)
		cfg.TLSServerName = "localhost"
		u, _ := newUpstream(t, cfg)
		if res, err := u.Search(ctx, req); err != nil || len(res.Entries) != 1 {
			t.Fatalf("ldaps: %+v %v", res, err)
		}
	})
	t.Run("ldaps_untrusted", func(t *testing.T) {
		cfg := cfgFor(secure)
		u, _ := newUpstream(t, cfg)
		if _, err := u.Search(ctx, req); !errors.Is(err, upstream.ErrUnavailable) || !strings.Contains(err.Error(), "tls") {
			t.Fatalf("untrusted: %v", err)
		}
	})
	t.Run("ldaps_insecure_skip_verify", func(t *testing.T) {
		cfg := cfgFor(secure)
		cfg.TLSInsecureSkipVerify = true
		u, ev := newUpstream(t, cfg)
		u.Start(ctx)
		if res, err := u.Search(ctx, req); err != nil || len(res.Entries) != 1 {
			t.Fatalf("insecure: %+v %v", res, err)
		}
		if ev.count(upstream.EventInsecureConfig, "") != 1 {
			t.Fatal("insecure_config not emitted")
		}
	})
	t.Run("starttls_required", func(t *testing.T) {
		cfg := cfgFor(plain)
		cfg.StartTLS, cfg.StartTLSRequired = true, true
		cfg.TLSCAFile = plain.CAFile(t)
		cfg.TLSServerName = "localhost"
		u, _ := newUpstream(t, cfg)
		if res, err := u.Search(ctx, req); err != nil || len(res.Entries) != 1 {
			t.Fatalf("starttls: %+v %v", res, err)
		}
		bad := cfgFor(plain)
		bad.StartTLS, bad.StartTLSRequired = true, true
		u2, _ := newUpstream(t, bad)
		if _, err := u2.Search(ctx, req); !errors.Is(err, upstream.ErrUnavailable) || !strings.Contains(err.Error(), "starttls") {
			t.Fatalf("starttls required without CA: %v", err)
		}
	})
	t.Run("starttls_handshake_failure_is_fatal", func(t *testing.T) {
		cfg := cfgFor(plain)
		cfg.StartTLS = true // no CA → handshake fails → connection unusable, no clear-text fallback
		u, _ := newUpstream(t, cfg)
		if _, err := u.Search(ctx, req); !errors.Is(err, upstream.ErrUnavailable) || !strings.Contains(err.Error(), "starttls") {
			t.Fatalf("handshake failure: %v", err)
		}
	})
	t.Run("starttls_refused_is_fatal", func(t *testing.T) {
		noTLS := testdir.Start(t, testdir.WithDirectory(plain.Dir), testdir.WithoutStartTLS())
		for _, required := range []bool{false, true} {
			cfg := cfgFor(noTLS)
			cfg.StartTLS, cfg.StartTLSRequired = true, required
			cfg.TLSCAFile = noTLS.CAFile(t)
			u, _ := newUpstream(t, cfg)
			if _, err := u.Search(ctx, req); !errors.Is(err, upstream.ErrUnavailable) || !strings.Contains(err.Error(), "starttls") {
				t.Fatalf("required=%v: %v", required, err)
			}
		}
		// Without starttls the same server works in clear text.
		cfg := cfgFor(noTLS)
		u, _ := newUpstream(t, cfg)
		if res, err := u.Search(ctx, req); err != nil || len(res.Entries) != 1 {
			t.Fatalf("plain: %+v %v", res, err)
		}
	})
	t.Run("connect_timeout", func(t *testing.T) {
		dead := testdir.Start(t, testdir.WithDirectory(plain.Dir))
		dead.Kill()
		cfg := cfgFor(dead)
		cfg.Timeouts.Connect = config.Duration(200 * time.Millisecond)
		u, _ := newUpstream(t, cfg)
		start := time.Now()
		if _, err := u.Search(ctx, req); !errors.Is(err, upstream.ErrUnavailable) {
			t.Fatalf("dead: %v", err)
		}
		if time.Since(start) > 2*time.Second {
			t.Fatal("connect did not time out")
		}
	})
}

func TestIntegration_AuditAndCheck(t *testing.T) {
	dc := testdir.StartFixture(t)
	ctx := context.Background()
	t.Run("read_only_account", func(t *testing.T) {
		cfg := cfgFor(dc)
		cfg.AuditServiceAccount = true
		u, ev := newUpstream(t, cfg)
		groups, err := u.AuditServiceAccount(ctx)
		if err != nil || len(groups) != 0 {
			t.Fatalf("audit: %v %v", groups, err)
		}
		u.Start(ctx)
		time.Sleep(100 * time.Millisecond)
		if ev.count(upstream.EventInsecureConfig, "") != 0 {
			t.Fatal("clean account flagged")
		}
	})
	t.Run("admin_account_nested", func(t *testing.T) {
		cfg := cfgFor(dc)
		cfg.AuditServiceAccount = true
		cfg.BindDN = "CN=svc-admin,CN=Users," + baseDN
		ev := &sink{}
		u, err := upstream.New("ad-test", cfg, "svc-admin-pass", upstream.Options{Events: ev, Logger: slog.New(slog.DiscardHandler)})
		if err != nil {
			t.Fatal(err)
		}
		defer u.Close()
		groups, err := u.AuditServiceAccount(ctx)
		if err != nil || len(groups) != 2 { // Domain Admins directly, Administrators through nesting
			t.Fatalf("audit: %v %v", groups, err)
		}
		u.Start(ctx)
		waitFor(t, "insecure_config", func() bool { return ev.count(upstream.EventInsecureConfig, "") == 1 })
	})
	t.Run("check", func(t *testing.T) {
		dead := testdir.Start(t, testdir.WithDirectory(dc.Dir))
		dead.Kill()
		cfg := cfgFor(dc, dead)
		cfg.AuditServiceAccount = true
		u, _ := newUpstream(t, cfg)
		var okN, failN, warnN int
		for _, f := range u.Check(ctx, []string{"OU=Office," + baseDN, "OU=Missing," + baseDN}) {
			switch {
			case f.Warn:
				warnN++
			case f.OK:
				okN++
			default:
				failN++
			}
		}
		// dc: connect, bind, rootdse, base ok, base missing (fail); dead: connect fail; audit ok.
		if okN != 5 || failN != 2 || warnN != 0 {
			t.Fatalf("ok=%d fail=%d warn=%d: %+v", okN, failN, warnN, u.Check(ctx, nil))
		}
	})
}

func TestIntegration_RoundRobin(t *testing.T) {
	dc1 := testdir.StartFixture(t)
	dc2 := testdir.Start(t, testdir.WithDirectory(dc1.Dir))
	cfg := cfgFor(dc1, dc2)
	cfg.Failover.Strategy = "roundrobin"
	u, _ := newUpstream(t, cfg)
	ctx := context.Background()
	u.Start(ctx)
	waitFor(t, "both up", func() bool { return u.Status()[0].State == upstream.StateUp && u.Status()[1].State == upstream.StateUp })
	dc1.ResetCalls()
	dc2.ResetCalls()
	for i := 0; i < 6; i++ {
		if _, err := u.Search(ctx, upstream.SearchRequest{Base: baseDN, Scope: upstream.ScopeBase}); err != nil {
			t.Fatal(err)
		}
	}
	if dc1.Calls().Searches != 3 || dc2.Calls().Searches != 3 {
		t.Fatalf("not balanced: %+v %+v", dc1.Calls(), dc2.Calls())
	}
}
