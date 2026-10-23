package vdir

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/cache"
	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/listener"
	"github.com/alstdev/aldap/internal/metrics"
	"github.com/alstdev/aldap/internal/profile"
)

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// rebuild replaces the directory of a fixture with one using o's cache
// options (same rules, upstream, events and guard).
func (f *fixture) rebuild(t *testing.T, mut func(o *Options)) {
	t.Helper()
	o := Options{Logger: slog.New(slog.DiscardHandler), Events: f.ev, Version: "test", StartTLS: true, MaxPagingStates: 2,
		Guard: testGuard(t, f.ev, nil), Sleep: func(context.Context, time.Duration) {}}
	mut(&o)
	f.d = New(f.d.rules, f.up, o)
}

// clientSearches counts the searches the test directory served for
// clients of the upstream (health probes read the root DSE).
func (f *fixture) clientSearches() int64 {
	c := f.dc.Calls()
	return c.Searches - c.RootDSE
}

// TESTING.md 21: the second identical search does not reach the
// upstream; after the ttl it does. cache_hit and the metric follow.
func TestTTL_SecondSearchFromCache(t *testing.T) {
	f := newFixture(t, withVirolaGroup)
	clk := &testClock{t: time.Now()}
	ttl := cache.NewTTL(cache.TTLOptions{TTL: time.Minute, MaxEntries: 1000, Now: clk.now})
	m := metrics.New("t", "", "")
	f.rebuild(t, func(o *Options) { o.Cache = ttl.Wrap(f.up); o.Metrics = m; o.Now = clk.now })
	before := f.clientSearches()
	_, first := f.search(t, usersDN, listener.ScopeSub, "(sAMAccountName=alice.adams)", "mail")
	afterFirst := f.clientSearches()
	if len(first) != 1 || afterFirst == before {
		t.Fatalf("first search: %d entries, %d upstream searches", len(first), afterFirst-before)
	}
	if e := f.ev.last(events.Search); e.Data["cache_hit"] != false || e.Data["upstream_queries"] == 0 {
		t.Errorf("first search event %v", e.Data)
	}
	_, second := f.search(t, usersDN, listener.ScopeSub, "(sAMAccountName=alice.adams)", "mail")
	if f.clientSearches() != afterFirst || len(second) != 1 || attr(second[0], "mail")[0] != "alice.adams@test.aldap" {
		t.Fatalf("second search reached the upstream or differs: %d %v", f.clientSearches()-afterFirst, second)
	}
	if e := f.ev.last(events.Search); e.Data["cache_hit"] != true || e.Data["upstream_queries"] != 0 || e.UpstreamServer != "" {
		t.Errorf("cached search event %+v", e)
	}
	clk.add(61 * time.Second)
	f.d.InvalidateMembership()
	f.search(t, usersDN, listener.ScopeSub, "(sAMAccountName=alice.adams)", "mail")
	if f.clientSearches() == afterFirst {
		t.Error("search after the ttl did not reach the upstream")
	}
	if got := f.d.cacheLabel(&searchCtx{queries: 1}); got != "miss" {
		t.Errorf("miss label = %s", got)
	}
	if ttl.Len() == 0 {
		t.Error("cache empty")
	}
}

// TESTING.md 22: every server down → expired results are served with
// stale_served; without stale_while_down → unavailable.
func TestTTL_StaleWhileDown(t *testing.T) {
	for _, swd := range []bool{true, false} {
		f := newFixture(t, nil)
		clk := &testClock{t: time.Now()}
		ttl := cache.NewTTL(cache.TTLOptions{TTL: time.Minute, MaxEntries: 1000, StaleWhileDown: swd, StaleMax: time.Hour, Now: clk.now})
		f.rebuild(t, func(o *Options) { o.Cache = ttl.Wrap(f.up); o.Now = clk.now })
		if res, es := f.search(t, usersDN, listener.ScopeSub, "(|(sAMAccountName=alice.adams)(sAMAccountName=bob.brown))", "uid"); res.Code != 0 || len(es) == 0 {
			t.Fatalf("warm-up: %v %d", res, len(es))
		}
		f.dc.Kill()
		clk.add(5 * time.Minute)
		res, es := f.searchFrom(t, testConn("10.0.0.9"), usersDN, listener.ScopeSub, "(|(sAMAccountName=alice.adams)(sAMAccountName=bob.brown))", "uid")
		if !swd {
			if res.Code != ldap.LDAPResultUnavailable || len(es) != 0 {
				t.Errorf("without stale_while_down: %v %d", res, len(es))
			}
			if f.ev.last(events.StaleServed) != nil {
				t.Error("stale_served without stale_while_down")
			}
			continue
		}
		if res.Code != 0 || len(es) == 0 {
			t.Fatalf("stale search: %v %d", res, len(es))
		}
		st := f.ev.last(events.StaleServed)
		if st == nil || st.Data["age_s"] != 300 || st.Data["entries"] != len(es) || st.ClientIP != "10.0.0.9" || st.Profile != "virola" || st.Level != events.LevelMedium {
			t.Fatalf("stale_served = %+v", st)
		}
		if e := f.ev.last(events.Search); e.Data["cache_hit"] != true {
			t.Errorf("stale search event %v", e.Data)
		}
		if got := f.d.cacheLabel(&searchCtx{hits: 1, stale: time.Second}); got != "stale" {
			t.Errorf("stale label = %s", got)
		}
		// A request never cached has nothing stale to serve.
		if res, _ := f.search(t, usersDN, listener.ScopeSub, "(sAMAccountName=leo.lewis)", "uid"); res.Code != ldap.LDAPResultUnavailable {
			t.Errorf("uncached while down: %v", res)
		}
	}
}

// User binds never use the cache: every bind (and its lookup) reaches the
// upstream, in ttl and in replica mode.
func TestCache_BindAlwaysUpstream(t *testing.T) {
	f := newFixture(t, nil)
	ttl := cache.NewTTL(cache.TTLOptions{TTL: time.Hour, MaxEntries: 1000})
	f.rebuild(t, func(o *Options) { o.Cache = ttl.Wrap(f.up) })
	vdn := "cn=alice.adams," + usersDN
	for i := range 2 {
		binds, searches := f.dc.Calls().Binds, f.clientSearches()
		if res := f.bind(t, testConn("10.0.0.1"), vdn, "alice.adams-pass"); res.Code != 0 {
			t.Fatalf("bind %d: %v", i, res)
		}
		if f.dc.Calls().Binds == binds || f.clientSearches() == searches {
			t.Errorf("bind %d: lookup or bind served without the upstream", i)
		}
	}
	if ttl.Len() != 0 {
		t.Errorf("bind lookups were cached: %d entries", ttl.Len())
	}
}

// replicaFixture is a fixture whose directory serves from a replica.
func replicaFixture(t *testing.T, mut func(p *config.Profile)) (*fixture, *cache.Replica) {
	t.Helper()
	f := newFixture(t, mut)
	rep := cache.NewReplica(cache.ReplicaOptions{Profile: "virola", Upstream: "ad-test", Interval: time.Hour, Events: f.ev, Logger: slog.New(slog.DiscardHandler)})
	ttl := cache.NewTTL(cache.TTLOptions{TTL: time.Hour})
	// A ttl cache passed along is ignored: the replica answers.
	f.rebuild(t, func(o *Options) { o.Replica = rep; o.Cache = ttl.Wrap(f.up) })
	return f, rep
}

// TESTING.md 23: after a sync the replica answers with the upstream gone;
// a user bind goes to the upstream and is unavailable.
func TestReplica_ServesWithoutUpstream(t *testing.T) {
	f, rep := replicaFixture(t, withVirolaGroup)
	// Before the first sync there is nothing to serve.
	if res, _ := f.search(t, usersDN, listener.ScopeSub, "(objectClass=*)"); res.Code != ldap.LDAPResultUnavailable {
		t.Fatalf("before sync: %v", res)
	}
	if res, _ := f.search(t, groupsDN, listener.ScopeOne, "(objectClass=*)"); res.Code != ldap.LDAPResultUnavailable {
		t.Fatalf("groups before sync: %v", res)
	}
	if err := rep.Sync(context.Background(), f.d.SyncReplica); err != nil {
		t.Fatal(err)
	}
	if e := f.ev.last(events.ReplicaSynced); e == nil || e.Data["entries"] != 19 {
		t.Fatalf("replica_synced = %+v", e)
	}
	// The same answers as a proxy profile over the live upstream.
	live := newFixture(t, withVirolaGroup)
	for _, q := range []struct {
		base   string
		scope  listener.Scope
		filter string
	}{
		{vb, listener.ScopeSub, "(objectClass=*)"},
		{usersDN, listener.ScopeSub, "(|(mail=alice*)(cn=Bob*))"},
		{usersDN, listener.ScopeSub, "(&(objectClass=user)(!(sAMAccountName=alice.adams)))"},
		{"cn=bob.brown," + usersDN, listener.ScopeBase, "(objectClass=*)"},
		{usersDN, listener.ScopeSub, "(memberOf=cn=virola-users,ou=groups,ou=virola,dc=aldap)"},
		{groupsDN, listener.ScopeSub, "(objectClass=groupOfNames)"},
	} {
		want, wes := live.search(t, q.base, q.scope, q.filter)
		got, ges := f.search(t, q.base, q.scope, q.filter)
		if got.Code != want.Code || strings.Join(dns(ges), ";") != strings.Join(dns(wes), ";") {
			t.Errorf("%s %s: replica %v %v, live %v %v", q.base, q.filter, got, dns(ges), want, dns(wes))
		}
	}
	f.dc.Kill()
	before := f.dc.Calls()
	res, es := f.search(t, usersDN, listener.ScopeSub, "(objectClass=*)", "mail", "memberOf")
	if res.Code != 0 || len(es) != 19 || len(attr(es[0], "memberOf")) != 1 {
		t.Fatalf("replica search with the upstream gone: %v %d", res, len(es))
	}
	if e := f.ev.last(events.Search); e.Data["cache_hit"] != true || e.Data["upstream_queries"] != 0 {
		t.Errorf("replica search event %v", e.Data)
	}
	if got := f.d.cacheLabel(&searchCtx{replica: true}); got != "replica" {
		t.Errorf("label = %s", got)
	}
	if res := f.bind(t, testConn("10.0.0.2"), "alice.adams@test.aldap", "alice.adams-pass"); res.Code != ldap.LDAPResultUnavailable {
		t.Errorf("user bind with the upstream gone: %v", res)
	}
	if res := f.bind(t, testConn("10.0.0.2"), "cn=alice.adams,"+usersDN, "alice.adams-pass"); res.Code != ldap.LDAPResultUnavailable {
		t.Errorf("virtual DN bind with the upstream gone (lookup not from the replica): %v", res)
	}
	if after := f.dc.Calls(); after.Searches != before.Searches {
		t.Error("the dead upstream was counted")
	}
	// A failed sync keeps the copy.
	if err := rep.Sync(context.Background(), f.d.SyncReplica); err == nil {
		t.Fatal("sync with the upstream gone succeeded")
	}
	if e := f.ev.last(events.ReplicaSyncFailed); e == nil || e.Data["entries"] != 19 || e.Reason != "upstream_unavailable" {
		t.Errorf("replica_sync_failed = %+v", e)
	}
	if res, es := f.search(t, usersDN, listener.ScopeSub, "(objectClass=*)"); res.Code != 0 || len(es) != 19 {
		t.Errorf("after the failed sync: %v %d", res, len(es))
	}
}

// User bind in replica mode is answered by the upstream (passwords are
// never in the replica).
func TestReplica_BindGoesUpstream(t *testing.T) {
	f, rep := replicaFixture(t, nil)
	if err := rep.Sync(context.Background(), f.d.SyncReplica); err != nil {
		t.Fatal(err)
	}
	binds := f.dc.Calls().Binds
	if res := f.bind(t, testConn("10.0.0.3"), "alice.adams@test.aldap", "alice.adams-pass"); res.Code != 0 {
		t.Fatalf("bind: %v", res)
	}
	if res := f.bind(t, testConn("10.0.0.3"), "bob.brown@test.aldap", "wrong"); res.Code != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("wrong password: %v", res)
	}
	if n := f.dc.Calls().Binds - binds; n != 2 {
		t.Errorf("upstream binds = %d, want 2", n)
	}
}

// RDN collisions in replica mode are decided over the whole profile, so a
// user has the same DN in a narrow search and in the group member values
// (closes DECISIONS «RDN collision suffix scope» for replica).
func TestReplica_RDNCollisionStable(t *testing.T) {
	collide := func(p *config.Profile) {
		withVirolaGroup(p)
		p.RDNAttr = "department"
		p.Attrs.Allow = append(p.Attrs.Allow, "department")
	}
	narrow := "(&(department=IT)(sAMAccountName=alice.adams))"
	// Proxy mode: the suffix depends on the result set (documented).
	live := newFixture(t, collide)
	_, es := live.search(t, usersDN, listener.ScopeOne, narrow)
	if len(es) != 1 || es[0].DN != "cn=IT,"+usersDN {
		t.Fatalf("proxy narrow search = %v", dns(es))
	}
	f, rep := replicaFixture(t, collide)
	if err := rep.Sync(context.Background(), f.d.SyncReplica); err != nil {
		t.Fatal(err)
	}
	_, es = f.search(t, usersDN, listener.ScopeOne, narrow)
	if len(es) != 1 || !strings.HasPrefix(strings.ToLower(es[0].DN), "cn=it+objectguid=") {
		t.Fatalf("replica narrow search = %v", dns(es))
	}
	alice := es[0].DN
	_, wide := f.search(t, usersDN, listener.ScopeOne, "(department=IT)")
	if !contains(dns(wide), alice) {
		t.Errorf("wide search lacks %s: %v", alice, dns(wide))
	}
	_, gs := f.search(t, groupsDN, listener.ScopeOne, "(cn=virola-users)", "member")
	if len(gs) != 1 || !contains(attr(gs[0], "member"), alice) {
		t.Errorf("group members lack %s", alice)
	}
	// The DN found in a search reads back by base search.
	if _, es := f.search(t, usersDN, listener.ScopeOne, "(department=Legal)"); len(es) != 1 || es[0].DN != "cn=Legal,"+usersDN {
		t.Errorf("unique rdn = %v", dns(es))
	}
}

// Honeytokens are served by a replica profile like by a proxy profile.
func TestReplica_Honeytokens(t *testing.T) {
	f, rep := replicaFixture(t, func(p *config.Profile) {
		withVirolaGroup(p)
		p.Honeytokens = []string{"backup.admin"}
		p.HoneytokenInGroups = true
	})
	if err := rep.Sync(context.Background(), f.d.SyncReplica); err != nil {
		t.Fatal(err)
	}
	_, es := f.search(t, usersDN, listener.ScopeSub, "(objectClass=*)")
	if len(es) != 20 || !contains(dns(es), "cn=backup.admin,"+usersDN) {
		t.Errorf("users = %d %v", len(es), dns(es))
	}
	if _, es := f.search(t, "cn=backup.admin,"+usersDN, listener.ScopeBase, "(objectClass=*)"); len(es) != 1 {
		t.Errorf("honeytoken by base = %v", dns(es))
	}
	if f.ev.last(events.Honeytoken) == nil {
		t.Error("no honeytoken event")
	}
}

// Group membership in mode none is reused for the group ttl.
func TestNone_MembershipTTL(t *testing.T) {
	f := newFixture(t, func(p *config.Profile) { withVirolaGroup(p); p.Cache.TTL = config.Duration(time.Minute) })
	clk := &testClock{t: time.Now()}
	f.rebuild(t, func(o *Options) { o.Now = clk.now })
	f.search(t, groupsDN, listener.ScopeOne, "(objectClass=*)")
	n := f.clientSearches()
	f.search(t, groupsDN, listener.ScopeOne, "(objectClass=*)")
	if f.clientSearches() != n {
		t.Error("membership recomputed within the ttl")
	}
	clk.add(2 * time.Minute)
	f.search(t, groupsDN, listener.ScopeOne, "(objectClass=*)")
	if f.clientSearches() == n {
		t.Error("membership not recomputed after the ttl")
	}
}

func TestReplica_Errors(t *testing.T) {
	// Without an upstream (honeypot) there is nothing to sync and the
	// cache options are dropped.
	p := baseProfile()
	p.Mode = "honeypot"
	rules, err := profile.Compile("virola", p, &config.Upstream{Kind: "ad"}, profile.Options{ClientPassword: clientPW, Argon2: fastArgon})
	if err != nil {
		t.Fatal(err)
	}
	rep := cache.NewReplica(cache.ReplicaOptions{})
	d := New(rules, &fakeUp{}, Options{Logger: slog.New(slog.DiscardHandler), Replica: rep})
	if _, _, err := d.SyncReplica(context.Background()); err == nil {
		t.Error("honeypot sync succeeded")
	}
	if d.o.Replica != nil || d.o.Cache != nil {
		t.Error("cache options kept without an upstream")
	}
	// A failing upstream fails the sync.
	d2, _ := fakeDirectory(t, &fakeUp{searchErr: context.DeadlineExceeded}, withVirolaGroup)
	if _, _, err := d2.SyncReplica(context.Background()); err == nil {
		t.Error("sync with a failing upstream succeeded")
	}
	// Data of another type is not a copy.
	d3, _ := fakeDirectory(t, &fakeUp{}, nil)
	d3.o.Replica = staticReplica{data: "x"}
	if _, err := d3.replicaData(); err == nil {
		t.Error("foreign data accepted")
	}
}

type staticReplica struct{ data any }

func (s staticReplica) Current() (any, time.Time, bool) { return s.data, time.Time{}, true }
