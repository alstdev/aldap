package cache

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/events/schematest"
	"github.com/alstdev/aldap/internal/ldapfilter"
	"github.com/alstdev/aldap/internal/upstream"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// fakeSource answers with n entries per request and counts the calls.
type fakeSource struct {
	mu    sync.Mutex
	calls int
	n     int
	err   error
	state upstream.State
}

func (f *fakeSource) Search(_ context.Context, req upstream.SearchRequest) (*upstream.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	r := &upstream.Result{Pages: 1, Server: "ldap://dc1"}
	for i := range f.n {
		r.Entries = append(r.Entries, upstream.Entry{DN: fmt.Sprintf("CN=u%d,%s", i, req.Base), Attrs: map[string][]string{"cn": {fmt.Sprintf("u%d", i)}}})
	}
	return r, nil
}

func (f *fakeSource) Status() []upstream.ServerStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return []upstream.ServerStatus{{URL: "ldap://dc1", State: f.state}}
}

func (f *fakeSource) set(n int, err error, st upstream.State) {
	f.mu.Lock()
	f.n, f.err, f.state = n, err, st
	f.mu.Unlock()
}

func (f *fakeSource) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func req(base, filter string, attrs ...string) upstream.SearchRequest {
	f, err := ldapfilter.Parse(filter)
	if err != nil {
		panic(err)
	}
	return upstream.SearchRequest{Base: base, Scope: upstream.ScopeSub, Filter: f, Attrs: attrs}
}

func TestKey_Normalized(t *testing.T) {
	a := Key(req("OU=Office,DC=test,DC=aldap", "(&(sAMAccountName=a)(objectClass=user))", "mail", "cn"))
	b := Key(req("ou=office, dc=test,dc=aldap", "(&(objectclass=user)(samaccountname=a))", "CN", "mail", "cn"))
	if a != b {
		t.Errorf("equivalent requests differ:\n%q\n%q", a, b)
	}
	for name, other := range map[string]upstream.SearchRequest{
		"base":   req("OU=Branch,DC=test,DC=aldap", "(&(sAMAccountName=a)(objectClass=user))", "mail", "cn"),
		"filter": req("OU=Office,DC=test,DC=aldap", "(&(sAMAccountName=b)(objectClass=user))", "mail", "cn"),
		"value":  req("OU=Office,DC=test,DC=aldap", "(&(sAMAccountName=A)(objectClass=user))", "mail", "cn"),
		"attrs":  req("OU=Office,DC=test,DC=aldap", "(&(sAMAccountName=a)(objectClass=user))", "mail"),
	} {
		if Key(other) == a {
			t.Errorf("%s: different request has the same key", name)
		}
	}
	scoped := req("OU=Office,DC=test,DC=aldap", "(&(sAMAccountName=a)(objectClass=user))", "mail", "cn")
	scoped.Scope = upstream.ScopeBase
	limited := req("OU=Office,DC=test,DC=aldap", "(&(sAMAccountName=a)(objectClass=user))", "mail", "cn")
	limited.SizeLimit = 5
	timed := req("OU=Office,DC=test,DC=aldap", "(&(sAMAccountName=a)(objectClass=user))", "mail", "cn")
	timed.TimeLimit = time.Second
	if Key(scoped) == a || Key(limited) == a || Key(timed) != a {
		t.Error("scope and size limit are part of the key, the time limit is not")
	}
	if Key(upstream.SearchRequest{Base: "not a dn"}) == "" {
		t.Error("empty key")
	}
}

// TESTING.md 21 (unit): the second identical request is served from
// memory; after the ttl the upstream is asked again.
func TestTTL_HitAndExpiry(t *testing.T) {
	clk, src := newClock(), &fakeSource{n: 2, state: upstream.StateUp}
	c := NewTTL(TTLOptions{TTL: time.Minute, MaxEntries: 100, Now: clk.now})
	s := c.Wrap(src)
	ctx := context.Background()
	r := req("OU=Office,DC=test,DC=aldap", "(objectClass=user)", "cn")
	first, err := s.Search(ctx, r)
	if err != nil || first.Cached || len(first.Entries) != 2 || src.count() != 1 {
		t.Fatalf("first: %+v %v calls=%d", first, err, src.count())
	}
	clk.add(30 * time.Second)
	second, err := s.Search(ctx, r)
	if err != nil || !second.Cached || second.Stale || second.Age != 30*time.Second || len(second.Entries) != 2 || src.count() != 1 {
		t.Fatalf("second: %+v %v calls=%d", second, err, src.count())
	}
	if c.Len() != 2 {
		t.Errorf("Len = %d, want 2 entries", c.Len())
	}
	clk.add(31 * time.Second)
	third, err := s.Search(ctx, r)
	if err != nil || third.Cached || src.count() != 2 {
		t.Fatalf("after ttl: %+v %v calls=%d", third, err, src.count())
	}
	// Errors are not cached.
	src.set(0, errors.New("boom"), upstream.StateUp)
	if _, err := s.Search(ctx, req("DC=x", "(cn=y)")); err == nil {
		t.Fatal("error swallowed")
	}
	src.set(1, nil, upstream.StateUp)
	if r, err := s.Search(ctx, req("DC=x", "(cn=y)")); err != nil || r.Cached {
		t.Fatalf("after error: %+v %v", r, err)
	}
	c.Purge()
	if c.Len() != 0 {
		t.Errorf("Len after Purge = %d", c.Len())
	}
}

// TESTING.md 22 (unit): every server down → the expired result is served
// marked stale up to stale_max; without stale_while_down → the error.
func TestTTL_StaleWhileDown(t *testing.T) {
	for _, tc := range []struct {
		name      string
		swd       bool
		state     upstream.State
		err       error
		age       time.Duration
		wantStale bool
		wantCalls int
	}{
		{"down_by_status", true, upstream.StateDown, upstream.ErrUnavailable, 2 * time.Minute, true, 1},
		{"unavailable_error", true, upstream.StateUnknown, upstream.ErrUnavailable, 2 * time.Minute, true, 2},
		{"pool_exhausted", true, upstream.StateUp, upstream.ErrPoolExhausted, 2 * time.Minute, true, 2},
		{"other_error", true, upstream.StateUp, errors.New("boom"), 2 * time.Minute, false, 2},
		{"beyond_stale_max", true, upstream.StateDown, upstream.ErrUnavailable, 2 * time.Hour, false, 2},
		{"disabled", false, upstream.StateDown, upstream.ErrUnavailable, 2 * time.Minute, false, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clk, src := newClock(), &fakeSource{n: 3, state: upstream.StateUp}
			c := NewTTL(TTLOptions{TTL: time.Minute, MaxEntries: 100, StaleWhileDown: tc.swd, StaleMax: time.Hour, Now: clk.now})
			s := c.Wrap(src)
			r := req("OU=Office,DC=test,DC=aldap", "(objectClass=user)")
			if _, err := s.Search(context.Background(), r); err != nil {
				t.Fatal(err)
			}
			clk.add(tc.age)
			src.set(3, tc.err, tc.state)
			got, err := s.Search(context.Background(), r)
			if tc.wantStale {
				if err != nil || !got.Cached || !got.Stale || got.Age != tc.age || len(got.Entries) != 3 {
					t.Fatalf("stale: %+v %v", got, err)
				}
			} else if err == nil {
				t.Fatalf("served %+v, want the upstream error", got)
			}
			if src.count() != tc.wantCalls {
				t.Errorf("upstream calls = %d, want %d", src.count(), tc.wantCalls)
			}
		})
	}
}

func TestTTL_MaxEntriesAndSweep(t *testing.T) {
	clk, src := newClock(), &fakeSource{n: 4, state: upstream.StateUp}
	c := NewTTL(TTLOptions{TTL: time.Minute, MaxEntries: 10, StaleWhileDown: true, StaleMax: 10 * time.Minute, Now: clk.now})
	s := c.Wrap(src)
	ctx := context.Background()
	a, b, d := req("DC=a", "(cn=*)"), req("DC=b", "(cn=*)"), req("DC=d", "(cn=*)")
	for _, r := range []upstream.SearchRequest{a, b} {
		if _, err := s.Search(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Search(ctx, a); err != nil || src.count() != 2 { // a is now the most recently used
		t.Fatalf("hit a: %v calls=%d", err, src.count())
	}
	if _, err := s.Search(ctx, d); err != nil || c.Len() != 8 {
		t.Fatalf("third result: %v len=%d (b evicted)", err, c.Len())
	}
	if r, _ := s.Search(ctx, a); !r.Cached {
		t.Error("recently used result evicted")
	}
	if r, _ := s.Search(ctx, b); r.Cached {
		t.Error("least recently used result kept")
	}
	// A result larger than the bound is not cached; an empty one costs 1.
	src.set(11, nil, upstream.StateUp)
	big := req("DC=big", "(cn=*)")
	_, _ = s.Search(ctx, big)
	if r, _ := s.Search(ctx, big); r.Cached {
		t.Error("oversized result cached")
	}
	src.set(0, nil, upstream.StateUp)
	empty := req("DC=empty", "(cn=*)")
	_, _ = s.Search(ctx, empty)
	if r, _ := s.Search(ctx, empty); !r.Cached {
		t.Error("empty result not cached")
	}
	// Sweep keeps results within stale_max, drops the older ones.
	clk.add(5 * time.Minute)
	c.Sweep()
	if c.Len() == 0 {
		t.Error("sweep dropped servable stale results")
	}
	clk.add(6 * time.Minute)
	c.Sweep()
	if c.Len() != 0 {
		t.Errorf("Len after sweep = %d", c.Len())
	}
	// Without stale results the retention is the ttl; lookups expire too.
	c2 := NewTTL(TTLOptions{TTL: time.Minute, Now: clk.now})
	s2 := c2.Wrap(src)
	_, _ = s2.Search(ctx, a)
	clk.add(2 * time.Minute)
	if r, _ := s2.Search(ctx, a); r.Cached || c2.Len() != 1 {
		t.Errorf("expired lookup: %+v len=%d", r, c2.Len())
	}
}

type evSink struct {
	mu sync.Mutex
	ev []events.Event
}

func (s *evSink) Emit(e events.Event) {
	s.mu.Lock()
	s.ev = append(s.ev, e)
	s.mu.Unlock()
}

func (s *evSink) kinds() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.ev))
	for _, e := range s.ev {
		out = append(out, e.Event)
	}
	return out
}

func (s *evSink) last() events.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ev[len(s.ev)-1]
}

func TestReplica_SyncKeepsLastCopy(t *testing.T) {
	clk, ev := newClock(), &evSink{}
	r := NewReplica(ReplicaOptions{Profile: "virola", Upstream: "ad", Interval: 5 * time.Minute, Jitter: 0.2, Events: ev,
		Logger: slog.New(slog.DiscardHandler), Now: clk.now, Rand: func() float64 { return 0.5 }})
	if _, _, ok := r.Current(); ok {
		t.Fatal("copy before the first sync")
	}
	if _, _, ok := r.Stats(); ok {
		t.Fatal("stats before the first sync")
	}
	if d := r.delay(); d != 0 {
		t.Errorf("first delay = %v, want 0", d)
	}
	ctx := context.Background()
	if err := r.Sync(ctx, func(context.Context) (any, int, error) { return "v1", 7, nil }); err != nil {
		t.Fatal(err)
	}
	data, at, ok := r.Current()
	if !ok || data != "v1" || !at.Equal(clk.now()) {
		t.Fatalf("current = %v %v %v", data, at, ok)
	}
	if e := ev.last(); e.Event != events.ReplicaSynced || e.Data["entries"] != 7 || e.Data["age_s"] != 0 || e.Profile != "virola" || e.Upstream != "ad" {
		t.Errorf("synced event %+v", e)
	}
	if d := r.delay(); d != 5*time.Minute {
		t.Errorf("delay after success = %v (jitter midpoint)", d)
	}
	clk.add(90 * time.Second)
	if d := r.delay(); d != 210*time.Second {
		t.Errorf("delay after 90s = %v", d)
	}
	err := r.Sync(ctx, func(context.Context) (any, int, error) {
		return nil, 0, fmt.Errorf("base: %w", upstream.ErrUnavailable)
	})
	if !errors.Is(err, upstream.ErrUnavailable) {
		t.Fatalf("failed sync: %v", err)
	}
	if data, _, _ := r.Current(); data != "v1" {
		t.Errorf("copy replaced by a failed sync: %v", data)
	}
	if e := ev.last(); e.Event != events.ReplicaSyncFailed || e.Reason != "upstream_unavailable" || e.Data["entries"] != 7 || e.Data["age_s"] != 90 || e.Level != events.LevelMedium {
		t.Errorf("failed event %+v", e)
	}
	if d := r.delay(); d != retryAfterFailure {
		t.Errorf("delay after failure = %v", d)
	}
	if age, n, ok := r.Stats(); !ok || age != 90*time.Second || n != 7 {
		t.Errorf("stats = %v %d %v", age, n, ok)
	}
	clk.add(time.Minute)
	if err := r.Sync(ctx, func(context.Context) (any, int, error) { return "v2", 9, nil }); err != nil {
		t.Fatal(err)
	}
	if e := ev.last(); e.Data["age_s"] != 150 || e.Data["entries"] != 9 {
		t.Errorf("second synced event %+v", e)
	}
	schematest.CheckEvents(t, ev.ev...)
}

func TestReplica_Jitter(t *testing.T) {
	clk := newClock()
	for _, tc := range []struct {
		rnd    float64
		jitter float64
		want   time.Duration
	}{
		{0, 0.2, 80 * time.Second},
		{0.999999999, 0.2, 120 * time.Second},
		{0, 0, 100 * time.Second},
		{0, 5, 0}, // jitter is capped at 100%
	} {
		r := NewReplica(ReplicaOptions{Interval: 100 * time.Second, Jitter: tc.jitter, Now: clk.now, Rand: func() float64 { return tc.rnd }})
		_ = r.Sync(context.Background(), func(context.Context) (any, int, error) { return 1, 1, nil })
		if d := r.delay(); d.Round(time.Second) != tc.want {
			t.Errorf("rand %v jitter %v: delay %v, want %v", tc.rnd, tc.jitter, d, tc.want)
		}
	}
	// A copy kept across a reload counts from its sync time.
	r := NewReplica(ReplicaOptions{Interval: 100 * time.Second, Now: clk.now})
	r.snap.Store(&Snapshot{Data: 1, At: clk.now().Add(-40 * time.Second)})
	if d := r.delay(); d != 60*time.Second {
		t.Errorf("kept copy delay = %v", d)
	}
}

func TestReplica_RunAndTrigger(t *testing.T) {
	ev := &evSink{}
	r := NewReplica(ReplicaOptions{Profile: "p", Interval: time.Hour, Events: ev, Logger: slog.New(slog.DiscardHandler)})
	var mu sync.Mutex
	n := 0
	fn := func(context.Context) (any, int, error) {
		mu.Lock()
		defer mu.Unlock()
		n++
		return n, n, nil
	}
	syncs := func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.Run(ctx, fn)
		close(done)
	}()
	waitUntil(t, func() bool { return syncs() == 1 }) // no copy → at once
	r.Trigger()
	r.Trigger() // absorbed while one is pending or running
	waitUntil(t, func() bool { return syncs() >= 2 })
	cancel()
	<-done
	if got := syncs(); got > 3 {
		t.Errorf("syncs = %d", got)
	}
	if k := strings.Join(ev.kinds(), ","); !strings.HasPrefix(k, "replica_synced,replica_synced") {
		t.Errorf("events = %s", k)
	}
	if syncReason(context.Canceled) != "canceled" || syncReason(errors.New("x")) != "upstream_error" {
		t.Error("sync reasons")
	}
	if NewReplica(ReplicaOptions{}).o.Interval != 5*time.Minute {
		t.Error("default interval")
	}
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
