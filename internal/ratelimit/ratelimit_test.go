package ratelimit

import (
	"log/slog"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/events/schematest"
)

type sink struct {
	mu sync.Mutex
	ev []events.Event
}

func (s *sink) Emit(e events.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ev = append(s.ev, e)
}

func (s *sink) count(kind string, match func(events.Event) bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, e := range s.ev {
		if e.Event == kind && (match == nil || match(e)) {
			n++
		}
	}
	return n
}

func (s *sink) check(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	schematest.CheckEvents(t, s.ev...)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

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

func newTest(t *testing.T, mod func(*config.Ratelimit)) (*Limiter, *Policy, *sink, *clock) {
	t.Helper()
	cl := &clock{t: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)}
	ev := &sink{}
	l := New(Options{Events: ev, Logger: slog.New(slog.DiscardHandler), Now: cl.now, Salt: []byte("s"), MaxEntries: 1000})
	cfg := config.Default().Ratelimit
	if mod != nil {
		mod(&cfg)
	}
	p, err := l.Policy("p", cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.Sleep = func(time.Duration) {}
	return l, p, ev, cl
}

func TestPolicy_AccountLock(t *testing.T) {
	l, p, ev, cl := newTest(t, nil)
	pw := l.HashPassword([]byte("wrong"))
	if pw == l.HashPassword([]byte("other")) || len(pw) != 64 {
		t.Fatal("hash")
	}
	for i := 1; i <= 3; i++ {
		if v := p.PreBind("10.0.0.1", "Alice", pw+"x"); !v.Allowed {
			t.Fatalf("attempt %d blocked: %+v", i, v)
		}
		wait := p.PostBind("10.0.0.1", "alice", pw, false, "invalid_password", time.Millisecond)
		if want := 250 * time.Millisecond << uint(i-1); wait != want {
			t.Errorf("attempt %d delay = %v, want %v", i, wait, want)
		}
	}
	if ev.count(events.Lock, func(e events.Event) bool {
		return e.Data["target"] == "account" && e.Data["key"] == "alice" && e.Data["source"] == "ratelimit" && e.Failures == 3
	}) != 1 {
		t.Errorf("account lock event missing: %+v", ev.ev)
	}
	// The 4th attempt, even with the right password, never reaches the upstream.
	if v := p.PreBind("10.0.0.1", "ALICE", l.HashPassword([]byte("right"))); v.Allowed || v.Reason != ReasonAccountLocked || v.Code != ldap.LDAPResultInvalidCredentials {
		t.Errorf("locked account: %+v", v)
	}
	// The lock consumed the account window; the IP window keeps counting.
	if ip, acct := p.Failures("10.0.0.1", "alice"); ip != 3 || acct != 0 {
		t.Errorf("failures = %d %d", ip, acct)
	}
	locks := l.Locks()
	if len(locks) != 1 || locks[0].Target != TargetAccount || locks[0].Key != "alice" || locks[0].Failures != 3 || locks[0].Profile != "p" {
		t.Errorf("locks = %+v", locks)
	}
	// After lock_duration the account works again and unlock{expiry} is reported.
	cl.add(15*time.Minute + time.Second)
	if v := p.PreBind("10.0.0.1", "alice", "h"); !v.Allowed {
		t.Errorf("after expiry: %+v", v)
	}
	if ev.count(events.Unlock, func(e events.Event) bool { return e.Data["source"] == "expiry" && e.Data["target"] == "account" }) != 1 {
		t.Error("unlock expiry event missing")
	}
	if p.PostBind("10.0.0.1", "alice", "h", true, "", 5*time.Millisecond) != 0 {
		t.Error("success delayed")
	}
	if _, acct := p.Failures("10.0.0.1", "alice"); acct != 0 {
		t.Error("success did not clear the account window")
	}
	ev.check(t)
}

func TestPolicy_NegativeCache(t *testing.T) {
	l, p, _, cl := newTest(t, nil)
	pw := l.HashPassword([]byte("wrong"))
	if v := p.PreBind("10.0.0.2", "bob", pw); !v.Allowed {
		t.Fatal(v)
	}
	p.PostBind("10.0.0.2", "bob", pw, false, "invalid_password", 0)
	if v := p.PreBind("10.0.0.2", "bob", pw); v.Allowed || v.Reason != ReasonNegativeCache || v.Code != ldap.LDAPResultInvalidCredentials {
		t.Errorf("second try with the same password: %+v", v)
	}
	if v := p.PreBind("10.0.0.2", "bob", l.HashPassword([]byte("other"))); !v.Allowed {
		t.Errorf("different password: %+v", v)
	}
	cl.add(61 * time.Second)
	if v := p.PreBind("10.0.0.2", "bob", pw); !v.Allowed {
		t.Errorf("after ttl: %+v", v)
	}
	// Upstream errors are not cached.
	p.PostBind("10.0.0.2", "bob", pw, false, "upstream_error", 0)
	if v := p.PreBind("10.0.0.2", "bob", pw); !v.Allowed {
		t.Errorf("upstream_error cached: %+v", v)
	}
	// Empty account or hash never caches.
	p.PostBind("10.0.0.2", "", pw, false, "invalid_password", 0)
	if v := p.PreBind("10.0.0.2", "", pw); !v.Allowed {
		t.Error("anonymous cached")
	}
}

func TestPolicy_IPLockAndAllowlists(t *testing.T) {
	l, p, ev, cl := newTest(t, func(c *config.Ratelimit) {
		c.AllowAccounts = []string{"svc-monitor"}
		c.AllowCIDRs = []string{"192.168.1.0/24", "fd00::1"}
		c.Account.MaxFailures = 100
	})
	for i := 0; i < 20; i++ {
		p.PostBind("10.0.0.3", "user"+string(rune('a'+i)), "h", false, "unknown_account", 0)
	}
	if v := p.PreBind("10.0.0.3", "anyone", "h"); v.Allowed || v.Reason != ReasonIPLocked {
		t.Errorf("ip lock: %+v", v)
	}
	if v := p.PreSearch("10.0.0.3", ""); v.Allowed || v.Reason != ReasonIPLocked || v.Code != ldap.LDAPResultUnwillingToPerform {
		t.Errorf("search from locked ip: %+v", v)
	}
	if ev.count(events.Lock, func(e events.Event) bool {
		return e.Data["target"] == "ip" && e.ClientIP == "10.0.0.3" && e.Failures == 20
	}) != 1 {
		t.Error("ip lock event")
	}
	// allow_accounts never lock, allow_cidrs have no IP limits.
	for i := 0; i < 5; i++ {
		p.PostBind("10.0.0.4", "SVC-Monitor", "h", false, "invalid_password", 0)
	}
	if v := p.PreBind("10.0.0.4", "svc-monitor", "h2"); !v.Allowed {
		t.Errorf("allow_accounts locked: %+v", v)
	}
	if v := p.PreBind("10.0.0.4", "svc-monitor", "h"); v.Allowed || v.Reason != ReasonNegativeCache {
		t.Errorf("allow_accounts bypassed the negative cache: %+v", v)
	}
	for i := 0; i < 50; i++ {
		h := "h" + strconv.Itoa(i)
		if w := p.PostBind("192.168.1.9", "x", h, false, "invalid_password", 0); w != 0 {
			t.Fatalf("exempt ip delayed %v", w)
		}
		if v := p.PreBind("192.168.1.9", "x", h+"'"); !v.Allowed {
			t.Fatalf("exempt ip blocked: %+v", v)
		}
	}
	if v := p.PreBind("fd00::1", "x", "h"); !v.Allowed {
		t.Error("single-address allow entry")
	}
	if len(l.Locks()) != 1 {
		t.Errorf("locks = %+v", l.Locks())
	}
	// Manual unlock clears the lock and the window; a second unlock is a no-op.
	if !l.Unlock(TargetIP, "10.0.0.3", SourceAPI) || l.Unlock(TargetIP, "10.0.0.3", SourceAPI) {
		t.Error("unlock")
	}
	if v := p.PreBind("10.0.0.3", "anyone", "h"); !v.Allowed {
		t.Errorf("after unlock: %+v", v)
	}
	if ipc, _ := p.Failures("10.0.0.3", ""); ipc != 0 {
		t.Error("window not cleared")
	}
	// Honeytoken-style lock through the Locker, listing and sweep expiry.
	l.LockIP("10.0.0.5", cl.now().Add(time.Hour), SourceHoneytoken)
	l.LockIP("10.0.0.5", cl.now().Add(time.Minute), SourceHoneytoken) // shorter: ignored
	l.LockIP("", cl.now().Add(time.Minute), SourceHoneytoken)
	l.LockAccount("Carol", cl.now().Add(time.Minute), SourceAPI)
	if until, ok := l.IPLocked("10.0.0.5", cl.now()); !ok || until != cl.now().Add(time.Hour) {
		t.Error("longer lock kept")
	}
	if _, ok := l.AccountLocked("carol", cl.now()); !ok {
		t.Error("account lock")
	}
	locks := l.Locks()
	if len(locks) != 2 || locks[0].Key != "carol" || locks[1].Source != SourceHoneytoken {
		t.Errorf("locks = %+v", locks)
	}
	cl.add(2 * time.Minute)
	l.Sweep(cl.now(), time.Hour)
	if n := ev.count(events.Unlock, func(e events.Event) bool { return e.Data["source"] == "expiry" }); n != 1 {
		t.Errorf("sweep unlocks = %d (10.0.0.3 was unlocked manually, carol expired, 10.0.0.5 active)", n)
	}
	if len(l.Locks()) != 1 {
		t.Errorf("locks after sweep = %+v", l.Locks())
	}
	ev.check(t)
}

func TestPolicy_BucketsLockdownTarpit(t *testing.T) {
	l, p, ev, cl := newTest(t, func(c *config.Ratelimit) {
		c.IP.BindRPS, c.IP.BindBurst, c.IP.SearchRPS, c.IP.SearchBurst = 1, 2, 2, 2
		c.Lockdown.AllowCIDRs = []string{"10.1.0.0/16"}
		c.Lockdown.AllowAccounts = []string{"admin"}
		c.Tarpit.Enabled, c.Tarpit.Delay, c.Tarpit.MaxConns = true, config.Duration(3*time.Second), 1
		c.LockResponse = "busy"
	})
	// Bind bucket: burst 2, then refill 1/s.
	for i := 0; i < 2; i++ {
		if v := p.PreBind("10.0.0.6", "a", "h"); !v.Allowed {
			t.Fatalf("burst %d: %+v", i, v)
		}
	}
	if v := p.PreBind("10.0.0.6", "a", "h"); v.Allowed || v.Reason != ReasonRateLimited || v.Code != ldap.LDAPResultBusy {
		t.Errorf("over burst: %+v", v)
	}
	cl.add(time.Second)
	if v := p.PreBind("10.0.0.6", "a", "h"); !v.Allowed {
		t.Errorf("after refill: %+v", v)
	}
	for i := 0; i < 2; i++ {
		if v := p.PreSearch("10.0.0.6", "a"); !v.Allowed {
			t.Fatalf("search burst %d: %+v", i, v)
		}
	}
	if v := p.PreSearch("10.0.0.6", "a"); v.Allowed || v.Reason != ReasonRateLimited {
		t.Errorf("search over burst: %+v", v)
	}
	// Lockdown: only the allowed network and accounts work.
	if !l.SetLockdown(true, SourceAPI) || l.SetLockdown(true, SourceAPI) {
		t.Error("lockdown toggle")
	}
	if on, src := l.Lockdown(); !on || src != SourceAPI {
		t.Error("lockdown state")
	}
	if v := p.PreBind("10.0.0.7", "bob", "h"); v.Allowed || v.Reason != ReasonLockdown || v.Code != ldap.LDAPResultBusy {
		t.Errorf("lockdown bind: %+v", v)
	}
	if v := p.PreBind("10.0.0.7", "Admin", "h"); !v.Allowed {
		t.Errorf("lockdown allow_accounts: %+v", v)
	}
	if v := p.PreBind("10.1.2.3", "bob", "h"); !v.Allowed {
		t.Errorf("lockdown allow_cidrs: %+v", v)
	}
	if v := p.PreSearch("10.0.0.7", ""); v.Allowed || v.Reason != ReasonLockdown || v.Code != ldap.LDAPResultUnwillingToPerform {
		t.Errorf("lockdown search: %+v", v)
	}
	l.SetLockdown(false, SourceTUI)
	if ev.count(events.Lockdown, func(e events.Event) bool { return e.Data["state"] == "on" }) != 1 || ev.count(events.Lockdown, func(e events.Event) bool { return e.Data["state"] == "off" && e.Data["source"] == "tui" }) != 1 {
		t.Error("lockdown events")
	}
	// Tarpit: attacking IPs wait tarpit.delay; beyond max_conns they are refused.
	l.SetAttack("10.0.0.8", true)
	if !l.Attacking("10.0.0.8") || l.Attacking("10.0.0.9") {
		t.Error("attack flag")
	}
	v1 := p.PreBind("10.0.0.8", "a", "h")
	if !v1.Allowed || v1.Wait != 3*time.Second || v1.Done == nil {
		t.Fatalf("tarpit verdict: %+v", v1)
	}
	if v2 := p.PreSearch("10.0.0.8", ""); v2.Allowed || v2.Reason != ReasonRateLimited || v2.Code != ldap.LDAPResultUnwillingToPerform {
		t.Errorf("tarpit over max_conns: %+v", v2)
	}
	v1.Done()
	v1.Done()
	if v3 := p.PreSearch("10.0.0.8", ""); !v3.Allowed || v3.Wait != 3*time.Second {
		t.Errorf("tarpit slot released: %+v", v3)
	}
	v3 := p.PreSearch("10.0.0.8", "")
	_ = v3
	if ev.count(events.Tarpit, func(e events.Event) bool { return e.Data["ip"] == "10.0.0.8" }) != 2 {
		t.Errorf("tarpit events: %+v", ev.ev)
	}
	l.SetAttack("10.0.0.8", false)
	if v := p.PreSearch("10.0.0.9", ""); !v.Allowed || v.Wait != 0 {
		t.Errorf("non-attacking ip: %+v", v)
	}
	ev.check(t)
}

func TestPolicy_ConstantTimeAndDisabled(t *testing.T) {
	_, p, _, _ := newTest(t, nil)
	for i := 0; i < 20; i++ {
		p.PostBind("10.0.1.1", "ok"+string(rune('a'+i)), "h", true, "", time.Duration(10+i)*time.Millisecond)
	}
	// p95 of 10..29ms ≈ 29ms; a 2ms failure is padded to it (beyond the 250ms delay? no: delay wins when larger).
	w := p.PostBind("10.0.1.2", "x", "h", false, "invalid_password", 2*time.Millisecond)
	if w != 250*time.Millisecond {
		t.Errorf("delay = %v, want the progressive delay (larger than the p95 pad)", w)
	}
	_, p2, _, _ := newTest(t, func(c *config.Ratelimit) { c.Delay.Base, c.Delay.Max = 0, 0 })
	for i := 0; i < 20; i++ {
		p2.PostBind("10.0.1.1", "ok", "h", true, "", 30*time.Millisecond)
	}
	if w := p2.PostBind("10.0.1.3", "x", "h", false, "invalid_password", 5*time.Millisecond); w != 25*time.Millisecond {
		t.Errorf("constant-time pad = %v, want 25ms", w)
	}
	if w := p2.PostBind("10.0.1.3", "x", "h", false, "invalid_password", 50*time.Millisecond); w != 0 {
		t.Errorf("slow failure padded: %v", w)
	}
	// Delay doubles and caps at delay.max.
	_, p3, _, _ := newTest(t, func(c *config.Ratelimit) {
		c.ConstantTimeBindFail = false
		c.IP.MaxFailures = 1000
		c.Account.MaxFailures = 1000
	})
	var last time.Duration
	for i := 0; i < 10; i++ {
		last = p3.PostBind("10.0.1.4", "x", "h", false, "invalid_password", 0)
	}
	if last != 4*time.Second {
		t.Errorf("capped delay = %v", last)
	}
	// Disabled policy allows everything and records nothing.
	l4, p4, _, _ := newTest(t, func(c *config.Ratelimit) { c.Enabled = false })
	for i := 0; i < 10; i++ {
		if w := p4.PostBind("10.0.1.5", "x", "h", false, "invalid_password", 0); w != 0 {
			t.Fatal("disabled policy delayed")
		}
	}
	if v := p4.PreBind("10.0.1.5", "x", "h"); !v.Allowed {
		t.Error("disabled policy blocked")
	}
	if v := p4.PreSearch("10.0.1.5", "x"); !v.Allowed {
		t.Error("disabled policy blocked search")
	}
	if len(l4.Locks()) != 0 || p4.LockResponse() != ldap.LDAPResultInvalidCredentials {
		t.Error("disabled policy state")
	}
	if _, err := l4.Policy("p", config.Ratelimit{AllowCIDRs: []string{"bad"}}); err == nil {
		t.Error("bad cidr accepted")
	}
	if _, err := l4.Policy("p", config.Ratelimit{Lockdown: config.Lockdown{AllowCIDRs: []string{"also/bad"}}}); err == nil {
		t.Error("bad lockdown cidr accepted")
	}
	if p4.Limiter() != l4 || p4.Config().Enabled || p4.Exempt("") {
		t.Error("accessors")
	}
}

func TestLimiter_Bounds(t *testing.T) {
	cl := &clock{t: time.Now()}
	ev := &sink{}
	l := New(Options{Events: ev, Logger: slog.New(slog.DiscardHandler), Now: cl.now, MaxEntries: 2})
	p, _ := l.Policy("p", config.Default().Ratelimit)
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		l.LockIP(ip, cl.now().Add(time.Hour), SourceIDs)
		p.PostBind(ip, "acct-"+ip, "h", false, "invalid_password", 0)
		p.PreBind(ip, "acct-"+ip, "h2")
	}
	if len(l.Locks()) != 2 {
		t.Errorf("lock table not bounded: %d", len(l.Locks()))
	}
	l.mu.Lock()
	n := len(l.ipFails) + len(l.acctFails) + len(l.negative) + len(l.buckets)
	l.mu.Unlock()
	if n > 8 {
		t.Errorf("tables not bounded: %d", n)
	}
	l.SetAttack("9.9.9.9", true)
	l.SetAttack("8.8.8.8", true)
	l.SetAttack("7.7.7.7", true)
	if l.Attacking("7.7.7.7") {
		t.Error("attack set not bounded")
	}
	// Default salt is random, hashing still works.
	l2 := New(Options{})
	if l2.HashPassword([]byte("a")) == l2.HashPassword([]byte("b")) {
		t.Error("hash")
	}
	// Sweep drops idle buckets and stale windows.
	cl.add(2 * time.Hour)
	l.Sweep(cl.now(), time.Hour)
	l.mu.Lock()
	n = len(l.ipFails) + len(l.acctFails) + len(l.negative) + len(l.buckets) + len(l.ipLocks)
	l.mu.Unlock()
	if n != 0 {
		t.Errorf("sweep left %d entries", n)
	}
	ev.check(t)
}

func TestWindowBucketLatency(t *testing.T) {
	var w window
	base := time.Now()
	for i := 0; i < 5; i++ {
		w.add(base.Add(time.Duration(i)*time.Second), 3*time.Second)
	}
	if len(w.ts) != 3 {
		t.Errorf("window = %d", len(w.ts))
	}
	var b bucket
	if !b.take(base, 10, 1) || b.take(base, 10, 1) || !b.take(base.Add(100*time.Millisecond), 10, 1) {
		t.Error("bucket")
	}
	var lat latencies
	if lat.p95() != 0 {
		t.Error("empty p95")
	}
	for i := 0; i < 300; i++ {
		lat.add(time.Duration(i) * time.Millisecond)
	}
	if p := lat.p95(); p < 280*time.Millisecond || p > 299*time.Millisecond {
		t.Errorf("p95 = %v", p)
	}
}

func TestLimiter_LockWithReason(t *testing.T) {
	l, _, ev, cl := newTest(t, nil)
	until := cl.now().Add(time.Hour)
	if !l.Lock(TargetIP, "10.0.0.7", until, SourceAPI, "ticket 42") || !l.Lock(TargetAccount, " JDoe ", until, SourceAPI, "") {
		t.Fatal("lock refused")
	}
	if l.Lock("host", "x", until, SourceAPI, "") {
		t.Error("unknown target accepted")
	}
	locks := l.Locks()
	if len(locks) != 2 || locks[1].Key != "10.0.0.7" || locks[1].Reason != "ticket 42" || locks[0].Key != "jdoe" || locks[0].Source != SourceAPI {
		t.Fatalf("locks = %+v", locks)
	}
	if ev.count(events.Lock, func(e events.Event) bool { return e.Data["reason"] == "ticket 42" && e.ClientIP == "10.0.0.7" }) != 1 {
		t.Error("lock event without reason")
	}
	ev.check(t)
}

// TestPolicy_AllowCIDRsKeepAccountLimits: allow_cidrs (an application server
// that binds for its users) lifts only the limits keyed by the address;
// brute force on one account through it still locks that account.
func TestPolicy_AllowCIDRsKeepAccountLimits(t *testing.T) {
	const app = "10.89.0.10"
	l, p, ev, _ := newTest(t, func(c *config.Ratelimit) {
		c.AllowCIDRs = []string{"10.89.0.10/32"}
		c.Account.MaxFailures = 3
		c.IP.MaxFailures = 5
		c.IP.BindRPS, c.IP.BindBurst = 1, 1
		c.Tarpit.Enabled = true
	})
	l.SetAttack(app, true)
	for i := 0; i < 3; i++ {
		if v := p.PreBind(app, "victim", "h"+strconv.Itoa(i)); !v.Allowed || v.Wait != 0 {
			t.Fatalf("attempt %d before the lock: %+v", i, v)
		}
		if w := p.PostBind(app, "victim", "h"+strconv.Itoa(i), false, "invalid_password", 0); w != 0 {
			t.Fatalf("progressive delay on an exempt source: %v", w)
		}
	}
	if v := p.PreBind(app, "victim", "h-next"); v.Allowed || v.Reason != ReasonAccountLocked {
		t.Fatalf("locked account through allow_cidrs: %+v", v)
	}
	if v := p.PreBind(app, "victim", "h0"); v.Allowed {
		t.Fatalf("allow_cidrs bypassed the account lock / negative cache: %+v", v)
	}
	if ev.count(events.Lock, func(e events.Event) bool { return e.Data["target"] == "account" && e.Account == "victim" }) != 1 {
		t.Error("account lock event")
	}
	// Other accounts keep working; the address is never locked, rate
	// limited or tarpitted although ip.max_failures and bind_rps are exceeded.
	for i := 0; i < 10; i++ {
		acct := "user" + strconv.Itoa(i)
		if v := p.PreBind(app, acct, "x"+strconv.Itoa(i)); !v.Allowed || v.Wait != 0 || v.Done != nil {
			t.Fatalf("%s: %+v", acct, v)
		}
		p.PostBind(app, acct, "x"+strconv.Itoa(i), i%2 == 0, "invalid_password", 0)
	}
	if _, locked := l.IPLocked(app, time.Now()); locked {
		t.Error("exempt address locked")
	}
	if v := p.PreSearch(app, "user1"); !v.Allowed {
		t.Errorf("search from the exempt address: %+v", v)
	}
	// A manual IP lock does not cut the exempt source either.
	l.LockIP(app, time.Now().Add(time.Hour), SourceAPI)
	if v := p.PreBind(app, "user3", "y"); !v.Allowed {
		t.Errorf("manual ip lock applied to allow_cidrs: %+v", v)
	}
	// Lockdown still applies (it has its own allowlist).
	l.SetLockdown(true, SourceAPI)
	if v := p.PreBind(app, "user3", "y"); v.Allowed || v.Reason != ReasonLockdown {
		t.Errorf("lockdown skipped for allow_cidrs: %+v", v)
	}
	ev.check(t)
}
