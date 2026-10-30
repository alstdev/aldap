package ratelimit

// Audit 14, area A.5 (rate limit and IDS). These tests are adversarial: a
// failing test here is a finding, not a bug in the test.

import (
	"fmt"
	"testing"
	"time"

	"github.com/alstdev/aldap/internal/config"
)

// Check 1: N binds that pass PreBind before any PostBind is recorded. The
// limiter keeps no in-flight count, so every parallel attempt is admitted
// to the upstream. Attacker: 20 connections, one failed bind each, same
// instant -> 20 AD bad-password counts although account.max_failures = 3.
func TestAudit14_A5_ParallelPreBindRace_Account(t *testing.T) {
	l, p, _, _ := newTest(t, nil)
	const n = 20
	allowed := 0
	hashes := make([]string, n)
	for i := 0; i < n; i++ {
		hashes[i] = l.HashPassword([]byte(fmt.Sprintf("guess-%d", i)))
		if p.PreBind("10.0.0.1", "alice", hashes[i]).Allowed {
			allowed++
		}
	}
	for i := 0; i < n; i++ { // the upstream answers, the failures are recorded afterwards
		p.PostBind("10.0.0.1", "alice", hashes[i], false, "invalid_password", time.Millisecond)
	}
	if allowed > p.cfg.Account.MaxFailures {
		t.Errorf("FINDING: %d parallel binds for one account admitted to the upstream, account.max_failures = %d", allowed, p.cfg.Account.MaxFailures)
	}
}

// Check 1 for the IP window: 40 parallel attempts from one address against
// distinct accounts; ip.max_failures = 20, ip.bind_burst = 20. The token
// bucket (taken atomically in PreBind) is the only thing that holds.
func TestAudit14_A5_ParallelPreBindRace_IP(t *testing.T) {
	l, p, _, _ := newTest(t, nil)
	const n = 40
	allowed := 0
	for i := 0; i < n; i++ {
		if p.PreBind("10.0.0.2", fmt.Sprintf("user%d", i), l.HashPassword([]byte("x"))).Allowed {
			allowed++
		}
	}
	if allowed > p.cfg.IP.BindBurst {
		t.Errorf("token bucket did not hold: %d admitted, burst %d", allowed, p.cfg.IP.BindBurst)
	}
	if allowed > p.cfg.IP.MaxFailures {
		t.Errorf("FINDING: %d parallel binds from one IP admitted, ip.max_failures = %d", allowed, p.cfg.IP.MaxFailures)
	}
}

// Check 1 for the negative cache: the same (account, password) presented
// twice in parallel goes upstream twice.
func TestAudit14_A5_ParallelPreBindRace_NegativeCache(t *testing.T) {
	l, p, _, _ := newTest(t, nil)
	h := l.HashPassword([]byte("same"))
	a := p.PreBind("10.0.0.3", "bob", h).Allowed
	b := p.PreBind("10.0.0.3", "bob", h).Allowed
	p.PostBind("10.0.0.3", "bob", h, false, "invalid_password", time.Millisecond)
	p.PostBind("10.0.0.3", "bob", h, false, "invalid_password", time.Millisecond)
	if a && b {
		t.Error("FINDING: identical (account, password) admitted twice while in flight; the negative cache only works sequentially")
	}
}

// Check 9 (bounded tables): every table "fails open" when full. With
// MaxEntries = 5 an attacker who fails five junk accounts first makes the
// victim's account unlockable; the same for IP windows and token buckets.
// In production MaxEntries is fixed at 100000 (daemon.go passes none).
func TestAudit14_A5_TableFullFailOpen_Account(t *testing.T) {
	cl := &clock{t: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)}
	l := New(Options{Events: &sink{}, Now: cl.now, Salt: []byte("s"), MaxEntries: 5})
	cfg := config.Default().Ratelimit
	cfg.AllowCIDRs = []string{"10.0.0.0/8"} // the attacker comes through the application server
	p, err := l.Policy("p", cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.Sleep = func(time.Duration) {}
	for i := 0; i < 5; i++ {
		junk := fmt.Sprintf("junk%d", i)
		h := l.HashPassword([]byte("x"))
		p.PreBind("10.0.0.9", junk, h)
		p.PostBind("10.0.0.9", junk, h, false, "unknown_account", time.Millisecond)
	}
	upstream := 0
	for i := 0; i < 10; i++ {
		h := l.HashPassword([]byte(fmt.Sprintf("guess-%d", i)))
		if p.PreBind("10.0.0.9", "victim", h).Allowed {
			upstream++
			p.PostBind("10.0.0.9", "victim", h, false, "invalid_password", time.Millisecond)
		}
	}
	if _, locked := l.AccountLocked("victim", cl.now()); !locked || upstream > cfg.Account.MaxFailures {
		t.Errorf("FINDING: account table full -> victim never locked (locked=%v), %d guesses reached the upstream (max_failures %d)", locked, upstream, cfg.Account.MaxFailures)
	}
}

func TestAudit14_A5_TableFullFailOpen_IP(t *testing.T) {
	cl := &clock{t: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)}
	l := New(Options{Events: &sink{}, Now: cl.now, Salt: []byte("s"), MaxEntries: 5})
	cfg := config.Default().Ratelimit
	cfg.IP.MaxFailures, cfg.IP.BindRPS, cfg.IP.BindBurst = 3, 20, 20 // the bucket must not be what stops the attack here
	p, err := l.Policy("p", cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.Sleep = func(time.Duration) {}
	// Five addresses of the attacker's /64 fill ipFails and the bucket table.
	for i := 0; i < 5; i++ {
		ip := fmt.Sprintf("2001:db8::%d", i)
		h := l.HashPassword([]byte("x"))
		p.PreBind(ip, "u", h)
		p.PostBind(ip, "u", h, false, "unknown_account", time.Millisecond)
	}
	allowed := 0
	for i := 0; i < 20; i++ {
		h := l.HashPassword([]byte(fmt.Sprintf("g%d", i)))
		if p.PreBind("2001:db8::ffff", fmt.Sprintf("acct%d", i), h).Allowed {
			allowed++
			p.PostBind("2001:db8::ffff", fmt.Sprintf("acct%d", i), h, false, "unknown_account", time.Millisecond)
		}
	}
	_, locked := l.IPLocked("2001:db8::ffff", cl.now())
	if !locked || allowed > cfg.IP.MaxFailures {
		t.Errorf("FINDING: IP tables full -> new address never locked (locked=%v) and never rate limited (%d of 20 admitted, burst %d, max_failures %d)", locked, allowed, cfg.IP.BindBurst, cfg.IP.MaxFailures)
	}
}

// Check 8/7: failures that are not credential failures count towards the
// account lock. During an upstream outage every retry of an application
// (reason upstream_error) locks the user for lock_duration after the
// directory is back; an unauthenticated bind (name, empty password; reason
// anonymous) locks any account without a single attempt reaching AD.
func TestAudit14_A5_NonCredentialFailuresLockAccount(t *testing.T) {
	for _, reason := range []string{"upstream_error", "anonymous"} {
		t.Run(reason, func(t *testing.T) {
			l, p, _, cl := newTest(t, nil)
			h := l.HashPassword([]byte("pw"))
			for i := 0; i < 3; i++ {
				p.PreBind("10.0.0.4", "carol", h)
				p.PostBind("10.0.0.4", "carol", h, false, reason, time.Millisecond)
			}
			if _, locked := l.AccountLocked("carol", cl.now()); locked {
				t.Errorf("FINDING: three failures with reason %q locked the account", reason)
			}
		})
	}
}

// Check 7 arithmetic with the defaults: account.max_failures = 3,
// account.lock_duration = 15m; the lock consumes the failure window. AD's
// lockoutObservationWindow (30m default, Samba 30m) resets badPwdCount only
// after 30 quiet minutes, so 3 attempts every 15 minutes accumulate: 6 by
// t=15m (>= Samba bench threshold 5), 9 by t=30m, 12 by t=45m (>= 10).
func TestAudit14_A5_ADLockoutNotPrevented(t *testing.T) {
	l, p, _, cl := newTest(t, nil)
	reached := 0
	attempt := func(i int) {
		h := l.HashPassword([]byte(fmt.Sprintf("guess-%d", i)))
		if p.PreBind("10.0.0.5", "dave", h).Allowed {
			reached++
			p.PostBind("10.0.0.5", "dave", h, false, "invalid_password", time.Millisecond)
		}
	}
	i := 0
	for cycle := 0; cycle < 3; cycle++ { // t = 0, 15m, 30m
		for k := 0; k < 10; k++ {
			attempt(i)
			i++
		}
		cl.add(p.cfg.Account.LockDuration.D())
	}
	// Within one AD observation window (30m, never quiet for 30m) the
	// directory saw `reached` bad passwords for one account.
	const samba, typical = 5, 10
	if reached >= samba {
		t.Errorf("FINDING: %d AD bad-password attempts for one account within 30 min of continuous attack (lockout threshold %d / %d)", reached, samba, typical)
	}
}

// Check 6 (regression of Stage 12b): allow_cidrs lifts only IP-keyed
// limits. Expected to pass.
func TestAudit14_A5_AllowCIDRsKeepAccountLocks(t *testing.T) {
	l, p, _, cl := newTest(t, func(c *config.Ratelimit) { c.AllowCIDRs = []string{"10.0.0.0/8"} })
	for i := 0; i < 3; i++ {
		h := l.HashPassword([]byte(fmt.Sprintf("g%d", i)))
		if !p.PreBind("10.0.0.20", "erin", h).Allowed {
			t.Fatalf("attempt %d refused", i)
		}
		p.PostBind("10.0.0.20", "erin", h, false, "invalid_password", time.Millisecond)
	}
	if v := p.PreBind("10.0.0.20", "erin", l.HashPassword([]byte("right"))); v.Allowed || v.Reason != ReasonAccountLocked {
		t.Errorf("locked account through allow_cidrs admitted: %+v", v)
	}
	if v := p.PreBind("10.0.0.20", "frank", l.HashPassword([]byte("right"))); !v.Allowed {
		t.Errorf("other account from the allowed address refused: %+v", v)
	}
	p.PostBind("10.0.0.20", "frank", l.HashPassword([]byte("right")), true, "", time.Millisecond)
	// Honeytoken and manual IP locks on the allowed address do not block it;
	// an attack mark (tarpit) does not either.
	l.LockIP("10.0.0.20", cl.now().Add(24*time.Hour), SourceHoneytoken)
	l.SetAttack("10.0.0.20", true)
	if v := p.PreBind("10.0.0.20", "frank", l.HashPassword([]byte("right"))); !v.Allowed || v.Wait != 0 {
		t.Errorf("allowed address blocked by IP lock/tarpit: %+v", v)
	}
	p.PostBind("10.0.0.20", "frank", l.HashPassword([]byte("right")), true, "", time.Millisecond)
	if v := p.PreSearch("10.0.0.20", "frank"); !v.Allowed || v.Wait != 0 {
		t.Errorf("allowed address search blocked: %+v", v)
	}
	if ip, _ := p.Failures("10.0.0.20", ""); ip != 0 {
		t.Errorf("IP failures counted for allowed address: %d", ip)
	}
	// Negative cache and lockdown still apply.
	h := l.HashPassword([]byte("bad"))
	p.PreBind("10.0.0.20", "gina", h)
	p.PostBind("10.0.0.20", "gina", h, false, "invalid_password", time.Millisecond)
	if v := p.PreBind("10.0.0.20", "gina", h); v.Allowed || v.Reason != ReasonNegativeCache {
		t.Errorf("negative cache skipped for allowed address: %+v", v)
	}
}

// Check 8: lockdown.allow_cidrs is a separate list; a deployment that lists
// the application server only in ratelimit.allow_cidrs (deploy/virola-stack)
// loses every user in a lockdown, which an attacker triggers with 15 binds
// when lockdown.auto is on.
func TestAudit14_A5_LockdownIgnoresRatelimitAllowCIDRs(t *testing.T) {
	l, p, _, _ := newTest(t, func(c *config.Ratelimit) { c.AllowCIDRs = []string{"10.89.10.20/32"} })
	l.SetLockdown(true, SourceIDs)
	if v := p.PreBind("10.89.10.20", "alice", l.HashPassword([]byte("right"))); !v.Allowed {
		t.Errorf("FINDING: application server in ratelimit.allow_cidrs refused during lockdown: %+v", v)
	}
}

// Check 5: the limiter keys on the string it is given; the listener
// normalizes (TCPAddr.IP.String() prints ::ffff:a.b.c.d as a.b.c.d, drops
// the zone) and the API unmaps. CIDR matching accepts both spellings for
// IPv4 CIDRs. Expected to pass; documents the contract.
func TestAudit14_A5_MappedIPv6Keys(t *testing.T) {
	l, p, _, cl := newTest(t, func(c *config.Ratelimit) { c.AllowCIDRs = []string{"10.0.0.0/8"} })
	if !p.Exempt("::ffff:10.0.0.5") || !p.Exempt("10.0.0.5") {
		t.Error("IPv4 CIDR does not match the mapped form")
	}
	if p.Exempt("fe80::1%eth0") {
		t.Error("zoned address exempt")
	}
	l.LockIP("10.0.0.6", cl.now().Add(time.Hour), SourceAPI)
	if _, locked := l.IPLocked("::ffff:10.0.0.6", cl.now()); locked {
		t.Log("limiter normalizes keys itself")
	} else {
		t.Log("INFO: limiter keys are raw strings; ::ffff:10.0.0.6 and 10.0.0.6 are different lock keys (callers must normalize; listener and API do)")
	}
}
