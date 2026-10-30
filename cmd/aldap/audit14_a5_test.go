//go:build integration

package main

// Audit 14, area A.5: rate limit and IDS through the full daemon (in-memory
// AD, real TLS listeners). A failing test is a finding.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/ratelimit"
)

// audit14Config: short durations, no tarpit, lockdown.auto on.
const audit14Config = `
[ratelimit]
negative_cache_ttl = "30s"
constant_time_bind_fail = false
[ratelimit.ip]
max_failures = 8
window = "5m"
lock_duration = "20s"
[ratelimit.account]
max_failures = 3
window = "5m"
lock_duration = "20s"
[ratelimit.delay]
base = "1ms"
max = "4ms"
[ratelimit.lockdown]
auto = true

[ids]
summary_interval = "500ms"
quiet_period = "1500ms"
[ids.spray]
min_accounts = 5
[ids.enumeration]
min_accounts = 10
[ids.anomaly]
learn_for = "1s"
`

// Check 1: 12 connections from one address bind the same account with
// different wrong passwords at the same instant while the upstream takes
// 400 ms to answer. The account lock is recorded only after the upstream
// answers, so every attempt reaches AD: 12 bad-password counts against
// account.max_failures = 3 (AD lockout threshold 5 reached in one shot).
func TestAudit14_A5_ParallelBindsReachUpstream(t *testing.T) {
	r := startDaemon(t, audit14Config)
	tlsCfg := r.tlsConfig(t)
	const n = 12 // below max_conns_per_ip = 16 of the profile
	conns := make([]*ldap.Conn, 0, n)
	for i := 0; i < n; i++ {
		c, err := ldap.DialURL("ldaps://"+r.ldapsAddr, ldap.DialWithTLSConfig(tlsCfg))
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		c.SetTimeout(10 * time.Second)
		t.Cleanup(func() { _ = c.Close() })
		conns = append(conns, c)
	}
	r.dc.SetDelay(400 * time.Millisecond)
	t.Cleanup(func() { r.dc.SetDelay(0) })
	before := r.dc.Calls().UserBinds()
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, c := range conns {
		wg.Add(1)
		go func(i int, c *ldap.Conn) {
			defer wg.Done()
			<-start
			_ = c.Bind("bob.brown@test.aldap", fmt.Sprintf("parallel-%d", i))
		}(i, c)
	}
	close(start)
	wg.Wait()
	reached := r.dc.Calls().UserBinds() - before
	if reached > 3 {
		t.Errorf("FINDING: %d parallel wrong-password binds for bob.brown reached the upstream (account.max_failures = 3)", reached)
	}
	// The lock exists afterwards, but AD already counted every attempt.
	waitEvents(t, r, "account lock", events.Lock, func(e events.Record) bool { return e.Data["target"] == "account" && e.Data["key"] == "bob.brown" })
}

// Check 8: weaponized auto-lockdown. The application server (Virola) is in
// ratelimit.allow_cidrs only, as in deploy/virola-stack. An attacker from
// one other address sprays one password over 15 account names: 8 reach the
// upstream, the IP is locked, the 7 refused binds still feed the detectors,
// the spray reaches level high (accounts >= 3 x min_accounts) and
// lockdown.auto switches lockdown on. Every Virola user is now refused.
func TestAudit14_A5_AutoLockdownCutsOffAllowCIDRsApp(t *testing.T) {
	r := startDaemonVirola(t, audit14Config, virolaAllow)
	virola := bindFrom(t, r, "127.0.0.1")
	if err := virola.Bind("alice.adams@test.aldap", "alice.adams-pass"); err != nil {
		t.Fatalf("baseline bind through the application server: %v", err)
	}
	attacker := bindFrom(t, r, "127.0.0.3")
	before := r.dc.Calls().UserBinds()
	// One password, five account names; the first four are repeated so that
	// when the fifth distinct account crosses spray.min_accounts (5) the
	// detector already counts >= 3*5 failed binds -> level high -> auto
	// lockdown on the first attack_start. Binds refused after the IP lock
	// (ip.max_failures 8) still feed the detector.
	for round := 0; round < 4; round++ {
		for acc := 0; acc < 4; acc++ {
			_ = attacker.Bind(fmt.Sprintf("spray%02d@test.aldap", acc), "Winter2026!")
		}
	}
	_ = attacker.Bind("spray04@test.aldap", "Winter2026!")
	cost := r.dc.Calls().UserBinds() - before
	ld := waitEvents(t, r, "lockdown", events.Lockdown, func(e events.Record) bool { return e.Data["state"] == "on" })
	t.Logf("lockdown entered by %v after %d upstream binds from one address", ld.Data["source"], cost)
	before = r.dc.Calls().UserBinds()
	err := virola.Bind("alice.adams@test.aldap", "alice.adams-pass")
	if err != nil {
		t.Errorf("FINDING: application server (ratelimit.allow_cidrs) refused during auto lockdown: %v (upstream binds: %d)", err, r.dc.Calls().UserBinds()-before)
	}
	if n := len(findEvents(r, events.BindBlocked, func(e events.Record) bool { return e.Reason == ratelimit.ReasonLockdown && e.ClientIP == "127.0.0.1" })); n > 0 {
		t.Logf("%d bind_blocked{lockdown} for the application server address", n)
	}
}

// Check 2 (SPEC §3.6): a reload that changes [ratelimit] keeps the account
// lock, the failure window, the attack marks and the lockdown flag. Expected
// to pass.
func TestAudit14_A5_ReloadKeepsLimiterState(t *testing.T) {
	r := startDaemon(t, strings.Replace(audit14Config, "auto = true", "auto = false", 1))
	c := r.ldaps(t)
	for i := 0; i < 3; i++ {
		_ = c.Bind("bob.brown@test.aldap", fmt.Sprintf("reload-%d", i))
	}
	waitEvents(t, r, "lock", events.Lock, func(e events.Record) bool { return e.Data["target"] == "account" && e.Data["key"] == "bob.brown" })
	_ = c.Bind("mia.moore@test.aldap", "one-failure") // one failure in the window
	old := r.d.state.limiter
	old.SetAttack("203.0.113.9", true)
	b, err := os.ReadFile(r.path)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(string(b), `negative_cache_ttl = "30s"`, `negative_cache_ttl = "31s"`, 1)
	body = strings.Replace(body, `max_failures = 3`, `max_failures = 4`, 1)
	if err := os.WriteFile(r.path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	o := r.d.opts
	o.State = r.d.state
	next, err := reload(context.Background(), r.d, r.path, true, o)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	r.d = next
	t.Cleanup(next.stop)
	if next.state.limiter != old {
		t.Fatal("FINDING: reload created a new limiter")
	}
	if !old.Attacking("203.0.113.9") {
		t.Error("FINDING: attack mark lost on reload")
	}
	before := r.dc.Calls().UserBinds()
	c2 := r.ldaps(t)
	if err := c2.Bind("bob.brown@test.aldap", "bob.brown-pass"); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) || r.dc.Calls().UserBinds() != before {
		t.Errorf("FINDING: account lock lost on reload: %v (upstream %d)", err, r.dc.Calls().UserBinds()-before)
	}
	// The failure window of mia.moore survived too: 3 more failures under
	// the new max_failures = 4 lock her.
	for i := 0; i < 3; i++ {
		_ = c2.Bind("mia.moore@test.aldap", fmt.Sprintf("after-%d", i))
	}
	waitEvents(t, r, "window kept", events.Lock, func(e events.Record) bool { return e.Data["target"] == "account" && e.Data["key"] == "mia.moore" })
}

// Check 3: two profiles (ldaps "virola", starttls "plain") on one process
// share the account and IP counters; alternating ports gives no extra
// guesses. Expected to pass.
func TestAudit14_A5_ProfilesShareCounters(t *testing.T) {
	r := startDaemon(t, strings.Replace(audit14Config, "auto = true", "auto = false", 1))
	a := r.ldaps(t)
	b := r.plain(t)
	if err := b.StartTLS(r.tlsConfig(t)); err != nil {
		t.Fatalf("StartTLS on the plain profile: %v", err)
	}
	_ = a.Bind("bob.brown@test.aldap", "p1")
	_ = b.Bind("bob.brown@test.aldap", "p2")
	_ = a.Bind(`TEST\bob.brown`, "p3")
	lock := waitEvents(t, r, "shared account lock", events.Lock, func(e events.Record) bool { return e.Data["target"] == "account" && e.Data["key"] == "bob.brown" })
	if lock.Data["failures"] != float64(3) {
		t.Errorf("lock after %v failures", lock.Data["failures"])
	}
	before := r.dc.Calls().UserBinds()
	if err := b.Bind("bob.brown@test.aldap", "bob.brown-pass"); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) || r.dc.Calls().UserBinds() != before {
		t.Errorf("FINDING: locked account admitted on the other profile: %v", err)
	}
	// IP window: eight failures split over both ports lock the shared address.
	for i := 0; i < 4; i++ {
		_ = a.Bind(fmt.Sprintf("x%d@test.aldap", i), "p")
		_ = b.Bind(fmt.Sprintf("y%d@test.aldap", i), "p")
	}
	waitEvents(t, r, "shared IP lock", events.Lock, func(e events.Record) bool { return e.Data["target"] == "ip" && e.Data["key"] == "127.0.0.1" })
}

// Check 8: a honeytoken bind from the application server address locks that
// address for honeytoken.lock_duration, but allow_cidrs lifts IP locks, so
// the other users of the application keep working. Expected to pass.
func TestAudit14_A5_HoneytokenLockExemptForAllowCIDRs(t *testing.T) {
	r := startDaemonVirola(t, strings.Replace(audit14Config, "auto = true", "auto = false", 1), "honeytokens = [\"h.petrenko@test.aldap\"]\n"+virolaAllow)
	c := bindFrom(t, r, "127.0.0.1")
	_ = c.Bind("h.petrenko@test.aldap", "anything")
	waitEvents(t, r, "honeytoken lock", events.Lock, func(e events.Record) bool { return e.Data["source"] == "honeytoken" && e.Data["key"] == "127.0.0.1" })
	if err := c.Bind("alice.adams@test.aldap", "alice.adams-pass"); err != nil {
		t.Errorf("FINDING: application server locked by a honeytoken hit of one of its users: %v", err)
	}
	if res, err := c.Search(ldap.NewSearchRequest(tUsersDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, "(uid=bob.brown)", []string{"uid"}, nil)); err != nil || len(res.Entries) != 1 {
		t.Errorf("search from the application server after a honeytoken hit: %v", err)
	}
}
