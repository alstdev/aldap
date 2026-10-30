//go:build integration

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/events/schematest"
	"github.com/alstdev/aldap/internal/ratelimit"
)

// stage6Config tightens the limits so the scenarios of TESTING.md 24–33
// run in seconds.
const stage6Config = `
[ratelimit]
negative_cache_ttl = "30s"
constant_time_bind_fail = false
allow_accounts = ["svc-monitor"]
[ratelimit.ip]
max_failures = 8
window = "5m"
lock_duration = "1s"
[ratelimit.account]
max_failures = 3
window = "5m"
lock_duration = "1500ms"
[ratelimit.delay]
base = "1ms"
max = "4ms"
[ratelimit.tarpit]
enabled = true
delay = "300ms"
max_conns = 1
[ratelimit.lockdown]
allow_cidrs = ["127.0.0.2/32"]
allow_accounts = ["svc-monitor"]

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

// eventsOf parses the JSON event lines of the daemon output.
func eventsOf(r *running) []events.Record {
	var out []events.Record
	for _, line := range strings.Split(r.logs.String(), "\n") {
		if !strings.HasPrefix(line, `{"schema":"aldap.event.v1"`) {
			continue
		}
		var rec events.Record
		if err := json.Unmarshal([]byte(line), &rec); err == nil {
			out = append(out, rec)
		}
	}
	return out
}

func findEvents(r *running, kind string, match func(events.Record) bool) []events.Record {
	var out []events.Record
	for _, e := range eventsOf(r) {
		if e.Event == kind && (match == nil || match(e)) {
			out = append(out, e)
		}
	}
	return out
}

func waitEvents(t *testing.T, r *running, what string, kind string, match func(events.Record) bool) events.Record {
	t.Helper()
	var got []events.Record
	waitFor(t, func() bool { got = findEvents(r, kind, match); return len(got) > 0 })
	if len(got) == 0 {
		t.Fatalf("no %s event (%s)", kind, what)
	}
	return got[0]
}

func bindFrom(t *testing.T, r *running, local string) *ldap.Conn {
	t.Helper()
	d := &net.Dialer{Timeout: 5 * time.Second}
	if local != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(local)}
	}
	c, err := ldap.DialURL("ldaps://"+r.ldapsAddr, ldap.DialWithDialer(d), ldap.DialWithTLSConfig(r.tlsConfig(t)))
	if err != nil {
		t.Fatalf("dial from %s: %v", local, err)
	}
	c.SetTimeout(5 * time.Second)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TESTING.md 24, 25: account lock after 3 failures, the 4th attempt with
// the right password never reaches the upstream, the negative cache stops
// a repeated (account, password) pair, success after lock_duration.
func TestStage6_AccountLockAndNegativeCache(t *testing.T) {
	r := startDaemon(t, stage6Config)
	c := r.ldaps(t)
	before := r.dc.Calls().UserBinds()
	if err := c.Bind("bob.brown@test.aldap", "wrong-1"); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Fatalf("first failure: %v", err)
	}
	if err := c.Bind("bob.brown@test.aldap", "wrong-1"); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Fatalf("cached failure: %v", err)
	}
	if n := r.dc.Calls().UserBinds() - before; n != 1 {
		t.Errorf("negative cache: upstream binds = %d, want 1", n)
	}
	waitEvents(t, r, "negative cache", events.BindBlocked, func(e events.Record) bool { return e.Reason == ratelimit.ReasonNegativeCache })
	_ = c.Bind("BOB.BROWN", "wrong-2")
	_ = c.Bind(`TEST\bob.brown`, "wrong-3")
	lock := waitEvents(t, r, "account lock", events.Lock, func(e events.Record) bool { return e.Data["target"] == "account" && e.Data["key"] == "bob.brown" })
	if lock.Data["source"] != "ratelimit" || lock.Data["failures"] != float64(3) {
		t.Errorf("lock event %+v", lock)
	}
	before = r.dc.Calls().UserBinds()
	if err := c.Bind("bob.brown@test.aldap", "bob.brown-pass"); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Fatalf("locked account with the right password: %v", err)
	}
	if r.dc.Calls().UserBinds() != before {
		t.Error("locked account reached the upstream")
	}
	waitEvents(t, r, "account_locked", events.BindBlocked, func(e events.Record) bool { return e.Reason == ratelimit.ReasonAccountLocked })
	// After lock_duration the account works again (polled, no fixed sleep).
	var lastErr error
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if lastErr = c.Bind("bob.brown@test.aldap", "bob.brown-pass"); lastErr == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("account still refused after lock_duration: %v\nevents: %+v", lastErr, findEvents(r, events.BindBlocked, nil))
	}
	waitEvents(t, r, "unlock expiry", events.Unlock, func(e events.Record) bool { return e.Data["key"] == "bob.brown" && e.Data["source"] == "expiry" })
	// Allowlisted accounts never lock (TESTING.md 26).
	for i := 0; i < 5; i++ {
		_ = c.Bind("svc-monitor", fmt.Sprintf("nope-%d", i))
	}
	if n := len(findEvents(r, events.Lock, func(e events.Record) bool { return e.Data["key"] == "svc-monitor" })); n != 0 {
		t.Error("allow_accounts locked")
	}
}

// TESTING.md 26 and 32: IP lock after ip.max_failures, lockdown refuses
// everything but the allowed network and accounts without upstream calls.
func TestStage6_IPLockAndLockdown(t *testing.T) {
	r := startDaemon(t, stage6Config)
	c := r.ldaps(t)
	for i := 0; i < 8; i++ {
		_ = c.Bind(fmt.Sprintf("user%d", i), fmt.Sprintf("pw-%d", i))
	}
	waitEvents(t, r, "ip lock", events.Lock, func(e events.Record) bool {
		return e.Data["target"] == "ip" && e.Data["key"] == "127.0.0.1" && e.Data["source"] == "ratelimit"
	})
	if err := c.Bind(tClientDN, clientPassword); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Errorf("bind from locked ip: %v", err)
	}
	if _, err := c.Search(ldap.NewSearchRequest(tUsersDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, "(uid=alice*)", []string{"uid"}, nil)); !ldap.IsErrorWithCode(err, ldap.LDAPResultUnwillingToPerform) {
		t.Errorf("search from locked ip: %v", err)
	}
	waitEvents(t, r, "search refused", events.RateLimited, func(e events.Record) bool { return e.Reason == ratelimit.ReasonIPLocked && e.Data["op"] == "search" })
	waitFor(t, func() bool { return c.Bind(tClientDN, clientPassword) == nil })
	// Lockdown (manual until the API of Stage 7): 127.0.0.1 is outside allow_cidrs.
	r.d.state.limiter.SetLockdown(true, ratelimit.SourceAPI)
	before := r.dc.Calls().UserBinds()
	if err := c.Bind("alice.adams@test.aldap", "alice.adams-pass"); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Errorf("lockdown bind: %v", err)
	}
	if r.dc.Calls().UserBinds() != before {
		t.Error("lockdown bind reached the upstream")
	}
	waitEvents(t, r, "lockdown", events.BindBlocked, func(e events.Record) bool { return e.Reason == ratelimit.ReasonLockdown })
	if _, err := c.Search(ldap.NewSearchRequest(tUsersDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, "(uid=alice*)", []string{"uid"}, nil)); !ldap.IsErrorWithCode(err, ldap.LDAPResultUnwillingToPerform) {
		t.Errorf("lockdown search: %v", err)
	}
	if err := c.Bind("svc-monitor", "x"); ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) && r.dc.Calls().UserBinds() == before {
		t.Error("lockdown allow_accounts did not reach the upstream")
	}
	c2 := bindFrom(t, r, "127.0.0.2")
	if err := c2.Bind("alice.adams@test.aldap", "alice.adams-pass"); err != nil {
		t.Errorf("lockdown allow_cidrs: %v", err)
	}
	r.d.state.limiter.SetLockdown(false, ratelimit.SourceAPI)
	if err := c.Bind("alice.adams@test.aldap", "alice.adams-pass"); err != nil {
		t.Errorf("after lockdown: %v", err)
	}
	if n := len(findEvents(r, events.Lockdown, nil)); n < 2 {
		t.Errorf("lockdown events = %d", n)
	}
}

// TESTING.md 27, 28: one password over 6 accounts is a spray with a summary
// and an end after quiet_period; 12 accounts without success are an
// enumeration.
func TestStage6_SprayAndEnumeration(t *testing.T) {
	r := startDaemon(t, stage6Config)
	c := r.ldaps(t)
	for i := 0; i < 6; i++ {
		_ = c.Bind(fmt.Sprintf("spray%d", i), "Spring2026!")
	}
	start := waitEvents(t, r, "spray", events.AttackStart, func(e events.Record) bool { return e.Data["kind"] == "spray" })
	if start.Data["accounts_count"].(float64) < 5 || start.Level == "" {
		t.Errorf("attack_start %+v", start)
	}
	waitEvents(t, r, "summary", events.AttackSummary, func(e events.Record) bool { return e.Data["attack_id"] == start.Data["attack_id"] })
	waitEvents(t, r, "end", events.AttackEnd, func(e events.Record) bool { return e.Data["attack_id"] == start.Data["attack_id"] })
	// Enumeration from a second source address (the first one is locked by now).
	c2 := bindFrom(t, r, "127.0.0.3")
	for i := 0; i < 12; i++ {
		_ = c2.Bind(fmt.Sprintf("enum%d", i), fmt.Sprintf("pw-%d", i))
	}
	waitEvents(t, r, "enumeration", events.AttackStart, func(e events.Record) bool { return e.Data["kind"] == "enumeration" })
}

// TESTING.md 29, 30, 31: recon signature, honeytoken bind and search with a
// 24 h source lock, baseline anomalies after learning.
func TestStage6_ReconHoneytokenAnomaly(t *testing.T) {
	r := startDaemonVirola(t, stage6Config, `honeytokens = ["h.petrenko@test.aldap"]`)
	c := r.ldaps(t)
	if err := c.Bind(tClientDN, clientPassword); err != nil {
		t.Fatal(err)
	}
	_, _ = c.Search(ldap.NewSearchRequest("ou=virola,dc=aldap", ldap.ScopeWholeSubtree, 0, 0, 0, false, "(objectClass=*)", []string{"nTSecurityDescriptor"}, nil))
	rec := waitEvents(t, r, "sd_dump", events.Recon, func(e events.Record) bool { return e.Data["signature"] == "sd_dump" })
	if rec.Data["base"] != "ou=virola,dc=aldap" || rec.ClientIP != "127.0.0.1" {
		t.Errorf("recon %+v", rec)
	}
	waitEvents(t, r, "root_dump", events.Recon, func(e events.Record) bool { return e.Data["signature"] == "root_dump" })
	// Baseline: learn_for is 1 s; after it a new filter shape and a new IP are anomalies.
	waitFor(t, func() bool { return !r.d.state.ids.Learning() })
	_, _ = c.Search(ldap.NewSearchRequest(tUsersDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, "(&(mail=*)(displayName=A*))", []string{"mail"}, nil))
	waitEvents(t, r, "new_filter", events.Anomaly, func(e events.Record) bool { return e.Reason == "new_filter" })
	c4 := bindFrom(t, r, "127.0.0.4")
	_ = c4.Bind("alice.adams@test.aldap", "alice.adams-pass")
	waitEvents(t, r, "new_ip", events.Anomaly, func(e events.Record) bool { return e.Reason == "new_ip" && e.Data["observed"] == "127.0.0.4" })
	// Honeytoken search locks the source for 24 h; the bind from another source too.
	_, _ = c.Search(ldap.NewSearchRequest(tUsersDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, "(mail=h.petrenko@test.aldap)", []string{"mail"}, nil))
	ht := waitEvents(t, r, "honeytoken search", events.Honeytoken, func(e events.Record) bool { return e.Data["op"] == "search" })
	if ht.Level != events.LevelHigh {
		t.Errorf("honeytoken level %s", ht.Level)
	}
	lock := waitEvents(t, r, "honeytoken lock", events.Lock, func(e events.Record) bool { return e.Data["source"] == "honeytoken" && e.Data["key"] == "127.0.0.1" })
	until, err := time.Parse(time.RFC3339Nano, lock.Data["until"].(string))
	if err != nil || until.Before(time.Now().Add(23*time.Hour)) {
		t.Errorf("honeytoken lock until %v (%v)", lock.Data["until"], err)
	}
	before := r.dc.Calls().UserBinds()
	c5 := bindFrom(t, r, "127.0.0.5")
	if err := c5.Bind("h.petrenko@test.aldap", "guess"); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Errorf("honeytoken bind: %v", err)
	}
	if r.dc.Calls().UserBinds() != before {
		t.Error("honeytoken bind reached the upstream")
	}
	waitEvents(t, r, "honeytoken bind", events.Honeytoken, func(e events.Record) bool { return e.Data["op"] == "bind" && e.ClientIP == "127.0.0.5" })
	waitEvents(t, r, "honeytoken bind lock", events.Lock, func(e events.Record) bool { return e.Data["source"] == "honeytoken" && e.Data["key"] == "127.0.0.5" })
	// Indicators rank the honeytoken source first.
	scored := false
	for _, in := range r.d.state.ids.Indicators(100) {
		if in.Type == "ip" && in.Key == "127.0.0.1" && in.Hits["honeytoken"] > 0 && in.Hits["recon"] > 0 {
			scored = true
		}
	}
	if !scored {
		t.Errorf("indicators %+v", r.d.state.ids.Indicators(0))
	}
}

// TESTING.md 33: a source in attack state is tarpitted (answer not before
// tarpit.delay) and at most max_conns connections are held.
func TestStage6_Tarpit(t *testing.T) {
	r := startDaemon(t, stage6Config)
	r.d.state.limiter.SetAttack("127.0.0.1", true)
	c := r.ldaps(t)
	startT := time.Now()
	if err := c.Bind(tClientDN, clientPassword); err != nil {
		t.Fatalf("tarpitted bind: %v", err)
	}
	if d := time.Since(startT); d < 300*time.Millisecond {
		t.Errorf("tarpitted bind answered after %v, want >= 300ms", d)
	}
	waitEvents(t, r, "tarpit", events.Tarpit, func(e events.Record) bool { return e.Data["ip"] == "127.0.0.1" })
	// Two concurrent searches: one is held, the other refused (max_conns = 1).
	c2 := r.ldaps(t)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, conn := range []*ldap.Conn{c, c2} {
		wg.Add(1)
		go func(conn *ldap.Conn) {
			defer wg.Done()
			_, err := conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, 0, 0, 0, false, "(objectClass=*)", []string{"namingContexts"}, nil))
			results <- err
		}(conn)
	}
	wg.Wait()
	close(results)
	refused := 0
	for err := range results {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultUnwillingToPerform) {
			refused++
		}
	}
	if refused != 1 {
		t.Errorf("refused = %d, want exactly 1 of 2 concurrent requests beyond max_conns", refused)
	}
	r.d.state.limiter.SetAttack("127.0.0.1", false)
}

// TESTING.md 34: every event the daemon wrote is valid against the schema,
// and session summaries carry the counters and fingerprint.
func TestStage6_EventsValid(t *testing.T) {
	r := startDaemon(t, stage6Config)
	c := r.ldaps(t)
	_ = c.Bind(tClientDN, clientPassword)
	_, _ = c.Search(ldap.NewSearchRequest(tUsersDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, "(uid=alice*)", []string{"uid"}, nil))
	_ = c.Bind("nobody", "x")
	_, _ = c.Compare("cn=alice.adams,"+tUsersDN, "mail", "x")
	_ = c.Close()
	sum := waitEvents(t, r, "session_summary", events.SessionSummary, nil)
	if sum.Data["binds_ok"] != float64(1) || sum.Data["binds_fail"] != float64(1) || sum.Data["searches"] != float64(1) || sum.Data["results_total"] != float64(1) ||
		sum.Data["denied"] != float64(1) || sum.Data["bytes_in"].(float64) <= 0 || sum.Data["bytes_out"].(float64) <= 0 || !strings.HasPrefix(sum.Data["fingerprint"].(string), "tls:") {
		t.Errorf("session_summary %+v", sum.Data)
	}
	r.d.stop()
	all := eventsOf(r)
	if len(all) < 6 {
		t.Fatalf("only %d events", len(all))
	}
	schematest.Check(t, all...)
	seq := uint64(0)
	for _, e := range all {
		if e.Seq <= seq || e.Host != "aldap-test" || e.ID == "" {
			t.Errorf("envelope %+v", e)
		}
		seq = e.Seq
	}
}
