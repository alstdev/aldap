package vdir

// Audit 14, area A.1 (authentication). These tests are evidence for the
// audit report; they do not change production code. Tests that currently
// FAIL document findings; tests that pass are regression guards.

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/listener"
	"github.com/alstdev/aldap/internal/profile"
	"github.com/alstdev/aldap/internal/ratelimit"
	"github.com/alstdev/aldap/internal/testdir"
	"github.com/alstdev/aldap/internal/upstream"
)

// auditUser builds an enabled AD-like user under OU=Office with the given
// identifiers and password.
func auditUser(cn, sam, upn, password string) *testdir.Entry {
	return &testdir.Entry{DN: "CN=" + cn + ",OU=Office,DC=test,DC=aldap", Attrs: []testdir.Attribute{
		{Name: "objectClass", Values: []string{"top", "person", "organizationalPerson", "user"}},
		{Name: "cn", Values: []string{cn}}, {Name: "sn", Values: []string{cn}}, {Name: "givenName", Values: []string{cn}},
		{Name: "displayName", Values: []string{cn}}, {Name: "sAMAccountName", Values: []string{sam}},
		{Name: "userPrincipalName", Values: []string{upn}},
		{Name: "objectCategory", Values: []string{"CN=Person,CN=Schema,CN=Configuration,DC=test,DC=aldap"}},
		{Name: "userAccountControl", Values: []string{"512"}}, {Name: "department", Values: []string{"IT"}},
		{Name: "objectGUID", Values: []string{"audit-guid-" + sam}},
		{Name: "userPassword", Values: []string{password}},
	}}
}

func (f *fixture) countEvents(kind, reason string) int {
	f.ev.mu.Lock()
	defer f.ev.mu.Unlock()
	n := 0
	for _, e := range f.ev.ev {
		if e.Event == kind && (reason == "" || e.Reason == reason) {
			n++
		}
	}
	return n
}

func (f *fixture) lockKeys() []string {
	f.ev.mu.Lock()
	defer f.ev.mu.Unlock()
	var out []string
	for _, e := range f.ev.ev {
		if e.Event == events.Lock && e.Data["target"] == ratelimit.TargetAccount {
			out = append(out, e.Data["key"].(string))
		}
	}
	return out
}

// Check 1: a bind with a name and an EMPTY password (RFC 4513 §5.1.2) must
// never reach the upstream (bind or lookup search) and must never bind the
// connection, in every name form and profile mode.
func TestAudit14_A1_EmptyPasswordNeverReachesUpstream(t *testing.T) {
	honeyFixture := func(p *config.Profile) { p.Honeytokens = []string{honeyAcct} }
	honeypot := func(p *config.Profile) { p.Mode = "honeypot" }
	cases := []struct {
		name string
		bind string
		mut  func(p *config.Profile)
	}{
		{"upn", "alice.adams@test.aldap", nil},
		{"domain", `TEST\alice.adams`, nil},
		{"account", "alice.adams", nil},
		{"virtual_dn", "cn=alice.adams," + usersDN, nil},
		{"client_dn", clientDN, nil},
		{"real_dn", "CN=Alice Adams,OU=Office,DC=test,DC=aldap", nil},
		{"spaces_only_name", "   ", nil},
		{"honeytoken", honeyAcct, honeyFixture},
		{"honeypot", "administrator@corp.local", honeypot},
		{"unknown", "nobody@test.aldap", nil},
	}
	for _, tc := range cases {
		for _, pw := range [][]byte{nil, {}} {
			t.Run(tc.name, func(t *testing.T) {
				f := newFixture(t, tc.mut)
				c := testConn("10.0.0.1")
				c.SetBound(listener.Bound{Kind: listener.BindAnonymous})
				before := f.dc.Calls()
				res := f.d.Bind(context.Background(), c, tc.bind, pw)
				if res.Code != ldap.LDAPResultInvalidCredentials {
					t.Errorf("bind(%q, empty) = %+v, want invalidCredentials", tc.bind, res)
				}
				after := f.dc.Calls()
				if after.Binds != before.Binds || after.Searches != before.Searches {
					t.Errorf("bind(%q, empty) reached the upstream: binds %d→%d searches %d→%d", tc.bind, before.Binds, after.Binds, before.Searches, after.Searches)
				}
				if b := c.Bound(); b.Kind != listener.BindAnonymous || b.Name != "" || b.UpstreamDN != "" {
					t.Errorf("bind(%q, empty) changed the authorization state: %+v", tc.bind, b)
				}
				if ev := f.ev.last(events.BindFail); ev == nil || ev.Reason != "anonymous" {
					t.Errorf("bind(%q, empty) event = %+v", tc.bind, ev)
				}
			})
		}
	}
}

// Check 2: odd password bytes (NUL in the middle, spaces only, non-UTF-8,
// long) reach the upstream untouched, are not truncated, and a prefix of
// the real password never authenticates.
func TestAudit14_A1_PasswordBytesExact(t *testing.T) {
	long := strings.Repeat("P", 60*1024) + "!end"
	users := []*testdir.Entry{
		auditUser("Nul Mid", "nul.mid", "nul.mid@test.aldap", "ab\x00cd"),
		auditUser("Spaces Only", "spaces.only", "spaces.only@test.aldap", "   "),
		auditUser("Non Utf8", "non.utf8", "non.utf8@test.aldap", "p\xff\xfe\x80q"),
		auditUser("Long Pw", "long.pw", "long.pw@test.aldap", long),
	}
	f := newFixture(t, nil, testdir.WithEntries(users...))
	// Warm the service pool: its own bind must not count as a user attempt.
	f.search(t, usersDN, listener.ScopeSub, "(uid=alice.adams)", "uid")
	cases := []struct {
		name, user string
		pw         []byte
		ok         bool
	}{
		{"nul_exact", "nul.mid@test.aldap", []byte("ab\x00cd"), true},
		{"nul_prefix", "nul.mid@test.aldap", []byte("ab"), false},
		{"nul_prefix_with_nul", "nul.mid@test.aldap", []byte("ab\x00"), false},
		{"spaces_exact", "spaces.only@test.aldap", []byte("   "), true},
		{"spaces_fewer", "spaces.only@test.aldap", []byte("  "), false},
		{"nul_only", "alice.adams@test.aldap", []byte("\x00\x00"), false},
		{"nonutf8_exact", "non.utf8@test.aldap", []byte("p\xff\xfe\x80q"), true},
		{"nonutf8_wrong", "non.utf8@test.aldap", []byte("p\xff\xfeq"), false},
		{"long_exact", "long.pw@test.aldap", []byte(long), true},
		{"long_prefix", "long.pw@test.aldap", []byte(long[:len(long)-1]), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Fresh guard: the negative cache and locks must not shadow the upstream answer.
			f.d.o.Guard = testGuard(t, f.ev, func(c *config.Ratelimit) { c.Account.MaxFailures = 100; c.IP.MaxFailures = 1000 })
			before := f.dc.Calls().Binds
			c := testConn("10.0.0.2")
			res := f.d.Bind(context.Background(), c, tc.user, tc.pw)
			if (res.Code == ldap.LDAPResultSuccess) != tc.ok {
				t.Errorf("bind(%q, %q) = %+v, want ok=%v", tc.user, tc.pw, res, tc.ok)
			}
			if f.dc.Calls().Binds != before+1 {
				t.Errorf("bind(%q) upstream binds = %d, want %d", tc.user, f.dc.Calls().Binds, before+1)
			}
		})
	}
}

// Check 5: a successful bind is never served from any cache; every
// successful bind reaches the upstream.
func TestAudit14_A1_SuccessNotCached(t *testing.T) {
	f := newFixture(t, nil)
	// Warm the service pool: its own bind must not count as a user attempt.
	f.search(t, usersDN, listener.ScopeSub, "(uid=alice.adams)", "uid")
	c := testConn("10.0.0.3")
	before := f.dc.Calls().Binds
	for i := 0; i < 3; i++ {
		if res := f.d.Bind(context.Background(), c, "alice.adams@test.aldap", []byte("alice.adams-pass")); res.Code != 0 {
			t.Fatalf("bind %d: %+v", i, res)
		}
	}
	if n := f.dc.Calls().Binds - before; n != 3 {
		t.Errorf("3 successful binds reached the upstream %d times", n)
	}
	// Negative cache: the same wrong pair is answered locally the second time.
	before = f.dc.Calls().Binds
	_ = f.d.Bind(context.Background(), c, "alice.adams@test.aldap", []byte("wrong"))
	_ = f.d.Bind(context.Background(), c, "alice.adams@test.aldap", []byte("wrong"))
	if n := f.dc.Calls().Binds - before; n != 1 {
		t.Errorf("negative cache: upstream binds = %d, want 1", n)
	}
	// A different password after a cached failure still reaches the upstream (no over-caching).
	before = f.dc.Calls().Binds
	if res := f.d.Bind(context.Background(), c, "alice.adams@test.aldap", []byte("alice.adams-pass")); res.Code != 0 {
		t.Errorf("correct password after cached failure: %+v", res)
	}
	if f.dc.Calls().Binds != before+1 {
		t.Error("correct password after cached failure did not reach the upstream")
	}
}

// Check 4: three different forms of one account share one lock key when
// rdn_attr = sAMAccountName; the 4th attempt (virtual DN, right password)
// is refused without touching the upstream.
func TestAudit14_A1_FormsShareLockKey_RDNAttrSAM(t *testing.T) {
	f := newFixture(t, nil) // rdn_attr = sAMAccountName in the fixture
	c := testConn("10.0.0.4")
	for i, name := range []string{"Alice.Adams@TEST.ALDAP", `test\alice.adams`, "  alice.adams  "} {
		if res := f.d.Bind(context.Background(), c, name, []byte("wrong-"+string(rune('a'+i)))); res.Code != ldap.LDAPResultInvalidCredentials {
			t.Fatalf("failure %d (%q): %+v", i, name, res)
		}
	}
	if keys := f.lockKeys(); len(keys) != 1 || keys[0] != "alice.adams" {
		t.Fatalf("lock keys after 3 forms = %v, want [alice.adams]", keys)
	}
	before := f.dc.Calls()
	res := f.d.Bind(context.Background(), c, "CN=alice.adams,OU=Users,OU=Virola,DC=aldap", []byte("alice.adams-pass"))
	if res.Code != ldap.LDAPResultInvalidCredentials {
		t.Errorf("4th form on a locked account = %+v", res)
	}
	if after := f.dc.Calls(); after.Binds != before.Binds || after.Searches != before.Searches {
		t.Errorf("4th form reached the upstream (binds %d→%d, searches %d→%d)", before.Binds, after.Binds, before.Searches, after.Searches)
	}
	if ev := f.ev.last(events.BindBlocked); ev == nil || ev.Reason != ratelimit.ReasonAccountLocked {
		t.Errorf("bind_blocked = %+v", ev)
	}
}

// FINDING A1-1a: with the default rdn_attr (cn) the virtual DN form
// cn=<cn>,ou=users,... is counted under key "<cn>" while UPN/DOMAIN\/bare
// forms are counted under "<sAMAccountName>". One account therefore has two
// independent failure budgets: 3 + 3 = 6 wrong passwords reach the
// directory although account.max_failures = 3 (SPEC §1.1 goal 4: the ALDAP
// lock must fire before the AD lockout).
func TestAudit14_A1_VirtualDNLockKey_RDNAttrCN(t *testing.T) {
	f := newFixture(t, func(p *config.Profile) { p.RDNAttr = "cn" })
	c := testConn("10.0.0.5")
	// Warm the service pool so its own bind does not count as a user attempt.
	f.search(t, usersDN, listener.ScopeSub, "(uid=alice.adams)", "uid")
	start := f.dc.Calls().Binds
	for i := 0; i < 3; i++ {
		_ = f.d.Bind(context.Background(), c, "alice.adams@test.aldap", []byte("wrong-upn-"+string(rune('0'+i))))
	}
	if keys := f.lockKeys(); len(keys) != 1 {
		t.Fatalf("lock after 3 UPN failures: %v", keys)
	}
	afterUPN := f.dc.Calls().Binds
	for i := 0; i < 3; i++ {
		res := f.d.Bind(context.Background(), c, "cn=Alice Adams,"+usersDN, []byte("wrong-dn-"+string(rune('0'+i))))
		if res.Code != ldap.LDAPResultInvalidCredentials {
			t.Fatalf("virtual dn failure %d: %+v", i, res)
		}
	}
	viaDN := f.dc.Calls().Binds - afterUPN
	total := f.dc.Calls().Binds - start
	t.Logf("upstream binds: via UPN before lock = %d, via virtual DN after the lock = %d, total = %d; lock keys = %v", afterUPN-start, viaDN, total, f.lockKeys())
	if viaDN != 0 {
		t.Errorf("FINDING: %d wrong passwords for a locked account reached the upstream through the virtual DN form (want 0)", viaDN)
	}
	if total > 3 {
		t.Errorf("FINDING: %d upstream bind attempts for one account, account.max_failures = 3", total)
	}
}

// FINDING A1-1b: when the UPN prefix differs from sAMAccountName (the
// common enterprise case: john.doe@corp vs jdoe) the two forms are two lock
// keys: 3 + 3 wrong passwords reach the directory.
func TestAudit14_A1_UPNPrefixDiffersFromSAM(t *testing.T) {
	f := newFixture(t, nil, testdir.WithEntries(auditUser("John Doe", "jdoe", "john.doe@test.aldap", "jdoe-pass")))
	c := testConn("10.0.0.6")
	// Warm the service pool: its own bind must not count as a user attempt.
	f.search(t, usersDN, listener.ScopeSub, "(uid=alice.adams)", "uid")
	start := f.dc.Calls().Binds
	for i := 0; i < 3; i++ {
		_ = f.d.Bind(context.Background(), c, "john.doe@test.aldap", []byte("wrong-"+string(rune('0'+i))))
	}
	for i := 0; i < 3; i++ {
		_ = f.d.Bind(context.Background(), c, "jdoe", []byte("wrong-"+string(rune('5'+i))))
	}
	for i := 0; i < 3; i++ {
		_ = f.d.Bind(context.Background(), c, `TEST\jdoe`, []byte("wrong-x"+string(rune('0'+i))))
	}
	total := f.dc.Calls().Binds - start
	t.Logf("upstream binds for one account over UPN/bare/DOMAIN forms = %d, lock keys = %v", total, f.lockKeys())
	if total > 3 {
		t.Errorf("FINDING: %d upstream bind attempts for one account (want ≤ 3); the account is locked under two keys %v", total, f.lockKeys())
	}
}

// FINDING A1-2: the client_bind lock / negative-cache key is the raw
// lower-cased bind string, not the canonical DN. A different spelling of the
// same DN (spaces after commas, hex escapes, different attribute case +
// spaces) is a new key, so the account lock is evaded and every attempt
// costs a full argon2id derivation (t=3, m=64 MiB, p=4 in production).
func TestAudit14_A1_ClientBindLockKeyCanonical(t *testing.T) {
	f := newFixture(t, nil)
	c := testConn("10.0.0.7")
	for i := 0; i < 3; i++ {
		if res := f.d.Bind(context.Background(), c, clientDN, []byte("wrong-"+string(rune('0'+i)))); res.Code != ldap.LDAPResultInvalidCredentials {
			t.Fatalf("client bind failure %d: %+v", i, res)
		}
	}
	if keys := f.lockKeys(); len(keys) != 1 {
		t.Fatalf("lock keys after 3 client bind failures = %v", keys)
	}
	for _, alt := range []string{
		"CN=Virola, OU=Services, DC=Aldap",
		"cn=virola,ou=services, dc=aldap",
		`cn=\76irola,ou=services,dc=aldap`,
		"cn=virola,ou=services,dc=aldap ",
	} {
		blockedBefore := f.countEvents(events.BindBlocked, ratelimit.ReasonAccountLocked)
		failBefore := f.countEvents(events.BindFail, "invalid_password")
		res := f.d.Bind(context.Background(), c, alt, []byte("wrong-alt"))
		if res.Code != ldap.LDAPResultInvalidCredentials {
			t.Errorf("bind(%q) = %+v", alt, res)
		}
		blocked := f.countEvents(events.BindBlocked, ratelimit.ReasonAccountLocked) - blockedBefore
		verified := f.countEvents(events.BindFail, "invalid_password") - failBefore
		if blocked != 1 || verified != 0 {
			t.Errorf("FINDING: bind(%q) on the locked client_bind DN was not blocked (blocked=%d, argon2 verified=%d); lock keys now %v", alt, blocked, verified, f.lockKeys())
		}
	}
}

// FINDING A1-3 (Low): SPEC §4.5 says *any* bind on a honeytoken (and any
// bind on a honeypot profile) is a honeytoken hit with lock_ip. A bind with
// an empty password is classified as anonymous first and never reaches the
// trap: no honeytoken event, no lock_ip, so recon with unauthenticated
// binds against trap accounts goes unreported.
func TestAudit14_A1_HoneytokenEmptyPasswordIsHit(t *testing.T) {
	cases := []struct {
		name string
		mut  func(p *config.Profile)
		bind string
	}{
		{"honeytoken", func(p *config.Profile) { p.Honeytokens = []string{honeyAcct} }, honeyAcct},
		{"honeypot", func(p *config.Profile) { p.Mode = "honeypot" }, "administrator@corp.local"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, tc.mut)
			c := testConn("10.0.0.8")
			_ = f.d.Bind(context.Background(), c, tc.bind, nil)
			if f.ev.last(events.Honeytoken) == nil {
				t.Errorf("FINDING: empty-password bind on %q raised no honeytoken event (last bind event: %+v)", tc.bind, f.ev.last(events.BindFail))
			}
		})
	}
}

// FINDING A1-4 (Low): ratelimit.allow_accounts / lockdown.allow_accounts
// entries are matched against the stripped key ("svc") while an operator
// naturally writes the UPN or DOMAIN\ form the application binds with; such
// an entry silently never matches and the exempted account is locked.
func TestAudit14_A1_AllowAccountsForms(t *testing.T) {
	for _, allow := range []string{"svc-monitor@test.aldap", `TEST\svc-monitor`} {
		t.Run(allow, func(t *testing.T) {
			f := newFixture(t, nil)
			f.d.o.Guard = testGuard(t, f.ev, func(c *config.Ratelimit) { c.AllowAccounts = []string{allow} })
			c := testConn("10.0.0.9")
			for i := 0; i < 4; i++ {
				_ = f.d.Bind(context.Background(), c, allow, []byte("wrong-"+string(rune('0'+i))))
			}
			if keys := f.lockKeys(); len(keys) != 0 {
				t.Errorf("FINDING: allow_accounts=[%q] but the account was locked under %v", allow, keys)
			}
		})
	}
}

// FINDING A1-6 (Low): timing oracle for client_bind.dn. A failed bind on the
// client_bind DN always pays a full argon2id derivation (~240 ms with the
// SPEC parameters) while a failed bind on any other DN is answered at once;
// constant_time_bind_fail pads only up to the p95 of *successful* binds,
// which is the latency of user binds (ms) whenever the application keeps a
// long-lived bound connection. An attacker can therefore tell which DN is
// the application's service login and target it (see A1-2).
func TestAudit14_A1_ClientBindTimingOracle(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 production cost")
	}
	dc := testdir.StartFixture(t)
	ucfg := config.DefaultUpstream()
	ucfg.Servers = []string{dc.URL()}
	ucfg.BindDN = svcDN
	ucfg.BaseDN = "DC=test,DC=aldap"
	ucfg.AuditServiceAccount = false
	up, err := upstream.New("ad-test", ucfg, svcPW, upstream.Options{Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(up.Close)
	rules, err := profile.Compile("virola", baseProfile(), ucfg, profile.Options{ClientPassword: clientPW, Argon2: profile.DefaultArgon2})
	if err != nil {
		t.Fatal(err)
	}
	ev := &sink{}
	var padded time.Duration
	d := New(rules, up, Options{Logger: slog.New(slog.DiscardHandler), Events: ev, Version: "test",
		Guard: testGuard(t, ev, func(c *config.Ratelimit) { c.ConstantTimeBindFail = true; c.Delay.Base = 0 }),
		Sleep: func(_ context.Context, w time.Duration) { padded += w }})
	c := testConn("10.0.0.10")
	// The application's long-lived session: user binds set the p95 (fast).
	for i := 0; i < 5; i++ {
		if res := d.Bind(context.Background(), c, "alice.adams@test.aldap", []byte("alice.adams-pass")); res.Code != 0 {
			t.Fatalf("user bind: %+v", res)
		}
	}
	observe := func(name string) time.Duration {
		padded = 0
		start := time.Now()
		res := d.Bind(context.Background(), c, name, []byte("wrong"))
		if res.Code != ldap.LDAPResultInvalidCredentials {
			t.Fatalf("bind(%q) = %+v", name, res)
		}
		return time.Since(start) + padded
	}
	other := observe("cn=svc-other,ou=services,dc=aldap")
	client := observe(clientDN)
	t.Logf("observable failure latency: unknown DN = %s, client_bind.dn = %s", other, client)
	// The failed bind on an unknown DN is padded to the measured argon2id
	// cost; allow scheduler noise (the race detector and parallel tests
	// make both sides jitter) but not the ~200 ms the oracle showed.
	if diff := client - other; diff > 100*time.Millisecond && diff > client/4 {
		t.Errorf("FINDING: a failed bind on client_bind.dn is %s slower than on an unknown DN: the service DN is enumerable by timing", client-other)
	}
}
