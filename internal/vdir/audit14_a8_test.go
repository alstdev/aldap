package vdir

// Audit 14, area A.8 (upstream data trust and bind diagnostics).

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/ldapfilter"
	"github.com/alstdev/aldap/internal/listener"
	"github.com/alstdev/aldap/internal/profile"
	"github.com/alstdev/aldap/internal/upstream"
)

// Check 6: a virtual group `include = ["alice.adams@test.aldap"]` is resolved
// with (|(userPrincipalName=X)(mail=X)). A user who can write his own `mail`
// (self-service, Exchange, delegated helpdesk, generic LDAP with self write,
// or a rogue DC) becomes a member by setting mail to the included UPN.
func TestAudit14_A8_GroupInclude_MailImpersonation(t *testing.T) {
	f := newFixture(t, func(p *config.Profile) {
		p.Groups = map[string]config.Group{
			"vip": {ObjectClass: "groupOfNames", Members: config.GroupMembers{Include: []string{"alice.adams@test.aldap"}}},
		}
	})
	bob := f.dc.Dir.Lookup("CN=Bob Brown,OU=Office,DC=test,DC=aldap").Clone()
	bob.Set("mail", "alice.adams@test.aldap") // attacker-controlled attribute
	if err := f.dc.Dir.Upsert(bob); err != nil {
		t.Fatal(err)
	}
	f.d.InvalidateMembership()
	_, es := f.search(t, "cn=vip,"+groupsDN, listener.ScopeBase, "(objectClass=*)", "member")
	if len(es) != 1 {
		t.Fatalf("group = %v", dns(es))
	}
	members := attr(es[0], "member")
	for _, m := range members {
		if strings.EqualFold(m, "cn=bob.brown,"+usersDN) {
			t.Errorf("bob joined vip by setting mail to an included UPN: members=%v", members)
		}
	}
	if !contains(members, "cn=alice.adams,"+usersDN) {
		t.Errorf("alice missing: %v", members)
	}
	// memberOf of bob must not list vip either.
	_, es = f.search(t, "cn=bob.brown,"+usersDN, listener.ScopeBase, "(objectClass=*)", "memberOf")
	if len(es) == 1 && contains(attr(es[0], "memberOf"), "cn=vip,"+groupsDN) {
		t.Errorf("bob memberOf = %v", attr(es[0], "memberOf"))
	}
}

// Check 6: the exclude list matches by mail too — a user can only remove
// himself (self-DoS), never someone else. Documented as OK.
func TestAudit14_A8_GroupExclude_MailSelfOnly(t *testing.T) {
	f := newFixture(t, func(p *config.Profile) {
		p.Groups = map[string]config.Group{
			"all": {ObjectClass: "groupOfNames", Members: config.GroupMembers{Exclude: []string{"svc-backup@test.aldap"}}},
		}
	})
	bob := f.dc.Dir.Lookup("CN=Bob Brown,OU=Office,DC=test,DC=aldap").Clone()
	bob.Set("mail", "svc-backup@test.aldap")
	if err := f.dc.Dir.Upsert(bob); err != nil {
		t.Fatal(err)
	}
	_, es := f.search(t, "cn=all,"+groupsDN, listener.ScopeBase, "(objectClass=*)", "member")
	if len(es) != 1 {
		t.Fatalf("group = %v", dns(es))
	}
	m := attr(es[0], "member")
	if contains(m, "cn=bob.brown,"+usersDN) {
		t.Logf("bob excluded himself via mail (self-DoS only)")
	}
	if !contains(m, "cn=alice.adams,"+usersDN) {
		t.Errorf("alice missing: %v", m)
	}
}

// Check 6: rdn_attr values with DN special characters are escaped per RFC 4514
// when the virtual DN is built (no injection of extra RDNs).
func TestAudit14_A8_VirtualDN_RDNEscaped(t *testing.T) {
	f := newFixture(t, func(p *config.Profile) { p.RDNAttr = "displayName" })
	bob := f.dc.Dir.Lookup("CN=Bob Brown,OU=Office,DC=test,DC=aldap").Clone()
	bob.Set("displayName", `x,ou=groups+cn=admin\#<>;"`)
	if err := f.dc.Dir.Upsert(bob); err != nil {
		t.Fatal(err)
	}
	_, es := f.search(t, usersDN, listener.ScopeSub, "(sAMAccountName=bob.brown)")
	if len(es) != 1 {
		t.Fatalf("bob = %v", dns(es))
	}
	dn := es[0].DN
	p, err := ldapfilter.ParseDN(dn)
	if err != nil {
		t.Fatalf("virtual DN %q does not parse: %v", dn, err)
	}
	base, _ := ldapfilter.ParseDN(usersDN)
	if !p.IsUnder(base) || len(p.RDNs) != len(base.RDNs)+1 {
		t.Errorf("virtual DN not exactly one RDN under the users container: %q", dn)
	}
	if leaf := p.RDNs[0]; len(leaf.AVAs) != 1 || leaf.AVAs[0].Value != `x,ou=groups+cn=admin\#<>;"` {
		t.Errorf("leaf RDN altered by the hostile value: %+v", leaf)
	}
	t.Logf("virtual DN = %q", dn)
}

type logBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// Check 3: a bind refused by the DC with strongerAuthRequired(8) must produce
// bind_fail{reason=upstream_error} (not invalid_password), must not enter the
// negative cache, and the WARN log must name the cause (result code), not
// just "upstream_error".
func TestAudit14_A8_Bind_SigningRequired_Diagnostics(t *testing.T) {
	ldapErr := ldap.NewError(ldap.LDAPResultStrongAuthRequired, errors.New(`00002028: LdapErr: DSID-0C090259, comment: The server requires binds to turn on integrity checking if SSL\TLS are not already active on the connection, data 0, v4563`))
	up := &fakeUp{bindErr: &upstream.BindError{Reason: upstream.ReasonUpstreamError, Err: ldapErr}}
	p := baseProfile()
	rules, err := profile.Compile("virola", p, &config.Upstream{Kind: "ad"}, profile.Options{ClientPassword: clientPW, Argon2: fastArgon})
	if err != nil {
		t.Fatal(err)
	}
	ev := &sink{}
	lb := &logBuf{}
	d := New(rules, up, Options{Logger: slog.New(slog.NewTextHandler(lb, &slog.HandlerOptions{Level: slog.LevelDebug})), Events: ev,
		Guard: testGuard(t, ev, nil), Sleep: func(context.Context, time.Duration) {}})
	c := testConn("10.9.9.9")
	for i := 0; i < 2; i++ {
		res := d.Bind(context.Background(), c, "bob.brown@test.aldap", []byte("Secret-pw-1"))
		if res.Code != ldap.LDAPResultInvalidCredentials {
			t.Fatalf("bind %d → %v", i, res)
		}
	}
	e := ev.last(events.BindFail)
	if e == nil || e.Reason != "upstream_error" {
		t.Fatalf("bind_fail = %+v", e)
	}
	if len(up.binds) != 2 {
		t.Errorf("second bind did not reach the upstream (negative cache hit?): binds=%d", len(up.binds))
	}
	out := lb.String()
	if strings.Contains(out, "Secret-pw-1") {
		t.Fatalf("password leaked into logs")
	}
	if !strings.Contains(out, "Result Code 8") && !strings.Contains(out, "Strong") && !strings.Contains(out, "integrity") {
		t.Errorf("WARN log does not name the LDAP result that refused the bind:\n%s", out)
	}
}
