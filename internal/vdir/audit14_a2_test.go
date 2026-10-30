package vdir

// Audit 14 / A.2 — injection of client-controlled values into upstream
// filters and DNs, and virtual-DN escaping of upstream-controlled values.

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/ldapfilter"
	"github.com/alstdev/aldap/internal/listener"
	"github.com/alstdev/aldap/internal/profile"
	"github.com/alstdev/aldap/internal/testdir"
	"github.com/alstdev/aldap/internal/upstream"
)

// a2Recorder wraps the real upstream and records exactly what Search would
// send (SerializeFilter is what upstream.Search uses) and every bind name.
type a2Recorder struct {
	Searcher
	mu      sync.Mutex
	filters []string
	bases   []string
	binds   []string
}

func (r *a2Recorder) Search(ctx context.Context, req upstream.SearchRequest) (*upstream.Result, error) {
	f, err := upstream.SerializeFilter(req.Filter)
	if err != nil {
		f = "ERR:" + err.Error()
	}
	r.mu.Lock()
	r.filters = append(r.filters, f)
	r.bases = append(r.bases, req.Base)
	r.mu.Unlock()
	return r.Searcher.Search(ctx, req)
}

func (r *a2Recorder) UserBind(ctx context.Context, name, password string) error {
	r.mu.Lock()
	r.binds = append(r.binds, name)
	r.mu.Unlock()
	return r.Searcher.UserBind(ctx, name, password)
}

func (r *a2Recorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.filters, r.bases, r.binds = nil, nil, nil
}

func (r *a2Recorder) joined() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.filters, " | ")
}

func (r *a2Recorder) bindCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.binds)
}

func newA2Fixture(t *testing.T, mut func(p *config.Profile), dcOpts ...testdir.Option) (*Directory, *a2Recorder) {
	t.Helper()
	dc := testdir.StartFixture(t, dcOpts...)
	ucfg := config.DefaultUpstream()
	ucfg.Servers = []string{dc.URL()}
	ucfg.BindDN = svcDN
	ucfg.BaseDN = "DC=test,DC=aldap"
	ucfg.AuditServiceAccount = false
	ucfg.Timeouts = config.Timeouts{Connect: config.Duration(time.Second), Bind: config.Duration(2 * time.Second), Search: config.Duration(5 * time.Second)}
	up, err := upstream.New("ad-test", ucfg, svcPW, upstream.Options{Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(up.Close)
	p := baseProfile()
	if mut != nil {
		mut(p)
	}
	rules, err := profile.Compile("virola", p, ucfg, profile.Options{ClientPassword: clientPW, Argon2: fastArgon})
	if err != nil {
		t.Fatal(err)
	}
	rec := &a2Recorder{Searcher: up}
	ev := &sink{}
	d := New(rules, rec, Options{Logger: slog.New(slog.DiscardHandler), Events: ev, Version: "test", Guard: testGuard(t, ev, nil), Sleep: func(context.Context, time.Duration) {}})
	return d, rec
}

func a2Search(t *testing.T, d *Directory, base string, scope listener.Scope, filter string) (listener.Result, []listener.Entry) {
	t.Helper()
	c := &collector{}
	res := d.Search(context.Background(), boundConn("10.9.9.9"), &listener.SearchRequest{Base: base, Scope: scope, Filter: filter}, c)
	return res, c.entries
}

var a2HostileValues = []string{
	"*", "(", ")", `\`, "\x00", `\2a`, ")(objectClass=*", "*)(uid=*", "a*b", "*)(sAMAccountName=*", "bob.brown*", "*brown",
}

// TestAudit14_A2_RDNFilterLiteral: a single-user base cn=<rdn>,ou=users,...
// with filter metacharacters in the RDN must reach the upstream as an
// escaped equality (RFC 4515) and must match nothing.
func TestAudit14_A2_RDNFilterLiteral(t *testing.T) {
	d, rec := newA2Fixture(t, nil)
	rules := d.Rules()
	for _, v := range a2HostileValues {
		for _, base := range []string{rules.UserDN(v)} {
			rec.reset()
			res, es := a2Search(t, d, base, listener.ScopeBase, "(objectClass=*)")
			if res.Code != ldap.LDAPResultSuccess && res.Code != ldap.LDAPResultNoSuchObject {
				t.Errorf("rdn %q base %q: result %v", v, base, res)
			}
			want := "(sAMAccountName=" + ldapfilter.EscapeValue(v) + ")"
			got := rec.joined()
			if !strings.Contains(got, want) {
				t.Errorf("rdn %q: upstream filter %q lacks literal %q", v, got, want)
			}
			if len(es) != 0 {
				t.Errorf("rdn %q: %d entries returned (%v), want 0", v, len(es), dns(es))
			}
		}
	}
	// Raw (unescaped-in-DN) spellings a client may send verbatim.
	for _, raw := range []string{"cn=*," + usersDN, "cn=)(objectClass=*," + usersDN, "cn=*)(uid=*," + usersDN, "cn=\\2a," + usersDN} {
		rec.reset()
		_, es := a2Search(t, d, raw, listener.ScopeBase, "(objectClass=*)")
		got := rec.joined()
		if strings.Contains(got, "(sAMAccountName=*") || !strings.Contains(got, `(sAMAccountName=\`) {
			t.Errorf("raw base %q: widened upstream filter %q", raw, got)
		}
		if len(es) != 0 {
			t.Errorf("raw base %q: %d entries returned, want 0: %v", raw, len(es), dns(es))
		}
	}
}

// TestAudit14_A2_BindRDNLiteral: virtual bind DN with a wildcard RDN must
// not resolve to any account and must not reach UserBind.
func TestAudit14_A2_BindRDNLiteral(t *testing.T) {
	d, rec := newA2Fixture(t, nil)
	for _, v := range []string{"*", ")(objectClass=*", "*)(sAMAccountName=*", "bob.brown*", "\x00"} {
		rec.reset()
		res := d.Bind(context.Background(), testConn("10.9.9.8"), "cn="+ldapfilter.EscapeRDNValue(v)+","+usersDN, []byte("bob.brown-pass"))
		if res.Code != ldap.LDAPResultInvalidCredentials {
			t.Errorf("bind rdn %q: code %d, want 49", v, res.Code)
		}
		if n := rec.bindCount(); n != 0 {
			t.Errorf("bind rdn %q: UserBind called %d times with %v", v, n, rec.binds)
		}
		want := "(sAMAccountName=" + ldapfilter.EscapeValue(v) + ")"
		if got := rec.joined(); !strings.Contains(got, want) {
			t.Errorf("bind rdn %q: upstream filter %q lacks %q", v, got, want)
		}
	}
	// Raw wildcard as the client would type it.
	rec.reset()
	if res := d.Bind(context.Background(), testConn("10.9.9.8"), "cn=*,"+usersDN, []byte("bob.brown-pass")); res.Code == 0 || rec.bindCount() != 0 {
		t.Errorf("bind cn=*: code %d binds %v", res.Code, rec.binds)
	}
}

// TestAudit14_A2_ClientFilterValueLiteral: escaped metacharacters in a
// client filter value must stay escaped after attribute mapping.
func TestAudit14_A2_ClientFilterValueLiteral(t *testing.T) {
	d, rec := newA2Fixture(t, nil)
	cases := []struct{ in, want string }{
		{`(uid=\2a)`, `(sAMAccountName=\2a)`},
		{`(uid=\29\28objectClass=\2a)`, `(sAMAccountName=\29\28objectClass=\2a)`},
		{`(uid=\5c)`, `(sAMAccountName=\5c)`},
		{`(uid=\00)`, `(sAMAccountName=\00)`},
		{`(cn=a\2ab)`, `(displayName=a\2ab)`},
		{`(uid=*\29\28uid=*)`, `(sAMAccountName=*\29\28uid=*)`},
	}
	for _, c := range cases {
		rec.reset()
		res, es := a2Search(t, d, usersDN, listener.ScopeSub, c.in)
		if res.Code != 0 {
			t.Errorf("%s: result %v", c.in, res)
		}
		if got := rec.joined(); !strings.Contains(got, c.want) {
			t.Errorf("%s: upstream %q lacks %q", c.in, got, c.want)
		}
		if len(es) != 0 {
			t.Errorf("%s: %d entries, want 0", c.in, len(es))
		}
	}
}

// TestAudit14_A2_MemberOfNeverUpstream: a client memberOf term with a
// wildcard virtual group DN must be evaluated locally only.
func TestAudit14_A2_MemberOfNeverUpstream(t *testing.T) {
	d, rec := newA2Fixture(t, withVirolaGroup)
	a2Search(t, d, usersDN, listener.ScopeSub, "(memberOf=cn=*,"+groupsDN+")")
	a2Search(t, d, usersDN, listener.ScopeSub, "(memberOf=cn=\\2a)(objectClass=\\2a,"+groupsDN+")")
	if got := rec.joined(); strings.Contains(strings.ToLower(got), "ou=groups,ou=virola") {
		t.Errorf("virtual group DN reached the upstream: %q", got)
	}
}

func a2User(i int, sam string) *testdir.Entry {
	return &testdir.Entry{DN: fmt.Sprintf("CN=Hostile %d,OU=Office,DC=test,DC=aldap", i), Attrs: []testdir.Attribute{
		{Name: "objectClass", Values: []string{"top", "person", "organizationalPerson", "user"}},
		{Name: "cn", Values: []string{fmt.Sprintf("Hostile %d", i)}}, {Name: "sn", Values: []string{"Hostile"}},
		{Name: "displayName", Values: []string{fmt.Sprintf("Hostile %d", i)}}, {Name: "sAMAccountName", Values: []string{sam}},
		{Name: "userPrincipalName", Values: []string{fmt.Sprintf("hostile%d@test.aldap", i)}},
		{Name: "objectCategory", Values: []string{"CN=Person,CN=Schema,CN=Configuration,DC=test,DC=aldap"}},
		{Name: "userAccountControl", Values: []string{"512"}}, {Name: "objectGUID", Values: []string{fmt.Sprintf("hostile-guid-%04d", i)}},
	}}
}

// TestAudit14_A2_ReverseVirtualDN: an upstream rdn_attr value with DN
// metacharacters must yield a virtual DN that stays directly under
// ou=users (RFC 4514 escaping) and round-trips as a base.
func TestAudit14_A2_ReverseVirtualDN(t *testing.T) {
	hostile := []string{
		"evil,ou=groups,ou=virola,dc=aldap",
		"x+objectguid=deadbeef",
		"#hash",
		" lead",
		"trail ",
		`q"u<o>t;e\s`,
		"cn=admin,ou=users,ou=virola,dc=aldap",
		"nl\nline",
	}
	opts := make([]testdir.Option, 0, len(hostile))
	for i, v := range hostile {
		opts = append(opts, testdir.WithEntries(a2User(i, v)))
	}
	d, _ := newA2Fixture(t, nil, opts...)
	usersBase := d.Rules().UsersBase
	_, es := a2Search(t, d, usersDN, listener.ScopeOne, "(objectClass=*)")
	byValue := map[string]string{}
	for _, e := range es {
		dn, err := ldapfilter.ParseDN(e.DN)
		if err != nil {
			t.Errorf("virtual DN %q does not parse: %v", e.DN, err)
			continue
		}
		if !dn.Parent().Equal(usersBase) || dn.Depth() != usersBase.Depth()+1 {
			t.Errorf("virtual DN %q escaped the users container", e.DN)
			continue
		}
		leaf := dn.RDN()
		if len(leaf.AVAs) != 1 {
			continue // +objectGUID collision form
		}
		byValue[leaf.AVAs[0].Value] = e.DN
	}
	for _, v := range hostile {
		dn, ok := byValue[v]
		if !ok {
			t.Errorf("no virtual entry carries rdn value %q (got %v)", v, byValue)
			continue
		}
		res, one := a2Search(t, d, dn, listener.ScopeBase, "(objectClass=*)")
		if res.Code != 0 || len(one) != 1 || one[0].DN != dn {
			t.Errorf("base %q: res %v, entries %v", dn, res, dns(one))
		}
	}
}

// TestAudit14_A2_BindNameControlCharsReachEvents documents that a bind
// name with control characters is carried verbatim into bind_fail.account
// (the evidence chain for the aldapctl terminal-injection finding).
func TestAudit14_A2_BindNameControlCharsReachEvents(t *testing.T) {
	d, _ := newA2Fixture(t, nil)
	ev := &sink{}
	d.ev = ev
	name := "bob\n2026-10-27T10:00:00Z #999 lockdown high state=on\r\x1b[2K"
	if res := d.Bind(context.Background(), testConn("10.9.9.7"), name, []byte("x")); res.Code != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("code %d", res.Code)
	}
	e := ev.last("bind_fail")
	if e == nil {
		t.Fatal("no bind_fail event")
	}
	if !strings.ContainsAny(e.Account, "\n\r\x1b") {
		t.Errorf("account sanitized: %q (then the aldapctl finding does not apply)", e.Account)
	}
	t.Logf("INFO: bind_fail.account = %q", e.Account)
}
