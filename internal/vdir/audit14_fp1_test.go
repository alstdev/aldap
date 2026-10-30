package vdir

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/listener"
)

// FP-1 (final pass, Critical): with anonymous_bind = false a connection that
// never bound — or whose bind failed — read the whole virtual directory.
// SPEC §4.3: an anonymous session has no rights.

func fp1Search(f *fixture, c *listener.Conn, base string, scope listener.Scope, filter string) (listener.Result, []listener.Entry) {
	col := &collector{}
	res := f.d.Search(context.Background(), c, &listener.SearchRequest{Base: base, Scope: scope, Filter: filter, Attrs: []string{"mail", "userPrincipalName"}}, col)
	return res, col.entries
}

func TestAudit14_FP1_UnboundSearchRefused(t *testing.T) {
	f := newFixture(t, nil) // anonymous_bind = false
	for _, base := range []string{vb, usersDN, groupsDN, "cn=h.petrenko," + usersDN} {
		res, es := fp1Search(f, listener.NewConn("c-x", "virola", nil), base, listener.ScopeSub, "(objectClass=*)")
		if res.Code != ldap.LDAPResultStrongAuthRequired || len(es) != 0 {
			t.Errorf("base %q: unbound search = %+v, %d entries; want strongAuthRequired and nothing", base, res, len(es))
		}
	}
	ev := f.ev.last(events.OpDenied)
	if ev == nil || ev.Data["op"] != "search" || ev.Data["reason"] != "not_bound" {
		t.Errorf("no op_denied{search, not_bound} event: %+v", ev)
	}
}

func TestAudit14_FP1_FailedBindThenSearch(t *testing.T) {
	f := newFixture(t, nil)
	conn := listener.NewConn("c-y", "virola", nil)
	if r := f.d.Bind(context.Background(), conn, "alice.adams", []byte("wrong")); r.Code == ldap.LDAPResultSuccess {
		t.Fatal("bind unexpectedly succeeded")
	}
	// The listener resets the state to anonymous before every bind.
	conn.SetBound(listener.Bound{Kind: listener.BindAnonymous})
	if res, es := fp1Search(f, conn, usersDN, listener.ScopeSub, "(objectClass=*)"); res.Code == ldap.LDAPResultSuccess || len(es) != 0 {
		t.Errorf("search after a failed bind = %+v, %d entries", res, len(es))
	}
}

func TestAudit14_FP1_UnboundSearchOverTCP(t *testing.T) {
	f := newFixture(t, nil)
	srv, err := listener.New(listener.Config{Profile: "virola", Transport: listener.TransportLDAP, Handler: f.d})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Close)
	c, err := ldap.DialURL("ldap://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sr, err := c.Search(ldap.NewSearchRequest(vb, ldap.ScopeWholeSubtree, 0, 0, 0, false, "(objectClass=*)", []string{"userPrincipalName", "mail"}, nil))
	if err == nil && len(sr.Entries) > 0 {
		t.Fatalf("an unauthenticated TCP client received %d entries, first: %s", len(sr.Entries), sr.Entries[0].DN)
	}
	if !ldap.IsErrorWithCode(err, ldap.LDAPResultStrongAuthRequired) {
		t.Errorf("err = %v, want strongAuthRequired", err)
	}
	// The root DSE stays readable: clients discover namingContexts there.
	rd, err := c.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, 0, 0, 0, false, "(objectClass=*)", []string{"namingContexts"}, nil))
	if err != nil || len(rd.Entries) != 1 {
		t.Errorf("unbound root DSE read: %v, %v", err, rd)
	}
}

// What stays allowed: root DSE and subschema for everyone, everything for
// an anonymous session when anonymous_bind = true, the traps of a honeypot,
// and a client or user bind.
func TestAudit14_FP1_StillAllowed(t *testing.T) {
	f := newFixture(t, nil)
	for _, base := range []string{"", "cn=Subschema"} {
		if res, es := fp1Search(f, listener.NewConn("c-r", "virola", nil), base, listener.ScopeBase, "(objectClass=*)"); res.Code != ldap.LDAPResultSuccess || len(es) != 1 {
			t.Errorf("unbound base-scope search of %q = %+v, %d entries", base, res, len(es))
		}
	}
	for _, kind := range []listener.BindKind{listener.BindClient, listener.BindUser} {
		c := listener.NewConn("c-b", "virola", nil)
		c.SetBound(listener.Bound{Kind: kind, Name: "app"})
		if res, es := fp1Search(f, c, usersDN, listener.ScopeSub, "(objectClass=*)"); res.Code != ldap.LDAPResultSuccess || len(es) == 0 {
			t.Errorf("%s-bound search = %+v, %d entries", kind, res, len(es))
		}
	}
	anon := newFixture(t, func(p *config.Profile) { p.AnonymousBind = true })
	if res, es := fp1Search(anon, listener.NewConn("c-a", "virola", nil), usersDN, listener.ScopeSub, "(objectClass=*)"); res.Code != ldap.LDAPResultSuccess || len(es) == 0 {
		t.Errorf("anonymous_bind = true: unbound search = %+v, %d entries", res, len(es))
	}
	// The operator's test search simulates the application's session.
	if tr := f.d.Test(context.Background(), TestRequest{Base: usersDN, Scope: listener.ScopeSub, Filter: "(objectClass=*)"}); tr.Result.Code != ldap.LDAPResultSuccess || len(tr.Entries) == 0 {
		t.Errorf("Directory.Test = %+v, %d entries", tr.Result, len(tr.Entries))
	}
}

// FP-9 (final pass; not confirmed): the subagent compared the pre-lookup
// guard key of four spellings of one account and found two. The key is
// re-keyed to the canonical account after the identity lookup (A1-1), so
// what matters is how many guesses reach the directory: with rdn_attr = cn
// four spellings (UPN, bare, DOMAIN\user, virtual DN) must share one budget
// of account.max_failures = 3.
func TestAudit14_FP9_FourSpellingsOneBudget(t *testing.T) {
	f := newFixture(t, func(p *config.Profile) { p.RDNAttr = "cn" })
	forms := []string{"alice.adams@test.aldap", "alice.adams", `TEST\alice.adams`, "cn=Alice Adams," + usersDN, "ALICE.ADAMS@test.aldap"}
	before := f.dc.Calls().UserBinds()
	for i, name := range forms {
		res := f.d.Bind(context.Background(), testConn("10.0.0.7"), name, []byte(fmt.Sprintf("wrong-%d", i)))
		if res.Code == ldap.LDAPResultSuccess {
			t.Fatalf("bind %q succeeded", name)
		}
	}
	if reached := f.dc.Calls().UserBinds() - before; reached != 3 {
		t.Errorf("%d guesses over %d spellings of one account reached the directory, want exactly account.max_failures = 3", reached, len(forms))
	}
}
