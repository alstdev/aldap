package vdir

// Audit 14, area A.4: virtual directory rule bypass. These tests probe the
// search/bind pipeline as a hostile client of one profile. Tests named
// *_Finding* are expected to FAIL on the audited code (they document a
// finding); the others are expected to pass (they document an OK verdict).

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/ldapfilter"
	"github.com/alstdev/aldap/internal/listener"
	"github.com/alstdev/aldap/internal/testdir"
	"github.com/alstdev/aldap/internal/upstream"
)

// recUp wraps the upstream and records every search request the directory
// sends, so a test can assert on the bases/filters that reach the upstream.
type recUp struct {
	up   *upstream.Upstream
	mu   sync.Mutex
	reqs []upstream.SearchRequest
}

func (r *recUp) Name() string { return r.up.Name() }
func (r *recUp) Search(ctx context.Context, req upstream.SearchRequest) (*upstream.Result, error) {
	r.mu.Lock()
	r.reqs = append(r.reqs, req)
	r.mu.Unlock()
	return r.up.Search(ctx, req)
}
func (r *recUp) UserBind(ctx context.Context, name, password string) error {
	return r.up.UserBind(ctx, name, password)
}
func (r *recUp) take() []upstream.SearchRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.reqs
	r.reqs = nil
	return out
}

// recordingFixture rebuilds the fixture's directory over a recording upstream.
func recordingFixture(t *testing.T, mut func(p *config.Profile), dcOpts ...testdir.Option) (*fixture, *recUp) {
	t.Helper()
	f := newFixture(t, mut, dcOpts...)
	rec := &recUp{up: f.up}
	f.d = New(f.d.rules, rec, Options{Logger: slog.New(slog.DiscardHandler), Events: f.ev, Version: "test", StartTLS: true,
		Guard: testGuard(t, f.ev, nil), Sleep: func(context.Context, time.Duration) {}})
	return f, rec
}

func canon(dn string) string {
	p, err := ldapfilter.ParseDN(dn)
	if err != nil {
		return strings.ToLower(dn)
	}
	return p.Canonical()
}

// leaksUpstream reports whether s names anything of the real directory.
func leaksUpstream(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "dc=test") || strings.Contains(l, "ou=office") || strings.Contains(l, "ou=branch") || strings.Contains(l, "cn=users,")
}

func sortedDNS(es []listener.Entry) string {
	d := dns(es)
	sort.Strings(d)
	return strings.Join(d, ";")
}

// pc99 is a computer account placed INSIDE a profile base (AD computers are
// objectClass user too) and a member of CN=Staff.
func pc99() *testdir.Entry {
	return &testdir.Entry{DN: "CN=PC-99,OU=Office,DC=test,DC=aldap", Attrs: []testdir.Attribute{
		{Name: "objectClass", Values: []string{"top", "person", "organizationalPerson", "user", "computer"}},
		{Name: "cn", Values: []string{"PC-99"}}, {Name: "name", Values: []string{"PC-99"}},
		{Name: "sAMAccountName", Values: []string{"PC-99$"}}, {Name: "userPrincipalName", Values: []string{"PC-99$@test.aldap"}},
		{Name: "displayName", Values: []string{"PC-99"}}, {Name: "mail", Values: []string{"pc-99@test.aldap"}},
		{Name: "objectCategory", Values: []string{"CN=Computer,CN=Schema,CN=Configuration,DC=test,DC=aldap"}},
		{Name: "userAccountControl", Values: []string{"4096"}}, {Name: "objectGUID", Values: []string{"pc-99-guid-00000001"}},
		{Name: "userPassword", Values: []string{"pc-99-pass"}}, {Name: "memberOf", Values: []string{staffGroup}},
	}}
}

// ---------------------------------------------------------------- check 1

// TestAudit14_A4_BaseConfinement: every upstream search must have one of the
// configured bases as its base; local answers must not reach the upstream.
func TestAudit14_A4_BaseConfinement(t *testing.T) {
	f, rec := recordingFixture(t, withVirolaGroup)
	bases := map[string]bool{}
	for _, b := range f.d.rules.Bases {
		bases[canon(b)] = true
	}
	cases := []struct {
		base     string
		scope    listener.Scope
		filter   string
		wantCode int
		local    bool // must not produce any upstream search
	}{
		{"", listener.ScopeBase, "(objectClass=*)", 0, true},
		{"", listener.ScopeOne, "(objectClass=*)", 0, true},
		{"", listener.ScopeSub, "(objectClass=*)", 0, true},
		{"cn=Subschema", listener.ScopeBase, "(objectClass=*)", 0, true},
		{"cn=Subschema", listener.ScopeSub, "(objectClass=*)", 0, true},
		{"CN=SUBSCHEMA", listener.ScopeOne, "(objectClass=*)", 0, true},
		{"DC=test,DC=aldap", listener.ScopeSub, "(objectClass=*)", ldap.LDAPResultNoSuchObject, true},
		{"OU=Office,DC=test,DC=aldap", listener.ScopeSub, "(objectClass=*)", ldap.LDAPResultNoSuchObject, true},
		{"CN=Alice Adams,OU=Office,DC=test,DC=aldap", listener.ScopeBase, "(objectClass=*)", ldap.LDAPResultNoSuchObject, true},
		{"dc=aldap", listener.ScopeSub, "(objectClass=*)", ldap.LDAPResultNoSuchObject, true},
		{"ou=virola2,dc=aldap", listener.ScopeSub, "(objectClass=*)", ldap.LDAPResultNoSuchObject, true},
		{"ou=virola,dc=aldap,dc=x", listener.ScopeSub, "(objectClass=*)", ldap.LDAPResultNoSuchObject, true},
		{"ou=users,ou=virola,dc=aldap,", listener.ScopeSub, "(objectClass=*)", ldap.LDAPResultNoSuchObject, true},
		{"ou=users;ou=virola;dc=aldap", listener.ScopeSub, "(objectClass=*)", ldap.LDAPResultNoSuchObject, true},
		{"ou=other,ou=virola,dc=aldap", listener.ScopeSub, "(objectClass=*)", ldap.LDAPResultNoSuchObject, true},
		{"uid=alice.adams,ou=users,ou=virola,dc=aldap", listener.ScopeBase, "(objectClass=*)", ldap.LDAPResultNoSuchObject, true},
		{"objectGUID=x+cn=alice.adams,ou=users,ou=virola,dc=aldap", listener.ScopeBase, "(objectClass=*)", ldap.LDAPResultNoSuchObject, true},
		{"cn=x,cn=alice.adams,ou=users,ou=virola,dc=aldap", listener.ScopeBase, "(objectClass=*)", ldap.LDAPResultNoSuchObject, true},
		{"cn=alice.adams,ou=users,ou=virola,dc=aldap", listener.ScopeOne, "(objectClass=*)", 0, true},
		{"cn=virola-users,ou=groups,ou=virola,dc=aldap", listener.ScopeOne, "(objectClass=*)", 0, true},
		// Variants that legitimately go upstream: the base must still be a profile base.
		{vb, listener.ScopeSub, "(objectClass=*)", 0, false},
		{" OU=Users , OU=Virola , DC=Aldap ", listener.ScopeSub, "(objectClass=*)", 0, false},
		{"ou=users,ou=virola,dc=aldap", listener.ScopeOne, "(objectClass=*)", 0, false},
		{"cn=alice.adams+sn=Adams,ou=users,ou=virola,dc=aldap", listener.ScopeBase, "(objectClass=*)", 0, false},
		{`cn=ou\3dusers\2cou\3dvirola\2cdc\3daldap,ou=users,ou=virola,dc=aldap`, listener.ScopeBase, "(objectClass=*)", 0, false},
		{`cn=ou\=users\,ou\=virola\,dc\=aldap,ou=users,ou=virola,dc=aldap`, listener.ScopeSub, "(objectClass=*)", 0, false},
		{"cn=#616c696365,ou=users,ou=virola,dc=aldap", listener.ScopeBase, "(objectClass=*)", 0, false},
		{"cn=alice.adams,ou=users,ou=virola,dc=aldap", listener.ScopeBase, "(&)", 0, false},
	}
	for _, tc := range cases {
		rec.take()
		res, es := f.search(t, tc.base, tc.scope, tc.filter)
		if res.Code != tc.wantCode {
			t.Errorf("%q/%s: code %d, want %d (entries %v)", tc.base, tc.scope, res.Code, tc.wantCode, dns(es))
		}
		if res.MatchedDN != "" || res.Diagnostic != "" {
			t.Errorf("%q/%s: matchedDN %q diag %q must be empty", tc.base, tc.scope, res.MatchedDN, res.Diagnostic)
		}
		reqs := rec.take()
		if tc.local && len(reqs) > 0 {
			t.Errorf("%q/%s: %d upstream searches for a local answer: %+v", tc.base, tc.scope, len(reqs), reqs)
		}
		for _, r := range reqs {
			if !bases[canon(r.Base)] {
				t.Errorf("%q/%s: upstream search with base %q outside the profile bases", tc.base, tc.scope, r.Base)
			}
			if r.Scope != upstream.ScopeSub {
				t.Errorf("%q/%s: upstream scope %d", tc.base, tc.scope, r.Scope)
			}
			if r.Filter == nil || !strings.Contains(r.Filter.String(), "objectCategory=person") {
				t.Errorf("%q/%s: upstream filter lacks the profile filter: %v", tc.base, tc.scope, r.Filter)
			}
		}
		for _, e := range es {
			if leaksUpstream(e.DN) {
				t.Errorf("%q/%s: entry DN %q names the real directory", tc.base, tc.scope, e.DN)
			}
		}
	}
	// Root DSE with scope sub must be answered locally and empty.
	if res, es := f.search(t, "", listener.ScopeSub, "(objectClass=*)"); res.Code != 0 || len(es) != 0 || len(rec.take()) != 0 {
		t.Errorf("root sub: %v %v", res, dns(es))
	}
}

// ---------------------------------------------------------------- check 2

// TestAudit14_A4_AttrAllowlist: whatever is requested, only allowed client
// attributes come back and no value names the real directory.
func TestAudit14_A4_AttrAllowlist(t *testing.T) {
	f, rec := recordingFixture(t, withVirolaGroup)
	allowed := map[string]bool{}
	for _, a := range f.d.rules.AllowedAttrs() {
		allowed[strings.ToLower(a)] = true
	}
	requests := [][]string{
		nil, {"*"}, {"+"}, {"*", "+"}, {"1.1"}, {"1.1", "*"},
		{"cn;binary"}, {"cn;range=0-*"}, {"member;range=0-1"}, {"memberOf;range=0-1"},
		{"SAMACCOUNTNAME", "Mail", "uID"},
		{"2.5.4.3", "0.9.2342.19200300.100.1.3", "1.2.840.113556.1.4.221"},
		{"nTSecurityDescriptor", "objectSid", "distinguishedName", "entryDN", "userAccountControl", "pwdLastSet", "unicodePwd", "userPassword", "department", "title", "name", "description", "ou", "member", "memberUid"},
		{"memberOf", "distinguishedName"},
	}
	for _, attrs := range requests {
		rec.take()
		res, es := f.search(t, usersDN, listener.ScopeSub, "(sAMAccountName=alice.adams)", attrs...)
		if res.Code != 0 || len(es) != 1 {
			t.Fatalf("%v: %v %v", attrs, res, dns(es))
		}
		for _, a := range es[0].Attrs {
			if !allowed[strings.ToLower(a.Name)] {
				t.Errorf("attrs %v: returned %q outside the allowlist", attrs, a.Name)
			}
			for _, v := range a.Values {
				if leaksUpstream(v) {
					t.Errorf("attrs %v: %s=%q names the real directory", attrs, a.Name, v)
				}
			}
		}
		for _, r := range rec.take() {
			for _, ua := range r.Attrs {
				switch strings.ToLower(ua) {
				case "samaccountname", "objectguid", "userprincipalname", "displayname", "givenname", "sn", "mail", "objectclass":
				case "uid": // membership computation (identityAttrs)
				case "memberof": // Info: fetched although virtual (upstreamAttrs does not skip IsVirtualAttr); never returned
				default:
					t.Errorf("attrs %v: upstream asked for %q", attrs, ua)
				}
			}
		}
	}
	// Group entries: member values are virtual DNs only.
	_, gs := f.search(t, groupsDN, listener.ScopeOne, "(objectClass=*)", "*", "+", "member;range=0-*")
	if len(gs) != 1 {
		t.Fatalf("groups = %v", dns(gs))
	}
	for _, a := range gs[0].Attrs {
		for _, v := range a.Values {
			if leaksUpstream(v) {
				t.Errorf("group %s=%q names the real directory", a.Name, v)
			}
		}
	}
	// Events never carry real DNs for searches.
	for _, e := range f.ev.ev {
		if e.Event != "search" {
			continue
		}
		if leaksUpstream(fmt.Sprint(e.Data["base"])) {
			t.Errorf("search event base %v", e.Data["base"])
		}
	}
}

// TestAudit14_A4_MappedNameOnly: when only the client name is mapped
// (uid = "sAMAccountName") the upstream name must be neither returned nor
// filterable (SPEC §3.4: allow + map keys form the allowlist).
func TestAudit14_A4_MappedNameOnly(t *testing.T) {
	f, rec := recordingFixture(t, func(p *config.Profile) {
		p.Attrs.Allow = []string{"displayName", "mail", "objectClass"}
		p.Attrs.Map = map[string]string{"uid": "sAMAccountName"}
	})
	_, es := f.search(t, usersDN, listener.ScopeSub, "(uid=alice.adams)", "uid", "sAMAccountName", "sAMAccountName;binary")
	if len(es) != 1 || attr(es[0], "uid") == nil || attr(es[0], "sAMAccountName") != nil {
		t.Errorf("mapped-only: %+v", es)
	}
	rec.take()
	res, es := f.search(t, usersDN, listener.ScopeSub, "(sAMAccountName=alice.adams)")
	if res.Code != 0 || len(es) != 0 || len(rec.take()) != 0 {
		t.Errorf("(sAMAccountName=) with only uid mapped must be denied: %v %v", res, dns(es))
	}
	if ev := f.ev.last("search"); fmt.Sprint(ev.Data["denied_terms"]) != "[sAMAccountName]" {
		t.Errorf("denied_terms = %v", ev.Data["denied_terms"])
	}
}

// ---------------------------------------------------------------- check 3

// TestAudit14_A4_DeniedFilterNoOracle: a filter term on a denied attribute
// must not change the answer depending on the real value (pairs of filters
// that differ only in the denied value must give identical results), must
// never widen beyond (objectClass=*) and must never reach the upstream.
func TestAudit14_A4_DeniedFilterNoOracle(t *testing.T) {
	f, rec := recordingFixture(t, func(p *config.Profile) {
		withVirolaGroup(p)
		p.Honeytokens = []string{honeyAcct}
	})
	f.d.o.HoneytokenLock = time.Hour
	_, all := f.search(t, usersDN, listener.ScopeSub, "(objectClass=*)")
	everyone := sortedDNS(all)
	if len(all) != 20 { // 19 users + honeytoken
		t.Fatalf("baseline = %d", len(all))
	}
	// alice: department=IT, title=Director, memberOf CN=Directors, UAC 512; the
	// honeytoken has title "Specialist" and no department.
	pairs := []struct{ hit, miss string }{
		{"(department=IT)", "(department=Nope)"},
		{"(!(department=IT))", "(!(department=Nope))"},
		{"(!(!(department=IT)))", "(!(!(department=Nope)))"},
		{"(&(!(department=IT))(sAMAccountName=alice.adams))", "(&(!(department=Nope))(sAMAccountName=alice.adams))"},
		{"(|(department=IT)(sAMAccountName=bob.brown))", "(|(department=Nope)(sAMAccountName=bob.brown))"},
		{"(department=I*)", "(department=N*)"},
		{"(department~=IT)", "(department~=Nope)"},
		{"(department>=IT)", "(department>=ZZZ)"},
		{"(department:caseExactMatch:=IT)", "(department:caseExactMatch:=Nope)"},
		{"(department:dn:=IT)", "(department:dn:=Nope)"},
		{"(title=Director)", "(title=Nope)"},
		{"(!(title=Director))", "(!(title=Nope))"},
		{"(&(!(title=Specialist))(sAMAccountName=h.petrenko))", "(&(!(title=Nope))(sAMAccountName=h.petrenko))"},
		{"(userAccountControl:1.2.840.113556.1.4.803:=512)", "(userAccountControl:1.2.840.113556.1.4.803:=2)"},
		{"(!(userAccountControl:1.2.840.113556.1.4.803:=512))", "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"},
		{"(userAccountControl=512)", "(userAccountControl=514)"},
		{"(memberOf=CN=Directors,CN=Users,DC=test,DC=aldap)", "(memberOf=CN=Nope,CN=Users,DC=test,DC=aldap)"},
		{"(!(memberOf=CN=Directors,CN=Users,DC=test,DC=aldap))", "(!(memberOf=CN=Nope,CN=Users,DC=test,DC=aldap))"},
		{"(memberOf:1.2.840.113556.1.4.1941:=CN=Staff,CN=Users,DC=test,DC=aldap)", "(memberOf:1.2.840.113556.1.4.1941:=CN=Nope,CN=Users,DC=test,DC=aldap)"},
		{"(distinguishedName=CN=Alice Adams,OU=Office,DC=test,DC=aldap)", "(distinguishedName=CN=Nope,OU=Office,DC=test,DC=aldap)"},
		{"(2.5.4.3=Alice Adams)", "(2.5.4.3=Nope)"},
		{"(1.2.840.113556.1.4.221=alice.adams)", "(1.2.840.113556.1.4.221=nope)"},
		{"(name=Alice Adams)", "(name=Nope)"},
		{"(objectCategory=person)", "(objectCategory=computer)"},
		{"(:1.2.840.113556.1.4.803:=512)", "(:1.2.840.113556.1.4.803:=2)"},
		{"(department;lang-en=IT)", "(department;lang-en=Nope)"},
		{"(userPassword=alice.adams-pass)", "(userPassword=nope)"},
		{"(unicodePwd=*)", "(unicodePwd=x)"},
	}
	for _, p := range pairs {
		rec.take()
		rh, hes := f.search(t, usersDN, listener.ScopeSub, p.hit)
		rm, mes := f.search(t, usersDN, listener.ScopeSub, p.miss)
		if rh.Code != 0 || rm.Code != 0 || rh.Diagnostic != "" || rm.Diagnostic != "" {
			t.Errorf("%s / %s: codes %v %v", p.hit, p.miss, rh, rm)
		}
		if sortedDNS(hes) != sortedDNS(mes) {
			t.Errorf("ORACLE %s → %v, %s → %v", p.hit, dns(hes), p.miss, dns(mes))
		}
		if len(hes) > len(all) {
			t.Errorf("%s widened the result: %d > %d", p.hit, len(hes), len(all))
		}
		for _, r := range rec.take() {
			for _, a := range r.Filter.Attrs() {
				switch strings.ToLower(a) {
				case "samaccountname", "objectclass", "objectcategory", "useraccountcontrol", "userprincipalname", "mail", "displayname", "sn", "givenname", "objectguid":
				default:
					t.Errorf("%s / %s: denied attribute %q reached the upstream filter %s", p.hit, p.miss, a, r.Filter)
				}
			}
			if strings.Contains(r.Filter.String(), "department") || strings.Contains(r.Filter.String(), "title") || strings.Contains(r.Filter.String(), "unicodePwd") {
				t.Errorf("%s / %s: upstream filter %s", p.hit, p.miss, r.Filter)
			}
		}
	}
	// Positive controls: a NOT of a denied term is TRUE (documented), never
	// more than everyone; denied presence is FALSE.
	if _, es := f.search(t, usersDN, listener.ScopeSub, "(!(department=*))"); sortedDNS(es) != everyone {
		t.Errorf("(!(denied=*)) = %v", dns(es))
	}
	if _, es := f.search(t, usersDN, listener.ScopeSub, "(department=*)"); len(es) != 0 {
		t.Errorf("(denied=*) = %v", dns(es))
	}
	// Hidden classes via objectClass/objectCategory never match.
	for _, fl := range []string{"(objectClass=computer)", "(objectCategory=computer)", "(objectClass=group)", "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))"} {
		if _, es := f.search(t, vb, listener.ScopeSub, fl); len(es) != 0 {
			t.Errorf("%s = %v", fl, dns(es))
		}
	}
	// (member=<real DN>) on groups.
	if _, es := f.search(t, groupsDN, listener.ScopeSub, "(member=CN=Alice Adams,OU=Office,DC=test,DC=aldap)"); len(es) != 0 {
		t.Errorf("(member=real) = %v", dns(es))
	}
	// Mapped vs upstream names: both allowed in this profile.
	if _, es := f.search(t, usersDN, listener.ScopeSub, "(cn=Alice Adams)"); len(es) != 1 {
		t.Errorf("(cn=) mapped to displayName = %v", dns(es))
	}
}

// TestAudit14_A4_MaskedFilterByOriginal documents SPEC §4.6: a filter on a
// masked attribute is evaluated on the original upstream value (by design;
// reported as Info, not a finding).
func TestAudit14_A4_MaskedFilterByOriginal(t *testing.T) {
	f := newFixture(t, func(p *config.Profile) { p.Attrs.Mask = map[string]string{"mail": "{first1}***@{domain}"} })
	_, es := f.search(t, usersDN, listener.ScopeSub, "(mail=alice.adams@test.aldap)", "mail")
	if len(es) != 1 || attr(es[0], "mail")[0] != "a***@test.aldap" {
		t.Fatalf("masked = %+v", es)
	}
	// Substring probing recovers the original value character by character.
	if _, es := f.search(t, usersDN, listener.ScopeSub, "(mail=alice.ad*)", "mail"); len(es) != 1 {
		t.Errorf("substring on masked attr = %v", dns(es))
	}
}

// ---------------------------------------------------------------- check 4

// TestAudit14_A4_HiddenEntries: computers inside a base, disabled users and
// exclude_filter matches never appear through any path.
func TestAudit14_A4_HiddenEntries(t *testing.T) {
	f, _ := recordingFixture(t, func(p *config.Profile) {
		p.ExcludeFilter = "(title=Director)" // alice, frank
		p.NestedGroups = true
		p.Groups = map[string]config.Group{
			"everyone": {},
			"staff":    {Members: config.GroupMembers{ADGroups: []string{staffGroup}}},
			"picked": {Members: config.GroupMembers{Include: []string{
				"CN=PC-99,OU=Office,DC=test,DC=aldap", "PC-99$", "PC-99$@test.aldap", "pc-99@test.aldap",
				"CN=Carol Clark,OU=Office,DC=test,DC=aldap", "carol.clark", "carol.clark@test.aldap",
				"alice.adams@test.aldap", "CN=Alice Adams,OU=Office,DC=test,DC=aldap",
				"CN=PC-01,CN=Computers,DC=test,DC=aldap", "PC-01$", "Administrator", "bob.brown"}}},
			"wide": {Members: config.GroupMembers{Bases: []string{"DC=test,DC=aldap"}, Filter: "(objectClass=user)"}},
		}
	}, testdir.WithEntries(pc99()))
	hidden := func(where string, es []listener.Entry) {
		t.Helper()
		for _, e := range es {
			l := strings.ToLower(e.DN)
			if strings.Contains(l, "pc-") || strings.Contains(l, "carol") || strings.Contains(l, "jack") || strings.Contains(l, "quinn") ||
				strings.Contains(l, "alice") || strings.Contains(l, "frank") || strings.Contains(l, "administrator") || strings.Contains(l, "svc-") || leaksUpstream(e.DN) {
				t.Errorf("%s: hidden entry %s", where, e.DN)
			}
		}
	}
	_, es := f.search(t, vb, listener.ScopeSub, "(objectClass=*)")
	hidden("tree", es)
	for _, fl := range []string{"(objectClass=*)", "(sAMAccountName=PC-99$)", "(sAMAccountName=carol.clark)", "(sAMAccountName=alice.adams)",
		"(mail=pc-99@test.aldap)", "(cn=PC-99)", "(userPrincipalName=PC-99$@test.aldap)", "(objectClass=computer)", "(!(objectClass=computer))", "(&)"} {
		_, es = f.search(t, usersDN, listener.ScopeSub, fl)
		hidden(fl, es)
	}
	for _, rdn := range []string{"PC-99$", "pc-99$", "carol.clark", "alice.adams", "frank.foster", "Administrator", "PC-01$"} {
		res, es := f.search(t, "cn="+rdn+","+usersDN, listener.ScopeBase, "(objectClass=*)")
		if res.Code != 0 {
			t.Errorf("lookup %s: %v", rdn, res)
		}
		hidden("lookup "+rdn, es)
		tr := f.d.Test(context.Background(), TestRequest{Base: "cn=" + rdn + "," + usersDN, Scope: listener.ScopeBase, Filter: "(objectClass=*)"})
		hidden("Test "+rdn, tr.Entries)
	}
	// Group member lists.
	_, gs := f.search(t, groupsDN, listener.ScopeOne, "(objectClass=*)", "member", "memberUid")
	if len(gs) != 4 {
		t.Fatalf("groups = %v", dns(gs))
	}
	for _, g := range gs {
		var ms []listener.Entry
		for _, m := range attr(g, "member") {
			if g.DN == "cn=wide,"+groupsDN && (strings.Contains(m, "Administrator") || strings.Contains(m, "svc-")) {
				// Info: members.bases wider than profile.bases lists users outside
				// the profile bases (SPEC §4.4 requires only ∩ profile.filter).
				t.Logf("wide group lists out-of-base member %s", m)
				continue
			}
			ms = append(ms, listener.Entry{DN: m})
		}
		hidden("members of "+g.DN, ms)
		if g.DN == "cn=picked,"+groupsDN && len(attr(g, "member")) != 1 {
			t.Errorf("picked members = %v", attr(g, "member"))
		}
	}
	// memberOf / member searches.
	_, es = f.search(t, usersDN, listener.ScopeSub, "(memberOf=cn=staff,"+groupsDN+")")
	hidden("(memberOf=staff)", es)
	_, es = f.search(t, usersDN, listener.ScopeSub, "(memberOf=cn=everyone,"+groupsDN+")")
	hidden("(memberOf=everyone)", es)
	for _, m := range []string{"cn=PC-99$,", "cn=carol.clark,", "cn=alice.adams,"} {
		if _, es = f.search(t, groupsDN, listener.ScopeSub, "(member="+m+usersDN+")"); len(es) != 0 {
			t.Errorf("(member=%s) = %v", m, dns(es))
		}
	}
	// Binds (see SPEC §4.3): disabled → upstream refuses; excluded/computer
	// are refused only with require_membership (documented).
	for _, tc := range []struct {
		name, pw string
		ok       bool
	}{
		// The two "ok" cases go first: a refused (account, password) pair is
		// negative-cached by the guard afterwards.
		{"PC-99$@test.aldap", "pc-99-pass", true},            // computer, require_membership = false: by design
		{"alice.adams@test.aldap", "alice.adams-pass", true}, // excluded, require_membership = false: by design
		{"carol.clark@test.aldap", "carol.clark-pass", false},
		{"cn=carol.clark," + usersDN, "carol.clark-pass", false},
		{"cn=PC-99$," + usersDN, "pc-99-pass", false},
		{"cn=alice.adams," + usersDN, "alice.adams-pass", false},
		{"alice.adams@test.aldams", "alice.adams-pass", false},
	} {
		res := f.bind(t, testConn(fmt.Sprintf("10.9.9.%d", len(tc.name))), tc.name, tc.pw)
		if (res.Code == 0) != tc.ok {
			t.Errorf("bind %s: %v (want ok=%v)", tc.name, res, tc.ok)
		}
	}
	strict := newFixture(t, func(p *config.Profile) {
		p.ExcludeFilter = "(title=Director)"
		p.UserBind.RequireMembership = true
	}, testdir.WithEntries(pc99()))
	for _, tc := range []struct{ name, pw string }{
		{"PC-99$@test.aldap", "pc-99-pass"}, {`TEST\PC-99$`, "pc-99-pass"}, {"alice.adams@test.aldap", "alice.adams-pass"},
		{"frank.foster", "frank.foster-pass"}, {"Administrator@test.aldap", "Administrator-pass"},
	} {
		if res := strict.bind(t, testConn(fmt.Sprintf("10.9.8.%d", len(tc.name))), tc.name, tc.pw); res.Code != ldap.LDAPResultInvalidCredentials {
			t.Errorf("require_membership bind %s: %v", tc.name, res)
		}
	}
}

// TestAudit14_A4_RDNCollisionNoHijack: two users sharing the RDN value both
// get the +objectGUID suffix and neither can bind as the bare virtual DN.
func TestAudit14_A4_RDNCollisionNoHijack(t *testing.T) {
	f := newFixture(t, func(p *config.Profile) {
		p.RDNAttr = "department"
		p.Attrs.Allow = append(p.Attrs.Allow, "department")
	})
	res, es := f.search(t, "cn=IT,"+usersDN, listener.ScopeBase, "(objectClass=*)")
	if res.Code != 0 || len(es) < 2 {
		t.Fatalf("cn=IT lookup = %v %v", res, dns(es))
	}
	for _, e := range es {
		if !strings.Contains(strings.ToLower(e.DN), "+objectguid=") {
			t.Errorf("colliding user without suffix: %s", e.DN)
		}
	}
	for _, pw := range []string{"alice.adams-pass", "bob.brown-pass"} {
		if r := f.bind(t, testConn("10.0.0.7"), "cn=IT,"+usersDN, pw); r.Code != ldap.LDAPResultInvalidCredentials {
			t.Errorf("bind as colliding RDN with %s: %v", pw, r)
		}
	}
	// A narrower client filter makes one of the colliding users appear under
	// the bare DN (documented in DECISIONS for proxy mode; stable in replica).
	_, es = f.search(t, "cn=IT,"+usersDN, listener.ScopeBase, "(sAMAccountName=alice.adams)")
	if len(es) != 1 || es[0].DN != "cn=IT,"+usersDN {
		t.Logf("narrow collision lookup = %v", dns(es))
	}
}

// TestAudit14_A4_Finding_RDNFallbackLeaksUpstreamDN: a user that lacks the
// rdn_attr value gets its REAL upstream DN as the virtual RDN
// (directory.go transform: `if rdn == "" { rdn = e.DN }`; groups.go
// newMember does the same), exposing the real base and structure to every
// client, also through group member/memberUid values and the replica.
func TestAudit14_A4_Finding_RDNFallbackLeaksUpstreamDN(t *testing.T) {
	mut := func(p *config.Profile) {
		p.RDNAttr = "mail"
		p.Groups = map[string]config.Group{"all": {ObjectClass: "posixGroup", GIDNumber: 1000}}
	}
	f := newFixture(t, mut, testdir.WithEntries(noMailUser()))
	check := func(where string, es []listener.Entry) {
		t.Helper()
		for _, e := range es {
			if leaksUpstream(e.DN) {
				t.Errorf("FINDING %s: virtual DN carries the real upstream DN: %s", where, e.DN)
			}
			for _, a := range e.Attrs {
				for _, v := range a.Values {
					if leaksUpstream(v) {
						t.Errorf("FINDING %s: %s=%q carries the real upstream DN", where, a.Name, v)
					}
				}
			}
		}
	}
	_, es := f.search(t, usersDN, listener.ScopeSub, "(sAMAccountName=no.mail)")
	if len(es) != 1 {
		t.Fatalf("no.mail = %v", dns(es))
	}
	check("proxy search", es)
	_, gs := f.search(t, groupsDN, listener.ScopeOne, "(objectClass=*)", "member", "memberUid")
	check("group entry", gs)
	// The leaked DN even reads back as a base.
	if res, es := f.search(t, "cn=CN\\=No Mail\\,OU\\=Office\\,DC\\=test\\,DC\\=aldap,"+usersDN, listener.ScopeBase, "(objectClass=*)"); res.Code == 0 && len(es) == 1 {
		t.Errorf("FINDING the real-DN-derived virtual DN resolves: %v", dns(es))
	}
	// Replica mode.
	rf, rep := replicaFixture(t, mut)
	if err := rf.dc.Dir.Upsert(noMailUser()); err != nil {
		t.Fatal(err)
	}
	if err := rep.Sync(context.Background(), rf.d.SyncReplica); err != nil {
		t.Fatal(err)
	}
	_, es = rf.search(t, usersDN, listener.ScopeSub, "(sAMAccountName=no.mail)")
	check("replica search", es)
}

// TestAudit14_A4_Finding_HoneytokenRDNAttrCasePanic: a single-user lookup
// panics when honeytokens are configured and rdn_attr is not spelled exactly
// like the honeytoken template key (directory.go users():
// h.Attrs[d.rules.RDNAttr][0] on a nil slice). The listener recovers, but
// every such search drops the connection (availability).
func TestAudit14_A4_Finding_HoneytokenRDNAttrCasePanic(t *testing.T) {
	f := newFixture(t, func(p *config.Profile) {
		p.RDNAttr = "samaccountname" // lower-case spelling of a valid attribute
		p.Honeytokens = []string{honeyAcct}
	})
	f.d.o.HoneytokenLock = time.Hour
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("FINDING single-user lookup panicked: %T", r)
		}
	}()
	res, es := f.search(t, "cn=alice.adams,"+usersDN, listener.ScopeBase, "(objectClass=*)")
	if res.Code != 0 || len(es) != 1 {
		t.Errorf("lookup = %v %v", res, dns(es))
	}
}

// ---------------------------------------------------------------- check 6

// TestAudit14_A4_RootDSENoLeak: root DSE, subschema and error results
// never name the upstream.
func TestAudit14_A4_RootDSENoLeak(t *testing.T) {
	f := newFixture(t, withVirolaGroup)
	for _, base := range []string{"", "cn=Subschema"} {
		_, es := f.search(t, base, listener.ScopeBase, "(objectClass=*)", "*", "+")
		if len(es) != 1 {
			t.Fatalf("%q = %v", base, dns(es))
		}
		for _, a := range es[0].Attrs {
			for _, v := range a.Values {
				if leaksUpstream(v) || strings.Contains(strings.ToLower(v), "test.aldap") || strings.Contains(v, "127.0.0.1") || strings.Contains(strings.ToLower(v), "testdir") {
					t.Errorf("%q: %s=%q leaks", base, a.Name, v)
				}
			}
		}
	}
	// Upstream down: generic diagnostics only.
	f.dc.Kill()
	time.Sleep(50 * time.Millisecond)
	res, _ := f.search(t, usersDN, listener.ScopeSub, "(objectClass=*)")
	if res.Code == 0 || strings.Contains(res.Diagnostic, "127.0.0.1") || strings.Contains(res.Diagnostic, "ldap://") || res.MatchedDN != "" {
		t.Errorf("down: %v", res)
	}
	res = f.bind(t, testConn("10.0.0.5"), "alice.adams@test.aldap", "alice.adams-pass")
	if res.Code == 0 || strings.Contains(res.Diagnostic, "127.0.0.1") || strings.Contains(res.Diagnostic, "ldap://") {
		t.Errorf("down bind: %v", res)
	}
}
