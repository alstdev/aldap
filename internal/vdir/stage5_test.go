package vdir

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/listener"
	"github.com/alstdev/aldap/internal/profile"
	"github.com/alstdev/aldap/internal/testdir"
	"github.com/alstdev/aldap/internal/upstream"
)

const (
	groupsDN   = "ou=groups,ou=virola,dc=aldap"
	virolaGrp  = "cn=virola-users," + groupsDN
	honeyAcct  = "h.petrenko@test.aldap"
	noMailDN   = "CN=No Mail,OU=Office,DC=test,DC=aldap"
	staffGroup = "CN=Staff,CN=Users,DC=test,DC=aldap"
)

// noMailUser is an enabled user without mail (computed-attribute scenario).
func noMailUser() *testdir.Entry {
	return &testdir.Entry{DN: noMailDN, Attrs: []testdir.Attribute{
		{Name: "objectClass", Values: []string{"top", "person", "organizationalPerson", "user"}},
		{Name: "cn", Values: []string{"No Mail"}}, {Name: "sn", Values: []string{"Mail"}}, {Name: "givenName", Values: []string{"No"}},
		{Name: "displayName", Values: []string{"No Mail"}}, {Name: "sAMAccountName", Values: []string{"no.mail"}},
		{Name: "userPrincipalName", Values: []string{"no.mail@test.aldap"}},
		{Name: "objectCategory", Values: []string{"CN=Person,CN=Schema,CN=Configuration,DC=test,DC=aldap"}},
		{Name: "userAccountControl", Values: []string{"512"}}, {Name: "department", Values: []string{"IT"}},
		{Name: "telephoneNumber", Values: []string{"+380441234567"}}, {Name: "objectGUID", Values: []string{"no-mail-guid-0001"}},
		{Name: "userPassword", Values: []string{"no.mail-pass"}},
	}}
}

func testConn(ip string) *listener.Conn {
	return listener.NewConn("c-t", "virola", &net.TCPAddr{IP: net.ParseIP(ip), Port: 4000})
}

func withVirolaGroup(p *config.Profile) {
	p.Groups = map[string]config.Group{"virola-users": {Description: "All Virola users", ObjectClass: "groupOfNames"}}
}

func (f *fixture) searchFrom(t *testing.T, c *listener.Conn, base string, scope listener.Scope, filter string, attrs ...string) (listener.Result, []listener.Entry) {
	t.Helper()
	col := &collector{}
	res := f.d.Search(context.Background(), c, &listener.SearchRequest{Base: base, Scope: scope, Filter: filter, Attrs: attrs}, col)
	return res, col.entries
}

func (f *fixture) bind(t *testing.T, c *listener.Conn, name, pw string) listener.Result {
	t.Helper()
	return f.d.Bind(context.Background(), c, name, []byte(pw))
}

// TestGroups_Virola is the mandatory Stage 5 scenario: two bases, computers
// excluded, a group with everyone, memberOf on users (TESTING.md 1, 7).
func TestGroups_Virola(t *testing.T) {
	f := newFixture(t, withVirolaGroup)
	// Whole tree: containers, 19 users from both bases, the group, no computer.
	res, es := f.search(t, vb, listener.ScopeSub, "(objectClass=*)")
	if res.Code != 0 || len(es) != 3+19+1 {
		t.Fatalf("tree = %d %v", len(es), dns(es))
	}
	for _, e := range es {
		if strings.Contains(strings.ToLower(e.DN), "pc-0") || strings.Contains(strings.ToLower(e.DN), "carol") {
			t.Errorf("unexpected entry %s", e.DN)
		}
	}
	// The group under ou=groups with every enabled user as member.
	_, es = f.search(t, groupsDN, listener.ScopeOne, "(objectClass=groupOfNames)")
	if len(es) != 1 || es[0].DN != virolaGrp {
		t.Fatalf("groups = %v", dns(es))
	}
	g := es[0]
	members := attr(g, "member")
	if len(members) != 19 || attr(g, "cn")[0] != "virola-users" || attr(g, "description")[0] != "All Virola users" || attr(g, "objectClass")[1] != "groupOfNames" {
		t.Errorf("group = %+v", g.Attrs)
	}
	for _, m := range members {
		if !strings.HasSuffix(m, ","+usersDN) {
			t.Errorf("member %s is not a virtual DN", m)
		}
		if strings.Contains(m, "carol") || strings.Contains(m, "jack") || strings.Contains(m, "quinn") {
			t.Errorf("disabled member %s", m)
		}
	}
	if !contains(members, "cn=alice.adams,"+usersDN) || !contains(members, "cn=olga.owens,"+usersDN) {
		t.Errorf("members miss both bases: %v", members)
	}
	// memberOf on users is the virtual group DN; (memberOf=) lists the same users.
	_, es = f.search(t, usersDN, listener.ScopeSub, "(uid=alice.adams)", "memberOf")
	if len(es) != 1 || len(attr(es[0], "memberOf")) != 1 || attr(es[0], "memberOf")[0] != virolaGrp {
		t.Errorf("alice memberOf = %+v", es)
	}
	before := f.dc.Calls().Searches
	_, es = f.search(t, usersDN, listener.ScopeSub, "(memberOf="+virolaGrp+")", "uid")
	if len(es) != 19 {
		t.Errorf("(memberOf=) = %d", len(es))
	}
	if n := f.dc.Calls().Searches - before; n != 2 {
		t.Errorf("membership must be cached: %d upstream searches", n)
	}
	if _, es = f.search(t, usersDN, listener.ScopeSub, "(memberOf=cn=other,"+groupsDN+")"); len(es) != 0 {
		t.Errorf("unknown group memberOf = %v", dns(es))
	}
	if _, es = f.search(t, usersDN, listener.ScopeSub, "(&(uid=bob*)(!(memberOf="+virolaGrp+")))"); len(es) != 0 {
		t.Errorf("negated memberOf = %v", dns(es))
	}
	// (member=<dn>) on groups, DN-compared.
	_, es = f.search(t, groupsDN, listener.ScopeSub, "(member=CN=Alice.Adams, "+usersDN+")", "cn")
	if len(es) != 1 || len(es[0].Attrs) != 1 {
		t.Errorf("(member=) = %v", es)
	}
	if _, es = f.search(t, groupsDN, listener.ScopeSub, "(member=cn=carol.clark,"+usersDN+")"); len(es) != 0 {
		t.Errorf("disabled member matched: %v", dns(es))
	}
	// One group by DN; unknown group; scope one of a group.
	if _, es = f.search(t, virolaGrp, listener.ScopeBase, "(objectClass=*)"); len(es) != 1 {
		t.Errorf("group base = %v", dns(es))
	}
	if _, es = f.search(t, "cn=VIROLA-USERS,"+groupsDN, listener.ScopeSub, "(cn=virola-users)"); len(es) != 1 {
		t.Errorf("group case-insensitive = %v", dns(es))
	}
	if res, es = f.search(t, "cn=nope,"+groupsDN, listener.ScopeBase, "(objectClass=*)"); res.Code != 0 || len(es) != 0 {
		t.Errorf("unknown group = %v %v", res, dns(es))
	}
	if _, es = f.search(t, virolaGrp, listener.ScopeOne, "(objectClass=*)"); len(es) != 0 {
		t.Errorf("group one level = %v", dns(es))
	}
	// Groups container listing: base and one level.
	if _, es = f.search(t, groupsDN, listener.ScopeBase, "(objectClass=*)"); len(es) != 1 || es[0].DN != groupsDN {
		t.Errorf("groups base = %v", dns(es))
	}
	if _, es = f.search(t, groupsDN, listener.ScopeSub, "(objectClass=*)"); len(es) != 2 {
		t.Errorf("groups sub = %v", dns(es))
	}
	// Subschema lists the group classes.
	_, es = f.search(t, "cn=Subschema", listener.ScopeBase, "(objectClass=*)", "objectClasses")
	if !strings.Contains(strings.Join(attr(es[0], "objectClasses"), "\n"), "'groupOfNames'") {
		t.Error("subschema lacks groupOfNames")
	}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

func TestGroups_Sources(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	f := newFixture(t, func(p *config.Profile) {
		p.NestedGroups = true
		p.Cache.TTL = config.Duration(time.Minute)
		p.Groups = map[string]config.Group{
			"staff":   {ObjectClass: "group", Members: config.GroupMembers{ADGroups: []string{staffGroup}}},
			"vip":     {ObjectClass: "posixGroup", GIDNumber: 10001, Members: config.GroupMembers{Include: []string{"alice.adams@test.aldap", "CN=Bob Brown,OU=Office,DC=test,DC=aldap", "nobody@test.aldap", "CN=Administrator,CN=Users,DC=test,DC=aldap"}, Exclude: []string{"bob.brown"}}},
			"branch":  {Members: config.GroupMembers{Bases: []string{"OU=Branch,DC=test,DC=aldap"}, Filter: "(sn=*)", Exclude: []string{"CN=Olga Owens,OU=Branch,DC=test,DC=aldap", "tina.turner@test.aldap"}}},
			"nothing": {Members: config.GroupMembers{Filter: "(sn=Nobody)"}},
		}
	})
	f.d.now = func() time.Time { return now }
	get := func(name string) listener.Entry {
		t.Helper()
		_, es := f.search(t, "cn="+name+","+groupsDN, listener.ScopeBase, "(objectClass=*)")
		if len(es) != 1 {
			t.Fatalf("group %s = %v", name, dns(es))
		}
		return es[0]
	}
	// staff: direct and nested members of CN=Staff that are enabled: Staff has 13 users
	// (carol, jack, quinn disabled → 10) + Managers (bob, dan, hank, olga) + Directors (alice, frank).
	staff := get("staff")
	m := attr(staff, "member")
	if len(m) != 16 || !contains(m, "cn=alice.adams,"+usersDN) || !contains(m, "cn=olga.owens,"+usersDN) || contains(m, "cn=carol.clark,"+usersDN) {
		t.Errorf("staff members (%d) = %v", len(m), m)
	}
	if attr(staff, "sAMAccountName")[0] != "staff" || attr(staff, "objectClass")[1] != "group" || attr(staff, "groupType") == nil {
		t.Errorf("staff attrs = %+v", staff.Attrs)
	}
	// vip: include by UPN and DN, a DN outside the bases and an unknown account are ignored, exclude by sAMAccountName.
	vip := get("vip")
	if m := attr(vip, "member"); len(m) != 1 || m[0] != "cn=alice.adams,"+usersDN {
		t.Errorf("vip members = %v", m)
	}
	if attr(vip, "gidNumber")[0] != "10001" || attr(vip, "memberUid")[0] != "alice.adams" || attr(vip, "objectClass")[1] != "posixGroup" {
		t.Errorf("vip attrs = %+v", vip.Attrs)
	}
	// branch: own base and filter, excludes by DN and UPN; quinn is disabled.
	branch := get("branch")
	if m := attr(branch, "member"); len(m) != 5 || contains(m, "cn=olga.owens,"+usersDN) || contains(m, "cn=tina.turner,"+usersDN) || contains(m, "cn=alice.adams,"+usersDN) {
		t.Errorf("branch members = %v", m)
	}
	if m := attr(get("nothing"), "member"); len(m) != 0 {
		t.Errorf("empty group = %v", m)
	}
	// memberOf lists every group of a user, sorted.
	_, es := f.search(t, "cn=alice.adams,"+usersDN, listener.ScopeBase, "(objectClass=*)", "memberOf")
	if got := strings.Join(attr(es[0], "memberOf"), ";"); got != "cn=staff,"+groupsDN+";cn=vip,"+groupsDN {
		t.Errorf("alice memberOf = %s", got)
	}
	// Cache: no upstream traffic until the TTL passes.
	before := f.dc.Calls().Searches
	get("staff")
	if f.dc.Calls().Searches != before {
		t.Error("membership recomputed within TTL")
	}
	now = now.Add(2 * time.Minute)
	get("staff")
	if f.dc.Calls().Searches == before {
		t.Error("membership not recomputed after TTL")
	}
	before = f.dc.Calls().Searches
	f.d.InvalidateMembership()
	get("staff")
	if f.dc.Calls().Searches == before {
		t.Error("membership not recomputed after invalidation")
	}
	// Without nested groups only direct members of Staff count.
	f2 := newFixture(t, func(p *config.Profile) {
		p.Groups = map[string]config.Group{"staff": {Members: config.GroupMembers{ADGroups: []string{staffGroup}}}}
	})
	_, es = f2.search(t, "cn=staff,"+groupsDN, listener.ScopeBase, "(objectClass=*)")
	if m := attr(es[0], "member"); len(m) != 10 || contains(m, "cn=alice.adams,"+usersDN) {
		t.Errorf("direct staff members (%d) = %v", len(m), m)
	}
	// Upstream failure while computing membership is reported, not cached.
	f2.d.InvalidateMembership()
	f2.dc.Kill()
	if res, _ := f2.search(t, "cn=staff,"+groupsDN, listener.ScopeBase, "(objectClass=*)"); res.Code != ldap.LDAPResultUnavailable && res.Code != ldap.LDAPResultOther {
		t.Errorf("membership with dead upstream = %v", res)
	}
}

func TestGroups_Generic(t *testing.T) {
	mk := func(nested bool, depth int) *fixture {
		return newFixture(t, func(p *config.Profile) {
			p.NestedGroups, p.NestedDepth = nested, depth
			p.Groups = map[string]config.Group{"staff": {Members: config.GroupMembers{ADGroups: []string{staffGroup, "CN=Missing,CN=Users,DC=test,DC=aldap"}}}}
		}, testdir.WithEntries(&testdir.Entry{DN: "CN=Loop,CN=Users,DC=test,DC=aldap", Attrs: []testdir.Attribute{
			{Name: "objectClass", Values: []string{"top", "group"}}, {Name: "cn", Values: []string{"Loop"}},
			{Name: "member", Values: []string{staffGroup, "CN=Alice Adams,OU=Office,DC=test,DC=aldap", "CN=Ghost,OU=Office,DC=test,DC=aldap"}},
		}}))
	}
	for _, tc := range []struct {
		name   string
		nested bool
		depth  int
		want   int
		alice  bool
	}{
		{"nested", true, 10, 16, true},
		{"flat", false, 10, 10, false},
		{"depth1", true, 1, 10, false},
		{"depth2", true, 2, 14, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := mk(tc.nested, tc.depth)
			f.d.rules.Kind = "generic"
			_, es := f.search(t, "cn=staff,"+groupsDN, listener.ScopeBase, "(objectClass=*)")
			if len(es) != 1 {
				t.Fatalf("group = %v", dns(es))
			}
			m := attr(es[0], "member")
			if len(m) != tc.want || contains(m, "cn=alice.adams,"+usersDN) != tc.alice {
				t.Errorf("members (%d) = %v", len(m), m)
			}
		})
	}
	// A loop through member attributes terminates.
	f := newFixture(t, func(p *config.Profile) {
		p.NestedGroups = true
		p.Groups = map[string]config.Group{"loop": {Members: config.GroupMembers{ADGroups: []string{"CN=Loop,CN=Users,DC=test,DC=aldap"}}}}
	}, testdir.WithEntries(&testdir.Entry{DN: "CN=Loop,CN=Users,DC=test,DC=aldap", Attrs: []testdir.Attribute{
		{Name: "objectClass", Values: []string{"top", "group"}}, {Name: "cn", Values: []string{"Loop"}},
		{Name: "member", Values: []string{"CN=Loop,CN=Users,DC=test,DC=aldap", staffGroup}},
	}}))
	f.d.rules.Kind = "generic"
	if _, es := f.search(t, "cn=loop,"+groupsDN, listener.ScopeBase, "(objectClass=*)"); len(es) != 1 || len(attr(es[0], "member")) != 16 {
		t.Errorf("loop group = %v", es)
	}
}

func TestTransform_ComputedMaskObjectClass(t *testing.T) {
	f := newFixture(t, func(p *config.Profile) {
		p.Attrs.Allow = append(p.Attrs.Allow, "telephoneNumber", "department")
		p.Attrs.Computed = map[string]string{
			"mail":        `{{ or .mail (printf "%s@corp.local" .sAMAccountName) }}`,
			"displayName": "{{ .sn }} {{ .givenName }}",
			"tag":         `{{ .department | lower | default "none" }}-{{ first "" .title "x" }}`,
			"initials":    `{{ regexReplace "^(.).*" "$1" .givenName }}{{ regexReplace "^(.).*" "$1" .sn }}`,
			"broken":      `{{ .sn | regexReplace "(" "x" }}`,
		}
		p.Attrs.Mask = map[string]string{"telephoneNumber": "***{last4}", "mail": "{first1}***@{domain}", "uid": "{first2}"}
		p.ObjectClass.Map = map[string]string{"user": "inetOrgPerson", "person": "person"}
	}, testdir.WithEntries(noMailUser()))
	// Computed mail for the user without mail, masked afterwards; mask of mail for a real one.
	_, es := f.search(t, usersDN, listener.ScopeSub, "(uid=no.mail)")
	if len(es) != 1 {
		t.Fatalf("no.mail = %v", dns(es))
	}
	e := es[0]
	if attr(e, "mail")[0] != "n***@corp.local" || attr(e, "telephoneNumber")[0] != "***4567" || attr(e, "uid")[0] != "no" ||
		attr(e, "displayName")[0] != "Mail No" || attr(e, "tag")[0] != "it-x" || attr(e, "initials")[0] != "NM" || attr(e, "broken") != nil {
		t.Errorf("no.mail = %+v", e.Attrs)
	}
	if oc := attr(e, "objectClass"); !contains(oc, "inetOrgPerson") || contains(oc, "user") {
		t.Errorf("objectClass = %v", oc)
	}
	// Filter on a computed attribute is post-filtered on the computed value (TESTING.md 6).
	before := f.dc.Calls().Searches
	_, es = f.search(t, usersDN, listener.ScopeSub, "(mail=no.mail@corp.local)", "uid")
	if len(es) != 1 || es[0].DN != "cn=no.mail,"+usersDN {
		t.Errorf("computed mail filter = %v", dns(es))
	}
	if f.dc.Calls().Searches-before != 2 {
		t.Errorf("post-filter should still query the bases once each: %d", f.dc.Calls().Searches-before)
	}
	if _, es = f.search(t, usersDN, listener.ScopeSub, "(mail=n***@corp.local)"); len(es) != 0 {
		t.Error("masked value must not match the filter")
	}
	if _, es = f.search(t, usersDN, listener.ScopeSub, "(&(uid=no*)(tag=it-x))"); len(es) != 1 {
		t.Errorf("and with computed = %v", dns(es))
	}
	if _, es = f.search(t, usersDN, listener.ScopeSub, "(|(uid=bob.brown)(initials=NM))", "uid"); len(es) != 2 {
		t.Errorf("or with computed = %v", dns(es))
	}
	if _, es = f.search(t, usersDN, listener.ScopeSub, "(displayName=Brown Bob)"); len(es) != 1 || es[0].DN != "cn=bob.brown,"+usersDN {
		t.Errorf("computed over allowed = %v", dns(es))
	}
	if _, es = f.search(t, usersDN, listener.ScopeSub, "(tag=*)"); len(es) != 20 {
		t.Errorf("present on computed = %d", len(es))
	}
	// Object class mapping in filters: the client class is sent as the upstream class.
	_, es = f.search(t, usersDN, listener.ScopeSub, "(objectClass=inetOrgPerson)", "objectClass")
	if len(es) != 20 || !contains(attr(es[0], "objectClass"), "inetOrgPerson") {
		t.Errorf("objectClass=inetOrgPerson = %d", len(es))
	}
	// Computed attributes are requestable by name and absent when not asked for.
	_, es = f.search(t, usersDN, listener.ScopeSub, "(uid=bob.brown)", "tag")
	if len(es) != 1 || len(es[0].Attrs) != 1 || attr(es[0], "tag") == nil {
		t.Errorf("tag only = %+v", es)
	}
	ev := f.ev.last(events.Search)
	if ev.Data["attrs_denied"] != nil {
		t.Errorf("computed attribute reported as denied: %v", ev.Data)
	}
	// Mask on multi-valued attributes and rune boundaries.
	m, err := profile.CompileMask("x", "{first1}…{last2}")
	if err != nil || m.Apply("ñandú") != "ñ…dú" || m.Apply("ab") != "a…ab" {
		t.Errorf("mask runes: %v %q", err, m.Apply("ñandú"))
	}
}

func TestHoneytokens(t *testing.T) {
	f := newFixture(t, func(p *config.Profile) {
		withVirolaGroup(p)
		p.Honeytokens = []string{honeyAcct, "backup-admin"}
		p.HoneytokenTemplate = map[string]string{"title": "{{ .domain }} admin", "department": "Finance"}
	})
	f.d.o.HoneytokenLock = time.Hour
	c := testConn("10.9.8.7")
	// The trap is listed like a real user, with computed/mapped attributes, and in the group.
	_, es := f.search(t, usersDN, listener.ScopeSub, "(objectClass=*)", "uid", "memberOf", "title")
	if len(es) != 21 {
		t.Fatalf("users with traps = %d", len(es))
	}
	var trap listener.Entry
	for _, e := range es {
		if e.DN == "cn=h.petrenko,"+usersDN {
			trap = e
		}
	}
	if trap.DN == "" || attr(trap, "uid")[0] != "h.petrenko" || attr(trap, "memberOf")[0] != virolaGrp || attr(trap, "title") != nil {
		t.Errorf("trap entry = %+v", trap)
	}
	if f.ev.last(events.Honeytoken) != nil {
		t.Error("a generic listing is not a hit")
	}
	// Traps obey the client filter like real users (and denied terms hide them too).
	if _, es := f.search(t, usersDN, listener.ScopeSub, "(uid=alice.adams)"); len(es) != 1 {
		t.Errorf("filter must exclude traps: %v", dns(es))
	}
	if _, es := f.search(t, usersDN, listener.ScopeSub, "(&(sn=Petrenko)(telephoneNumber=1))"); len(es) != 0 {
		t.Errorf("denied term must hide traps: %v", dns(es))
	}
	if _, es := f.search(t, usersDN, listener.ScopeSub, "(|(sn=Petrenko)(uid=bob.brown))", "uid"); len(es) != 2 {
		t.Errorf("or over trap and user: %v", dns(es))
	}
	_, es = f.search(t, virolaGrp, listener.ScopeBase, "(objectClass=*)", "member")
	if !contains(attr(es[0], "member"), "cn=h.petrenko,"+usersDN) || !contains(attr(es[0], "member"), "cn=backup-admin,"+usersDN) {
		t.Errorf("traps missing from the group: %v", attr(es[0], "member"))
	}
	// Targeted searches hit: identity attributes (mapped too) and the single-user base.
	for _, tc := range []struct{ base, filter string }{
		{usersDN, "(sAMAccountName=H.Petrenko)"}, {usersDN, "(mail=" + honeyAcct + ")"}, {usersDN, "(uid=h.petrenko)"},
		{usersDN, "(&(objectClass=user)(userPrincipalName=" + honeyAcct + "))"}, {"cn=h.petrenko," + usersDN, "(objectClass=*)"},
		{usersDN, "(cn=Backup Admin)"}, {vb, "(|(uid=alice.adams)(uid=backup-admin))"},
	} {
		f.ev.ev = nil
		cc := testConn("10.9.8.7")
		res, es := f.searchFrom(t, cc, tc.base, listener.ScopeSub, tc.filter, "uid")
		if res.Code != 0 || len(es) == 0 {
			t.Errorf("%s: %v %v", tc.filter, res, dns(es))
		}
		ev := f.ev.last(events.Honeytoken)
		if ev == nil || ev.Level != events.LevelHigh || ev.Data["op"] != "search" || ev.ClientIP != "10.9.8.7" {
			t.Errorf("%s: honeytoken event = %+v", tc.filter, ev)
		}
		lk := f.ev.last(events.Lock)
		if lk == nil || lk.Data["target"] != "ip" || lk.Data["key"] != "10.9.8.7" || lk.Data["source"] != "honeytoken" {
			t.Errorf("%s: lock event = %+v", tc.filter, lk)
		}
		if se := f.ev.last(events.Search); se.Data["honeytoken"] == nil {
			t.Errorf("%s: search event lacks honeytoken: %v", tc.filter, se.Data)
		}
	}
	if until, ok := f.d.Locks().IPLocked("10.9.8.7", f.d.now()); !ok || until.Before(f.d.now().Add(59*time.Minute)) {
		t.Errorf("ip not locked: %v %v", until, ok)
	}
	// A locked IP cannot bind at all; searches on existing sessions go on.
	f.ev.ev = nil
	if res := f.bind(t, c, clientDN, clientPW); res.Code != ldap.LDAPResultInvalidCredentials {
		t.Errorf("bind from locked ip = %v", res)
	}
	if ev := f.ev.last(events.BindBlocked); ev == nil || ev.Reason != "ip_locked" {
		t.Errorf("bind_blocked = %+v", ev)
	}
	if res := f.bind(t, testConn("10.9.8.8"), clientDN, clientPW); res.Code != 0 {
		t.Errorf("bind from another ip = %v", res)
	}
	// Binds on trap accounts in every form hit and never reach the upstream.
	for i, name := range []string{honeyAcct, "h.petrenko", "TEST\\h.petrenko", "cn=h.petrenko," + usersDN, "backup-admin"} {
		f.ev.ev = nil
		before := f.dc.Calls().Binds
		cc := testConn(fmt.Sprintf("10.9.9.%d", i)) // every hit locks its source
		if res := f.bind(t, cc, name, "whatever"); res.Code != ldap.LDAPResultInvalidCredentials {
			t.Errorf("%s: bind = %v", name, res)
		}
		if ev := f.ev.last(events.Honeytoken); ev == nil || ev.Data["op"] != "bind" || (ev.Data["account"] != honeyAcct && ev.Data["account"] != "backup-admin") {
			t.Errorf("%s: honeytoken event = %+v", name, ev)
		}
		if ev := f.ev.last(events.BindFail); ev == nil || ev.Reason != "unknown_account" {
			t.Errorf("%s: bind_fail = %+v", name, ev)
		}
		if f.dc.Calls().Binds != before {
			t.Errorf("%s: trap bind reached the upstream", name)
		}
	}
	// honeytoken_in_groups = false keeps traps out of groups but in searches.
	f2 := newFixture(t, func(p *config.Profile) {
		withVirolaGroup(p)
		p.Honeytokens = []string{honeyAcct}
		p.HoneytokenInGroups = false
	})
	_, es = f2.search(t, virolaGrp, listener.ScopeBase, "(objectClass=*)", "member")
	if contains(attr(es[0], "member"), "cn=h.petrenko,"+usersDN) {
		t.Error("trap in group despite honeytoken_in_groups = false")
	}
	if _, es = f2.search(t, usersDN, listener.ScopeSub, "(sn=Petrenko)", "memberOf"); len(es) != 1 || attr(es[0], "memberOf") != nil {
		t.Errorf("trap without groups = %+v", es)
	}
}

func TestHoneypot(t *testing.T) {
	f := newFixture(t, func(p *config.Profile) {
		p.Mode = "honeypot"
		withVirolaGroup(p)
		p.Honeytokens = []string{honeyAcct}
	})
	c := testConn("192.0.2.1")
	before := f.dc.Calls()
	// Root DSE is served quietly; anything in the tree is a hit.
	if res, es := f.searchFrom(t, c, "", listener.ScopeBase, "(objectClass=*)"); res.Code != 0 || len(es) != 1 || f.ev.last(events.Honeytoken) != nil {
		t.Errorf("root DSE in honeypot = %v %v", res, len(es))
	}
	res, es := f.searchFrom(t, c, vb, listener.ScopeSub, "(objectClass=*)")
	if res.Code != 0 || len(es) != 3+1+1 { // containers, the trap user, the group
		t.Errorf("honeypot tree = %v %v", res, dns(es))
	}
	ev := f.ev.last(events.Honeytoken)
	if ev == nil || ev.Data["op"] != "search" || ev.Data["account"] != "anonymous" {
		t.Errorf("honeypot search event = %+v", ev)
	}
	if ev := f.ev.last(events.Search); ev.Upstream != "" {
		t.Errorf("honeypot search event names an upstream: %+v", ev)
	}
	for i, name := range []string{clientDN, "alice.adams@test.aldap", "cn=alice.adams," + usersDN, "x"} {
		f.ev.ev = nil
		if res := f.bind(t, testConn(fmt.Sprintf("192.0.2.%d", 2+i)), name, "pw"); res.Code != ldap.LDAPResultInvalidCredentials {
			t.Errorf("%s: honeypot bind = %v", name, res)
		}
		if ev := f.ev.last(events.Honeytoken); ev == nil || ev.Data["op"] != "bind" || ev.Account != name {
			t.Errorf("%s: event = %+v", name, ev)
		}
	}
	if _, ok := f.d.Locks().IPLocked("192.0.2.2", f.d.now()); !ok {
		t.Error("honeypot bind did not lock the ip")
	}
	if f.dc.Calls() != before {
		t.Errorf("honeypot touched the upstream: %+v", f.dc.Calls())
	}
	// Anonymous bind stays anonymous even in a honeypot.
	if res := f.bind(t, testConn("192.0.2.3"), "", ""); res.Code != ldap.LDAPResultInvalidCredentials {
		t.Errorf("anonymous = %v", res)
	}
}

func TestMock(t *testing.T) {
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "mock.toml")
	if err := os.WriteFile(tomlPath, []byte(`
base_dn = "ou=people,dc=mock"
[[users]]
cn = "Alice Mock"
sAMAccountName = "amock"
userPrincipalName = "amock@mock.local"
mail = ["amock@mock.local", "alice@mock.local"]
userPassword = "S3CR3T-amock"
department = "IT"
uidNumber = 1001
active = true
[[users]]
dn = "cn=Bob Mock,ou=people,dc=mock"
cn = "Bob Mock"
sAMAccountName = "bmock"
userPassword = "S3CR3T-bmock"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	csvPath := filepath.Join(dir, "mock.csv")
	if err := os.WriteFile(csvPath, []byte("cn,sAMAccountName,mail,userPassword\nCarol Mock,cmock,cmock@mock.local|carol@mock.local,S3CR3T-cmock\n,dmock,,x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMock(csvPath, "ou=people,dc=mock"); err == nil || !strings.Contains(err.Error(), "user 2") {
		t.Errorf("csv without cn: %v", err)
	}
	if err := os.WriteFile(csvPath, []byte("cn,sAMAccountName,mail,userPassword\nCarol Mock,cmock,cmock@mock.local|carol@mock.local,S3CR3T-cmock\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, base, want string }{
		{filepath.Join(dir, "none.toml"), "dc=x", "mock file"},
		{filepath.Join(dir, "mock.txt"), "dc=x", ".toml or .csv"},
		{csvPath, "", "base_dn is required"},
		{csvPath, "not a dn", "base_dn"},
	} {
		if _, err := LoadMock(tc.path, tc.base); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.path, err)
		}
	}
	bad := filepath.Join(dir, "bad.toml")
	_ = os.WriteFile(bad, []byte("nope = 1\n"), 0o600)
	if _, err := LoadMock(bad, "dc=x"); err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Errorf("unknown key: %v", err)
	}
	_ = os.WriteFile(bad, []byte("[[users]]\ncn = \"x\"\ndn = \"broken\"\n"), 0o600)
	if _, err := LoadMock(bad, "dc=x"); err == nil || !strings.Contains(err.Error(), "dn") {
		t.Errorf("bad dn: %v", err)
	}
	m, err := LoadMock(tomlPath, "")
	if err != nil || m.Len() != 2 || m.BaseDN() != "ou=people,dc=mock" {
		t.Fatalf("load toml: %v", err)
	}
	cm, err := LoadMock(csvPath, "ou=people,dc=mock")
	if err != nil || cm.Len() != 1 {
		t.Fatalf("load csv: %v", err)
	}
	// A mock profile over the TOML file with a group.
	p := baseProfile()
	p.Mode, p.Filter, p.Upstream = "mock", "(objectClass=*)", ""
	p.UserBind.DefaultDomain = "mock.local"
	p.Bases = []string{m.BaseDN()}
	p.Attrs.Allow = []string{"sAMAccountName", "mail", "department", "uidNumber", "active", "cn"}
	p.Attrs.Map = map[string]string{"uid": "sAMAccountName"}
	p.Groups = map[string]config.Group{"all": {}, "it": {Members: config.GroupMembers{Filter: "(department=IT)"}}}
	rules, err := profile.Compile("mock", p, nil, profile.Options{ClientPassword: clientPW, Argon2: fastArgon})
	if err != nil {
		t.Fatal(err)
	}
	ev := &sink{}
	d := New(rules, m, Options{Events: ev})
	f := &fixture{d: d, ev: ev}
	_, es := f.search(t, usersDN, listener.ScopeSub, "(objectClass=*)", "uid", "mail", "uidNumber", "active", "memberOf")
	if len(es) != 2 || es[0].DN != "cn=amock,"+usersDN || len(attr(es[0], "mail")) != 2 || attr(es[0], "uidNumber")[0] != "1001" || attr(es[0], "active")[0] != "true" {
		t.Errorf("mock users = %+v", es)
	}
	if got := strings.Join(attr(es[0], "memberOf"), ";"); got != "cn=all,"+groupsDN+";cn=it,"+groupsDN {
		t.Errorf("amock memberOf = %s", got)
	}
	if _, es = f.search(t, usersDN, listener.ScopeSub, "(mail=alice@mock.local)", "cn"); len(es) != 1 || attr(es[0], "cn")[0] != "Alice Mock" {
		t.Errorf("mock filter = %v", es)
	}
	if _, es = f.search(t, usersDN, listener.ScopeSub, "(userPassword=*)"); len(es) != 0 {
		t.Error("userPassword must be hidden (denied term)")
	}
	if _, es = f.search(t, "cn=bmock,"+usersDN, listener.ScopeBase, "(objectClass=*)"); len(es) != 1 {
		t.Errorf("mock single user = %v", dns(es))
	}
	if ev := f.ev.last(events.Search); ev.Upstream != "mock" || ev.UpstreamServer != "mock" {
		t.Errorf("mock search event = %+v", ev)
	}
	// Mock binds compare userPassword in every bind form.
	for _, tc := range []struct {
		name, pw string
		code     int
		reason   string
	}{
		{"amock@mock.local", "S3CR3T-amock", 0, ""}, {"amock", "S3CR3T-amock", 0, ""}, {"cn=bmock," + usersDN, "S3CR3T-bmock", 0, ""},
		{"MOCK\\amock", "S3CR3T-amock", 0, ""}, {"amock@mock.local", "nope", ldap.LDAPResultInvalidCredentials, "invalid_password"},
		{"zzz@mock.local", "x", ldap.LDAPResultInvalidCredentials, "unknown_account"}, {clientDN, clientPW, 0, ""},
	} {
		f.ev.ev = nil
		if res := f.bind(t, testConn("127.0.0.1"), tc.name, tc.pw); res.Code != tc.code {
			t.Errorf("%s: bind = %v", tc.name, res)
		}
		if tc.reason != "" {
			if ev := f.ev.last(events.BindFail); ev == nil || ev.Reason != tc.reason {
				t.Errorf("%s: bind_fail = %+v", tc.name, ev)
			}
		}
	}
	// Scope handling of the mock searcher itself.
	ctx := context.Background()
	if r, _ := m.Search(ctx, upstream.SearchRequest{Base: "ou=people,dc=mock", Scope: upstream.ScopeOne}); len(r.Entries) != 2 {
		t.Errorf("one level = %d", len(r.Entries))
	}
	if r, _ := m.Search(ctx, upstream.SearchRequest{Base: "cn=Bob Mock,ou=people,dc=mock", Scope: upstream.ScopeBase, Attrs: []string{"cn"}}); len(r.Entries) != 1 || len(r.Entries[0].Attrs) != 1 {
		t.Errorf("base = %+v", r.Entries)
	}
	if r, _ := m.Search(ctx, upstream.SearchRequest{Base: "dc=mock", Scope: upstream.ScopeSub, SizeLimit: 1}); len(r.Entries) != 1 || !r.Truncated {
		t.Errorf("size limit = %+v", r)
	}
	if _, err := m.Search(ctx, upstream.SearchRequest{Base: "bad dn"}); !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		t.Errorf("bad base: %v", err)
	}
}

func TestTestAndLocks(t *testing.T) {
	f := newFixture(t, func(p *config.Profile) {
		withVirolaGroup(p)
		p.Attrs.Computed = map[string]string{"tag": "{{ .department }}"}
	})
	r := f.d.Test(context.Background(), TestRequest{Base: usersDN, Scope: listener.ScopeSub, Filter: "(&(uid=alice*)(tag=IT)(telephoneNumber=1))", Attrs: []string{"uid", "tag", "memberOf", "secret"}})
	if r.Result.Code != 0 || len(r.Entries) != 0 || r.UpstreamFilter != "" || len(r.DeniedTerms) != 1 || len(r.DeniedAttrs) != 1 || r.UpstreamQueries != 0 {
		t.Errorf("denied test = %+v", r)
	}
	r = f.d.Test(context.Background(), TestRequest{Base: usersDN, Scope: listener.ScopeSub, Filter: "(&(uid=alice*)(tag=IT))", Attrs: []string{"uid", "tag", "memberOf"}, SizeLimit: 5})
	if r.Result.Code != 0 || len(r.Entries) != 1 || !strings.Contains(r.UpstreamFilter, "(sAMAccountName=alice*)") || r.PostFilter != "(tag=IT)" || r.UpstreamQueries != 2 {
		t.Errorf("test = %+v", r)
	}
	s := r.String()
	if !strings.Contains(s, "dn: cn=alice.adams,"+usersDN) || !strings.Contains(s, "memberOf: "+virolaGrp) || !strings.Contains(s, "# upstream_filter:") || !strings.Contains(s, "# post_filter: (tag=IT)") {
		t.Errorf("test output:\n%s", s)
	}
	r = f.d.Test(context.Background(), TestRequest{Base: "dc=other", Scope: listener.ScopeSub, Filter: "(sAMAccountName=h.p)"})
	if r.Result.Code != ldap.LDAPResultNoSuchObject || !strings.Contains(r.String(), "# result: 32") {
		t.Errorf("outside = %+v", r)
	}
	// MemoryLocks semantics.
	l := NewMemoryLocks()
	now := time.Now()
	if _, ok := l.IPLocked("1.1.1.1", now); ok {
		t.Error("fresh table locked")
	}
	l.LockIP("1.1.1.1", now.Add(time.Hour), "honeytoken")
	l.LockIP("1.1.1.1", now.Add(time.Minute), "honeytoken") // shorter lock does not shrink
	if until, ok := l.IPLocked("1.1.1.1", now); !ok || !until.Equal(now.Add(time.Hour)) {
		t.Errorf("lock = %v %v", until, ok)
	}
	if _, ok := l.IPLocked("1.1.1.1", now.Add(2*time.Hour)); ok {
		t.Error("expired lock still active")
	}
	if _, ok := l.IPLocked("1.1.1.1", now); ok {
		t.Error("expired lock not purged")
	}
	d := New(f.d.rules, f.up, Options{})
	if d.Locks() == nil || d.o.HoneytokenLock != 24*time.Hour {
		t.Error("defaults")
	}
}
