package vdir

import (
	"context"
	"errors"
	"log/slog"
	"sort"
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
	"github.com/alstdev/aldap/internal/testdir"
	"github.com/alstdev/aldap/internal/upstream"
)

const (
	svcDN    = "CN=svc-aldap,CN=Users,DC=test,DC=aldap"
	svcPW    = "svc-aldap-pass"
	clientDN = "cn=virola,ou=services,dc=aldap"
	clientPW = "S3CR3T-client"
	vb       = "ou=virola,dc=aldap"
	usersDN  = "ou=users,ou=virola,dc=aldap"
)

var fastArgon = profile.Argon2Params{Time: 1, Memory: 1024, Threads: 1, KeyLen: 16, SaltLen: 8}

type sink struct {
	mu sync.Mutex
	ev []events.Event
}

func (s *sink) Emit(e events.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ev = append(s.ev, e)
}

func (s *sink) last(kind string) *events.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.ev) - 1; i >= 0; i-- {
		if s.ev[i].Event == kind {
			e := s.ev[i]
			return &e
		}
	}
	return nil
}

type collector struct{ entries []listener.Entry }

func (c *collector) Entry(e listener.Entry) error {
	c.entries = append(c.entries, e)
	return nil
}

type failingWriter struct{}

func (failingWriter) Entry(listener.Entry) error { return errors.New("client gone") }

// fixture is a Directory over a testdir upstream.
type fixture struct {
	dc  *testdir.Server
	up  *upstream.Upstream
	d   *Directory
	ev  *sink
	cfg *config.Profile
}

func baseProfile() *config.Profile {
	p := config.DefaultProfile()
	p.Listen = []string{":636"}
	p.VirtualBase = vb
	p.Bases = []string{"OU=Office,DC=test,DC=aldap", "OU=Branch,DC=test,DC=aldap"}
	p.Filter = config.DefaultADFilter
	p.RDNAttr = "sAMAccountName"
	p.Attrs.Allow = []string{"userPrincipalName", "sAMAccountName", "displayName", "givenName", "sn", "mail", "objectGUID", "objectClass", "memberOf"}
	p.Attrs.Map = map[string]string{"uid": "sAMAccountName", "cn": "displayName"}
	p.ClientBind.DN = clientDN
	p.UserBind.DefaultDomain = "test.aldap"
	p.Limits.UpstreamParallel = 2
	return p
}

func newFixture(t *testing.T, mut func(p *config.Profile), dcOpts ...testdir.Option) *fixture {
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
	ev := &sink{}
	d := New(rules, up, Options{Logger: slog.New(slog.DiscardHandler), Events: ev, Version: "test", StartTLS: true, MaxPagingStates: 2})
	return &fixture{dc: dc, up: up, d: d, ev: ev, cfg: p}
}

func (f *fixture) search(t *testing.T, base string, scope listener.Scope, filter string, attrs ...string) (listener.Result, []listener.Entry) {
	t.Helper()
	return f.searchReq(t, &listener.SearchRequest{Base: base, Scope: scope, Filter: filter, Attrs: attrs})
}

func (f *fixture) searchReq(t *testing.T, req *listener.SearchRequest) (listener.Result, []listener.Entry) {
	t.Helper()
	c := &collector{}
	res := f.d.Search(context.Background(), &listener.Conn{}, req, c)
	return res, c.entries
}

func dns(es []listener.Entry) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.DN)
	}
	return out
}

func attr(e listener.Entry, name string) []string {
	for _, a := range e.Attrs {
		if strings.EqualFold(a.Name, name) {
			return a.Values
		}
	}
	return nil
}

func TestSearch_Static(t *testing.T) {
	f := newFixture(t, nil)
	res, es := f.search(t, "", listener.ScopeBase, "(objectClass=*)")
	if res.Code != 0 || len(es) != 1 || es[0].DN != "" {
		t.Fatalf("root DSE: %v %v", res, dns(es))
	}
	root := es[0]
	if attr(root, "namingContexts")[0] != vb || attr(root, "supportedControl")[0] != oidPagedResults ||
		attr(root, "supportedExtension")[0] != oidStartTLS || attr(root, "vendorName")[0] != "ALDAP" || attr(root, "vendorVersion")[0] != "test" ||
		attr(root, "subschemaSubentry")[0] != "cn=Subschema" {
		t.Errorf("root DSE = %+v", root.Attrs)
	}
	if _, es := f.search(t, "", listener.ScopeBase, "(objectClass=*)", "vendorName"); len(es[0].Attrs) != 1 {
		t.Errorf("projection: %+v", es[0].Attrs)
	}
	if _, es := f.search(t, "", listener.ScopeSub, "(objectClass=*)"); len(es) != 0 {
		t.Error("root DSE with scope sub must not match")
	}
	if _, es := f.search(t, "", listener.ScopeBase, "(vendorName=other)"); len(es) != 0 {
		t.Error("root DSE filter ignored")
	}
	_, es = f.search(t, "cn=Subschema", listener.ScopeBase, "(objectClass=subschema)")
	if len(es) != 1 {
		t.Fatalf("subschema: %v", dns(es))
	}
	types := strings.Join(attr(es[0], "attributeTypes"), "\n")
	if !strings.Contains(types, "1.2.840.113556.1.4.221 NAME 'sAMAccountName'") || !strings.Contains(types, "NAME 'uid'") ||
		strings.Contains(types, "memberOf") == false || len(attr(es[0], "objectClasses")) != len(objectClassDefs) {
		t.Errorf("subschema types:\n%s", types)
	}
	// Containers.
	_, es = f.search(t, vb, listener.ScopeBase, "(objectClass=*)")
	if len(es) != 1 || es[0].DN != vb || attr(es[0], "objectClass")[1] != "organizationalUnit" || attr(es[0], "ou")[0] != "virola" {
		t.Errorf("virtual base = %+v", es)
	}
	_, es = f.search(t, vb, listener.ScopeOne, "(ou=*)")
	if got := strings.Join(dns(es), ";"); got != usersDN+";ou=groups,ou=virola,dc=aldap" {
		t.Errorf("one level = %s", got)
	}
	_, es = f.search(t, "ou=groups,ou=virola,dc=aldap", listener.ScopeBase, "(objectClass=organizationalUnit)")
	if len(es) != 1 {
		t.Errorf("groups container = %v", dns(es))
	}
	_, es = f.search(t, "ou=groups,ou=virola,dc=aldap", listener.ScopeSub, "(objectClass=*)")
	if len(es) != 1 {
		t.Errorf("groups subtree (Stage 4: container only) = %v", dns(es))
	}
	// Container DN of other shapes.
	for dn, oc := range map[string]string{"dc=aldap": "domain", "o=corp": "organization", "cn=x": "container", "cn=a+sn=b": "container"} {
		d, _ := ldapfilter.ParseDN(dn)
		if got := containerEntry(d, "").get("objectClass")[1]; got != oc {
			t.Errorf("%s → %s, want %s", dn, got, oc)
		}
	}
}

func TestSearch_Users(t *testing.T) {
	f := newFixture(t, nil)
	res, es := f.search(t, vb, listener.ScopeSub, "(objectClass=*)")
	if res.Code != 0 {
		t.Fatalf("res = %v", res)
	}
	// 3 containers + 22 users − carol, jack, quinn (disabled by the default AD filter).
	if len(es) != 22 {
		t.Fatalf("entries = %d: %v", len(es), dns(es))
	}
	var alice listener.Entry
	for _, e := range es {
		if e.DN == "cn=alice.adams,"+usersDN {
			alice = e
		}
		if strings.Contains(e.DN, "carol") {
			t.Error("disabled account returned")
		}
	}
	if alice.DN == "" {
		t.Fatalf("alice missing: %v", dns(es))
	}
	if attr(alice, "uid")[0] != "alice.adams" || attr(alice, "cn")[0] != "Alice Adams" || attr(alice, "sAMAccountName")[0] != "alice.adams" ||
		attr(alice, "mail")[0] != "alice.adams@test.aldap" || len(attr(alice, "objectGUID")) != 1 || len(attr(alice, "memberOf")) != 2 {
		t.Errorf("alice = %+v", alice.Attrs)
	}
	for _, forbidden := range []string{"telephoneNumber", "userPassword", "department", "title", "distinguishedName", "userAccountControl"} {
		if attr(alice, forbidden) != nil {
			t.Errorf("%s leaked", forbidden)
		}
	}
	ev := f.ev.last(events.Search)
	if ev == nil || ev.Data["results"] != 22 || ev.Data["upstream_queries"] != 2 || ev.Data["scope"] != "sub" || ev.Data["base"] != vb ||
		ev.Data["filter_norm"] != "(objectclass=*)" || ev.Upstream != "ad-test" || ev.UpstreamServer == "" {
		t.Errorf("search event = %+v", ev)
	}
	// ou=users one level: users only, renamed filter attribute.
	_, es = f.search(t, usersDN, listener.ScopeOne, "(uid=alice*)", "uid", "mail")
	if len(es) != 1 || len(es[0].Attrs) != 2 {
		t.Errorf("uid filter = %v %+v", dns(es), es)
	}
	// Mixed-case base and attribute options.
	_, es = f.search(t, "OU=Users, OU=Virola, DC=Aldap", listener.ScopeSub, "(CN=Bob Brown)", "mail;lang-en")
	if len(es) != 1 || attr(es[0], "mail") == nil {
		t.Errorf("mixed case = %v", es)
	}
	// Attribute outside the allowlist: absent from entries, filter yields nothing without an error.
	res, es = f.search(t, usersDN, listener.ScopeSub, "(objectClass=user)", "telephoneNumber", "mail")
	if res.Code != 0 || len(es) != 19 || attr(es[0], "telephoneNumber") != nil || attr(es[0], "mail") == nil {
		t.Errorf("denied attr: %v %d", res, len(es))
	}
	ev = f.ev.last(events.Search)
	if d, _ := ev.Data["attrs_denied"].([]string); len(d) != 1 || d[0] != "telephoneNumber" {
		t.Errorf("attrs_denied = %v", ev.Data["attrs_denied"])
	}
	before := f.dc.Calls().Searches
	res, es = f.search(t, usersDN, listener.ScopeSub, "(telephoneNumber=555*)")
	if res.Code != 0 || len(es) != 0 {
		t.Errorf("denied term: %v %d", res, len(es))
	}
	if f.dc.Calls().Searches != before {
		t.Error("denied term must not reach the upstream")
	}
	ev = f.ev.last(events.Search)
	if d, _ := ev.Data["denied_terms"].([]string); len(d) != 1 || d[0] != "telephoneNumber" || ev.Data["upstream_queries"] != 0 {
		t.Errorf("denied_terms = %v, queries %v", ev.Data["denied_terms"], ev.Data["upstream_queries"])
	}
	// OR with a denied term still works for the allowed branch.
	_, es = f.search(t, usersDN, listener.ScopeSub, "(|(telephoneNumber=1)(uid=bob.brown))")
	if len(es) != 1 {
		t.Errorf("or with denied term = %v", dns(es))
	}
	// "1.1" returns no attributes; "*" everything allowed; "+" nothing virtual.
	_, es = f.search(t, usersDN, listener.ScopeSub, "(uid=bob.brown)", "1.1")
	if len(es) != 1 || len(es[0].Attrs) != 0 {
		t.Errorf("1.1 = %+v", es)
	}
	_, es = f.search(t, usersDN, listener.ScopeSub, "(uid=bob.brown)", "*", "+")
	if len(es) != 1 || attr(es[0], "uid") == nil || attr(es[0], "objectClass") == nil {
		t.Errorf("* = %+v", es)
	}
	// Single user lookups.
	_, es = f.search(t, "cn=bob.brown,"+usersDN, listener.ScopeBase, "(objectClass=*)")
	if len(es) != 1 || es[0].DN != "cn=bob.brown,"+usersDN {
		t.Errorf("user base = %v", dns(es))
	}
	if _, es = f.search(t, "cn=bob.brown,"+usersDN, listener.ScopeSub, "(objectClass=*)"); len(es) != 1 {
		t.Errorf("user sub = %v", dns(es))
	}
	if _, es = f.search(t, "cn=bob.brown,"+usersDN, listener.ScopeOne, "(objectClass=*)"); len(es) != 0 {
		t.Errorf("user one = %v", dns(es))
	}
	if res, es = f.search(t, "cn=carol.clark,"+usersDN, listener.ScopeBase, "(objectClass=*)"); res.Code != 0 || len(es) != 0 {
		t.Errorf("disabled user lookup = %v %v", res, dns(es))
	}
	if res, es = f.search(t, "cn=nobody,"+usersDN, listener.ScopeBase, "(objectClass=*)"); res.Code != 0 || len(es) != 0 {
		t.Errorf("unknown user lookup = %v %v", res, dns(es))
	}
	// Outside the virtual base.
	for _, base := range []string{"DC=test,DC=aldap", "dc=aldap", "ou=other," + vb, "uid=x," + usersDN, "not a dn", "cn=g,ou=groups," + vb + ",dc=more"} {
		if res, _ := f.search(t, base, listener.ScopeSub, "(objectClass=*)"); res.Code != ldap.LDAPResultNoSuchObject || res.MatchedDN != "" {
			t.Errorf("%s → %v", base, res)
		}
	}
	if res, es := f.search(t, "cn=g,ou=groups,"+vb, listener.ScopeBase, "(objectClass=*)"); res.Code != 0 || len(es) != 0 {
		t.Errorf("group (Stage 5) = %v %v", res, dns(es))
	}
	// Filter limits and syntax.
	deep := strings.Repeat("(&", 25) + "(uid=a)" + strings.Repeat(")", 25)
	if res, _ := f.search(t, usersDN, listener.ScopeSub, deep); res.Code != ldap.LDAPResultAdminLimitExceeded {
		t.Errorf("deep filter → %v", res)
	}
	if res, _ := f.search(t, usersDN, listener.ScopeSub, "(uid="); res.Code != ldap.LDAPResultProtocolError {
		t.Errorf("bad filter → %v", res)
	}
	// Writer failure.
	if res := f.d.Search(context.Background(), &listener.Conn{}, &listener.SearchRequest{Base: vb, Scope: listener.ScopeBase, Filter: "(objectClass=*)"}, failingWriter{}); res.Code != ldap.LDAPResultOther {
		t.Errorf("writer failure → %v", res)
	}
}

func TestSearch_Limits(t *testing.T) {
	f := newFixture(t, func(p *config.Profile) { p.Limits.MaxResultSize = 5 })
	res, es := f.search(t, usersDN, listener.ScopeSub, "(objectClass=user)")
	if res.Code != ldap.LDAPResultSizeLimitExceeded || len(es) != 5 {
		t.Errorf("max_result_size: %v %d", res, len(es))
	}
	res, es = f.searchReq(t, &listener.SearchRequest{Base: usersDN, Scope: listener.ScopeSub, Filter: "(objectClass=user)", SizeLimit: 3})
	if res.Code != ldap.LDAPResultSizeLimitExceeded || len(es) != 3 {
		t.Errorf("client size limit: %v %d", res, len(es))
	}
	res, es = f.searchReq(t, &listener.SearchRequest{Base: usersDN, Scope: listener.ScopeSub, Filter: "(uid=a*)", SizeLimit: 3})
	if res.Code != 0 || len(es) != 1 {
		t.Errorf("under the limit: %v %d", res, len(es))
	}
	// Static entries are limited too.
	res, es = f.searchReq(t, &listener.SearchRequest{Base: vb, Scope: listener.ScopeOne, Filter: "(objectClass=*)", SizeLimit: 1})
	if res.Code != ldap.LDAPResultSizeLimitExceeded || len(es) != 1 {
		t.Errorf("static limit: %v %d", res, len(es))
	}
}

func TestSearch_MergeDedupeExclude(t *testing.T) {
	f := newFixture(t, func(p *config.Profile) {
		p.Bases = []string{"DC=test,DC=aldap", "OU=Office,DC=test,DC=aldap"}
		p.ExcludeFilter = "(sAMAccountName=svc-*)"
	})
	_, es := f.search(t, usersDN, listener.ScopeOne, "(objectClass=user)")
	// 19 enabled users + Administrator; svc-* excluded; Office users not duplicated.
	if len(es) != 20 {
		t.Errorf("merged = %d: %v", len(es), dns(es))
	}
	seen := map[string]bool{}
	for _, e := range es {
		if seen[e.DN] {
			t.Errorf("duplicate %s", e.DN)
		}
		seen[e.DN] = true
		if strings.HasPrefix(e.DN, "cn=svc-") {
			t.Errorf("excluded %s returned", e.DN)
		}
	}
	if !sort.StringsAreSorted(dns(es)) {
		t.Error("entries not sorted by DN")
	}
	// Generic kind de-duplicates by DN.
	g := newFixture(t, func(p *config.Profile) { p.Bases = []string{"DC=test,DC=aldap", "OU=Branch,DC=test,DC=aldap"} })
	g.d.rules.Kind = "generic"
	_, es = g.search(t, usersDN, listener.ScopeOne, "(objectClass=user)")
	if len(es) != 22 {
		t.Errorf("generic merged = %d", len(es))
	}
	if k := g.d.dedupeKey(upstream.Entry{DN: "not a dn"}); k != "dn:not a dn" {
		t.Errorf("fallback key = %s", k)
	}
}

func TestSearch_RDNCollision(t *testing.T) {
	f := newFixture(t, func(p *config.Profile) {
		p.RDNAttr = "department"
		p.Attrs.Allow = append(p.Attrs.Allow, "department")
	})
	_, es := f.search(t, usersDN, listener.ScopeOne, "(department=IT)")
	if len(es) < 2 {
		t.Fatalf("IT users = %v", dns(es))
	}
	for _, e := range es {
		if !strings.HasPrefix(strings.ToLower(e.DN), "cn=it+objectguid=") {
			t.Errorf("collision DN = %s", e.DN)
		}
	}
	_, es = f.search(t, usersDN, listener.ScopeOne, "(department=Legal)")
	if len(es) != 1 || es[0].DN != "cn=Legal,"+usersDN {
		t.Errorf("unique rdn = %v", dns(es))
	}
}

func TestSearch_Paging(t *testing.T) {
	f := newFixture(t, nil)
	c := &listener.Conn{}
	page := func(cookie []byte, size uint32) (listener.Result, []listener.Entry, *ldap.ControlPaging) {
		col := &collector{}
		res := f.d.Search(context.Background(), c, &listener.SearchRequest{Base: usersDN, Scope: listener.ScopeSub, Filter: "(objectClass=user)",
			Controls: []ldap.Control{&ldap.ControlPaging{PagingSize: size, Cookie: cookie}}}, col)
		var ctl *ldap.ControlPaging
		for _, x := range res.Controls {
			if p, ok := x.(*ldap.ControlPaging); ok {
				ctl = p
			}
		}
		return res, col.entries, ctl
	}
	res, es, ctl := page(nil, 8)
	if res.Code != 0 || len(es) != 8 || ctl == nil || len(ctl.Cookie) == 0 {
		t.Fatalf("page 1: %v %d %v", res, len(es), ctl)
	}
	before := f.dc.Calls().Searches
	res2, es2, ctl2 := page(ctl.Cookie, 8)
	if res2.Code != 0 || len(es2) != 8 || len(ctl2.Cookie) == 0 || es2[0].DN == es[0].DN {
		t.Fatalf("page 2: %v %d %v", res2, len(es2), ctl2)
	}
	if f.dc.Calls().Searches != before {
		t.Error("second page must be served from memory")
	}
	res3, es3, ctl3 := page(ctl2.Cookie, 8)
	if res3.Code != 0 || len(es3) != 3 || len(ctl3.Cookie) != 0 {
		t.Fatalf("page 3: %v %d %v", res3, len(es3), ctl3)
	}
	if res, _, _ := page(ctl2.Cookie, 8); res.Code != ldap.LDAPResultUnwillingToPerform {
		t.Errorf("finished cookie → %v", res)
	}
	if res, _, _ := page([]byte("bogus"), 10); res.Code != ldap.LDAPResultUnwillingToPerform {
		t.Errorf("unknown cookie → %v", res)
	}
	// Abandon: size 0 with a live cookie.
	_, _, c1 := page(nil, 5)
	if res, es, ctl := page(c1.Cookie, 0); res.Code != 0 || len(es) != 0 || len(ctl.Cookie) != 0 {
		t.Errorf("abandon → %v %d %v", res, len(es), ctl)
	}
	// Eviction: MaxPagingStates = 2.
	_, _, a := page(nil, 5)
	_, _, b := page(nil, 5)
	_, _, _ = page(nil, 5)
	if res, _, _ := page(a.Cookie, 5); res.Code != ldap.LDAPResultUnwillingToPerform {
		t.Errorf("evicted cookie → %v", res)
	}
	if res, _, _ := page(b.Cookie, 5); res.Code != 0 {
		t.Errorf("kept cookie → %v", res)
	}
	// Size limit exceeded is reported on the first page.
	g := newFixture(t, func(p *config.Profile) { p.Limits.MaxResultSize = 7 })
	col := &collector{}
	res = g.d.Search(context.Background(), &listener.Conn{}, &listener.SearchRequest{Base: usersDN, Scope: listener.ScopeSub, Filter: "(objectClass=user)",
		Controls: []ldap.Control{&ldap.ControlPaging{PagingSize: 5}}}, col)
	if res.Code != ldap.LDAPResultSizeLimitExceeded || len(col.entries) != 5 {
		t.Errorf("limited page: %v %d", res, len(col.entries))
	}
}

// fakeUp is a Searcher with scripted failures.
type fakeUp struct {
	searchErr error
	bindErr   error
	entries   []upstream.Entry
	binds     []string
}

func (f *fakeUp) Name() string { return "fake" }
func (f *fakeUp) Search(context.Context, upstream.SearchRequest) (*upstream.Result, error) {
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	return &upstream.Result{Entries: f.entries, Pages: 1, Server: "ldap://fake"}, nil
}
func (f *fakeUp) UserBind(_ context.Context, name, _ string) error {
	f.binds = append(f.binds, name)
	return f.bindErr
}

func fakeDirectory(t *testing.T, up *fakeUp, mut func(p *config.Profile)) (*Directory, *sink) {
	t.Helper()
	p := baseProfile()
	if mut != nil {
		mut(p)
	}
	rules, err := profile.Compile("virola", p, &config.Upstream{Kind: "ad"}, profile.Options{ClientPassword: clientPW, Argon2: fastArgon})
	if err != nil {
		t.Fatal(err)
	}
	ev := &sink{}
	return New(rules, up, Options{Logger: slog.New(slog.DiscardHandler), Events: ev}), ev
}

func TestSearch_UpstreamErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code int
	}{
		{upstream.ErrUnavailable, ldap.LDAPResultUnavailable},
		{upstream.ErrClosed, ldap.LDAPResultUnavailable},
		{context.DeadlineExceeded, ldap.LDAPResultTimeLimitExceeded},
		{errors.New("boom"), ldap.LDAPResultOther},
	} {
		d, _ := fakeDirectory(t, &fakeUp{searchErr: tc.err}, nil)
		col := &collector{}
		res := d.Search(context.Background(), &listener.Conn{}, &listener.SearchRequest{Base: usersDN, Scope: listener.ScopeSub, Filter: "(objectClass=*)"}, col)
		if res.Code != tc.code || len(col.entries) != 0 {
			t.Errorf("%v → %v", tc.err, res)
		}
	}
	// Entry without rdn_attr falls back to its DN; without objectGUID the key is the DN.
	d, _ := fakeDirectory(t, &fakeUp{entries: []upstream.Entry{{DN: "CN=x,DC=y", Attrs: map[string][]string{"mail": {"x@y"}}}}}, nil)
	col := &collector{}
	d.Search(context.Background(), &listener.Conn{}, &listener.SearchRequest{Base: usersDN, Scope: listener.ScopeSub, Filter: "(objectClass=*)"}, col)
	if want := d.rules.UserDN("CN=x,DC=y"); len(col.entries) != 1 || col.entries[0].DN != want {
		t.Errorf("fallback rdn = %v", dns(col.entries))
	}
}

func TestRedactFilter(t *testing.T) {
	for in, want := range map[string]string{
		"(&(uid=a)(userPassword=secret))": "(&(uid=a)(userpassword=***))",
		"(unicodePwd=*)":                  "(unicodepwd=*)",
		"(userPassword=sec*ret)":          "(userpassword=***)",
		"(|(UID=b)(uid=a))":               "(|(uid=a)(uid=b))",
		"(userPassword>=x)":               "(userpassword>=***)",
	} {
		f, err := ldapfilter.Parse(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := redactFilter(f); got != want {
			t.Errorf("redact(%s) = %s, want %s", in, got, want)
		}
	}
	if redactFilter(nil) != "" {
		t.Error("nil filter")
	}
}

func TestBind_Fixture(t *testing.T) {
	f := newFixture(t, nil)
	bind := func(name, pw string) (listener.Result, *events.Event) {
		c := &listener.Conn{}
		res := f.d.Bind(context.Background(), c, name, []byte(pw))
		if res.Code == 0 {
			return res, f.ev.last(events.BindOK)
		}
		return res, f.ev.last(events.BindFail)
	}
	cases := []struct {
		name, pw string
		code     int
		reason   string
		level    string
		kind     string
	}{
		{"", "", ldap.LDAPResultInvalidCredentials, "anonymous", "low", "anonymous"},
		{"alice.adams", "", ldap.LDAPResultInvalidCredentials, "anonymous", "low", "anonymous"},
		{"", "pw", ldap.LDAPResultInvalidCredentials, "anonymous", "low", "anonymous"},
		{clientDN, clientPW, 0, "", "low", "client"},
		{"CN=Virola, OU=Services, DC=Aldap", clientPW, 0, "", "low", "client"},
		{clientDN, "wrong", ldap.LDAPResultInvalidCredentials, "invalid_password", "low", "client"},
		{"alice.adams@test.aldap", "alice.adams-pass", 0, "", "low", "user"},
		{`TEST\alice.adams`, "alice.adams-pass", 0, "", "low", "user"},
		{"alice.adams", "alice.adams-pass", 0, "", "low", "user"},
		{"cn=alice.adams," + usersDN, "alice.adams-pass", 0, "", "low", "user"},
		{"alice.adams@test.aldap", "wrong", ldap.LDAPResultInvalidCredentials, "invalid_password", "low", "user"},
		{"carol.clark@test.aldap", "carol.clark-pass", ldap.LDAPResultInvalidCredentials, "disabled", "low", "user"},
		{"eve.evans@test.aldap", "eve.evans-pass", ldap.LDAPResultInvalidCredentials, "locked_in_ad", "medium", "user"},
		{"nobody@test.aldap", "x", ldap.LDAPResultInvalidCredentials, "unknown_account", "low", "user"},
		{"cn=nobody," + usersDN, "x", ldap.LDAPResultInvalidCredentials, "unknown_account", "low", "user"},
		{"cn=carol.clark," + usersDN, "carol.clark-pass", ldap.LDAPResultInvalidCredentials, "unknown_account", "low", "user"},
		{"CN=Alice Adams,OU=Office,DC=test,DC=aldap", "alice.adams-pass", ldap.LDAPResultInvalidCredentials, "unknown_account", "low", "user"},
	}
	for _, tc := range cases {
		res, ev := bind(tc.name, tc.pw)
		if res.Code != tc.code {
			t.Errorf("bind(%q) = %v, want %d", tc.name, res, tc.code)
			continue
		}
		if ev == nil || ev.Reason != tc.reason || ev.Level != tc.level || ev.Data["bind_kind"] != tc.kind {
			t.Errorf("bind(%q) event = %+v", tc.name, ev)
		}
		if res.Diagnostic != "" {
			t.Errorf("bind(%q) leaks diagnostic %q", tc.name, res.Diagnostic)
		}
	}
	// Virtual DN bind sets the upstream DN on the connection and in the event.
	c := &listener.Conn{}
	if res := f.d.Bind(context.Background(), c, "cn=bob.brown,"+usersDN, []byte("bob.brown-pass")); res.Code != 0 {
		t.Fatalf("virtual dn bind: %v", res)
	}
	if b := c.Bound(); b.Kind != listener.BindUser || b.Name != "cn=bob.brown,"+usersDN || b.UpstreamDN != "CN=Bob Brown,OU=Office,DC=test,DC=aldap" {
		t.Errorf("bound = %+v", b)
	}
	if ev := f.ev.last(events.BindOK); ev.Data["upstream_dn"] != "CN=Bob Brown,OU=Office,DC=test,DC=aldap" || ev.Account != "bob.brown" {
		t.Errorf("bind_ok = %+v", ev)
	}
	// Real DNs never reach the upstream.
	before := f.dc.Calls().Binds
	bind("CN=Alice Adams,OU=Office,DC=test,DC=aldap", "alice.adams-pass")
	if f.dc.Calls().Binds != before {
		t.Error("real DN bind reached the upstream")
	}
	// A bad password carries the AD data code in the event only.
	_, ev := bind("alice.adams@test.aldap", "nope")
	if ev.Data["ad_data"] != "52e" || ev.Data["form"] != "upn" {
		t.Errorf("bind_fail data = %v", ev.Data)
	}
}

func TestBind_Policies(t *testing.T) {
	anon := newFixture(t, func(p *config.Profile) { p.AnonymousBind = true })
	c := &listener.Conn{}
	if res := anon.d.Bind(context.Background(), c, "", nil); res.Code != 0 || anon.ev.last(events.BindOK).Data["bind_kind"] != "anonymous" {
		t.Errorf("anonymous allowed: %v", res)
	}
	noUsers := newFixture(t, func(p *config.Profile) { p.UserBind.Allow = false })
	before := noUsers.dc.Calls().Binds
	if res := noUsers.d.Bind(context.Background(), c, "alice.adams", []byte("alice.adams-pass")); res.Code != ldap.LDAPResultInvalidCredentials ||
		noUsers.ev.last(events.BindFail).Reason != "unknown_account" || noUsers.dc.Calls().Binds != before {
		t.Errorf("user_bind.allow=false: %v", res)
	}
	member := newFixture(t, func(p *config.Profile) {
		p.Filter = "(&(objectClass=user)(department=IT))"
		p.UserBind.RequireMembership = true
	})
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"alice.adams@test.aldap", true}, {`TEST\alice.adams`, true}, {"alice.adams", true}, {"cn=alice.adams," + usersDN, true},
		{"dan.davis@test.aldap", false}, {"dan.davis", false}, {"cn=dan.davis," + usersDN, false},
	} {
		pw := strings.Split(strings.TrimPrefix(strings.Split(tc.name, "@")[0], `TEST\`), ",")[0]
		pw = strings.TrimPrefix(pw, "cn=") + "-pass"
		res := member.d.Bind(context.Background(), &listener.Conn{}, tc.name, []byte(pw))
		if (res.Code == 0) != tc.ok {
			t.Errorf("membership bind(%q) = %v", tc.name, res)
		}
		if !tc.ok {
			if ev := member.ev.last(events.BindFail); ev.Reason != "not_member" && ev.Reason != "unknown_account" {
				t.Errorf("membership bind(%q) reason = %s", tc.name, ev.Reason)
			}
		} else if ev := member.ev.last(events.BindOK); ev.Data["upstream_dn"] != "CN=Alice Adams,OU=Office,DC=test,DC=aldap" {
			t.Errorf("membership bind_ok = %+v", ev)
		}
	}
	// Upstream down → unavailable.
	down := newFixture(t, nil)
	down.dc.Kill()
	down.up.Close()
	res := down.d.Bind(context.Background(), &listener.Conn{}, "alice.adams", []byte("alice.adams-pass"))
	if res.Code != ldap.LDAPResultUnavailable || down.ev.last(events.BindFail).Reason != "upstream_error" {
		t.Errorf("upstream down bind = %v", res)
	}
	if res, _ := down.search(t, usersDN, listener.ScopeSub, "(objectClass=*)"); res.Code != ldap.LDAPResultUnavailable {
		t.Errorf("upstream down search = %v", res)
	}
}

func TestBind_FakeErrors(t *testing.T) {
	d, ev := fakeDirectory(t, &fakeUp{bindErr: errors.New("weird")}, nil)
	if res := d.Bind(context.Background(), &listener.Conn{}, "alice", []byte("x")); res.Code != ldap.LDAPResultInvalidCredentials || ev.last(events.BindFail).Reason != "upstream_error" {
		t.Errorf("unknown error → %v", res)
	}
	d, ev = fakeDirectory(t, &fakeUp{bindErr: &upstream.BindError{Reason: upstream.ReasonUpstreamError}}, nil)
	if res := d.Bind(context.Background(), &listener.Conn{}, "alice", []byte("x")); res.Code != ldap.LDAPResultInvalidCredentials || ev.last(events.BindFail).Reason != "upstream_error" {
		t.Errorf("BindError upstream_error → %v", res)
	}
	// Virtual DN that matches two accounts is refused.
	two := &fakeUp{entries: []upstream.Entry{{DN: "CN=a,DC=x"}, {DN: "CN=b,DC=x"}}}
	d, ev = fakeDirectory(t, two, nil)
	if res := d.Bind(context.Background(), &listener.Conn{}, "cn=dup,"+usersDN, []byte("x")); res.Code != ldap.LDAPResultInvalidCredentials ||
		ev.last(events.BindFail).Reason != "unknown_account" || len(two.binds) != 0 {
		t.Errorf("ambiguous → %v", res)
	}
	// Lookup failure during a virtual DN bind.
	d, _ = fakeDirectory(t, &fakeUp{searchErr: upstream.ErrUnavailable}, nil)
	if res := d.Bind(context.Background(), &listener.Conn{}, "cn=a,"+usersDN, []byte("x")); res.Code != ldap.LDAPResultUnavailable {
		t.Errorf("lookup unavailable → %v", res)
	}
	// Membership lookup failure after a successful bind.
	one := &fakeUp{searchErr: errors.New("boom")}
	d, ev = fakeDirectory(t, one, func(p *config.Profile) { p.UserBind.RequireMembership = true })
	if res := d.Bind(context.Background(), &listener.Conn{}, "alice", []byte("x")); res.Code != ldap.LDAPResultInvalidCredentials || ev.last(events.BindFail).Reason != "upstream_error" {
		t.Errorf("membership lookup error → %v", res)
	}
}
