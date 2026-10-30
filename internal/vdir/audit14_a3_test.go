package vdir

// Audit 14, area A.3 (protocol and DoS): resource bounds of the search
// pipeline — upstream fetch size, paging state, event field sizes and the
// algorithmic cost of the local matcher. Failing tests document findings
// (scratchpad/audit/A3.md); nothing here changes production code.

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
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

// recSearcher is a fake upstream that records every request and answers
// with a generated user set (n users), honoring SizeLimit like the real
// one (which stops paging once SizeLimit entries arrived).
type recSearcher struct {
	mu   sync.Mutex
	reqs []upstream.SearchRequest
	n    int
	// served counts the entries handed to the directory in total.
	served int
}

func (s *recSearcher) Name() string { return "fake" }

func (s *recSearcher) UserBind(context.Context, string, string) error { return nil }

func (s *recSearcher) Search(_ context.Context, req upstream.SearchRequest) (*upstream.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reqs = append(s.reqs, req)
	n := s.n
	if req.SizeLimit > 0 && req.SizeLimit < n {
		n = req.SizeLimit
	}
	res := &upstream.Result{Pages: 1, Server: "ldaps://fake"}
	for i := 0; i < n; i++ {
		res.Entries = append(res.Entries, upstream.Entry{DN: fmt.Sprintf("CN=User %06d,OU=Office,DC=test,DC=aldap", i), Attrs: map[string][]string{
			"samaccountname":    {fmt.Sprintf("user%06d", i)},
			"userprincipalname": {fmt.Sprintf("user%06d@test.aldap", i)},
			"displayname":       {fmt.Sprintf("User %06d", i)},
			"mail":              {fmt.Sprintf("user%06d@test.aldap", i)},
			"objectguid":        {fmt.Sprintf("guid-%06d", i)},
			"objectclass":       {"top", "person", "organizationalPerson", "user"},
		}})
	}
	s.served += n
	return res, nil
}

func (s *recSearcher) last(t *testing.T) upstream.SearchRequest {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.reqs) == 0 {
		t.Fatal("no upstream request recorded")
	}
	return s.reqs[len(s.reqs)-1]
}

// fakeDir builds a Directory over recSearcher with the test profile.
func fakeDir(t *testing.T, n int, mut func(*config.Profile), o Options) (*Directory, *recSearcher, *sink) {
	t.Helper()
	p := baseProfile()
	if mut != nil {
		mut(p)
	}
	rules, err := profile.Compile("virola", p, config.DefaultUpstream(), profile.Options{ClientPassword: clientPW, Argon2: fastArgon})
	if err != nil {
		t.Fatal(err)
	}
	ev := &sink{}
	o.Logger = slog.New(slog.DiscardHandler)
	o.Events = ev
	o.Sleep = func(context.Context, time.Duration) {}
	s := &recSearcher{n: n}
	d := New(rules, s, o)
	t.Cleanup(func() { ev.check(t) })
	return d, s, ev
}

func heapInUse() uint64 {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

// ---------------------------------------------------------------- 6. upstream pull

// A filter term on a Local attribute (memberOf — always virtual, also
// without groups — or a computed attribute) moves the whole filter into
// the post-filter and the upstream search runs with SizeLimit 0: the
// entire profile tree (every user of every base) is pulled, transformed
// and only then cut to max_result_size. FINDING A3-2.
func TestAudit14_A3_PostFilterPullsWholeDirectory(t *testing.T) {
	const users = 20000 // "a large domain"; max_result_size stays 5000
	d, s, _ := fakeDir(t, users, nil, Options{})
	for _, f := range []string{
		"(memberOf=cn=x," + groupsDN + ")",
		"(|(uid=nobody)(memberOf=cn=x," + groupsDN + "))",
		"(!(memberOf=cn=x," + groupsDN + "))",
	} {
		t.Run(f, func(t *testing.T) {
			s.mu.Lock()
			s.reqs, s.served = nil, 0
			s.mu.Unlock()
			col := &collector{}
			start := time.Now()
			res := d.Search(context.Background(), boundConn("10.0.0.9"), &listener.SearchRequest{Base: usersDN, Scope: listener.ScopeSub, Filter: f, Attrs: []string{"uid"}, SizeLimit: 10}, col)
			el := time.Since(start)
			s.mu.Lock()
			served, n := s.served, len(s.reqs)
			s.mu.Unlock()
			if n == 0 {
				// Stronger than bounded: without virtual groups a memberOf
				// term is false and nothing is asked upstream.
				t.Logf("filter %s: no upstream request, %d returned (code %d)", f, len(col.entries), res.Code)
				return
			}
			req := s.last(t)
			t.Logf("filter %s: client sizeLimit=10, max_result_size=5000 → upstream SizeLimit=%d, %d entries pulled and transformed, %d returned (code %d) in %v",
				f, req.SizeLimit, served, len(col.entries), res.Code, el)
			if req.SizeLimit <= 0 || served > 2*5000 {
				t.Errorf("upstream fetch is unbounded for a post-filtered search: SizeLimit=%d, pulled %d entries for a 10-entry answer", req.SizeLimit, served)
			}
		})
	}
	// Baseline: a plain upstream term is bounded (limit + 1).
	col := &collector{}
	d.Search(context.Background(), boundConn("10.0.0.9"), &listener.SearchRequest{Base: usersDN, Scope: listener.ScopeSub, Filter: "(uid=user*)", Attrs: []string{"uid"}, SizeLimit: 10}, col)
	if req := s.last(t); req.SizeLimit != 11 {
		t.Errorf("plain search SizeLimit = %d, want 11", req.SizeLimit)
	}
}

// ---------------------------------------------------------------- 6. event sizes

// The search event copies base and the requested attribute list verbatim:
// a client can make every search event ~1 MiB (max_request_bytes) and the
// ring buffer keeps buffer_size (100 000) of them. FINDING A3-3.
func TestAudit14_A3_SearchEventFieldsUnbounded(t *testing.T) {
	d, _, ev := fakeDir(t, 3, nil, Options{})
	hugeBase := "cn=" + strings.Repeat("a", 512<<10) + "," + usersDN // 512 KiB, > DefaultMaxDNLen → noSuchObject
	attrs := make([]string, 50000)
	for i := range attrs {
		attrs[i] = fmt.Sprintf("attr%05d", i)
	}
	before := heapInUse()
	col := &collector{}
	res := d.Search(context.Background(), boundConn("10.0.0.9"), &listener.SearchRequest{Base: hugeBase, Scope: listener.ScopeSub, Filter: "(uid=x)", Attrs: attrs}, col)
	if res.Code != ldap.LDAPResultNoSuchObject {
		t.Fatalf("code = %d", res.Code)
	}
	e := ev.last(events.Search)
	if e == nil {
		t.Fatal("no search event")
	}
	base, _ := e.Data["base"].(string)
	reqAttrs, _ := e.Data["attrs_requested"].([]string)
	denied, _ := e.Data["attrs_denied"].([]string)
	after := heapInUse()
	t.Logf("search event: base %d bytes, attrs_requested %d names, attrs_denied %d names; heap +%d KiB; ×100000 ring = %d GiB",
		len(base), len(reqAttrs), len(denied), int64(after-before)/1024, int64(len(base)+len(reqAttrs)*9*2)*100000>>30)
	if len(base) > 8192 {
		t.Errorf("event field base is %d bytes: not truncated (ring = buffer_size × client-controlled size)", len(base))
	}
	if len(reqAttrs) > 1000 {
		t.Errorf("attrs_requested holds %d names: not bounded", len(reqAttrs))
	}
}

// bind_fail copies the presented bind name verbatim (no length bound).
func TestAudit14_A3_BindEventAccountUnbounded(t *testing.T) {
	d, _, ev := fakeDir(t, 3, func(p *config.Profile) { p.UserBind.Allow = false }, Options{})
	name := strings.Repeat("x", 256<<10) + "@test.aldap"
	res := d.Bind(context.Background(), testConn("10.0.0.9"), name, []byte("pw"))
	if res.Code != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("code = %d", res.Code)
	}
	e := ev.last(events.BindFail)
	if e == nil {
		t.Fatal("no bind_fail event")
	}
	t.Logf("bind_fail account field: %d bytes", len(e.Account))
	if len(e.Account) > 8192 {
		t.Errorf("account field is %d bytes: not truncated", len(e.Account))
	}
}

// ---------------------------------------------------------------- 5. paging

// Cookies are random, bound to the connection; a foreign or stale cookie
// is refused; size 0 abandons; a huge size serves everything.
func TestAudit14_A3_PagingCookieIsolation(t *testing.T) {
	d, _, _ := fakeDir(t, 5, nil, Options{})
	a, b := boundConn("10.0.0.1"), boundConn("10.0.0.2")
	page := func(c *listener.Conn, size uint32, cookie []byte) (listener.Result, int, []byte) {
		col := &collector{}
		res := d.Search(context.Background(), c, &listener.SearchRequest{Base: usersDN, Scope: listener.ScopeSub, Filter: "(uid=*)", Attrs: []string{"uid"},
			Controls: []ldap.Control{&ldap.ControlPaging{PagingSize: size, Cookie: cookie}}}, col)
		var next []byte
		for _, ctl := range res.Controls {
			if p, ok := ctl.(*ldap.ControlPaging); ok {
				next = p.Cookie
			}
		}
		return res, len(col.entries), next
	}
	res, n, cookie := page(a, 2, nil)
	if res.Code != 0 || n != 2 || len(cookie) != 32 {
		t.Fatalf("first page: code %d n %d cookie %q", res.Code, n, cookie)
	}
	if res, _, _ := page(b, 2, cookie); res.Code != ldap.LDAPResultUnwillingToPerform {
		t.Errorf("foreign cookie accepted: %d", res.Code)
	}
	if res, _, _ := page(a, 2, []byte(strings.Repeat("0", 32))); res.Code != ldap.LDAPResultUnwillingToPerform {
		t.Errorf("guessed cookie accepted: %d", res.Code)
	}
	res, n, cookie2 := page(a, 1<<31, cookie) // huge page size → rest
	if res.Code != 0 || n != 3 || len(cookie2) != 0 {
		t.Errorf("huge page: code %d n %d cookie %q", res.Code, n, cookie2)
	}
	if res, _, _ := page(a, 2, cookie); res.Code != ldap.LDAPResultUnwillingToPerform {
		t.Errorf("stale cookie accepted after completion: %d", res.Code)
	}
	// Size 0 on a live cursor abandons it.
	_, _, c3 := page(a, 1, nil)
	if res, n, _ := page(a, 0, c3); res.Code != 0 || n != 0 {
		t.Errorf("abandon: %d %d", res.Code, n)
	}
	if res, _, _ := page(a, 1, c3); res.Code != ldap.LDAPResultUnwillingToPerform {
		t.Errorf("abandoned cookie still live: %d", res.Code)
	}
	// Size 0 on a fresh search returns nothing and stores nothing.
	if res, n, c := page(a, 0, nil); res.Code != 0 || n != 0 || len(c) != 0 {
		t.Errorf("size 0 first page: %d %d %q", res.Code, n, c)
	}
	states := d.pagingStates(a)
	if len(states) != 0 {
		t.Errorf("%d cursors left after abandon/completion", len(states))
	}
}

// Paging state is bounded per connection by count (8 cursors), not by
// bytes or time: 8 × max_result_size entries live until the connection
// closes. The log line gives the measured bytes for the worst-case
// computation in the report.
func TestAudit14_A3_PagingStateRetention(t *testing.T) {
	d, _, _ := fakeDir(t, 5000, nil, Options{}) // max_result_size 5000, cursors 8
	c := boundConn("10.0.0.1")
	before := heapInUse()
	var cookies [][]byte
	for i := 0; i < 9; i++ {
		col := &collector{}
		res := d.Search(context.Background(), c, &listener.SearchRequest{Base: usersDN, Scope: listener.ScopeSub, Filter: "(uid=*)", Attrs: []string{"uid", "mail", "cn", "sn", "givenName"},
			Controls: []ldap.Control{&ldap.ControlPaging{PagingSize: 1}}}, col)
		if res.Code != 0 || len(col.entries) != 1 {
			t.Fatalf("search %d: code %d entries %d", i, res.Code, len(col.entries))
		}
		for _, ctl := range res.Controls {
			if p, ok := ctl.(*ldap.ControlPaging); ok {
				cookies = append(cookies, p.Cookie)
			}
		}
	}
	after := heapInUse()
	states := d.pagingStates(c)
	held := 0
	for _, st := range states {
		held += len(st.entries) - st.pos
	}
	perConn := int64(after - before)
	t.Logf("one connection holds %d cursors, %d entries, ~%d MiB; × server.max_connections 1024 = ~%d GiB worst case (no byte or time bound)",
		len(states), held, perConn>>20, perConn*1024>>30)
	if len(states) != 8 {
		t.Errorf("cursors = %d, want 8 (oldest evicted)", len(states))
	}
	// The evicted (first) cookie is refused, the 9th is live.
	col := &collector{}
	res := d.Search(context.Background(), c, &listener.SearchRequest{Base: usersDN, Scope: listener.ScopeSub, Filter: "(uid=*)",
		Controls: []ldap.Control{&ldap.ControlPaging{PagingSize: 1, Cookie: cookies[0]}}}, col)
	if res.Code != ldap.LDAPResultUnwillingToPerform {
		t.Errorf("evicted cookie → %d", res.Code)
	}
}

// ---------------------------------------------------------------- 7. matcher cost

// Substring matching with many '*' is greedy left-to-right (strings.Index),
// so the worst case is linear per '*', not exponential.
func TestAudit14_A3_SubstringManyStarsLinear(t *testing.T) {
	value := strings.Repeat("a", 4000) + "c" // never ends with b
	stars := strings.Repeat("*a", 1500)      // 3000 chars + envelope < 4096
	f, err := ldapfilter.ParseWithLimits("(cn="+stars+"*b)", ldapfilter.Limits{MaxLen: 4096})
	if err != nil {
		t.Fatal(err)
	}
	e := &entry{dn: "cn=x"}
	e.add("cn", value)
	start := time.Now()
	for i := 0; i < 5000; i++ { // one max_result_size worth of entries
		if e.matches(f) {
			t.Fatal("unexpected match")
		}
	}
	el := time.Since(start)
	t.Logf("(cn=*a×1500*b) against a 4 KB value × 5000 entries: %v", el)
	if el > 3*time.Second {
		t.Errorf("substring matching too slow: %v", el)
	}
}

// Equality on DN-syntax attributes parses the assertion and every entry
// value per term: an OR of memberOf terms over max_result_size entries
// costs terms × values × ParseDN. Measured, reported.
func TestAudit14_A3_DNEqualityORCost(t *testing.T) {
	var terms []string
	for i := 0; len(strings.Join(terms, "")) < 3900; i++ {
		terms = append(terms, fmt.Sprintf("(memberOf=cn=group-%03d,%s)", i, groupsDN))
	}
	terms = terms[:len(terms)-1]
	f, err := ldapfilter.ParseWithLimits("(|"+strings.Join(terms, "")+")", ldapfilter.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	e := &entry{dn: "cn=x"}
	for i := 0; i < 20; i++ {
		e.add("memberOf", fmt.Sprintf("cn=other-%03d,%s", i, groupsDN))
	}
	const entries = 1000 // one fifth of max_result_size; the log extrapolates
	start := time.Now()
	for i := 0; i < entries; i++ {
		if e.matches(f) {
			t.Fatal("unexpected match")
		}
	}
	el := time.Since(start)
	t.Logf("%d memberOf OR terms × 20 values × %d entries: %v (%d ParseDN calls; ×5 for max_result_size ≈ %v per search)",
		len(terms), entries, el, len(terms)*21*entries, el*5)
	// One group entry with 5000 members under the same filter on member.
	g := &entry{dn: virolaGrp}
	for i := 0; i < 5000; i++ {
		g.add("member", fmt.Sprintf("cn=user%06d,%s", i, usersDN))
	}
	gf, err := ldapfilter.ParseWithLimits("(|"+strings.ReplaceAll(strings.Join(terms, ""), "memberOf=", "member=")+")", ldapfilter.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	if g.matches(gf) {
		t.Fatal("unexpected match")
	}
	gel := time.Since(start)
	t.Logf("%d member OR terms against one group of 5000 members: %v", len(terms), gel)
	// More than 1 ms per entry for a 4 KB filter is quadratic territory:
	// FINDING A3-4 (every term re-parses every DN value).
	if el > time.Second || gel > time.Second {
		t.Errorf("DN equality post-filter: %v per %d entries, %v per 5000-member group", el, entries, gel)
	}
}

// Deeply nested NOT/AND with wildcards at the depth limit: Normalize,
// Simplify, Split and matching stay linear in the filter size.
func TestAudit14_A3_DeepFilterOpsCost(t *testing.T) {
	d, _, _ := fakeDir(t, 100, nil, Options{})
	inner := "(|(uid=*a*)(mail=*b*)(cn=*c*)(sn=*d*))"
	f := inner
	for i := 0; i < 19; i++ { // depth 20 = max_filter_depth
		if i%2 == 0 {
			f = "(!" + f + ")"
		} else {
			f = "(&" + f + inner + ")"
		}
	}
	if len(f) > 4096 {
		t.Fatalf("filter %d bytes", len(f))
	}
	start := time.Now()
	for i := 0; i < 20; i++ {
		col := &collector{}
		res := d.Search(context.Background(), boundConn("10.0.0.9"), &listener.SearchRequest{Base: usersDN, Scope: listener.ScopeSub, Filter: f, Attrs: []string{"uid"}}, col)
		if res.Code != 0 {
			t.Fatalf("code %d", res.Code)
		}
	}
	el := time.Since(start)
	t.Logf("depth-20 NOT/AND wildcard filter (%d bytes) × 20 searches over 100 users: %v", len(f), el)
	if el > 5*time.Second {
		t.Errorf("deep filter pipeline too slow: %v", el)
	}
}

// The canonical-DN cache of assertion values stays bounded and returns the
// same answer as a direct parse, for valid and invalid values.
func TestAudit14_A3_FilterDNCacheBounded(t *testing.T) {
	for i := 0; i < filterDNCacheMax*2+10; i++ {
		v := fmt.Sprintf("CN=User%d, DC=Test", i)
		got, ok := canonicalFilterDN(v)
		dn, err := ldapfilter.ParseDN(v)
		if err != nil || !ok || got != dn.Canonical() {
			t.Fatalf("%q: got (%q,%v), parse err %v", v, got, ok, err)
		}
	}
	if _, ok := canonicalFilterDN("not a dn"); ok {
		t.Error("invalid DN accepted")
	}
	long := "cn=" + strings.Repeat("a", filterDNCacheMaxLen) + ",dc=x"
	if _, ok := canonicalFilterDN(long); !ok {
		t.Error("long valid DN rejected")
	}
	filterDNCache.RLock()
	n := len(filterDNCache.m)
	filterDNCache.RUnlock()
	if n > filterDNCacheMax {
		t.Errorf("cache holds %d entries, max %d", n, filterDNCacheMax)
	}
}
