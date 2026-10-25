package vdir

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/ids"
	"github.com/alstdev/aldap/internal/ldapfilter"
	"github.com/alstdev/aldap/internal/listener"
	"github.com/alstdev/aldap/internal/metrics"
	"github.com/alstdev/aldap/internal/profile"
	"github.com/alstdev/aldap/internal/upstream"
)

// Searcher is the part of *upstream.Upstream the directory uses; *Mock
// implements it for mode = mock.
type Searcher interface {
	Name() string
	Search(ctx context.Context, req upstream.SearchRequest) (*upstream.Result, error)
	UserBind(ctx context.Context, name, password string) error
}

// SearchSource answers upstream searches: the ttl cache in front of the
// upstream (cache.mode = ttl).
type SearchSource interface {
	Search(ctx context.Context, req upstream.SearchRequest) (*upstream.Result, error)
}

// ReplicaSource holds the synced copy of the profile (cache.mode =
// replica, *cache.Replica); data is what SyncReplica returned.
type ReplicaSource interface {
	Current() (data any, at time.Time, ok bool)
}

// Options tune a Directory.
type Options struct {
	Logger *slog.Logger
	Events events.Sink
	// Version is reported as vendorVersion in the root DSE.
	Version string
	// StartTLS advertises the StartTLS extension in the root DSE.
	StartTLS bool
	// MaxPagingStates bounds the paged-results cursors kept per connection (0 = 8).
	MaxPagingStates int
	// Guard is the rate limiter (nil = no limits and no locks).
	Guard Guard
	// Observer feeds the intrusion detectors (nil = none).
	Observer Observer
	// HoneytokenLock is the IP lock applied on a honeytoken hit (0 = 24h).
	HoneytokenLock time.Duration
	Now            func() time.Time
	// Sleep performs the delays the guard asks for (nil = time.Sleep with ctx).
	Sleep func(context.Context, time.Duration)
	// Metrics receives counters and histograms (nil = none).
	Metrics *metrics.Metrics
	// Cache answers the searches in place of the upstream (cache.mode =
	// ttl). Binds never use it.
	Cache SearchSource
	// Replica serves every search from memory (cache.mode = replica);
	// binds still go to the upstream.
	Replica ReplicaSource
	// Taps observe every client search that ran the pipeline (record,
	// shadow); they are called after the entries were written.
	Taps []Tap
}

// Tap observes client searches (the recorder and the shadow rules,
// internal/record). Search is called on the connection goroutine after
// the entries were sent and must not block: work belongs on its own
// goroutines. It must treat the TapSearch as read-only.
type Tap interface {
	Search(t TapSearch)
}

// TapSearch is one client search seen by a Tap: the request and the whole
// result before paging (a paged search is reported once, at its first
// page; pages served from the cookie are not reported). Searches refused
// by the rate limiter are not reported.
type TapSearch struct {
	Conn      *listener.Conn
	Base      string
	Scope     listener.Scope
	RawFilter string
	// Filter is nil when RawFilter does not parse.
	Filter    *ldapfilter.Filter
	Attrs     []string
	SizeLimit int
	Result    listener.Result
	Entries   []listener.Entry
	// Local marks an answer that does not depend on the filter or the
	// bases: root DSE, subschema, a base outside the virtual tree.
	Local bool
}

// Directory serves one profile. It implements listener.Handler. up is nil
// for mode = honeypot (no upstream at all).
type Directory struct {
	rules *profile.Rules
	up    Searcher
	// src serves searches: the ttl cache or up; binds use up only.
	src SearchSource
	log *slog.Logger
	ev  events.Sink
	o   Options
	now func() time.Time

	memMu sync.Mutex
	mem   *membership
}

var _ listener.Handler = (*Directory)(nil)

// New builds the directory of a profile over its upstream (nil for honeypot).
func New(rules *profile.Rules, up Searcher, o Options) *Directory {
	d := &Directory{rules: rules, up: up, log: o.Logger, ev: o.Events, o: o, now: o.Now}
	if d.log == nil {
		d.log = slog.Default()
	}
	d.log = d.log.With("profile", rules.Name)
	if d.ev == nil {
		d.ev = events.Discard
	}
	if d.now == nil {
		d.now = time.Now
	}
	if d.o.MaxPagingStates <= 0 {
		d.o.MaxPagingStates = 8
	}
	if d.o.Guard == nil {
		d.o.Guard = noGuard{}
	}
	if d.o.Sleep == nil {
		d.o.Sleep = sleepCtx
	}
	if d.o.HoneytokenLock <= 0 {
		d.o.HoneytokenLock = 24 * time.Hour
	}
	if rules.Mode == "honeypot" {
		d.up = nil
	}
	switch {
	case d.up == nil:
		d.o.Cache, d.o.Replica = nil, nil
	case d.o.Replica != nil:
		// Searches are answered from the replica; its sync reads the upstream.
		d.o.Cache, d.src = nil, d.up
	case d.o.Cache != nil:
		d.src = d.o.Cache
	default:
		d.src = d.up
	}
	return d
}

// Rules returns the compiled profile rules.
func (d *Directory) Rules() *profile.Rules { return d.rules }

// sleepCtx waits d or until ctx ends.
func sleepCtx(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func (d *Directory) upstreamName() string {
	if d.up == nil {
		return ""
	}
	return d.up.Name()
}

// Attributes always fetched from the upstream for internal use.
const (
	attrObjectGUID = "objectGUID"
	attrDN         = "distinguishedName"
)

// ---------------------------------------------------------------- Search

// searchCtx carries one client search through the pipeline.
type searchCtx struct {
	conn   *listener.Conn
	req    *listener.SearchRequest
	start  time.Time
	filter *ldapfilter.Filter
	// post is the part of the filter evaluated on the transformed entries
	// (nil = none); upstream is the filter sent to the directory.
	post     *ldapfilter.Filter
	upstream *ldapfilter.Filter
	// want are the requested client attributes (lower-case); all means "*" or none.
	want    map[string]bool
	all     bool
	denied  []string
	terms   []string
	queries int
	server  string
	trap    string // honeytoken account targeted, "" when none
	kind    profile.BaseKind
	known   bool // kind is set (first page of a search)
	// hits counts upstream requests answered by the ttl cache; stale is
	// the age of the oldest stale result served (0 = none); replica marks
	// a search answered from the replica.
	hits    int
	stale   time.Duration
	replica bool
}

// Search answers a client search (SPEC §4.2). A paged request with a
// cookie is served from the result kept on the connection; everything else
// runs the pipeline.
func (d *Directory) Search(ctx context.Context, c *listener.Conn, req *listener.SearchRequest, w listener.EntryWriter) listener.Result {
	sc := &searchCtx{conn: c, req: req, start: d.now()}
	if res, ok := d.searchGate(ctx, sc); !ok {
		return res
	}
	var paging *ldap.ControlPaging
	for _, ctl := range req.Controls {
		if p, ok := ctl.(*ldap.ControlPaging); ok {
			paging = p
		}
	}
	var res listener.Result
	var entries []listener.Entry
	var tap *TapSearch
	switch {
	case paging != nil && len(paging.Cookie) > 0:
		if f, err := ldapfilter.Parse(req.Filter); err == nil {
			sc.filter = f // for the event only; the stored result is served as is
		}
		res, entries = d.nextPage(c, sc, paging)
	default:
		res, entries = d.search(ctx, sc)
		if len(d.o.Taps) > 0 {
			tap = &TapSearch{Conn: c, Base: req.Base, Scope: req.Scope, RawFilter: req.Filter, Filter: sc.filter, Attrs: req.Attrs,
				SizeLimit: req.SizeLimit, Result: res, Entries: entries, Local: sc.kind == profile.BaseRootDSE || sc.kind == profile.BaseSubschema || sc.kind == profile.BaseOutside}
		}
		if paging != nil && (res.Code == ldap.LDAPResultSuccess || res.Code == ldap.LDAPResultSizeLimitExceeded) {
			res, entries = d.firstPage(c, sc, res, entries, paging)
		}
	}
	for _, e := range entries {
		if err := w.Entry(e); err != nil {
			d.log.Debug("entry write failed", "conn_id", c.ID(), "err", err)
			res = listener.Result{Code: ldap.LDAPResultOther}
			break
		}
	}
	d.emitSearch(sc, res, len(entries))
	d.observeSearch(sc)
	if tap != nil {
		for _, t := range d.o.Taps {
			t.Search(*tap)
		}
	}
	return res
}

// searchGate applies the rate limiter before any work: a refused search
// is answered with the guard's code and reported as rate_limited; a
// tarpitted one waits first.
func (d *Directory) searchGate(ctx context.Context, sc *searchCtx) (listener.Result, bool) {
	c := sc.conn
	v := d.o.Guard.PreSearch(c.ClientIP(), c.Bound().Name)
	if v.Done != nil {
		defer v.Done()
	}
	if v.Wait > 0 {
		d.o.Sleep(ctx, v.Wait)
	}
	if v.Allowed {
		return listener.Result{}, true
	}
	ev := c.Event(events.RateLimited, events.LevelLow)
	ev.Reason = v.Reason
	ev.Data = map[string]any{"target": "ip", "key": c.ClientIP(), "op": "search", "reason": v.Reason}
	d.ev.Emit(ev)
	d.log.Info("search refused", "conn_id", c.ID(), "client_ip", c.ClientIP(), "reason", v.Reason)
	return listener.Result{Code: v.Code}, false
}

// observeSearch hands the first page of a search to the detectors.
func (d *Directory) observeSearch(sc *searchCtx) {
	if d.o.Observer == nil || !sc.known {
		return
	}
	if (sc.kind == profile.BaseRootDSE || sc.kind == profile.BaseSubschema) && sc.req.Scope == listener.ScopeBase {
		return
	}
	c := sc.conn
	d.o.Observer.Search(ids.SearchObs{Profile: d.rules.Name, IP: c.ClientIP(), ConnID: c.ID(), Account: c.Bound().Name,
		Base: sc.req.Base, Scope: sc.req.Scope.String(), FilterNorm: redactFilter(sc.filter), Filter: sc.filter, Attrs: sc.req.Attrs, BaseKind: baseKindName(sc.kind)})
}

// baseKindName names a base kind for the detectors.
func baseKindName(k profile.BaseKind) string {
	switch k {
	case profile.BaseRootDSE:
		return "rootdse"
	case profile.BaseSubschema:
		return "subschema"
	case profile.BaseVirtual:
		return "virtual"
	case profile.BaseUsers:
		return "users"
	case profile.BaseGroups:
		return "groups"
	case profile.BaseUser:
		return "user"
	case profile.BaseGroup:
		return "group"
	case profile.BaseOutside:
	}
	return "outside"
}

// search runs the pipeline up to the merged, transformed, size-limited
// result (before paging).
func (d *Directory) search(ctx context.Context, sc *searchCtx) (listener.Result, []listener.Entry) {
	req := sc.req
	f, err := ldapfilter.ParseWithLimits(req.Filter, ldapfilter.Limits{MaxDepth: d.rules.Limits.MaxFilterDepth, MaxLen: d.rules.Limits.MaxFilterLen})
	if err != nil {
		if errors.Is(err, ldapfilter.ErrTooDeep) || errors.Is(err, ldapfilter.ErrTooLong) {
			return listener.Result{Code: ldap.LDAPResultAdminLimitExceeded, Diagnostic: "filter too complex"}, nil
		}
		return listener.Result{Code: ldap.LDAPResultProtocolError, Diagnostic: "invalid filter"}, nil
	}
	sc.filter = f
	sc.want, sc.all, sc.denied = d.requestedAttrs(req.Attrs)
	kind, rdn, err := d.rules.ClassifyBase(req.Base)
	sc.kind, sc.known = kind, true
	if err != nil || kind == profile.BaseOutside {
		sc.kind = profile.BaseOutside
		return listener.Result{Code: ldap.LDAPResultNoSuchObject}, nil
	}
	d.detectTrap(sc, kind, rdn)
	out, res := d.entriesFor(ctx, sc, kind, rdn)
	if res.Code != ldap.LDAPResultSuccess {
		return res, nil
	}
	if kind == profile.BaseRootDSE || kind == profile.BaseSubschema {
		return listener.Success, out
	}
	return d.sizeLimit(sc, out)
}

// detectTrap raises the honeytoken event for a search that targets a trap
// (SPEC §4.5) and, in honeypot mode, for every search of the virtual tree.
func (d *Directory) detectTrap(sc *searchCtx, kind profile.BaseKind, rdn string) {
	if kind == profile.BaseRootDSE || kind == profile.BaseSubschema {
		return
	}
	if h := d.honeytokenTarget(sc.filter, rdn); h != nil {
		sc.trap = h.Account
	} else if d.rules.Mode == "honeypot" {
		sc.trap = sc.conn.Bound().Name
		if sc.trap == "" {
			sc.trap = "anonymous"
		}
	}
	if sc.trap != "" {
		d.honeytokenHit(sc.conn, "search", sc.trap)
	}
}

// entriesFor serves the entries of one base kind (SPEC §4.2 step 2).
func (d *Directory) entriesFor(ctx context.Context, sc *searchCtx, kind profile.BaseKind, rdn string) ([]listener.Entry, listener.Result) {
	scope := sc.req.Scope
	switch kind {
	case profile.BaseRootDSE:
		if scope == listener.ScopeBase {
			return d.static(sc, rootDSE(d.rules, d.o.Version, d.o.StartTLS)), listener.Success
		}
	case profile.BaseSubschema:
		if scope == listener.ScopeBase {
			return d.static(sc, subschema(d.rules)), listener.Success
		}
	case profile.BaseVirtual, profile.BaseUsers, profile.BaseGroups:
		return d.containerEntries(ctx, sc, kind)
	case profile.BaseUser:
		if scope != listener.ScopeOne {
			return d.users(ctx, sc, rdn)
		}
	case profile.BaseGroup:
		if scope != listener.ScopeOne {
			return d.groups(ctx, sc, rdn)
		}
	case profile.BaseOutside:
	}
	return nil, listener.Success
}

// containerEntries serves <virtual_base>, ou=users and ou=groups with
// their children according to the scope.
func (d *Directory) containerEntries(ctx context.Context, sc *searchCtx, kind profile.BaseKind) ([]listener.Entry, listener.Result) {
	root := containerEntry(d.rules.VirtualBase, "ALDAP virtual directory")
	users := containerEntry(d.rules.UsersBase, "Users")
	groups := containerEntry(d.rules.GroupsBase, "Virtual groups")
	var out []listener.Entry
	withUsers, withGroups := false, false
	switch {
	case kind == profile.BaseVirtual && sc.req.Scope == listener.ScopeBase:
		out = d.static(sc, root)
	case kind == profile.BaseVirtual && sc.req.Scope == listener.ScopeOne:
		out = d.static(sc, users, groups)
	case kind == profile.BaseVirtual:
		out = d.static(sc, root, users, groups)
		withUsers, withGroups = true, true
	case kind == profile.BaseUsers && sc.req.Scope == listener.ScopeBase:
		out = d.static(sc, users)
	case kind == profile.BaseUsers:
		withUsers = true
	case kind == profile.BaseGroups && sc.req.Scope == listener.ScopeOne:
		withGroups = true
	case kind == profile.BaseGroups && sc.req.Scope == listener.ScopeBase:
		out = d.static(sc, groups)
	default:
		out = d.static(sc, groups)
		withGroups = true
	}
	if withUsers {
		es, res := d.users(ctx, sc, "")
		if res.Code != ldap.LDAPResultSuccess {
			return nil, res
		}
		out = append(out, es...)
	}
	if withGroups {
		es, res := d.groups(ctx, sc, "")
		if res.Code != ldap.LDAPResultSuccess {
			return nil, res
		}
		out = append(out, es...)
	}
	return out, listener.Success
}

// static filters the locally served entries with the client filter (client
// attribute names, no rewriting) and projects the requested attributes.
func (d *Directory) static(sc *searchCtx, es ...*entry) []listener.Entry {
	var out []listener.Entry
	for _, e := range es {
		if e.matches(sc.filter) {
			out = append(out, e.project(sc.want, sc.all))
		}
	}
	return out
}

// groups serves the virtual groups (one when name is given) that match
// the client filter, evaluated locally (member is DN-compared).
func (d *Directory) groups(ctx context.Context, sc *searchCtx, name string) ([]listener.Entry, listener.Result) {
	if !d.rules.HasGroups() {
		return nil, listener.Success
	}
	m, err := d.membership(ctx)
	if err != nil {
		return nil, d.upstreamError(sc, err)
	}
	if d.o.Replica != nil {
		sc.replica = true
	} else {
		sc.queries++
	}
	var out []listener.Entry
	for _, gd := range m.groups {
		if name != "" && !strings.EqualFold(gd.g.Name, name) {
			continue
		}
		e := d.groupEntry(gd)
		if e.matches(sc.filter) {
			out = append(out, e.project(sc.want, sc.all))
		}
	}
	return out, listener.Success
}

// sizeLimit applies the client sizeLimit and limits.max_result_size.
func (d *Directory) sizeLimit(sc *searchCtx, out []listener.Entry) (listener.Result, []listener.Entry) {
	limit := d.rules.Limits.MaxResultSize
	if sc.req.SizeLimit > 0 && (limit <= 0 || sc.req.SizeLimit < limit) {
		limit = sc.req.SizeLimit
	}
	if limit > 0 && len(out) > limit {
		return listener.Result{Code: ldap.LDAPResultSizeLimitExceeded}, out[:limit]
	}
	return listener.Success, out
}

// requestedAttrs classifies the requested attribute list: lower-case client
// names that are allowed (or belong to ALDAP's own entries), whether
// everything was requested ("*", "+" alone or an empty list), and the
// names outside the allowlist.
func (d *Directory) requestedAttrs(attrs []string) (want map[string]bool, all bool, denied []string) {
	want = map[string]bool{}
	if len(attrs) == 0 {
		return want, true, nil
	}
	for _, a := range attrs {
		switch a {
		case "*":
			all = true
		case "1.1", "+":
			// 1.1 = no attributes; "+" = operational attributes, none of which are virtualized.
		default:
			l := strings.ToLower(a)
			if i := strings.IndexByte(l, ';'); i > 0 {
				l = l[:i]
			}
			if d.rules.IsAllowed(l) || isStaticAttr(l) || groupAttrs[l] {
				want[l] = true
			} else {
				denied = append(denied, a)
			}
		}
	}
	return want, all, denied
}

// isStaticAttr lists attributes of ALDAP's own entries that are always
// readable (root DSE, subschema and containers carry no directory data).
func isStaticAttr(l string) bool {
	switch l {
	case "objectclass", "namingcontexts", "defaultnamingcontext", "subschemasubentry", "supportedldapversion",
		"supportedcontrol", "supportedextension", "supportedsaslmechanisms", "vendorname", "vendorversion",
		"attributetypes", "objectclasses", "ou", "dc", "o", "cn", "description":
		return true
	}
	return false
}

// splitFilter separates the client filter into the upstream part and the
// local post-filter (SPEC §4.2 steps 3 and 7): denied terms are recorded
// and become false, computed attributes and memberOf are evaluated
// locally. The upstream part is rewritten to upstream names (attrs.map,
// objectclass.map), AND profile filter, AND NOT exclude, and for a
// single-user lookup AND (rdn_attr=value).
func (d *Directory) splitFilter(sc *searchCtx, rdn string) {
	for _, a := range sc.filter.Attrs() {
		if d.rules.Classify(a) == ldapfilter.Denied {
			sc.terms = append(sc.terms, a)
		}
	}
	exec, post := ldapfilter.Split(sc.filter, d.rules.Classify)
	if !post.IsTrue() {
		sc.post = post
	}
	if exec.IsFalse() {
		sc.upstream = exec
		return
	}
	up := exec.Clone()
	ldapfilter.Walk(up, func(n *ldapfilter.Filter) bool {
		if n.Kind == ldapfilter.Equality && strings.EqualFold(n.Attr, "objectClass") {
			n.Value = d.rules.UpstreamObjectClass(n.Value)
		}
		return true
	})
	up = ldapfilter.MapAttrs(up, d.rules.AttrMap())
	up = d.profileFilter(up)
	if rdn != "" {
		up = ldapfilter.Inject(up, &ldapfilter.Filter{Kind: ldapfilter.Equality, Attr: d.rules.RDNAttr, Value: rdn})
	}
	sc.upstream = up
}

// upstreamAttrs lists the upstream attributes to fetch: rdn_attr and
// objectGUID, the requested allowed attributes, the dependencies of
// computed attributes and the allowed attributes the post-filter reads.
func (d *Directory) upstreamAttrs(sc *searchCtx) []string {
	seen := map[string]bool{}
	var out []string
	add := func(a string) {
		if l := strings.ToLower(a); !seen[l] {
			seen[l] = true
			out = append(out, a)
		}
	}
	add(d.rules.RDNAttr)
	if d.rules.Kind == "ad" {
		add(attrObjectGUID)
	}
	for _, client := range d.rules.AllowedAttrs() {
		if sc.all || sc.want[strings.ToLower(client)] {
			add(d.rules.UpstreamAttr(client))
		}
	}
	for _, c := range d.rules.Computed() {
		for _, dep := range c.Deps {
			add(dep)
		}
	}
	if sc.post != nil {
		for _, a := range sc.post.Attrs() {
			if d.rules.IsAllowed(a) && !d.rules.IsVirtualAttr(a) {
				add(d.rules.UpstreamAttr(a))
			}
		}
	}
	return out
}

// needMembership reports whether the search needs group membership:
// memberOf is returned or filtered on.
func (d *Directory) needMembership(sc *searchCtx) bool {
	if !d.rules.HasGroups() {
		return false
	}
	if sc.all || sc.want[strings.ToLower(profile.AttrMemberOf)] {
		return true
	}
	if sc.post != nil {
		for _, a := range sc.post.Attrs() {
			if strings.EqualFold(a, profile.AttrMemberOf) {
				return true
			}
		}
	}
	return false
}

// users searches every base, merges, de-duplicates and transforms the
// result into virtual user entries; honeytokens are added as if they came
// from the upstream. rdn restricts the search to one user.
func (d *Directory) users(ctx context.Context, sc *searchCtx, rdn string) ([]listener.Entry, listener.Result) {
	d.splitFilter(sc, rdn)
	if sc.upstream.IsFalse() {
		return nil, listener.Success
	}
	if d.o.Replica != nil {
		return d.replicaUsers(sc, rdn)
	}
	var merged []upstream.Entry
	if d.up != nil {
		var res listener.Result
		if merged, res = d.fetchUsers(ctx, sc); res.Code != ldap.LDAPResultSuccess {
			return nil, res
		}
		if sc.stale > 0 {
			d.emitStale(sc, len(merged))
		}
	}
	traps := len(merged)
	for _, h := range d.rules.Honeytokens() {
		if rdn == "" || strings.EqualFold(h.Attrs[d.rules.RDNAttr][0], rdn) {
			merged = append(merged, honeytokenEntry(h))
		}
	}
	var mem *membership
	if d.needMembership(sc) {
		m, err := d.membership(ctx)
		if err != nil {
			return nil, d.upstreamError(sc, err)
		}
		mem = m
	}
	rdns := map[string]int{}
	for _, e := range merged {
		rdns[strings.ToLower(e.First(d.rules.RDNAttr))]++
	}
	out := make([]listener.Entry, 0, len(merged))
	for i, e := range merged {
		collision := rdns[strings.ToLower(e.First(d.rules.RDNAttr))] > 1
		if collision {
			d.log.Warn("virtual RDN collision", "rdn", e.First(d.rules.RDNAttr), "upstream_dn", e.DN)
		}
		full := d.transform(e, mem, collision)
		// Upstream entries were selected by the directory and need only the
		// post-filter; traps never went upstream and face the whole filter.
		if i < traps && sc.post != nil && !full.matches(sc.post) || i >= traps && !full.matches(sc.filter) {
			continue
		}
		d.mask(full)
		out = append(out, full.project(sc.want, sc.all))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].DN < out[j].DN })
	return out, listener.Success
}

// fetchUsers runs the upstream searches over the profile bases in parallel
// and merges them with de-duplication.
func (d *Directory) fetchUsers(ctx context.Context, sc *searchCtx) ([]upstream.Entry, listener.Result) {
	attrs := d.upstreamAttrs(sc)
	limit := d.rules.Limits.MaxResultSize
	if sc.req.SizeLimit > 0 && (limit <= 0 || sc.req.SizeLimit < limit) {
		limit = sc.req.SizeLimit
	}
	fetch := 0
	if limit > 0 && sc.post == nil {
		fetch = limit + 1 // one more to detect the overflow; a post-filter needs the whole set
	}
	results := make([]*upstream.Result, len(d.rules.Bases))
	errs := make([]error, len(d.rules.Bases))
	par := d.rules.Limits.UpstreamParallel
	if par <= 0 {
		par = 1
	}
	sem := make(chan struct{}, par)
	var wg sync.WaitGroup
	for i, base := range d.rules.Bases {
		wg.Add(1)
		go func(i int, base string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i], errs[i] = d.src.Search(ctx, upstream.SearchRequest{Base: base, Scope: upstream.ScopeSub, Filter: sc.upstream,
				Attrs: attrs, SizeLimit: fetch, TimeLimit: sc.req.TimeLimit})
		}(i, base)
	}
	wg.Wait()
	var merged []upstream.Entry
	seen := map[string]bool{}
	for i, r := range results {
		if errs[i] != nil {
			return nil, d.upstreamError(sc, errs[i])
		}
		switch {
		case r.Cached:
			sc.hits++
			if r.Stale {
				sc.stale = max(sc.stale, max(r.Age, time.Millisecond))
			}
		case r.Pages > 0:
			sc.queries++
		}
		if r.Server != "" && !r.Cached {
			sc.server = r.Server
		}
		for _, e := range r.Entries {
			key := d.dedupeKey(e)
			if seen[key] {
				continue
			}
			seen[key] = true
			merged = append(merged, e)
		}
	}
	return merged, listener.Success
}

// dedupeKey identifies an upstream entry across bases: objectGUID for AD,
// the canonical DN otherwise.
func (d *Directory) dedupeKey(e upstream.Entry) string {
	if d.rules.Kind == "ad" {
		if g := e.First(attrObjectGUID); g != "" {
			return "guid:" + g
		}
	}
	return "dn:" + canonicalDN(e.DN)
}

// transform maps an upstream entry to its full virtual form (SPEC §4.2
// step 6): virtual DN from rdn_attr, allowed attributes renamed, computed
// attributes evaluated, object classes mapped and memberOf set from the
// virtual groups. Masking and projection happen afterwards.
func (d *Directory) transform(e upstream.Entry, mem *membership, collision bool) *entry {
	rdn := e.First(d.rules.RDNAttr)
	if rdn == "" {
		rdn = e.DN
	}
	out := &entry{dn: d.virtualUserDN(rdn, e.First(attrObjectGUID), e.DN, collision)}
	for _, client := range d.rules.AllowedAttrs() {
		if d.rules.IsVirtualAttr(client) {
			continue
		}
		vals := e.Get(d.rules.UpstreamAttr(client))
		if strings.EqualFold(client, "objectClass") {
			vals = d.rules.MapObjectClass(vals)
		}
		out.add(client, vals...)
	}
	for _, c := range d.rules.Computed() {
		data := make(map[string]string, len(c.Deps))
		for _, dep := range c.Deps {
			data[dep] = e.First(dep)
		}
		v, err := c.Eval(data)
		if err != nil {
			d.log.Debug("computed attribute failed", "attr", c.Name, "err", err)
			continue
		}
		if v != "" {
			out.set(c.Name, v)
		}
	}
	if mem != nil {
		out.set(profile.AttrMemberOf, mem.userGroups[d.dedupeKey(e)]...)
	}
	return out
}

// mask applies attrs.mask to the entry (after computed, before projection).
func (d *Directory) mask(e *entry) {
	for _, m := range d.rules.Masks() {
		vals := e.get(m.Name)
		if len(vals) == 0 {
			continue
		}
		masked := make([]string, len(vals))
		for i, v := range vals {
			masked[i] = m.Apply(v)
		}
		e.set(m.Name, masked...)
	}
}

// upstreamError maps an upstream failure to a client result.
func (d *Directory) upstreamError(sc *searchCtx, err error) listener.Result {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return listener.Result{Code: ldap.LDAPResultTimeLimitExceeded}
	case errors.Is(err, errNoReplica):
		d.log.Warn("replica not synced yet", "conn_id", sc.conn.ID())
		return listener.Result{Code: ldap.LDAPResultUnavailable, Diagnostic: "directory unavailable"}
	case errors.Is(err, upstream.ErrUnavailable), errors.Is(err, upstream.ErrClosed):
		d.log.Warn("upstream unavailable", "conn_id", sc.conn.ID(), "err", err)
		return listener.Result{Code: ldap.LDAPResultUnavailable, Diagnostic: "directory unavailable"}
	default:
		d.log.Warn("upstream search failed", "conn_id", sc.conn.ID(), "err", err)
		return listener.Result{Code: ldap.LDAPResultOther}
	}
}

// ---------------------------------------------------------------- paging

// pagingState is a merged result kept for a paged search (SPEC §4.2 step 8).
type pagingState struct {
	cookie  string
	code    int
	entries []listener.Entry
	pos     int
	created time.Time
}

const pagingKey = "vdir.paging"

func (d *Directory) pagingStates(c *listener.Conn) map[string]*pagingState {
	if v, ok := c.Load(pagingKey); ok {
		if m, ok := v.(map[string]*pagingState); ok {
			return m
		}
	}
	m := map[string]*pagingState{}
	c.Store(pagingKey, m)
	return m
}

// firstPage stores the merged result on the connection under a random
// cookie and returns the first page; size 0 returns nothing (RFC 2696).
func (d *Directory) firstPage(c *listener.Conn, sc *searchCtx, res listener.Result, all []listener.Entry, ctl *ldap.ControlPaging) (listener.Result, []listener.Entry) {
	if ctl.PagingSize == 0 {
		res.Controls = append(res.Controls, &ldap.ControlPaging{})
		return res, nil
	}
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return listener.Result{Code: ldap.LDAPResultUnwillingToPerform, Diagnostic: "paging unavailable"}, nil
	}
	states := d.pagingStates(c)
	st := &pagingState{cookie: hex.EncodeToString(buf[:]), code: res.Code, entries: all, created: sc.start}
	if len(states) >= d.o.MaxPagingStates {
		d.evictOldest(states)
	}
	states[st.cookie] = st
	return d.servePage(states, st, ctl.PagingSize)
}

// nextPage continues a paged search; an unknown cookie is refused and a
// size of 0 abandons the cursor.
func (d *Directory) nextPage(c *listener.Conn, sc *searchCtx, ctl *ldap.ControlPaging) (listener.Result, []listener.Entry) {
	states := d.pagingStates(c)
	st, ok := states[string(ctl.Cookie)]
	if !ok {
		return listener.Result{Code: ldap.LDAPResultUnwillingToPerform, Diagnostic: "unknown paging cookie"}, nil
	}
	if ctl.PagingSize == 0 {
		delete(states, st.cookie)
		return listener.Result{Code: ldap.LDAPResultSuccess, Controls: []ldap.Control{&ldap.ControlPaging{}}}, nil
	}
	sc.queries = 0
	return d.servePage(states, st, ctl.PagingSize)
}

func (d *Directory) servePage(states map[string]*pagingState, st *pagingState, size uint32) (listener.Result, []listener.Entry) {
	resp := &ldap.ControlPaging{PagingSize: size}
	end := st.pos + int(size)
	if end >= len(st.entries) {
		end = len(st.entries)
		delete(states, st.cookie)
	} else {
		resp.Cookie = []byte(st.cookie)
	}
	page := st.entries[st.pos:end]
	st.pos = end
	return listener.Result{Code: st.code, Controls: []ldap.Control{resp}}, page
}

func (d *Directory) evictOldest(states map[string]*pagingState) {
	var oldest *pagingState
	for _, s := range states {
		if oldest == nil || s.created.Before(oldest.created) {
			oldest = s
		}
	}
	if oldest != nil {
		delete(states, oldest.cookie)
	}
}

// ---------------------------------------------------------------- events

// redactFilter renders the normalized filter with password values hidden.
func redactFilter(f *ldapfilter.Filter) string {
	if f == nil {
		return ""
	}
	n := f.Normalize()
	ldapfilter.Walk(n, func(x *ldapfilter.Filter) bool {
		switch strings.ToLower(x.Attr) {
		case "userpassword", "unicodepwd":
			if x.Kind != ldapfilter.Present {
				x.Value, x.Initial, x.Any, x.Final = "***", "", nil, ""
				if x.Kind == ldapfilter.Substring {
					x.Kind = ldapfilter.Equality
				}
			}
		}
		return true
	})
	// The serializer escapes '*' in values; show the SPEC §6 marker literally.
	return strings.ReplaceAll(n.String(), `\2a\2a\2a`, "***")
}

func (d *Directory) emitSearch(sc *searchCtx, res listener.Result, results int) {
	ev := sc.conn.Event(events.Search, events.LevelLow)
	ev.Upstream = d.upstreamName()
	ev.UpstreamServer = sc.server
	ev.Duration = d.now().Sub(sc.start)
	data := map[string]any{
		"base": sc.req.Base, "scope": sc.req.Scope.String(), "filter_norm": redactFilter(sc.filter),
		"results": results, "upstream_queries": sc.queries, "cache_hit": sc.cacheHit(), "result_code": res.Code,
	}
	if sc.filter == nil {
		data["filter_norm"] = "(invalid)"
	}
	if len(sc.req.Attrs) > 0 {
		data["attrs_requested"] = sc.req.Attrs
	}
	if len(sc.denied) > 0 {
		data["attrs_denied"] = sc.denied
	}
	if len(sc.terms) > 0 {
		data["denied_terms"] = sc.terms
	}
	if sc.trap != "" {
		data["honeytoken"] = sc.trap
	}
	ev.Data = data
	d.ev.Emit(ev)
	d.o.Metrics.Search(d.rules.Name, d.cacheLabel(sc), results, sc.queries)
}

// cacheHit reports a search answered from memory without an upstream
// query: the replica, or the ttl cache for every upstream request.
func (sc *searchCtx) cacheHit() bool {
	return sc.replica || sc.hits > 0 && sc.queries == 0
}

// cacheLabel is the cache outcome of searches_total: replica, stale, hit
// or miss (ttl), local (nothing asked upstream) or none.
func (d *Directory) cacheLabel(sc *searchCtx) string {
	switch {
	case sc.replica:
		return "replica"
	case sc.stale > 0:
		return "stale"
	case sc.cacheHit():
		return "hit"
	case sc.queries == 0:
		return "local"
	case d.o.Cache != nil:
		return "miss"
	}
	return "none"
}

// emitStale reports a search answered with expired cache results while
// every upstream server was down (SPEC §5.1 stale_while_down).
func (d *Directory) emitStale(sc *searchCtx, entries int) {
	ev := sc.conn.Event(events.StaleServed, events.LevelMedium)
	ev.Upstream = d.upstreamName()
	ev.Data = map[string]any{"age_s": int(sc.stale / time.Second), "entries": entries}
	d.ev.Emit(ev)
	d.log.Warn("stale cache served, upstream down", "conn_id", sc.conn.ID(), "age_s", int(sc.stale/time.Second), "entries", entries)
}
