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
	"github.com/alstdev/aldap/internal/ldapfilter"
	"github.com/alstdev/aldap/internal/listener"
	"github.com/alstdev/aldap/internal/profile"
	"github.com/alstdev/aldap/internal/upstream"
)

// Searcher is the part of *upstream.Upstream the directory uses.
type Searcher interface {
	Name() string
	Search(ctx context.Context, req upstream.SearchRequest) (*upstream.Result, error)
	UserBind(ctx context.Context, name, password string) error
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
	Now             func() time.Time
}

// Directory serves one profile. It implements listener.Handler.
type Directory struct {
	rules *profile.Rules
	up    Searcher
	log   *slog.Logger
	ev    events.Sink
	o     Options
	now   func() time.Time
}

var _ listener.Handler = (*Directory)(nil)

// New builds the directory of a profile over its upstream.
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
	return d
}

// Rules returns the compiled profile rules.
func (d *Directory) Rules() *profile.Rules { return d.rules }

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
	// want are the requested client attributes (lower-case); all means "*" or none.
	want    map[string]bool
	all     bool
	denied  []string
	terms   []string
	queries int
	server  string
}

// Search answers a client search (SPEC §4.2). A paged request with a
// cookie is served from the result kept on the connection; everything else
// runs the pipeline.
func (d *Directory) Search(ctx context.Context, c *listener.Conn, req *listener.SearchRequest, w listener.EntryWriter) listener.Result {
	sc := &searchCtx{conn: c, req: req, start: d.now()}
	var paging *ldap.ControlPaging
	for _, ctl := range req.Controls {
		if p, ok := ctl.(*ldap.ControlPaging); ok {
			paging = p
		}
	}
	var res listener.Result
	var entries []listener.Entry
	switch {
	case paging != nil && len(paging.Cookie) > 0:
		if f, err := ldapfilter.Parse(req.Filter); err == nil {
			sc.filter = f // for the event only; the stored result is served as is
		}
		res, entries = d.nextPage(c, sc, paging)
	default:
		res, entries = d.search(ctx, sc)
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
	return res
}

// search runs the pipeline up to the merged, transformed, size-limited
// result (before paging).
func (d *Directory) search(ctx context.Context, sc *searchCtx) (listener.Result, []listener.Entry) {
	req := sc.req
	f, err := ldapfilter.ParseWithLimits(req.Filter, ldapfilter.Limits{MaxDepth: sc.limits(d).MaxFilterDepth, MaxLen: sc.limits(d).MaxFilterLen})
	if err != nil {
		if errors.Is(err, ldapfilter.ErrTooDeep) || errors.Is(err, ldapfilter.ErrTooLong) {
			return listener.Result{Code: ldap.LDAPResultAdminLimitExceeded, Diagnostic: "filter too complex"}, nil
		}
		return listener.Result{Code: ldap.LDAPResultProtocolError, Diagnostic: "invalid filter"}, nil
	}
	sc.filter = f
	sc.want, sc.all, sc.denied = d.requestedAttrs(req.Attrs)
	kind, rdn, err := d.rules.ClassifyBase(req.Base)
	if err != nil || kind == profile.BaseOutside {
		return listener.Result{Code: ldap.LDAPResultNoSuchObject}, nil
	}
	out, res := d.entriesFor(ctx, sc, kind, rdn)
	if res.Code != ldap.LDAPResultSuccess {
		return res, nil
	}
	if kind == profile.BaseRootDSE || kind == profile.BaseSubschema {
		return listener.Success, out
	}
	return d.sizeLimit(sc, out)
}

// entriesFor serves the entries of one base kind (SPEC §4.2 step 2).
func (d *Directory) entriesFor(ctx context.Context, sc *searchCtx, kind profile.BaseKind, rdn string) ([]listener.Entry, listener.Result) {
	req := sc.req
	var out []listener.Entry
	switch kind {
	case profile.BaseRootDSE:
		if req.Scope == listener.ScopeBase {
			out = d.static(sc, rootDSE(d.rules, d.o.Version, d.o.StartTLS))
		}
	case profile.BaseSubschema:
		if req.Scope == listener.ScopeBase {
			out = d.static(sc, subschema(d.rules))
		}
	case profile.BaseVirtual:
		switch req.Scope {
		case listener.ScopeBase:
			out = d.static(sc, containerEntry(d.rules.VirtualBase, "ALDAP virtual directory"))
		case listener.ScopeOne:
			out = d.static(sc, containerEntry(d.rules.UsersBase, "Users"), containerEntry(d.rules.GroupsBase, "Virtual groups"))
		default:
			out = d.static(sc, containerEntry(d.rules.VirtualBase, "ALDAP virtual directory"),
				containerEntry(d.rules.UsersBase, "Users"), containerEntry(d.rules.GroupsBase, "Virtual groups"))
			users, res := d.users(ctx, sc, "")
			if res.Code != ldap.LDAPResultSuccess {
				return nil, res
			}
			out = append(out, users...)
		}
	case profile.BaseUsers:
		if req.Scope == listener.ScopeBase {
			out = d.static(sc, containerEntry(d.rules.UsersBase, "Users"))
		} else {
			users, res := d.users(ctx, sc, "")
			if res.Code != ldap.LDAPResultSuccess {
				return nil, res
			}
			out = users
		}
	case profile.BaseGroups:
		if req.Scope != listener.ScopeOne {
			// Virtual groups arrive with Stage 5; the container itself exists.
			out = d.static(sc, containerEntry(d.rules.GroupsBase, "Virtual groups"))
		}
	case profile.BaseUser:
		if req.Scope != listener.ScopeOne {
			users, res := d.users(ctx, sc, rdn)
			if res.Code != ldap.LDAPResultSuccess {
				return nil, res
			}
			out = users
		}
	case profile.BaseGroup, profile.BaseOutside:
		// Virtual groups arrive with Stage 5.
	}
	return out, listener.Success
}

func (sc *searchCtx) limits(d *Directory) struct{ MaxFilterDepth, MaxFilterLen int } {
	return struct{ MaxFilterDepth, MaxFilterLen int }{d.rules.Limits.MaxFilterDepth, d.rules.Limits.MaxFilterLen}
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
// names that are allowed, whether everything allowed was requested ("*", "+"
// alone or an empty list), and the names outside the allowlist.
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
			if d.rules.IsAllowed(l) || isStaticAttr(l) {
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

// upstreamFilter rewrites the client filter for the upstream: attribute
// renames, denied terms → false, AND profile filter, AND NOT exclude, and
// for a single-user lookup AND (rdn_attr=value).
func (d *Directory) upstreamFilter(sc *searchCtx, rdn string) *ldapfilter.Filter {
	for _, a := range sc.filter.Attrs() {
		if d.rules.Classify(a) == ldapfilter.Denied {
			sc.terms = append(sc.terms, a)
		}
	}
	mapped := ldapfilter.MapAttrs(sc.filter, d.rules.AttrMap())
	exec, _ := ldapfilter.Split(mapped, func(attr string) ldapfilter.Class {
		// Attributes were renamed to upstream names; classify by client names.
		for _, c := range d.rules.ClientAttrs(attr) {
			if d.rules.Classify(c) == ldapfilter.Upstream {
				return ldapfilter.Upstream
			}
		}
		return d.rules.Classify(attr)
	})
	if exec.IsFalse() {
		return exec
	}
	f := exec
	if d.rules.Filter != nil {
		f = ldapfilter.Inject(f, d.rules.Filter)
	}
	if d.rules.Exclude != nil {
		f = ldapfilter.Exclude(f, d.rules.Exclude)
	}
	if rdn != "" {
		f = ldapfilter.Inject(f, &ldapfilter.Filter{Kind: ldapfilter.Equality, Attr: d.rules.RDNAttr, Value: rdn})
	}
	return f
}

// upstreamAttrs lists the upstream attributes to fetch for the requested
// client attributes plus the ones the pipeline needs itself.
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
	return out
}

// users searches every base, merges, de-duplicates and transforms the
// result into virtual user entries. rdn restricts the search to one user.
func (d *Directory) users(ctx context.Context, sc *searchCtx, rdn string) ([]listener.Entry, listener.Result) {
	f := d.upstreamFilter(sc, rdn)
	if f.IsFalse() {
		return nil, listener.Success
	}
	attrs := d.upstreamAttrs(sc)
	limit := d.rules.Limits.MaxResultSize
	if sc.req.SizeLimit > 0 && (limit <= 0 || sc.req.SizeLimit < limit) {
		limit = sc.req.SizeLimit
	}
	fetch := 0
	if limit > 0 {
		fetch = limit + 1 // one more to detect the overflow
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
			results[i], errs[i] = d.up.Search(ctx, upstream.SearchRequest{Base: base, Scope: upstream.ScopeSub, Filter: f,
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
		if r.Pages > 0 {
			sc.queries++
		}
		if r.Server != "" {
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
	out := make([]listener.Entry, 0, len(merged))
	rdns := map[string]int{}
	for _, e := range merged {
		rdns[strings.ToLower(e.First(d.rules.RDNAttr))]++
	}
	for _, e := range merged {
		out = append(out, d.transform(sc, e, rdns[strings.ToLower(e.First(d.rules.RDNAttr))] > 1))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].DN < out[j].DN })
	return out, listener.Success
}

// dedupeKey identifies an upstream entry across bases: objectGUID for AD,
// the canonical DN otherwise.
func (d *Directory) dedupeKey(e upstream.Entry) string {
	if d.rules.Kind == "ad" {
		if g := e.First(attrObjectGUID); g != "" {
			return "guid:" + g
		}
	}
	if dn, err := ldapfilter.ParseDN(e.DN); err == nil {
		return "dn:" + dn.Canonical()
	}
	return "dn:" + strings.ToLower(e.DN)
}

// transform maps an upstream entry to its virtual form (SPEC §4.2 step 6):
// virtual DN from rdn_attr, attributes renamed and reduced to the requested
// allowed ones.
func (d *Directory) transform(sc *searchCtx, e upstream.Entry, collision bool) listener.Entry {
	rdn := e.First(d.rules.RDNAttr)
	if rdn == "" {
		rdn = e.DN
	}
	var dn string
	if collision {
		guid := hex.EncodeToString([]byte(e.First(attrObjectGUID)))
		if guid == "" {
			guid = hex.EncodeToString([]byte(e.DN))
		}
		dn = d.rules.UsersBase.Child(ldapfilter.RDN{AVAs: []ldapfilter.AVA{{Type: "cn", Value: rdn}, {Type: "objectGUID", Value: guid}}}).String()
		d.log.Warn("virtual RDN collision", "rdn", rdn, "upstream_dn", e.DN)
	} else {
		dn = d.rules.UserDN(rdn)
	}
	out := &entry{dn: dn}
	for _, client := range d.rules.AllowedAttrs() {
		l := strings.ToLower(client)
		if !sc.all && !sc.want[l] {
			continue
		}
		if vals := e.Get(d.rules.UpstreamAttr(client)); len(vals) > 0 {
			out.add(client, vals...)
		}
	}
	return listener.Entry{DN: out.dn, Attrs: out.attrs}
}

// upstreamError maps an upstream failure to a client result.
func (d *Directory) upstreamError(sc *searchCtx, err error) listener.Result {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return listener.Result{Code: ldap.LDAPResultTimeLimitExceeded}
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
	ev.Upstream = d.up.Name()
	ev.UpstreamServer = sc.server
	ev.Duration = d.now().Sub(sc.start)
	data := map[string]any{
		"base": sc.req.Base, "scope": sc.req.Scope.String(), "filter_norm": redactFilter(sc.filter),
		"results": results, "upstream_queries": sc.queries, "cache_hit": false, "result_code": res.Code,
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
	ev.Data = data
	d.ev.Emit(ev)
}
