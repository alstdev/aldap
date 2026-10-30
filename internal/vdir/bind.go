package vdir

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/ids"
	"github.com/alstdev/aldap/internal/ldapfilter"
	"github.com/alstdev/aldap/internal/listener"
	"github.com/alstdev/aldap/internal/profile"
	"github.com/alstdev/aldap/internal/ratelimit"
	"github.com/alstdev/aldap/internal/upstream"
)

// invalidCredentials is the only failure clients see (SPEC §9).
var invalidCredentials = listener.Result{Code: ldap.LDAPResultInvalidCredentials}

// Bind authenticates a client (SPEC §4.3): anonymous, client_bind or user.
func (d *Directory) Bind(ctx context.Context, c *listener.Conn, name string, password []byte) listener.Result {
	start := d.now()
	// A bind name longer than any real identifier is kept clipped: events,
	// logs and the guard tables must not store what the client sends.
	name = clipString(name, maxBindName)
	// Gate (SPEC §9): locks, negative cache, lockdown and rate limits answer
	// without touching the upstream.
	ip := c.ClientIP()
	acct := d.guardAccount(name)
	pwHash := d.o.Guard.HashPassword(password)
	b := &bindCtx{conn: c, name: name, start: start, ip: ip, key: acct, pwHash: pwHash}
	v := d.o.Guard.PreBind(ip, acct, pwHash)
	if v.Done != nil {
		defer v.Done()
	}
	if v.Wait > 0 {
		d.o.Sleep(ctx, v.Wait)
	}
	if !v.Allowed {
		return d.blocked(b, v)
	}
	res := d.bind(ctx, b, password)
	if b.blocked != nil {
		// The resolved account turned out to be locked (or cached): the
		// guard released the reservation, nothing is recorded.
		return d.blocked(b, *b.blocked)
	}
	ok := res.Code == ldap.LDAPResultSuccess
	elapsed := d.now().Sub(start)
	wait := d.o.Guard.PostBind(ip, b.key, pwHash, ok, string(b.reason), elapsed)
	if !ok {
		// A failed bind on client_bind.dn costs one argon2id verification;
		// every other failure is padded to it so timing does not tell the
		// service DN from an unknown one (SPEC §9).
		if floor := d.rules.ClientVerifyCost(); floor > 0 && elapsed+wait < floor {
			wait = floor - elapsed
		}
	}
	if ok {
		d.o.Metrics.Bind(d.rules.Name, "ok", elapsed)
	} else {
		d.o.Metrics.Bind(d.rules.Name, "fail", elapsed)
	}
	if d.o.Observer != nil && b.kind != listener.BindAnonymous {
		d.o.Observer.Bind(ids.BindObs{Profile: d.rules.Name, IP: ip, KnownSource: d.knownSource(c), ConnID: c.ID(), Account: b.key, PwHash: pwHash, OK: ok, Reason: string(b.reason)})
	}
	if wait > 0 {
		d.o.Sleep(ctx, wait)
	}
	if ok {
		c.SetBound(listener.Bound{Kind: b.kind, Name: name, UpstreamDN: b.upstreamDN})
		ev := c.Event(events.BindOK, events.LevelLow)
		ev.Account = b.account
		ev.Upstream, ev.UpstreamServer = d.upstreamName(), b.server
		ev.Duration = d.now().Sub(start)
		ev.Data = map[string]any{"bind_kind": string(b.kind)}
		if b.upstreamDN != "" {
			ev.Data["upstream_dn"] = b.upstreamDN
		}
		d.ev.Emit(ev)
		d.log.Info("bind ok", "conn_id", c.ID(), "client_ip", c.ClientIP(), "account", b.account, "bind_kind", string(b.kind))
		return res
	}
	level := events.LevelLow
	if b.reason == upstream.ReasonLockedInAD {
		level = events.LevelMedium // the attacker reached the directory's lockout
	}
	ev := c.Event(events.BindFail, level)
	ev.Account = b.account
	ev.Reason = string(b.reason)
	ev.Upstream, ev.UpstreamServer = d.upstreamName(), b.server
	ev.Duration = d.now().Sub(start)
	ev.Data = map[string]any{"bind_kind": string(b.kind), "form": string(b.form)}
	if b.data != "" {
		ev.Data["ad_data"] = b.data
	}
	d.ev.Emit(ev)
	d.log.Info("bind failed", "conn_id", c.ID(), "client_ip", c.ClientIP(), "account", b.account, "reason", string(b.reason), "result", res.Code)
	return res
}

// guardAccount is the account key the guard counts failures under before
// the account is resolved: the normalized bare account (user@domain,
// DOMAIN\user and user count as one, ratelimit.AccountKey), or the canonical
// client_bind.dn for client binds — however the client spells it.
func (d *Directory) guardAccount(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if dn, err := ldapfilter.ParseDN(name); err == nil && d.rules.IsClientBindDN(dn) {
		return strings.ToLower(d.rules.ClientBindDN.String())
	}
	return ratelimit.AccountKey(d.rules.NormalizeBindName(name).Account)
}

// blocked answers a bind the guard refused: bind_blocked event, the
// detectors still see the attempt, the configured lock response.
func (d *Directory) blocked(b *bindCtx, v ratelimit.Verdict) listener.Result {
	c := b.conn
	d.o.Metrics.Bind(d.rules.Name, "blocked", d.now().Sub(b.start))
	ev := c.Event(events.BindBlocked, events.LevelMedium)
	ev.Account = strings.TrimSpace(b.name)
	ev.Reason = v.Reason
	ev.Data = map[string]any{"reason": v.Reason}
	d.ev.Emit(ev)
	d.log.Info("bind blocked", "conn_id", c.ID(), "client_ip", b.ip, "reason", v.Reason)
	if d.o.Observer != nil && b.key != "" {
		// The detectors see the attempt even though it was refused.
		d.o.Observer.Bind(ids.BindObs{Profile: d.rules.Name, IP: b.ip, KnownSource: d.knownSource(c), ConnID: c.ID(), Account: b.key, PwHash: b.pwHash, OK: false, Reason: v.Reason})
	}
	return listener.Result{Code: v.Code}
}

// identityAttr is the upstream attribute whose value is the canonical
// account key: every bind form of one user resolves to it.
func (d *Directory) identityAttr() string {
	if d.rules.Kind == "ad" {
		return "sAMAccountName"
	}
	return "uid"
}

// rekey switches the guard to the canonical key of the resolved user (its
// sAMAccountName or uid) so that UPN, DOMAIN\user, bare and virtual-DN forms
// share one failure budget. It reports false when the resolved account is
// locked or cached; b.blocked then carries the verdict.
func (d *Directory) rekey(b *bindCtx, e *upstream.Entry) bool {
	if e == nil {
		return true
	}
	key := ratelimit.AccountKey(e.First(d.identityAttr()))
	if key == "" || key == b.key {
		return true
	}
	v := d.o.Guard.Rekey(b.ip, b.key, key, b.pwHash)
	b.key = key
	if v.Allowed {
		return true
	}
	b.blocked = &v
	return false
}

// resolveIdentity looks the presented UPN/account up through the service
// account to learn its canonical key; failures and unknown names leave the
// presented key in place. Results are cached briefly per profile.
func (d *Directory) resolveIdentity(ctx context.Context, b *bindCtx, bn profile.BindName) *upstream.Entry {
	if d.up == nil || bn.Account == "" {
		return nil
	}
	ck := strings.ToLower(bn.Upstream + "\x00" + bn.Account)
	if e, ok := d.identityCached(ck); ok {
		return e
	}
	id := d.identityAttr()
	terms := []*ldapfilter.Filter{{Kind: ldapfilter.Equality, Attr: id, Value: bn.Account}}
	if d.rules.Kind == "ad" {
		terms = append(terms, &ldapfilter.Filter{Kind: ldapfilter.Equality, Attr: "userPrincipalName", Value: bn.Upstream})
	} else {
		terms = append(terms, &ldapfilter.Filter{Kind: ldapfilter.Equality, Attr: "mail", Value: bn.Upstream})
	}
	f := &ldapfilter.Filter{Kind: ldapfilter.Or, Children: terms}
	var found *upstream.Entry
	for _, bs := range d.rules.Bases {
		r, err := d.up.Search(ctx, upstream.SearchRequest{Base: bs, Scope: upstream.ScopeSub, Filter: f, Attrs: []string{id}, SizeLimit: 2})
		if err != nil {
			d.log.Debug("identity lookup failed", "conn_id", b.conn.ID(), "err", err)
			return nil
		}
		if len(r.Entries) > 1 || (found != nil && len(r.Entries) == 1) {
			return nil // ambiguous: keep the presented key
		}
		if len(r.Entries) == 1 {
			e := r.Entries[0]
			found = &e
		}
	}
	d.identityStore(ck, found)
	return found
}

const (
	identityTTL        = 5 * time.Minute
	identityMaxEntries = 10000
)

type identityEntry struct {
	e   *upstream.Entry
	exp time.Time
}

func (d *Directory) identityCached(key string) (*upstream.Entry, bool) {
	d.idMu.Lock()
	defer d.idMu.Unlock()
	ie, ok := d.ids[key]
	if !ok || d.now().After(ie.exp) {
		delete(d.ids, key)
		return nil, false
	}
	return ie.e, true
}

func (d *Directory) identityStore(key string, e *upstream.Entry) {
	d.idMu.Lock()
	defer d.idMu.Unlock()
	if d.ids == nil || len(d.ids) >= identityMaxEntries {
		d.ids = map[string]identityEntry{}
	}
	d.ids[key] = identityEntry{e: e, exp: d.now().Add(identityTTL)}
}

// bindCtx carries one bind through the pipeline.
type bindCtx struct {
	conn  *listener.Conn
	name  string
	start time.Time
	// ip, key and pwHash are what the guard counts under; key is replaced
	// by the canonical account once the user is resolved.
	ip, key, pwHash string
	// blocked is set when the guard refused the resolved account.
	blocked    *ratelimit.Verdict
	kind       listener.BindKind
	form       profile.BindForm
	account    string
	reason     upstream.Reason
	data       string
	upstreamDN string
	server     string
}

// anonymousBind handles empty names or passwords: an anonymous bind is
// accepted only with anonymous_bind = true; a name without a password is
// an unauthenticated bind (RFC 4513 §5.1.2), refused like anonymous.
func (d *Directory) anonymousBind(b *bindCtx, name string, password []byte) (listener.Result, bool) {
	if name != "" && len(password) > 0 {
		return listener.Result{}, false
	}
	b.kind = listener.BindAnonymous
	if name == "" && len(password) == 0 && d.rules.AnonymousBind {
		return listener.Success, true
	}
	b.reason = upstream.ReasonAnonymous
	return invalidCredentials, true
}

func (d *Directory) bind(ctx context.Context, b *bindCtx, password []byte) listener.Result {
	name := strings.TrimSpace(b.name)
	b.account = name
	if name != "" && len(password) == 0 {
		// An unauthenticated probe of a trap is a hit like any bind (SPEC
		// §4.5), although it is answered as anonymous below.
		switch bn := d.rules.NormalizeBindName(name); {
		case d.rules.Mode == "honeypot":
			d.honeytokenHit(b.conn, "bind", name)
		case bn.Form != profile.FormOtherDN:
			if h := d.rules.MatchHoneytoken(bn.Account); h != nil {
				d.honeytokenHit(b.conn, "bind", h.Account)
			}
		}
	}
	if res, done := d.anonymousBind(b, name, password); done {
		return res
	}
	if d.rules.Mode == "honeypot" {
		// The whole profile is a trap (SPEC §4.5): every bind is a hit.
		b.kind = listener.BindUser
		b.reason = upstream.ReasonUnknownAccount
		d.honeytokenHit(b.conn, "bind", name)
		return invalidCredentials
	}
	if dn, err := ldapfilter.ParseDN(name); err == nil && d.rules.IsClientBindDN(dn) {
		b.kind = listener.BindClient
		if d.rules.VerifyClientPassword(password) {
			return listener.Success
		}
		b.reason = upstream.ReasonInvalidPassword
		return invalidCredentials
	}
	b.kind = listener.BindUser
	if !d.rules.UserBind.Allow {
		b.reason = upstream.ReasonUnknownAccount
		return invalidCredentials
	}
	bn := d.rules.NormalizeBindName(name)
	b.form, b.account = bn.Form, bn.Account
	if h := d.rules.MatchHoneytoken(bn.Account); h != nil && bn.Form != profile.FormOtherDN {
		b.reason = upstream.ReasonUnknownAccount
		d.honeytokenHit(b.conn, "bind", h.Account)
		return invalidCredentials
	}
	if d.up == nil {
		b.reason = upstream.ReasonUnknownAccount
		return invalidCredentials
	}
	var realDN string
	switch bn.Form {
	case profile.FormOtherDN:
		// Real directory DNs are never accepted: only the virtual tree exists.
		b.reason = upstream.ReasonUnknownAccount
		return invalidCredentials
	case profile.FormVirtualDN:
		e, res := d.lookupUser(ctx, b, &ldapfilter.Filter{Kind: ldapfilter.Equality, Attr: d.rules.RDNAttr, Value: bn.RDN}, "")
		if res != nil {
			return *res
		}
		realDN = e.DN
		bn.Upstream = realDN
		if !d.rekey(b, e) {
			return invalidCredentials
		}
	case profile.FormUPN, profile.FormDomain, profile.FormAccount:
		if !d.rekey(b, d.resolveIdentity(ctx, b, bn)) {
			return invalidCredentials
		}
	}
	err := d.up.UserBind(ctx, bn.Upstream, string(password))
	if err != nil {
		return d.bindError(b, err)
	}
	b.upstreamDN = realDN
	if d.rules.UserBind.RequireMembership {
		if res := d.requireMembership(ctx, b, bn, realDN); res != nil {
			return *res
		}
	}
	return listener.Success
}

// bindError maps an upstream bind failure (SPEC §4.3).
func (d *Directory) bindError(b *bindCtx, err error) listener.Result {
	var be *upstream.BindError
	switch {
	case errors.As(err, &be):
		b.reason, b.data = be.Reason, be.Data
		if be.Reason == upstream.ReasonUpstreamError {
			d.log.Warn("upstream bind error", "conn_id", b.conn.ID(), "err", err)
		}
		return invalidCredentials
	case errors.Is(err, upstream.ErrUnavailable), errors.Is(err, upstream.ErrClosed):
		b.reason = upstream.ReasonUpstreamError
		d.log.Warn("upstream unavailable for bind", "conn_id", b.conn.ID(), "err", err)
		return listener.Result{Code: ldap.LDAPResultUnavailable, Diagnostic: "directory unavailable"}
	default:
		b.reason = upstream.ReasonUpstreamError
		d.log.Warn("bind failed", "conn_id", b.conn.ID(), "err", err)
		return invalidCredentials
	}
}

// lookupUser finds exactly one user matching f (AND profile filter) in the
// profile bases, or base alone when given. It returns a client result on failure.
func (d *Directory) lookupUser(ctx context.Context, b *bindCtx, f *ldapfilter.Filter, base string) (*upstream.Entry, *listener.Result) {
	if d.rules.Filter != nil {
		f = ldapfilter.Inject(f, d.rules.Filter)
	}
	if d.rules.Exclude != nil {
		f = ldapfilter.Exclude(f, d.rules.Exclude)
	}
	bases := d.rules.Bases
	scope := upstream.ScopeSub
	if base != "" {
		bases, scope = []string{base}, upstream.ScopeBase
	}
	var found []upstream.Entry
	for _, bs := range bases {
		r, err := d.up.Search(ctx, upstream.SearchRequest{Base: bs, Scope: scope, Filter: f, Attrs: []string{d.rules.RDNAttr, attrObjectGUID, d.identityAttr()}, SizeLimit: 2})
		if err != nil {
			res := d.bindError(b, fmt.Errorf("lookup: %w", err))
			return nil, &res
		}
		b.server = r.Server
		found = append(found, r.Entries...)
		if len(found) > 1 {
			break
		}
	}
	switch len(found) {
	case 1:
		return &found[0], nil
	case 0:
		b.reason = upstream.ReasonUnknownAccount
	default:
		d.log.Warn("bind name matches several accounts", "conn_id", b.conn.ID(), "account", b.account)
		b.reason = upstream.ReasonUnknownAccount
	}
	res := invalidCredentials
	return nil, &res
}

// requireMembership checks that the authenticated user passes the profile
// filter (user_bind.require_membership).
func (d *Directory) requireMembership(ctx context.Context, b *bindCtx, bn profile.BindName, realDN string) *listener.Result {
	var f *ldapfilter.Filter
	base := ""
	switch bn.Form {
	case profile.FormVirtualDN:
		f, base = ldapfilter.True(), realDN
	case profile.FormUPN:
		f = &ldapfilter.Filter{Kind: ldapfilter.Equality, Attr: "userPrincipalName", Value: bn.Upstream}
	case profile.FormDomain, profile.FormAccount, profile.FormOtherDN:
		f = &ldapfilter.Filter{Kind: ldapfilter.Equality, Attr: "sAMAccountName", Value: bn.Account}
	}
	e, res := d.lookupUser(ctx, b, f, base)
	if res != nil {
		if b.reason == upstream.ReasonUnknownAccount {
			b.reason = "not_member"
		}
		return res
	}
	b.upstreamDN = e.DN
	return nil
}
