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
	"github.com/alstdev/aldap/internal/upstream"
)

// invalidCredentials is the only failure clients see (SPEC §9).
var invalidCredentials = listener.Result{Code: ldap.LDAPResultInvalidCredentials}

// Bind authenticates a client (SPEC §4.3): anonymous, client_bind or user.
func (d *Directory) Bind(ctx context.Context, c *listener.Conn, name string, password []byte) listener.Result {
	start := d.now()
	b := &bindCtx{conn: c, name: name, start: start}
	// Gate (SPEC §9): locks, negative cache, lockdown and rate limits answer
	// without touching the upstream.
	ip := c.ClientIP()
	acct := d.guardAccount(name)
	pwHash := d.o.Guard.HashPassword(password)
	v := d.o.Guard.PreBind(ip, acct, pwHash)
	if v.Done != nil {
		defer v.Done()
	}
	if v.Wait > 0 {
		d.o.Sleep(ctx, v.Wait)
	}
	if !v.Allowed {
		d.o.Metrics.Bind(d.rules.Name, "blocked", d.now().Sub(start))
		ev := c.Event(events.BindBlocked, events.LevelMedium)
		ev.Account = strings.TrimSpace(name)
		ev.Reason = v.Reason
		ev.Data = map[string]any{"reason": v.Reason}
		d.ev.Emit(ev)
		d.log.Info("bind blocked", "conn_id", c.ID(), "client_ip", ip, "reason", v.Reason)
		if d.o.Observer != nil && acct != "" {
			// The detectors see the attempt even though it was refused.
			d.o.Observer.Bind(ids.BindObs{Profile: d.rules.Name, IP: ip, ConnID: c.ID(), Account: acct, PwHash: pwHash, OK: false, Reason: v.Reason})
		}
		return listener.Result{Code: v.Code}
	}
	res := d.bind(ctx, b, password)
	ok := res.Code == ldap.LDAPResultSuccess
	elapsed := d.now().Sub(start)
	wait := d.o.Guard.PostBind(ip, acct, pwHash, ok, string(b.reason), elapsed)
	if ok {
		d.o.Metrics.Bind(d.rules.Name, "ok", elapsed)
	} else {
		d.o.Metrics.Bind(d.rules.Name, "fail", elapsed)
	}
	if d.o.Observer != nil && b.kind != listener.BindAnonymous {
		d.o.Observer.Bind(ids.BindObs{Profile: d.rules.Name, IP: ip, ConnID: c.ID(), Account: acct, PwHash: pwHash, OK: ok, Reason: string(b.reason)})
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

// guardAccount is the account key the guard counts failures under: the
// normalized user account, or the name as presented for client binds.
func (d *Directory) guardAccount(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if dn, err := ldapfilter.ParseDN(name); err == nil && d.rules.IsClientBindDN(dn) {
		return strings.ToLower(name)
	}
	acct := strings.ToLower(d.rules.NormalizeBindName(name).Account)
	// user@domain, DOMAIN\user and user count as one account.
	if i := strings.IndexByte(acct, '@'); i > 0 {
		acct = acct[:i]
	}
	if i := strings.LastIndexByte(acct, '\\'); i >= 0 {
		acct = acct[i+1:]
	}
	return acct
}

// bindCtx carries one bind through the pipeline.
type bindCtx struct {
	conn       *listener.Conn
	name       string
	start      time.Time
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
	case profile.FormUPN, profile.FormDomain, profile.FormAccount:
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
		r, err := d.up.Search(ctx, upstream.SearchRequest{Base: bs, Scope: scope, Filter: f, Attrs: []string{d.rules.RDNAttr, attrObjectGUID}, SizeLimit: 2})
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
