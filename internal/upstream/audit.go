package upstream

import (
	"context"
	"strings"
	"time"

	"github.com/alstdev/aldap/internal/ldapfilter"
)

// AdminGroups are the group names a read-only service account must not be in.
var AdminGroups = []string{"Domain Admins", "Enterprise Admins", "Administrators", "Account Operators"}

// RuleInChain is LDAP_MATCHING_RULE_IN_CHAIN (transitive membership).
const RuleInChain = "1.2.840.113556.1.4.1941"

// auditFilter builds the group search for the service account: transitive
// membership for kind = ad, direct membership for generic.
func (u *Upstream) auditFilter() *ldapfilter.Filter {
	names := &ldapfilter.Filter{Kind: ldapfilter.Or}
	for _, g := range AdminGroups {
		names.Children = append(names.Children, &ldapfilter.Filter{Kind: ldapfilter.Equality, Attr: "cn", Value: g})
	}
	member := &ldapfilter.Filter{Kind: ldapfilter.Equality, Attr: "member", Value: u.cfg.BindDN}
	if u.cfg.Kind == "ad" {
		member = &ldapfilter.Filter{Kind: ldapfilter.Extensible, Attr: "member", MatchingRule: RuleInChain, Value: u.cfg.BindDN}
	}
	return &ldapfilter.Filter{Kind: ldapfilter.And, Children: []*ldapfilter.Filter{
		{Kind: ldapfilter.Equality, Attr: "objectClass", Value: "group"}, names, member,
	}}
}

// AuditServiceAccount returns the administrative groups the service account
// belongs to (SPEC §3.4 audit_service_account). An empty bind_dn yields nil.
func (u *Upstream) AuditServiceAccount(ctx context.Context) ([]string, error) {
	if u.cfg.BindDN == "" {
		return nil, nil
	}
	base := u.cfg.BaseDN
	if base == "" {
		root, err := u.RootDSE(ctx, "defaultNamingContext", "namingContexts")
		if err != nil {
			return nil, err
		}
		base = root.First("defaultNamingContext")
		if base == "" {
			base = root.First("namingContexts")
		}
	}
	res, err := u.Search(ctx, SearchRequest{Base: base, Scope: ScopeSub, Filter: u.auditFilter(), Attrs: []string{"cn"}})
	if err != nil {
		return nil, err
	}
	groups := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		groups = append(groups, e.DN)
	}
	return groups, nil
}

// runAudit retries the audit until it succeeds (the upstream may still be
// coming up), then warns and emits insecure_config when the account is
// privileged.
func (u *Upstream) runAudit(ctx context.Context) {
	interval := time.Duration(u.cfg.HealthInterval)
	if interval <= 0 {
		interval = 10 * time.Second
	}
	for attempt := 0; attempt < 30; attempt++ {
		groups, err := u.AuditServiceAccount(ctx)
		if err == nil {
			if len(groups) > 0 {
				u.log.Warn("service account is a member of an administrative group; use a read-only account",
					"bind_dn", u.cfg.BindDN, "groups", strings.Join(groups, "; "))
				u.emit(Event{Kind: EventInsecureConfig, Level: "medium", Upstream: u.name,
					Data: map[string]any{"what": "service_account_admin", "bind_dn": u.cfg.BindDN, "groups": groups}})
			} else {
				u.log.Info("service account audit passed", "bind_dn", u.cfg.BindDN)
			}
			return
		}
		if ctx.Err() != nil {
			return
		}
		u.log.Debug("service account audit postponed", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}
