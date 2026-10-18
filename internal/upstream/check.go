package upstream

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Finding is one result of Check (`aldap check --online`).
type Finding struct {
	// Server is the server URL ("" for upstream-wide findings).
	Server string `json:"server,omitempty"`
	// Check names the probe: connect, bind, rootdse, base, audit.
	Check string `json:"check"`
	// OK is false for an error; Warn marks a non-fatal finding.
	OK   bool   `json:"ok"`
	Warn bool   `json:"warn,omitempty"`
	Msg  string `json:"msg,omitempty"`
}

// String renders the finding for a report.
func (f Finding) String() string {
	where := f.Check
	if f.Server != "" {
		where = f.Server + " " + f.Check
	}
	return where + ": " + f.Msg
}

// Check connects to every server, binds the service account, reads the root
// DSE, verifies each base with a base-scope search and audits the service
// account (SPEC §3.5 --online). It uses fresh connections and never starts
// the health loops.
func (u *Upstream) Check(ctx context.Context, bases []string) []Finding {
	var out []Finding
	for _, s := range u.servers {
		out = append(out, u.checkServer(ctx, s.url, bases)...)
	}
	if u.cfg.AuditServiceAccount && u.cfg.BindDN != "" {
		groups, err := u.AuditServiceAccount(ctx)
		switch {
		case err != nil:
			out = append(out, Finding{Check: "audit", Warn: true, Msg: fmt.Sprintf("service account audit failed: %v", err)})
		case len(groups) > 0:
			out = append(out, Finding{Check: "audit", Warn: true, Msg: "service account is a member of " + strings.Join(groups, "; ")})
		default:
			out = append(out, Finding{Check: "audit", OK: true, Msg: "service account is not in an administrative group"})
		}
	}
	return out
}

func (u *Upstream) checkServer(ctx context.Context, srv ServerURL, bases []string) []Finding {
	url := srv.String()
	budget := time.Duration(u.cfg.Timeouts.Connect + u.cfg.Timeouts.Bind + u.cfg.Timeouts.Search)
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	c, err := u.dial(ctx, srv)
	if err != nil {
		return []Finding{{Server: url, Check: "connect", Msg: err.Error()}}
	}
	defer closeQuietly(c, u.log)
	out := []Finding{{Server: url, Check: "connect", OK: true, Msg: "connected"}}
	if u.cfg.BindDN != "" {
		c.SetTimeout(time.Duration(u.cfg.Timeouts.Bind))
		if err := c.Bind(u.cfg.BindDN, u.password); err != nil {
			reason, _ := ClassifyBindError(err)
			return append(out, Finding{Server: url, Check: "bind", Msg: fmt.Sprintf("service bind failed: %s", reason)})
		}
		out = append(out, Finding{Server: url, Check: "bind", OK: true, Msg: "service bind ok"})
	}
	c.SetTimeout(time.Duration(u.cfg.Timeouts.Search))
	root, err := c.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, PresentAll, []string{"defaultNamingContext", "namingContexts", "supportedControl"}, nil))
	switch {
	case err != nil:
		out = append(out, Finding{Server: url, Check: "rootdse", Msg: err.Error()})
	case len(root.Entries) == 0:
		out = append(out, Finding{Server: url, Check: "rootdse", Msg: "empty root DSE"})
	default:
		e := convertEntry(root.Entries[0])
		nc := e.First("defaultNamingContext")
		out = append(out, Finding{Server: url, Check: "rootdse", OK: true, Msg: "defaultNamingContext=" + nc})
		if u.cfg.BaseDN != "" && nc != "" && !strings.EqualFold(nc, u.cfg.BaseDN) {
			out = append(out, Finding{Server: url, Check: "rootdse", OK: true, Warn: true, Msg: fmt.Sprintf("base_dn %q differs from defaultNamingContext %q", u.cfg.BaseDN, nc)})
		}
		if u.cfg.Kind == "ad" && !contains(e.Get("supportedControl"), ldap.ControlTypePaging) {
			out = append(out, Finding{Server: url, Check: "rootdse", OK: true, Warn: true, Msg: "paged results control not advertised"})
		}
	}
	for _, b := range bases {
		_, err := c.Search(ldap.NewSearchRequest(b, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, PresentAll, []string{"1.1"}, nil))
		if err != nil {
			out = append(out, Finding{Server: url, Check: "base", Msg: fmt.Sprintf("%s: %v", b, err)})
			continue
		}
		out = append(out, Finding{Server: url, Check: "base", OK: true, Msg: b + " ok"})
	}
	return out
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
