package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/listener"
	"github.com/alstdev/aldap/internal/profile"
	"github.com/alstdev/aldap/internal/secret"
	"github.com/alstdev/aldap/internal/upstream"
	"github.com/alstdev/aldap/internal/vdir"
)

// clientTest is the JSON shape of `aldap check --as-client`.
type clientTest struct {
	Profile         string           `json:"profile"`
	Base            string           `json:"base"`
	Scope           string           `json:"scope"`
	Filter          string           `json:"filter"`
	ResultCode      int              `json:"result_code"`
	Entries         []listener.Entry `json:"entries"`
	DeniedAttrs     []string         `json:"denied_attrs,omitempty"`
	DeniedTerms     []string         `json:"denied_terms,omitempty"`
	UpstreamFilter  string           `json:"upstream_filter,omitempty"`
	PostFilter      string           `json:"post_filter,omitempty"`
	UpstreamQueries int              `json:"upstream_queries"`
	Honeytoken      string           `json:"honeytoken,omitempty"`
	DurationMs      int64            `json:"duration_ms"`
	Text            string           `json:"-"`
}

// clientTestRequest are the --as-client flags.
type clientTestRequest struct {
	Profile, Base, Scope, Filter, Attrs string
	Size                                int
}

// parseScope maps base/one/sub to a listener scope.
func parseScope(s string) (listener.Scope, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "base":
		return listener.ScopeBase, nil
	case "one", "onelevel":
		return listener.ScopeOne, nil
	case "sub", "subtree", "":
		return listener.ScopeSub, nil
	}
	return 0, fmt.Errorf("scope %q: use base, one or sub", s)
}

// clientSource picks the data source of the profile like the daemon does:
// the upstream for proxy, a Mock for mock, nothing for honeypot.
func clientSource(cfg *config.Config, name string, pcfg *config.Profile, secrets secret.Resolver) (vdir.Searcher, func(), error) {
	noop := func() {}
	switch pcfg.Mode {
	case "mock":
		base := ""
		if len(pcfg.Bases) > 0 {
			base = pcfg.Bases[0]
		}
		m, err := vdir.LoadMock(pcfg.Mock.File, base)
		if err != nil {
			return nil, noop, err
		}
		if len(pcfg.Bases) == 0 {
			pcfg.Bases = []string{m.BaseDN()}
		}
		return m, noop, nil
	case "honeypot":
		return nil, noop, nil
	}
	ucfg, ok := cfg.Upstreams[pcfg.Upstream]
	if !ok {
		return nil, noop, fmt.Errorf("profile %q: upstream %q is not defined", name, pcfg.Upstream)
	}
	pw, _, err := secrets.Resolve(ucfg.BindPasswordSource())
	if err != nil {
		return nil, noop, fmt.Errorf("upstream.%s.bind_password: %w", pcfg.Upstream, err)
	}
	u, err := upstream.New(pcfg.Upstream, ucfg, pw.Reveal(), upstream.Options{Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		return nil, noop, err
	}
	return u, u.Close, nil
}

// runAsClient runs one search through the virtual directory of a profile
// exactly as a client would see it (SPEC §7 POST /v1/profiles/{name}/test,
// TASKS Stage 5) and returns the entries with the pipeline diagnostics.
func runAsClient(ctx context.Context, cfg *config.Config, req clientTestRequest, secrets secret.Resolver) (*clientTest, error) {
	pcfg, ok := cfg.Profiles[req.Profile]
	if !ok {
		return nil, fmt.Errorf("profile %q is not defined", req.Profile)
	}
	scope, err := parseScope(req.Scope)
	if err != nil {
		return nil, err
	}
	src, closeSrc, err := clientSource(cfg, req.Profile, pcfg, secrets)
	if err != nil {
		return nil, err
	}
	defer closeSrc()
	clientPW := ""
	if pcfg.ClientBind.DN != "" && !pcfg.ClientBind.PasswordHash.IsSet() {
		pw, _, err := secrets.Resolve(pcfg.ClientBind.PasswordSource())
		if err != nil {
			return nil, fmt.Errorf("profile.%s.client_bind.password: %w", req.Profile, err)
		}
		clientPW = pw.Reveal()
	}
	rules, err := profile.Compile(req.Profile, pcfg, cfg.Upstreams[pcfg.Upstream], profile.Options{ClientPassword: clientPW})
	if err != nil {
		return nil, err
	}
	d := vdir.New(rules, src, vdir.Options{Logger: slog.New(slog.DiscardHandler), Version: version})
	base := req.Base
	if base == "" {
		base = rules.UsersBase.String()
	}
	filter := req.Filter
	if filter == "" {
		filter = "(objectClass=*)"
	}
	var attrs []string
	for _, a := range strings.Split(req.Attrs, ",") {
		if a = strings.TrimSpace(a); a != "" {
			attrs = append(attrs, a)
		}
	}
	r := d.Test(ctx, vdir.TestRequest{Base: base, Scope: scope, Filter: filter, Attrs: attrs, SizeLimit: req.Size})
	out := &clientTest{Profile: req.Profile, Base: base, Scope: scope.String(), Filter: filter, ResultCode: r.Result.Code, Entries: r.Entries,
		DeniedAttrs: r.DeniedAttrs, DeniedTerms: r.DeniedTerms, UpstreamFilter: r.UpstreamFilter, PostFilter: r.PostFilter,
		UpstreamQueries: r.UpstreamQueries, Honeytoken: r.Honeytoken, DurationMs: r.Duration.Milliseconds(), Text: r.String()}
	if out.Entries == nil {
		out.Entries = []listener.Entry{}
	}
	if r.Result.Code != 0 && r.Result.Code != 4 { // success or sizeLimitExceeded
		return out, errors.New("search failed with result code " + fmt.Sprint(r.Result.Code))
	}
	return out, nil
}
