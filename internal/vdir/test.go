package vdir

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/alstdev/aldap/internal/listener"
)

// TestRequest describes a search run on behalf of a client for
// diagnostics (`aldap check --as-client`, POST /v1/profiles/{name}/test).
type TestRequest struct {
	Base   string
	Scope  listener.Scope
	Filter string
	Attrs  []string
	// SizeLimit caps the entries (0 = profile limit).
	SizeLimit int
}

// TestResult is what the client would see plus the pipeline diagnostics.
type TestResult struct {
	Result  listener.Result
	Entries []listener.Entry
	// DeniedAttrs are requested attributes outside the allowlist;
	// DeniedTerms are filter attributes that were replaced by false.
	DeniedAttrs []string
	DeniedTerms []string
	// UpstreamFilter is the filter sent to the directory ("" when none);
	// PostFilter is the part evaluated locally ("" when none).
	UpstreamFilter string
	PostFilter     string
	// UpstreamQueries counts the directory searches run.
	UpstreamQueries int
	// Honeytoken names the trap the search targeted ("" when none).
	Honeytoken string
	Duration   time.Duration
}

// Test runs the search pipeline without a client connection and without
// paging; events are emitted like for a real search from 127.0.0.1.
func (d *Directory) Test(ctx context.Context, req TestRequest) TestResult {
	c := listener.NewConn("c-test", d.rules.Name, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	c.SetBound(listener.Bound{Kind: listener.BindClient}) // simulates the application's bound session
	sc := &searchCtx{conn: c, start: d.now(), req: &listener.SearchRequest{Base: req.Base, Scope: req.Scope, Filter: req.Filter, Attrs: req.Attrs, SizeLimit: req.SizeLimit}}
	res, entries := d.search(ctx, sc)
	d.emitSearch(sc, res, len(entries))
	out := TestResult{Result: res, Entries: entries, DeniedAttrs: sc.denied, DeniedTerms: sc.terms, UpstreamQueries: sc.queries,
		Honeytoken: sc.trap, Duration: d.now().Sub(sc.start)}
	if sc.upstream != nil && !sc.upstream.IsFalse() {
		out.UpstreamFilter = sc.upstream.String()
	}
	if sc.post != nil {
		out.PostFilter = sc.post.String()
	}
	return out
}

// Evaluate runs the search pipeline like Test without the search event
// and the metrics (shadow rules, internal/record). Whatever else the
// pipeline reports goes to the directory's own Options, so a shadow
// directory is built without events, guard and observer.
func (d *Directory) Evaluate(ctx context.Context, req TestRequest) (listener.Result, []listener.Entry) {
	c := listener.NewConn("c-shadow", d.rules.Name, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	c.SetBound(listener.Bound{Kind: listener.BindClient})
	sc := &searchCtx{conn: c, start: d.now(), req: &listener.SearchRequest{Base: req.Base, Scope: req.Scope, Filter: req.Filter, Attrs: req.Attrs, SizeLimit: req.SizeLimit}}
	return d.search(ctx, sc)
}

// String renders the result as LDIF-like text with the diagnostics.
func (r TestResult) String() string {
	s := ""
	for _, e := range r.Entries {
		s += "dn: " + e.DN + "\n"
		for _, a := range e.Attrs {
			for _, v := range a.Values {
				s += a.Name + ": " + v + "\n"
			}
		}
		s += "\n"
	}
	s += fmt.Sprintf("# result: %d, entries: %d, upstream_queries: %d, duration: %s\n", r.Result.Code, len(r.Entries), r.UpstreamQueries, r.Duration.Round(time.Millisecond))
	if r.UpstreamFilter != "" {
		s += "# upstream_filter: " + r.UpstreamFilter + "\n"
	}
	if r.PostFilter != "" {
		s += "# post_filter: " + r.PostFilter + "\n"
	}
	if len(r.DeniedAttrs) > 0 {
		s += fmt.Sprintf("# denied_attrs: %v\n", r.DeniedAttrs)
	}
	if len(r.DeniedTerms) > 0 {
		s += fmt.Sprintf("# denied_terms: %v\n", r.DeniedTerms)
	}
	if r.Honeytoken != "" {
		s += "# honeytoken: " + r.Honeytoken + "\n"
	}
	return s
}
