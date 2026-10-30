package vdir

import (
	"context"
	"sync"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/listener"
	"github.com/alstdev/aldap/internal/ratelimit"
)

type tapLog struct {
	mu sync.Mutex
	ts []TapSearch
}

func (l *tapLog) Search(t TapSearch) { l.mu.Lock(); l.ts = append(l.ts, t); l.mu.Unlock() }

type refuseSearch struct{ noGuard }

func (refuseSearch) PreSearch(string, string) ratelimit.Verdict {
	return ratelimit.Verdict{Reason: "rate_limited", Code: ldap.LDAPResultBusy}
}

// TestTaps: every search that ran the pipeline is reported once with the
// whole result (a paged search at its first page), after the entries
// were written; cookie pages and refused searches are not; Evaluate runs
// the pipeline without the search event.
func TestTaps(t *testing.T) {
	f := newFixture(t, nil)
	log := &tapLog{}
	d := New(f.d.rules, f.up, Options{Events: f.ev, Taps: []Tap{log}})
	c := boundConn("192.0.2.10")
	col := &collector{}
	res := d.Search(context.Background(), c, &listener.SearchRequest{Base: usersDN, Scope: listener.ScopeSub, Filter: "(objectClass=*)", Attrs: []string{"mail"}, SizeLimit: 50}, col)
	if res.Code != ldap.LDAPResultSuccess || len(log.ts) != 1 {
		t.Fatalf("plain: %v %d", res, len(log.ts))
	}
	tp := log.ts[0]
	if tp.Conn != c || tp.Base != usersDN || tp.Scope != listener.ScopeSub || tp.RawFilter != "(objectClass=*)" || tp.Filter == nil || tp.SizeLimit != 50 ||
		tp.Attrs[0] != "mail" || len(tp.Entries) != len(col.entries) || tp.Local {
		t.Errorf("tap: %+v", tp)
	}
	// Paged: reported once, with every entry.
	var cookie []byte
	pages := 0
	for {
		col := &collector{}
		res := d.Search(context.Background(), c, &listener.SearchRequest{Base: usersDN, Scope: listener.ScopeSub, Filter: "(objectClass=*)",
			Controls: []ldap.Control{&ldap.ControlPaging{PagingSize: 3, Cookie: cookie}}}, col)
		pages++
		cookie = nil
		for _, x := range res.Controls {
			if p, ok := x.(*ldap.ControlPaging); ok {
				cookie = p.Cookie
			}
		}
		if len(cookie) == 0 {
			break
		}
	}
	if pages < 2 || len(log.ts) != 2 || len(log.ts[1].Entries) != len(tp.Entries) {
		t.Errorf("paged: %d pages, %d taps, %d entries", pages, len(log.ts), len(log.ts[1].Entries))
	}
	// Root DSE is local; an invalid filter has no parsed filter.
	_ = d.Search(context.Background(), c, &listener.SearchRequest{Base: "", Scope: listener.ScopeBase, Filter: "(objectClass=*)"}, &collector{})
	_ = d.Search(context.Background(), c, &listener.SearchRequest{Base: usersDN, Scope: listener.ScopeSub, Filter: "(uid="}, &collector{})
	if len(log.ts) != 4 || !log.ts[2].Local || log.ts[3].Filter != nil || log.ts[3].Result.Code != ldap.LDAPResultProtocolError {
		t.Errorf("local/invalid: %+v", log.ts[2:])
	}
	// Refused by the rate limiter: not reported.
	refused := New(f.d.rules, f.up, Options{Events: f.ev, Taps: []Tap{log}, Guard: refuseSearch{}})
	if res := refused.Search(context.Background(), c, &listener.SearchRequest{Base: usersDN, Scope: listener.ScopeSub, Filter: "(objectClass=*)"}, &collector{}); res.Code != ldap.LDAPResultBusy || len(log.ts) != 4 {
		t.Errorf("refused: %v %d", res, len(log.ts))
	}
	// Evaluate: same result as Test, no search event.
	before := f.ev.count()
	er, ee := d.Evaluate(context.Background(), TestRequest{Base: usersDN, Scope: listener.ScopeSub, Filter: "(objectClass=*)"})
	if er.Code != ldap.LDAPResultSuccess || len(ee) != len(tp.Entries) || f.ev.count() != before {
		t.Errorf("evaluate: %v %d entries, %d new events", er, len(ee), f.ev.count()-before)
	}
}

func (s *sink) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.ev) }
