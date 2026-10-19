package metrics

import (
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMetrics_Exposition(t *testing.T) {
	m := New("1.2.3", "abc", "2026-10-19")
	m.Bind("virola", "ok", 20*time.Millisecond)
	m.Bind("virola", "fail", 5*time.Millisecond)
	m.Search("virola", "miss", 3, 2)
	m.Connection("virola", 1)
	m.Connection("virola", -1)
	m.Connection("virola", 1)
	m.Upstream("ad", "ldaps://dc:636", "search", "ok", 30*time.Millisecond)
	m.SetUpstreamUp("ad", "ldaps://dc:636", true)
	m.SetUpstreamUp("ad", "ldaps://dc2:636", false)
	m.Event("bind_fail")
	m.Dropped("webhook", 2)
	m.Dropped("webhook", 0)
	m.SetLocks(2, 1)
	m.SetAttack("spray", true)
	m.SetCertExpiry("virola", time.Now().Add(48*time.Hour))
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), "GET", "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	out := string(body)
	for _, want := range []string{
		`aldap_build_info{commit="abc",date="2026-10-19",version="1.2.3"} 1`,
		`aldap_binds_total{profile="virola",result="ok"} 1`,
		`aldap_binds_total{profile="virola",result="fail"} 1`,
		`aldap_bind_duration_seconds_count{profile="virola"} 2`,
		`aldap_searches_total{cache="miss",profile="virola"} 1`,
		`aldap_search_results_sum{profile="virola"} 3`,
		`aldap_profile_cost_sum{profile="virola"} 2`,
		`aldap_connections_active{profile="virola"} 1`,
		`aldap_upstream_queries_total{op="search",result="ok",server="ldaps://dc:636",upstream="ad"} 1`,
		`aldap_upstream_up{server="ldaps://dc:636",upstream="ad"} 1`,
		`aldap_upstream_up{server="ldaps://dc2:636",upstream="ad"} 0`,
		`aldap_events_total{event="bind_fail"} 1`,
		`aldap_events_dropped_total{sink="webhook"} 2`,
		`aldap_locks_active{target="ip"} 2`,
		`aldap_locks_active{target="account"} 1`,
		`aldap_attack_active{kind="spray"} 1`,
		`aldap_cert_expiry_seconds{listener="virola"} 17`,
		"go_goroutines",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if fams, err := m.Gather(); err != nil || len(fams) < 15 || m.Registry() == nil {
		t.Errorf("gather: %d %v", len(fams), err)
	}
	// A nil receiver is a no-op everywhere.
	var none *Metrics
	none.Bind("p", "ok", 0)
	none.Search("p", "miss", 0, 0)
	none.Connection("p", 1)
	none.Upstream("u", "s", "op", "ok", 0)
	none.SetUpstreamUp("u", "s", true)
	none.Event("x")
	none.Dropped("s", 1)
	none.SetLocks(0, 0)
	none.SetAttack("k", false)
	none.SetCertExpiry("l", time.Now())
}
