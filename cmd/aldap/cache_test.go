package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/metrics"
)

func TestCacheSet_Fingerprint(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	prof := func(mode string) *config.Profile {
		p := config.DefaultProfile()
		p.Mode, p.Upstream, p.Bases = "proxy", "ad", []string{"DC=test,DC=aldap"}
		p.Cache.Mode = mode
		return p
	}
	u := config.DefaultUpstream()
	u.Servers = []string{"ldaps://dc1"}
	var s cacheSet
	if pc := s.get("p", prof("none"), u, events.Discard, log); pc != nil {
		t.Error("cache for mode none")
	}
	mock := prof("ttl")
	mock.Mode = "mock"
	if pc := s.get("p", mock, u, events.Discard, log); pc != nil {
		t.Error("cache for mode mock")
	}
	ttl := s.get("p", prof("ttl"), u, events.Discard, log)
	rep := s.get("r", prof("replica"), u, events.Discard, log)
	if ttl == nil || ttl.ttl == nil || rep == nil || rep.replica == nil || ttl.fp == "" {
		t.Fatalf("caches = %+v %+v", ttl, rep)
	}
	// Nothing is reused before commit (a reload that fails to start).
	if again := s.get("p", prof("ttl"), u, events.Discard, log); again == ttl {
		t.Error("uncommitted cache reused")
	}
	s.commit([]*servedProfile{{name: "p", cache: ttl}, {name: "r", cache: rep}, {name: "n"}})
	if again := s.get("p", prof("ttl"), u, events.Discard, log); again != ttl {
		t.Error("unchanged profile got a new cache")
	}
	changed := prof("ttl")
	changed.Cache.TTL = config.Duration(2 * time.Minute)
	if again := s.get("p", changed, u, events.Discard, log); again == ttl || again.ttl == nil {
		t.Error("changed profile kept its cache")
	}
	u2 := *u
	u2.Servers = []string{"ldaps://dc2"}
	pu2 := &u2
	if again := s.get("r", prof("replica"), pu2, events.Discard, log); again == rep {
		t.Error("changed upstream kept the replica")
	}
	if cacheFingerprint(prof("ttl"), u) == cacheFingerprint(prof("ttl"), pu2) {
		t.Error("fingerprint ignores the upstream")
	}

	m := metrics.New("t", "", "")
	ttl.sweep("p", m)
	rep.sweep("r", m) // not synced: no gauge
	_ = rep.replica.Sync(t.Context(), func(context.Context) (any, int, error) { return 1, 4, nil })
	rep.sweep("r", m)
	body := scrape(t, m)
	for _, want := range []string{`aldap_cache_entries{profile="p"} 0`, `aldap_cache_entries{profile="r"} 4`, `aldap_replica_age_seconds{profile="r"}`} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
}

func scrape(t *testing.T, m *metrics.Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	return rec.Body.String()
}
