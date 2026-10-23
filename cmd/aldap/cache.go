package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"sync"

	"github.com/alstdev/aldap/internal/cache"
	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/metrics"
)

// profileCache is the cache of one profile (cache.mode = ttl or replica).
// It survives a reload that leaves the profile and its upstream unchanged
// (same fingerprint) and is replaced, i.e. invalidated, otherwise.
type profileCache struct {
	fp      string
	mode    string
	ttl     *cache.TTL
	replica *cache.Replica
}

// cacheSet holds the caches of the running daemon generation.
type cacheSet struct {
	mu sync.Mutex
	m  map[string]*profileCache
}

// cacheFingerprint identifies what cached data depends on: the profile
// section and its upstream section (secrets render as "***").
func cacheFingerprint(p *config.Profile, u *config.Upstream) string {
	b, err := json.Marshal(struct {
		P *config.Profile
		U *config.Upstream
	}{p, u})
	if err != nil {
		return "" // never equal to a stored fingerprint: a fresh cache
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// get returns the cache of a profile: the running one when the
// fingerprint matches, a new empty one otherwise (nil for cache.mode =
// none and for profiles without an upstream). Nothing is stored until
// commit, so a failed reload leaves the running caches in place.
func (s *cacheSet) get(name string, p *config.Profile, u *config.Upstream, ev events.Sink, log *slog.Logger) *profileCache {
	if p.Mode != "proxy" || (p.Cache.Mode != "ttl" && p.Cache.Mode != "replica") {
		return nil
	}
	fp := cacheFingerprint(p, u)
	s.mu.Lock()
	cur := s.m[name]
	s.mu.Unlock()
	if cur != nil && fp != "" && cur.fp == fp {
		return cur
	}
	pc := &profileCache{fp: fp, mode: p.Cache.Mode}
	c := p.Cache
	switch c.Mode {
	case "ttl":
		pc.ttl = cache.NewTTL(cache.TTLOptions{TTL: c.TTL.D(), MaxEntries: c.MaxEntries, StaleWhileDown: c.StaleWhileDown, StaleMax: c.StaleMax.D()})
	case "replica":
		pc.replica = cache.NewReplica(cache.ReplicaOptions{Profile: name, Upstream: p.Upstream, Interval: c.SyncInterval.D(),
			Jitter: float64(c.SyncJitter), Events: ev, Logger: log})
	}
	if cur != nil {
		log.Info("profile changed, cache invalidated", "profile", name, "cache", c.Mode)
	}
	return pc
}

// commit makes the caches of a started daemon the running ones.
func (s *cacheSet) commit(profiles []*servedProfile) {
	m := map[string]*profileCache{}
	for _, sp := range profiles {
		if sp.cache != nil {
			m[sp.name] = sp.cache
		}
	}
	s.mu.Lock()
	s.m = m
	s.mu.Unlock()
}

// sweep expires ttl results and publishes cache_entries and
// replica_age_seconds.
func (pc *profileCache) sweep(profile string, m *metrics.Metrics) {
	switch {
	case pc.ttl != nil:
		pc.ttl.Sweep()
		m.SetCache(profile, pc.ttl.Len(), -1)
	case pc.replica != nil:
		if age, n, ok := pc.replica.Stats(); ok {
			m.SetCache(profile, n, max(age, 0))
		}
	}
}
