package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/profile"
	"github.com/alstdev/aldap/internal/record"
	"github.com/alstdev/aldap/internal/vdir"
)

// profileRecorder is the recorder of one profile and what it was built
// from.
type profileRecorder struct {
	fp      string
	enabled bool // record.enabled when built
	rec     *record.Recorder
}

// recorderSet holds the recorders of the process. A recorder outlives a
// reload that leaves [profile.<name>.record] unchanged, together with its
// run-time state (aldapctl record start/stop); a changed section replaces
// it and record.enabled applies again.
type recorderSet struct {
	mu sync.Mutex
	m  map[string]*profileRecorder
}

func recordFingerprint(r config.Record) string {
	b, err := json.Marshal(r)
	if err != nil {
		return ""
	}
	return string(b)
}

// get returns the recorder for a profile build (nil without record.file);
// a new one is not started until commit.
func (s *recorderSet) get(name string, p *config.Profile, log *slog.Logger) *profileRecorder {
	if p.Record.File == "" {
		return nil
	}
	fp := recordFingerprint(p.Record)
	s.mu.Lock()
	cur := s.m[name]
	s.mu.Unlock()
	if cur != nil && fp != "" && cur.fp == fp {
		return cur
	}
	return &profileRecorder{fp: fp, enabled: p.Record.Enabled, rec: record.NewRecorder(record.RecorderOptions{
		Profile: name, Path: p.Record.File, MaxBytes: int64(p.Record.MaxSizeMB) << 20, MaxFiles: p.Record.MaxFiles, Logger: log})}
}

// commit makes the recorders of the started generation current: replaced
// and removed ones are stopped (queued searches written), new ones start
// when record.enabled.
func (s *recorderSet) commit(profiles []*servedProfile, log *slog.Logger) {
	m := map[string]*profileRecorder{}
	for _, sp := range profiles {
		if sp.rec != nil {
			m[sp.name] = sp.rec
		}
	}
	s.mu.Lock()
	old := s.m
	s.m = m
	s.mu.Unlock()
	for name, pr := range old {
		if m[name] != pr {
			pr.rec.Stop()
		}
	}
	for name, pr := range m {
		if old[name] == pr || !pr.enabled {
			continue
		}
		if err := pr.rec.Start(); err != nil {
			log.Error("recording not started", "profile", name, "err", err)
		}
	}
}

// closeAll stops every recorder (process exit).
func (s *recorderSet) closeAll() {
	s.mu.Lock()
	m := s.m
	s.m = nil
	s.mu.Unlock()
	for _, pr := range m {
		pr.rec.Stop()
	}
}

// buildShadow compiles the shadow rules of a profile (shadow.filter and
// shadow.bases replace filter and bases) into a directory without events,
// guard, observer or metrics, over the same upstream (and ttl cache) as
// the profile; the replica is not used, its copy covers the main bases
// only. nil when no shadow rules are set or there is no upstream.
func (d *daemon) buildShadow(name string, pcfg *config.Profile, up vdir.Searcher, cache vdir.SearchSource, opts profile.Options) (*record.Shadow, error) {
	if !pcfg.Shadow.Enabled() || up == nil {
		return nil, nil
	}
	sc := *pcfg
	if pcfg.Shadow.Filter != "" {
		sc.Filter = pcfg.Shadow.Filter
	}
	if len(pcfg.Shadow.Bases) > 0 {
		sc.Bases = pcfg.Shadow.Bases
	}
	rules, err := profile.Compile(name, &sc, d.cfg.Upstreams[pcfg.Upstream], opts)
	if err != nil {
		return nil, fmt.Errorf("profile.%s.shadow: %w", name, err)
	}
	dir := vdir.New(rules, up, vdir.Options{Logger: d.log.With("shadow", true), Events: events.Discard, Version: version, Cache: cache})
	return record.NewShadow(dir, record.ShadowOptions{MaxParallel: pcfg.Shadow.MaxParallel, Timeout: pcfg.Shadow.Timeout.D(),
		Events: d.events, Logger: d.log}), nil
}
