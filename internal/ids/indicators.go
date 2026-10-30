package ids

import (
	"math"
	"sort"
	"strings"
	"time"

	"github.com/alstdev/aldap/internal/events"
)

// Indicator weights: the score of a key is the decayed sum of its hits.
const (
	weightHoneytoken = 100.0
	weightAttackHigh = 80.0
	weightAttackMed  = 50.0
	weightLock       = 30.0
	weightRecon      = 20.0
	weightAnomaly    = 10.0
	weightBindFail   = 1.0
	weightOpDenied   = 2.0
)

// HalfLife is the decay half-life of indicator scores.
const HalfLife = time.Hour

func weightAttack(level string) float64 {
	if level == events.LevelHigh {
		return weightAttackHigh
	}
	return weightAttackMed
}

// Indicator is one scored source or account (/v1/indicators).
type Indicator struct {
	Type      string         `json:"type"`
	Key       string         `json:"key"`
	Score     float64        `json:"score"`
	FirstSeen time.Time      `json:"first_seen"`
	LastSeen  time.Time      `json:"last_seen"`
	Hits      map[string]int `json:"hits"`
}

type indicator struct {
	Indicator
	updated time.Time
}

func keyIP(ip string) string     { return "ip:" + ip }
func keyAccount(a string) string { return "account:" + strings.ToLower(a) }

func weightName(w float64) string {
	switch w {
	case weightHoneytoken:
		return "honeytoken"
	case weightAttackHigh, weightAttackMed:
		return "attack"
	case weightLock:
		return "lock"
	case weightRecon:
		return "recon"
	case weightAnomaly:
		return "anomaly"
	case weightOpDenied:
		return "op_denied"
	}
	return "bind_fail"
}

// score adds a weighted hit to key with decay applied first.
func (e *Engine) score(key string, w float64, now time.Time) {
	if strings.HasSuffix(key, ":") {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	in := e.ind[key]
	if in == nil {
		if len(e.ind) >= e.o.MaxSources {
			e.evictIndicator(now)
		}
		typ, k, _ := strings.Cut(key, ":")
		in = &indicator{Indicator: Indicator{Type: typ, Key: k, FirstSeen: now, Hits: map[string]int{}}, updated: now}
		e.ind[key] = in
	}
	in.Score = decay(in.Score, now.Sub(in.updated)) + w
	in.updated, in.LastSeen = now, now
	in.Hits[weightName(w)]++
}

// evictIndicator makes room in the indicator table: about one percent of it
// (at least one), the lowest decayed scores first, in one pass, so that a
// flood of fresh keys (IPv6 rotation, PROXY headers) pays one scan per
// thousand new keys and not one per key under the engine lock; the caller
// holds mu.
func (e *Engine) evictIndicator(now time.Time) {
	type scored struct {
		key   string
		score float64
	}
	all := make([]scored, 0, len(e.ind))
	for k, in := range e.ind {
		all = append(all, scored{k, decay(in.Score, now.Sub(in.updated))})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].score < all[j].score })
	n := max(len(all)/100, 1)
	for i := 0; i < n && i < len(all); i++ {
		delete(e.ind, all[i].key)
	}
}

func decay(score float64, age time.Duration) float64 {
	if age <= 0 || score == 0 {
		return score
	}
	return score * math.Pow(0.5, age.Hours()/HalfLife.Hours())
}

// Indicators lists the keys whose decayed score is at least minScore,
// highest first.
func (e *Engine) Indicators(minScore float64) []Indicator {
	now := e.now()
	e.mu.Lock()
	out := make([]Indicator, 0, len(e.ind))
	for k, in := range e.ind {
		s := decay(in.Score, now.Sub(in.updated))
		if s < minScore || s < 0.01 {
			if s < 0.01 {
				delete(e.ind, k)
			}
			continue
		}
		cp := in.Indicator
		cp.Score = math.Round(s*100) / 100
		cp.Hits = make(map[string]int, len(in.Hits))
		for h, n := range in.Hits {
			cp.Hits[h] = n
		}
		out = append(out, cp)
	}
	e.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score == out[j].Score {
			return out[i].Type+out[i].Key < out[j].Type+out[j].Key
		}
		return out[i].Score > out[j].Score
	})
	return out
}

// Note scores events produced elsewhere (locks, honeytoken hits, refused
// operations) so the indicators reflect the whole picture. It implements
// events.Sink and never emits anything.
func (e *Engine) Note(ev events.Event) {
	now := e.now()
	switch ev.Event {
	case events.Honeytoken:
		e.score(keyIP(ev.ClientIP), weightHoneytoken, now)
		if ev.Account != "" {
			e.score(keyAccount(ev.Account), weightHoneytoken, now)
		}
	case events.Lock:
		if ev.Data["source"] == "ratelimit" || ev.Data["source"] == "ids" {
			if ev.Data["target"] == "ip" {
				e.score(keyIP(ev.ClientIP), weightLock, now)
			} else {
				e.score(keyAccount(ev.Account), weightLock, now)
			}
		}
	case events.OpDenied:
		e.score(keyIP(ev.ClientIP), weightOpDenied, now)
	}
}

// Emit implements events.Sink via Note.
func (e *Engine) Emit(ev events.Event) { e.Note(ev) }
