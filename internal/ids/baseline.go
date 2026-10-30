package ids

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/ldapfilter"
)

// baseline is what a profile looked like during learning.
type baseline struct {
	ips, filters, bases, attrs, fingerprints map[string]bool
	// reported holds values already reported as anomalies (once each).
	reported map[string]bool
	// perSecond counts searches in the current second; rates keeps the
	// learned per-second counts for the p95.
	second    time.Time
	perSecond int
	rates     []int
	lastSpike time.Time
}

func newBaseline() *baseline {
	return &baseline{ips: map[string]bool{}, filters: map[string]bool{}, bases: map[string]bool{}, attrs: map[string]bool{}, fingerprints: map[string]bool{}, reported: map[string]bool{}}
}

// FilterShape reduces a normalized filter to its structure: attribute
// names and operators with every value replaced by "?" so a new query
// pattern is an anomaly, not every new value.
func FilterShape(norm string) string {
	f, err := ldapfilter.Parse(norm)
	if err != nil {
		return norm
	}
	ldapfilter.Walk(f, func(n *ldapfilter.Filter) bool {
		switch n.Kind {
		case ldapfilter.Equality, ldapfilter.Approx, ldapfilter.GreaterOrEqual, ldapfilter.LessOrEqual, ldapfilter.Extensible:
			n.Value = "?"
		case ldapfilter.Substring:
			n.Initial, n.Any, n.Final = "?", nil, ""
		case ldapfilter.And, ldapfilter.Or, ldapfilter.Not, ldapfilter.Present:
		}
		return true
	})
	return f.String()
}

// Fingerprint records a client fingerprint for the profile; a fingerprint
// not seen during learning is an anomaly when the detector is enabled.
func (e *Engine) Fingerprint(profile, ip, connID, fp string) {
	if fp == "" {
		return
	}
	now := e.now()
	e.mu.Lock()
	cfg := e.cfg
	if !cfg.Fingerprint.Enabled {
		e.mu.Unlock()
		return
	}
	b := e.base(profile)
	learning := now.Before(e.learnTill)
	known := b.fingerprints[fp]
	if learning {
		b.fingerprints[fp] = true
	}
	report := !learning && !known && !b.reported["fp:"+fp]
	if report {
		b.reported["fp:"+fp] = true
	}
	n := len(b.fingerprints)
	e.mu.Unlock()
	if report {
		e.anomaly(profile, ip, connID, AnomalyFingerprint, fp, n, now)
	}
}

func (e *Engine) base(profile string) *baseline {
	b := e.baselines[profile]
	if b == nil {
		b = newBaseline()
		e.baselines[profile] = b
	}
	return b
}

// Bounds on client-controlled values kept in the baseline sets.
const (
	maxBaselineValue = 8192
	maxBaselineAttrs = 64
)

// baselineFinding is one value outside the learned baseline.
type baselineFinding struct {
	reason, observed string
	baseline         int
}

// baselineObserve learns or checks one observation; bind marks a bind
// (only the IP is relevant).
func (e *Engine) baselineObserve(profile, ip, connID, base, filterNorm string, attrs []string, now time.Time, bind bool) {
	e.mu.Lock()
	if !e.cfg.Anomaly.Enabled {
		e.mu.Unlock()
		return
	}
	b := e.base(profile)
	learning := now.Before(e.learnTill)
	var out []baselineFinding
	check := func(set map[string]bool, key, reason, observed string) {
		if observed == "" {
			return
		}
		if learning {
			if len(set) < 100000 {
				set[observed] = true
			}
			return
		}
		if set[observed] || b.reported[key+observed] {
			return
		}
		b.reported[key+observed] = true
		out = append(out, baselineFinding{reason, observed, len(set)})
	}
	check(b.ips, "ip:", AnomalyNewIP, ip)
	if !bind {
		if len(base) > maxBaselineValue {
			base = base[:maxBaselineValue]
		}
		check(b.bases, "base:", AnomalyNewBase, strings.ToLower(base))
		check(b.filters, "filter:", AnomalyNewFilter, FilterShape(filterNorm))
		check(b.attrs, "attrs:", AnomalyNewAttrs, attrSetKey(attrs))
		if f, ok := b.observeRate(now, learning); ok {
			out = append(out, f)
		}
	}
	e.mu.Unlock()
	for _, f := range out {
		e.anomaly(profile, ip, connID, f.reason, f.observed, f.baseline, now)
	}
}

// attrSetKey is the order-independent, lower-cased key of a requested
// attribute set ("" for none).
func attrSetKey(attrs []string) string {
	if len(attrs) > maxBaselineAttrs {
		attrs = attrs[:maxBaselineAttrs]
	}
	if len(attrs) == 0 {
		return ""
	}
	cp := make([]string, len(attrs))
	for i, a := range attrs {
		cp[i] = strings.ToLower(a)
	}
	sort.Strings(cp)
	return strings.Join(cp, ",")
}

// observeRate counts one search in the current second against the learned
// p95 (rps_spike at most once a minute). The engine lock is held.
func (b *baseline) observeRate(now time.Time, learning bool) (baselineFinding, bool) {
	sec := now.Truncate(time.Second)
	if !sec.Equal(b.second) {
		if learning && !b.second.IsZero() {
			b.rates = append(b.rates, b.perSecond)
			if len(b.rates) > 3600 {
				b.rates = b.rates[len(b.rates)-3600:]
			}
		}
		b.second, b.perSecond = sec, 0
	}
	b.perSecond++
	if learning || len(b.rates) == 0 || now.Sub(b.lastSpike) < time.Minute {
		return baselineFinding{}, false
	}
	p95 := percentile(b.rates, 95)
	if b.perSecond <= max(2*p95, 10) {
		return baselineFinding{}, false
	}
	b.lastSpike = now
	return baselineFinding{AnomalyRPSSpike, strconv.Itoa(b.perSecond), p95}, true
}

func (e *Engine) anomaly(profile, ip, connID, reason, observed string, baseline int, now time.Time) {
	e.ev.Emit(events.Event{Event: events.Anomaly, Level: events.LevelMedium, Profile: profile, ConnID: connID, ClientIP: ip, Reason: reason,
		Data: map[string]any{"reason": reason, "observed": observed, "baseline": baseline}})
	e.log.Warn("anomaly", "reason", reason, "observed", observed, "ip", ip, "profile", profile)
	e.score(keyIP(ip), weightAnomaly, now)
}

func percentile(vals []int, p int) int {
	cp := append([]int(nil), vals...)
	sort.Ints(cp)
	idx := (len(cp)*p+99)/100 - 1 // nearest rank
	if idx >= len(cp) {
		idx = len(cp) - 1
	}
	if idx < 0 {
		return 0
	}
	return cp[idx]
}
