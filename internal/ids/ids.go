// Package ids detects attack patterns from what the proxy observes (SPEC
// §3.4 [ids]): password spray, credential stuffing, slow brute force and
// account enumeration on binds; reconnaissance signatures on searches; a
// learned baseline with anomaly reports; client fingerprints. Detections
// become attack_start/attack_summary/attack_end, recon and anomaly events,
// and feed the indicator scores served by /v1/indicators.
package ids

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/ldapfilter"
	"github.com/alstdev/aldap/internal/metrics"
)

// Attack kinds (SPEC §6 attack_start.kind).
const (
	KindSpray       = "spray"
	KindStuffing    = "stuffing"
	KindSlowBrute   = "slow_brute"
	KindEnumeration = "enumeration"
)

// Recon signatures (SPEC §3.4 recon).
const (
	SigRootDump    = "root_dump"
	SigSDDump      = "sd_dump"
	SigSIDHistory  = "sid_history"
	SigTrusts      = "trusts"
	SigMSDS        = "msds_attrs"
	SigAdminCount  = "admin_count"
	SigSPNSweep    = "spn_sweep"
	SigBaseOutside = "base_outside"
)

// Anomaly reasons (SPEC §6 anomaly.reason).
const (
	AnomalyNewIP       = "new_ip"
	AnomalyNewFilter   = "new_filter"
	AnomalyNewBase     = "new_base"
	AnomalyNewAttrs    = "new_attrs"
	AnomalyRPSSpike    = "rps_spike"
	AnomalyFingerprint = "fingerprint"
)

// Attack describes an active attack for callbacks and summaries.
type Attack struct {
	ID         string
	Kind       string
	Level      string
	IPs        []string
	Accounts   int
	Failures   int
	RatePerMin float64
	FirstSeen  time.Time
	LastSeen   time.Time
}

// Options tune an Engine.
type Options struct {
	Events events.Sink
	Logger *slog.Logger
	Now    func() time.Time
	// OnAttack is called after attack_start (lockdown auto, tarpit marking).
	OnAttack func(Attack)
	// OnAttackEnd is called after attack_end.
	OnAttackEnd func(Attack)
	// MaxSources bounds the per-IP tables (default 100000).
	MaxSources int
	// Metrics publishes attack_active (nil = none).
	Metrics *metrics.Metrics
}

// BindObs is one bind outcome.
type BindObs struct {
	Profile, IP, ConnID, Account string
	// PwHash is the salted hash of the presented password (never the password).
	PwHash string
	OK     bool
	Reason string
}

// SearchObs is one client search.
type SearchObs struct {
	Profile, IP, ConnID, Account string
	Base, Scope, FilterNorm      string
	Filter                       *ldapfilter.Filter
	Attrs                        []string
	// BaseKind classifies the base: rootdse, subschema, virtual, users,
	// groups, user, group or outside.
	BaseKind string
}

// attempt is one bind attempt seen from a source.
type attempt struct {
	t       time.Time
	account string
	pwHash  string
	ok      bool
}

// source is the recent history of one client IP.
type source struct {
	attempts  []attempt
	streak    map[string]bool // distinct accounts since the last success
	lastRecon map[string]time.Time
	lastSeen  time.Time
}

type attack struct {
	Attack
	ips         map[string]bool
	accounts    map[string]bool
	lastSummary time.Time
}

// Engine is the detector state of the process.
type Engine struct {
	o   Options
	ev  events.Sink
	log *slog.Logger
	now func() time.Time

	mu        sync.Mutex
	cfg       config.Intrusion
	sources   map[string]*source
	attacks   map[string]*attack
	baselines map[string]*baseline
	learnTill time.Time
	seq       atomic.Uint64
	ind       map[string]*indicator
}

// New creates an engine with cfg; learning starts now.
func New(cfg config.Intrusion, o Options) *Engine {
	if o.Events == nil {
		o.Events = events.Discard
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.MaxSources <= 0 {
		o.MaxSources = 100000
	}
	e := &Engine{o: o, ev: o.Events, log: o.Logger, now: o.Now, cfg: cfg, sources: map[string]*source{}, attacks: map[string]*attack{},
		baselines: map[string]*baseline{}, ind: map[string]*indicator{}}
	e.learnTill = e.now().Add(cfg.Anomaly.LearnFor.D())
	return e
}

// Reconfigure replaces the detector settings (reload); state is kept.
func (e *Engine) Reconfigure(cfg config.Intrusion) {
	e.mu.Lock()
	e.cfg = cfg
	e.mu.Unlock()
}

// Learn restarts baseline learning for d (aldapctl baseline learn).
func (e *Engine) Learn(d time.Duration) {
	e.mu.Lock()
	e.learnTill = e.now().Add(d)
	e.mu.Unlock()
}

// Learning reports whether the baseline is still being learned.
func (e *Engine) Learning() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.now().Before(e.learnTill)
}

func (e *Engine) src(ip string) *source {
	s := e.sources[ip]
	if s == nil {
		if len(e.sources) >= e.o.MaxSources {
			e.evictSource()
		}
		s = &source{streak: map[string]bool{}, lastRecon: map[string]time.Time{}}
		e.sources[ip] = s
	}
	return s
}

// evictSource drops the least recently seen source; the caller holds mu.
func (e *Engine) evictSource() {
	var oldest string
	var at time.Time
	for ip, s := range e.sources {
		if oldest == "" || s.lastSeen.Before(at) {
			oldest, at = ip, s.lastSeen
		}
	}
	delete(e.sources, oldest)
}

// Bind feeds one bind outcome to the detectors.
func (e *Engine) Bind(o BindObs) {
	now := e.now()
	if o.IP == "" {
		return
	}
	e.mu.Lock()
	cfg := e.cfg
	s := e.src(o.IP)
	s.lastSeen = now
	acct := strings.ToLower(strings.TrimSpace(o.Account))
	s.attempts = append(s.attempts, attempt{t: now, account: acct, pwHash: o.PwHash, ok: o.OK})
	s.prune(now, maxWindow(cfg))
	if o.OK {
		s.streak = map[string]bool{}
	} else if acct != "" {
		s.streak[acct] = true
	}
	var hits []detection
	if !o.OK {
		hits = s.detect(cfg, now)
	}
	e.mu.Unlock()
	for _, h := range hits {
		e.record(h, o.IP, o.Profile, now)
	}
	e.baselineObserve(o.Profile, o.IP, o.ConnID, "", "", nil, now, true)
	if !o.OK {
		e.score(keyIP(o.IP), weightBindFail, now)
		if acct != "" {
			e.score(keyAccount(acct), weightBindFail, now)
		}
	}
}

func maxWindow(cfg config.Intrusion) time.Duration {
	w := cfg.Spray.Window.D()
	for _, d := range []time.Duration{cfg.Stuffing.Window.D(), cfg.SlowBrute.Window.D(), 10 * time.Minute} {
		if d > w {
			w = d
		}
	}
	return w
}

func (s *source) prune(now time.Time, span time.Duration) {
	cut := now.Add(-span)
	i := 0
	for i < len(s.attempts) && s.attempts[i].t.Before(cut) {
		i++
	}
	if i > 0 {
		s.attempts = append(s.attempts[:0], s.attempts[i:]...)
	}
	// Bound the history of a single source as well.
	if len(s.attempts) > 10000 {
		s.attempts = append(s.attempts[:0], s.attempts[len(s.attempts)-10000:]...)
	}
}

// detection is one detector firing for a source.
type detection struct {
	kind     string
	accounts int
	failures int
	span     time.Duration
}

// detect runs the bind detectors over the source history.
func (s *source) detect(cfg config.Intrusion, now time.Time) []detection {
	var out []detection
	if cfg.Spray.Enabled {
		if d, ok := s.spray(cfg.Spray, now); ok {
			out = append(out, d)
		}
	}
	if cfg.Stuffing.Enabled {
		if d, ok := s.stuffing(cfg.Stuffing, now); ok {
			out = append(out, d)
		}
	}
	if cfg.SlowBrute.Enabled {
		if d, ok := s.slowBrute(cfg.SlowBrute, now); ok {
			out = append(out, d)
		}
	}
	if cfg.Enumeration.Enabled && cfg.Enumeration.MinAccounts > 0 && len(s.streak) >= cfg.Enumeration.MinAccounts {
		out = append(out, detection{kind: KindEnumeration, accounts: len(s.streak), failures: len(s.streak)})
	}
	return out
}

func (s *source) within(now time.Time, w time.Duration) []attempt {
	cut := now.Add(-w)
	i := 0
	for i < len(s.attempts) && s.attempts[i].t.Before(cut) {
		i++
	}
	return s.attempts[i:]
}

// spray: one password (hash) tried against min_accounts distinct accounts.
func (s *source) spray(c config.Spray, now time.Time) (detection, bool) {
	byHash := map[string]map[string]bool{}
	all := map[string]bool{}
	failures := 0
	for _, a := range s.within(now, c.Window.D()) {
		if a.account == "" {
			continue
		}
		if !a.ok {
			failures++
		}
		all[a.account] = true
		if a.pwHash == "" {
			continue
		}
		m := byHash[a.pwHash]
		if m == nil {
			m = map[string]bool{}
			byHash[a.pwHash] = m
		}
		m[a.account] = true
	}
	best := 0
	for _, m := range byHash {
		if len(m) > best {
			best = len(m)
		}
	}
	n := best
	if !c.SamePasswordHash {
		n = len(all)
	}
	if c.MinAccounts <= 0 || n < c.MinAccounts {
		return detection{}, false
	}
	return detection{kind: KindSpray, accounts: n, failures: failures, span: c.Window.D()}, true
}

// stuffing: min_pairs distinct (account, password) pairs with mostly
// distinct passwords (a leaked credential list, not a spray).
func (s *source) stuffing(c config.Stuffing, now time.Time) (detection, bool) {
	pairs := map[string]bool{}
	hashes := map[string]bool{}
	accounts := map[string]bool{}
	failures := 0
	for _, a := range s.within(now, c.Window.D()) {
		if a.account == "" || a.pwHash == "" {
			continue
		}
		if !a.ok {
			failures++
		}
		pairs[a.account+"\x00"+a.pwHash] = true
		hashes[a.pwHash] = true
		accounts[a.account] = true
	}
	if c.MinPairs <= 0 || len(pairs) < c.MinPairs || len(hashes) < (c.MinPairs+1)/2 {
		return detection{}, false
	}
	return detection{kind: KindStuffing, accounts: len(accounts), failures: failures, span: c.Window.D()}, true
}

// slowBrute: min_failures within the window at a rate at or below
// max_rate_per_min.
func (s *source) slowBrute(c config.SlowBrute, now time.Time) (detection, bool) {
	var first time.Time
	failures := 0
	accounts := map[string]bool{}
	for _, a := range s.within(now, c.Window.D()) {
		if a.ok {
			continue
		}
		if first.IsZero() {
			first = a.t
		}
		failures++
		accounts[a.account] = true
	}
	if c.MinFailures <= 0 || failures < c.MinFailures {
		return detection{}, false
	}
	span := now.Sub(first)
	minutes := math.Max(span.Minutes(), 1)
	if float64(failures)/minutes > float64(c.MaxRatePerMin) {
		return detection{}, false
	}
	return detection{kind: KindSlowBrute, accounts: len(accounts), failures: failures, span: span}, true
}

// record updates or starts the attack of the detection's kind.
func (e *Engine) record(d detection, ip, profile string, now time.Time) {
	e.mu.Lock()
	a := e.attacks[d.kind]
	started := false
	if a == nil {
		started = true
		a = &attack{Attack: Attack{ID: fmt.Sprintf("%s-%d-%d", d.kind, now.Unix(), e.seq.Add(1)), Kind: d.kind, FirstSeen: now}, ips: map[string]bool{}, accounts: map[string]bool{}, lastSummary: now}
		e.attacks[d.kind] = a
	}
	a.ips[ip] = true
	a.LastSeen = now
	if d.accounts > a.Accounts {
		a.Accounts = d.accounts
	}
	if d.failures > a.Failures {
		a.Failures = d.failures
	}
	span := a.LastSeen.Sub(a.FirstSeen)
	if d.span > span {
		span = d.span
	}
	a.RatePerMin = float64(a.Failures) / math.Max(span.Minutes(), 1)
	a.Level = e.level(d, a)
	snap := a.snapshot()
	e.mu.Unlock()
	e.score(keyIP(ip), weightAttack(snap.Level), now)
	if !started {
		return
	}
	e.o.Metrics.SetAttack(snap.Kind, true)
	e.emitAttack(events.AttackStart, snap, profile)
	e.log.Warn("attack detected", "kind", snap.Kind, "attack_id", snap.ID, "level", snap.Level, "ip", ip, "accounts", snap.Accounts, "failures", snap.Failures)
	if e.o.OnAttack != nil {
		e.o.OnAttack(snap)
	}
}

// level grades an attack: high when it is broad or fast, medium otherwise.
func (e *Engine) level(d detection, a *attack) string {
	threshold := 1
	switch d.kind {
	case KindSpray:
		threshold = e.cfg.Spray.MinAccounts
	case KindStuffing:
		threshold = e.cfg.Stuffing.MinPairs
	case KindSlowBrute:
		threshold = e.cfg.SlowBrute.MinFailures
	case KindEnumeration:
		threshold = e.cfg.Enumeration.MinAccounts
	}
	if threshold <= 0 {
		threshold = 1
	}
	if len(a.ips) >= 3 || a.Failures >= 3*threshold || a.Accounts >= 3*threshold || a.RatePerMin >= 60 {
		return events.LevelHigh
	}
	return events.LevelMedium
}

func (a *attack) snapshot() Attack {
	s := a.Attack
	s.IPs = make([]string, 0, len(a.ips))
	for ip := range a.ips {
		s.IPs = append(s.IPs, ip)
	}
	sort.Strings(s.IPs)
	return s
}

func (e *Engine) emitAttack(kind string, a Attack, profile string) {
	e.ev.Emit(events.Event{Event: kind, Level: a.Level, Profile: profile, Data: map[string]any{
		"kind": a.Kind, "attack_id": a.ID, "ips": a.IPs, "accounts_count": a.Accounts, "failures": a.Failures,
		"rate_per_min": math.Round(a.RatePerMin*100) / 100, "first_seen": a.FirstSeen.UTC().Format(time.RFC3339Nano), "last_seen": a.LastSeen.UTC().Format(time.RFC3339Nano)}})
}

// Attacks lists the active attacks.
func (e *Engine) Attacks() []Attack {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Attack, 0, len(e.attacks))
	for _, a := range e.attacks {
		out = append(out, a.snapshot())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out
}

// Tick emits attack_summary every summary_interval and attack_end after
// quiet_period without detections. Call it periodically (Run does).
func (e *Engine) Tick() {
	now := e.now()
	e.mu.Lock()
	cfg := e.cfg
	var ended, summaries []Attack
	for kind, a := range e.attacks {
		switch {
		case now.Sub(a.LastSeen) >= cfg.QuietPeriod.D():
			ended = append(ended, a.snapshot())
			delete(e.attacks, kind)
			for ip := range a.ips {
				if s := e.sources[ip]; s != nil {
					s.attempts = nil
					s.streak = map[string]bool{}
				}
			}
		case now.Sub(a.lastSummary) >= cfg.SummaryInterval.D():
			a.lastSummary = now
			summaries = append(summaries, a.snapshot())
		}
	}
	e.mu.Unlock()
	for _, a := range summaries {
		e.emitAttack(events.AttackSummary, a, "")
	}
	for _, a := range ended {
		e.o.Metrics.SetAttack(a.Kind, false)
		e.emitAttack(events.AttackEnd, a, "")
		e.log.Info("attack ended", "kind", a.Kind, "attack_id", a.ID)
		if e.o.OnAttackEnd != nil {
			e.o.OnAttackEnd(a)
		}
	}
}

// Run calls Tick every interval until ctx ends.
func (e *Engine) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.Tick()
		}
	}
}
