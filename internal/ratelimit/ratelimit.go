// Package ratelimit enforces the [ratelimit] policy of SPEC §3.4/§9: per-IP
// and per-account failure windows with locks, token buckets for binds and
// searches, the negative cache, progressive delays, constant-time bind
// failures, allowlists, tarpit and lockdown. State lives in memory only.
//
// A Limiter holds the shared state of the process; a Policy applies the
// effective configuration of one profile to it ([profile.<name>.ratelimit]
// overrides). The Limiter implements the Locker the virtual directory uses
// for honeytoken hits.
package ratelimit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/metrics"
)

// Block reasons (SPEC §6 bind_blocked.reason).
const (
	ReasonIPLocked      = "ip_locked"
	ReasonAccountLocked = "account_locked"
	ReasonNegativeCache = "negative_cache"
	ReasonLockdown      = "lockdown"
	ReasonRateLimited   = "rate_limited"
)

// Lock targets and sources (SPEC §6 lock/unlock).
const (
	TargetIP      = "ip"
	TargetAccount = "account"

	SourceRatelimit  = "ratelimit"
	SourceIDs        = "ids"
	SourceAPI        = "api"
	SourceTUI        = "tui"
	SourceHoneytoken = "honeytoken"
	SourceExpiry     = "expiry"
)

// Options tune a Limiter.
type Options struct {
	Events events.Sink
	Logger *slog.Logger
	Now    func() time.Time
	// Salt for password hashing; random per process when nil.
	Salt []byte
	// MaxEntries bounds every state table (default 100000).
	MaxEntries int
	// Metrics publishes locks_active (nil = none).
	Metrics *metrics.Metrics
}

// Verdict is the decision of a pre-check.
type Verdict struct {
	// Allowed is false when the request must be refused without upstream.
	Allowed bool
	// Reason is the bind_blocked/rate_limited reason when refused.
	Reason string
	// Code is the LDAP result to answer with when refused.
	Code int
	// Wait is the tarpit delay to apply before answering (allowed or not).
	Wait time.Duration
	// Done releases the tarpit slot; nil when none was taken.
	Done func()
}

// LockInfo describes one active lock.
type LockInfo struct {
	Target   string    `json:"target"`
	Key      string    `json:"key"`
	Until    time.Time `json:"until"`
	Source   string    `json:"source"`
	Failures int       `json:"failures"`
	Profile  string    `json:"profile,omitempty"`
	Reason   string    `json:"reason,omitempty"`
}

type lockEntry struct {
	until    time.Time
	source   string
	failures int
	profile  string
	reason   string
}

// window holds the timestamps of failures within a sliding window.
type window struct {
	ts []time.Time
}

func (w *window) add(t time.Time, span time.Duration) int {
	w.prune(t, span)
	w.ts = append(w.ts, t)
	return len(w.ts)
}

func (w *window) prune(now time.Time, span time.Duration) {
	cut := now.Add(-span)
	i := 0
	for i < len(w.ts) && !w.ts[i].After(cut) {
		i++
	}
	if i > 0 {
		w.ts = append(w.ts[:0], w.ts[i:]...)
	}
}

// bucket is a token bucket.
type bucket struct {
	tokens float64
	last   time.Time
}

func (b *bucket) take(now time.Time, rps, burst int) bool {
	if b.last.IsZero() {
		b.tokens = float64(burst)
	} else {
		b.tokens += now.Sub(b.last).Seconds() * float64(rps)
		if b.tokens > float64(burst) {
			b.tokens = float64(burst)
		}
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// latencies keeps a bounded sample of successful bind durations for p95.
type latencies struct {
	samples []time.Duration
	next    int
}

const latencySamples = 256

func (l *latencies) add(d time.Duration) {
	if len(l.samples) < latencySamples {
		l.samples = append(l.samples, d)
		return
	}
	l.samples[l.next] = d
	l.next = (l.next + 1) % latencySamples
}

func (l *latencies) p95() time.Duration {
	if len(l.samples) == 0 {
		return 0
	}
	cp := append([]time.Duration(nil), l.samples...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	idx := (len(cp)*95+99)/100 - 1 // nearest rank
	if idx >= len(cp) {
		idx = len(cp) - 1
	}
	return cp[idx]
}

// Limiter is the shared rate-limit state of the process.
type Limiter struct {
	o    Options
	ev   events.Sink
	log  *slog.Logger
	now  func() time.Time
	salt []byte

	mu        sync.Mutex
	ipFails   map[string]*window
	acctFails map[string]*window
	ipLocks   map[string]lockEntry
	acctLocks map[string]lockEntry
	buckets   map[string]*bucket
	negative  map[string]time.Time
	delays    map[string]int
	// pending counts the binds admitted to the upstream whose outcome is
	// not recorded yet, per account ("a:"), source address ("i:") and
	// (account, password) pair ("p:"), so that parallel attempts cannot
	// exceed the failure budget before the first answer arrives.
	pending map[string]*pending
	// relocks remembers recent account locks: a re-lock doubles the
	// duration and one failure right after an expiry locks again.
	relocks   map[string]relock
	lat       latencies
	lockdown  bool
	lockSrc   string
	attackIPs map[string]struct{}
	tarpitted int
}

// pendingTTL bounds how long an in-flight reservation counts when its
// outcome is never recorded (a connection that died mid-bind).
const pendingTTL = 2 * time.Minute

// relockMemory is how long a lock makes the next lock of the key longer.
const relockMemory = 24 * time.Hour

// maxLockDuration caps the escalated account lock.
const maxLockDuration = 24 * time.Hour

// pending holds the start times of in-flight binds under one key.
type pending struct {
	ts []time.Time
}

func (p *pending) count(now time.Time) int {
	cut := now.Add(-pendingTTL)
	i := 0
	for i < len(p.ts) && p.ts[i].Before(cut) {
		i++
	}
	if i > 0 {
		p.ts = append(p.ts[:0], p.ts[i:]...)
	}
	return len(p.ts)
}

// relock is the lock history of an account.
type relock struct {
	n     int       // locks so far within relockMemory
	until time.Time // expiry of the last lock
}

// New creates an empty limiter.
func New(o Options) *Limiter {
	if o.Events == nil {
		o.Events = events.Discard
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.MaxEntries <= 0 {
		o.MaxEntries = 100000
	}
	salt := o.Salt
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			o.Logger.Error("ratelimit: random salt unavailable, hashing without salt", "err", err)
			salt = nil
		}
	}
	return &Limiter{o: o, ev: o.Events, log: o.Logger, now: o.Now, salt: salt,
		ipFails: map[string]*window{}, acctFails: map[string]*window{}, ipLocks: map[string]lockEntry{}, acctLocks: map[string]lockEntry{},
		buckets: map[string]*bucket{}, negative: map[string]time.Time{}, delays: map[string]int{}, pending: map[string]*pending{},
		relocks: map[string]relock{}, attackIPs: map[string]struct{}{}}
}

// HashPassword returns hex(sha256(salt || password)); the password itself
// is never stored.
func (l *Limiter) HashPassword(password []byte) string {
	h := sha256.New()
	h.Write(l.salt)
	h.Write(password)
	return hex.EncodeToString(h.Sum(nil))
}

func normAccount(a string) string { return strings.ToLower(strings.TrimSpace(a)) }

// AccountKey is the key an account is counted under: trimmed and
// lower-cased, with the realm of a UPN (`user@realm`) and the domain of a
// `DOMAIN\user` name removed, so that every form of one account shares its
// failure budget, lock and negative cache. A DN (a client_bind.dn) is kept
// whole. allow_accounts, lockdown.allow_accounts and the API use the same
// function, so an entry may be written in any form.
func AccountKey(name string) string {
	a := normAccount(name)
	if strings.ContainsRune(a, '=') {
		return a
	}
	if i := strings.IndexByte(a, '@'); i > 0 {
		a = a[:i]
	}
	if i := strings.LastIndexByte(a, '\\'); i >= 0 {
		a = a[i+1:]
	}
	return a
}

// evictBatch removes about one percent of a full table (at least one
// entry), the entries least worth keeping first, so that a flood of keys
// can neither grow the table nor make it refuse new keys.
func evictBatch[V any](m map[string]V, less func(a, b V) bool) {
	n := len(m) / 100
	if n < 1 {
		n = 1
	}
	type kv struct {
		k string
		v V
	}
	all := make([]kv, 0, len(m))
	for k, v := range m {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool { return less(all[i].v, all[j].v) })
	for i := 0; i < n && i < len(all); i++ {
		delete(m, all[i].k)
	}
}

// windowLast is the newest timestamp of a window (zero when empty).
func windowLast(w *window) time.Time {
	if w == nil || len(w.ts) == 0 {
		return time.Time{}
	}
	return w.ts[len(w.ts)-1]
}

// LockIP implements the directory's Locker: a later expiry replaces an
// earlier one; a lock event is emitted.
func (l *Limiter) LockIP(ip string, until time.Time, source string) {
	l.lock(TargetIP, ip, until, source, 0, "", "")
}

// LockAccount locks an account (API, TUI, IDS).
func (l *Limiter) LockAccount(account string, until time.Time, source string) {
	l.lock(TargetAccount, normAccount(account), until, source, 0, "", "")
}

// Lock locks an IP or an account with a free-text reason (API, TUI); it
// reports false for an unknown target. An existing lock that lasts longer
// is kept.
func (l *Limiter) Lock(target, key string, until time.Time, source, reason string) bool {
	switch target {
	case TargetIP:
		l.lock(TargetIP, key, until, source, 0, "", reason)
	case TargetAccount:
		l.lock(TargetAccount, normAccount(key), until, source, 0, "", reason)
	default:
		return false
	}
	return true
}

func (l *Limiter) lock(target, key string, until time.Time, source string, failures int, profile, reason string) {
	if key == "" {
		return
	}
	l.mu.Lock()
	m := l.ipLocks
	if target == TargetAccount {
		m = l.acctLocks
	}
	cur, ok := m[key]
	if ok && !until.After(cur.until) {
		l.mu.Unlock()
		return
	}
	if !ok && len(m) >= l.o.MaxEntries {
		// Never drop a lock: make room by dropping the locks that expire
		// first (expired ones among them).
		l.log.Warn("ratelimit: lock table full, evicting the locks that expire first", "target", target)
		evictBatch(m, func(a, b lockEntry) bool { return a.until.Before(b.until) })
	}
	m[key] = lockEntry{until: until, source: source, failures: failures, profile: profile, reason: reason}
	// The failures are consumed by the lock: counting restarts after expiry.
	if target == TargetIP {
		delete(l.ipFails, key)
		delete(l.delays, key)
	} else {
		delete(l.acctFails, key)
	}
	l.mu.Unlock()
	ev := events.Event{Event: events.Lock, Level: events.LevelMedium, Profile: profile, Failures: failures,
		Data: map[string]any{"target": target, "key": key, "until": until.UTC().Format(time.RFC3339Nano), "source": source, "failures": failures}}
	if reason != "" {
		ev.Data["reason"] = reason
	}
	if target == TargetIP {
		ev.ClientIP = key
	} else {
		ev.Account = key
	}
	l.ev.Emit(ev)
	l.log.Warn("lock", "target", target, "key", key, "until", until.UTC().Format(time.RFC3339), "source", source, "failures", failures)
}

// IPLocked implements Locker; an expired lock is removed and reported as unlock{expiry}.
func (l *Limiter) IPLocked(ip string, now time.Time) (time.Time, bool) {
	return l.locked(TargetIP, ip, now)
}

// AccountLocked reports whether the account is locked at now.
func (l *Limiter) AccountLocked(account string, now time.Time) (time.Time, bool) {
	return l.locked(TargetAccount, normAccount(account), now)
}

func (l *Limiter) locked(target, key string, now time.Time) (time.Time, bool) {
	l.mu.Lock()
	m := l.ipLocks
	if target == TargetAccount {
		m = l.acctLocks
	}
	e, ok := m[key]
	if ok && !now.Before(e.until) {
		delete(m, key)
		l.mu.Unlock()
		l.emitUnlock(target, key, SourceExpiry)
		return time.Time{}, false
	}
	l.mu.Unlock()
	if !ok {
		return time.Time{}, false
	}
	return e.until, true
}

func (l *Limiter) emitUnlock(target, key, source string) {
	ev := events.Event{Event: events.Unlock, Level: events.LevelLow, Data: map[string]any{"target": target, "key": key, "source": source}}
	if target == TargetIP {
		ev.ClientIP = key
	} else {
		ev.Account = key
	}
	l.ev.Emit(ev)
}

// Unlock removes a lock (API/TUI); it reports whether one existed. The
// failure window of the key is cleared too.
func (l *Limiter) Unlock(target, key, source string) bool {
	if target == TargetAccount {
		key = normAccount(key)
	}
	l.mu.Lock()
	m, w := l.ipLocks, l.ipFails
	if target == TargetAccount {
		m, w = l.acctLocks, l.acctFails
	}
	_, ok := m[key]
	delete(m, key)
	delete(w, key)
	delete(l.delays, key)
	l.mu.Unlock()
	if ok {
		l.emitUnlock(target, key, source)
	}
	return ok
}

// Locks lists the active locks, oldest expiry first.
func (l *Limiter) Locks() []LockInfo {
	now := l.now()
	l.mu.Lock()
	var out []LockInfo
	for target, m := range map[string]map[string]lockEntry{TargetIP: l.ipLocks, TargetAccount: l.acctLocks} {
		for k, e := range m {
			if now.Before(e.until) {
				out = append(out, LockInfo{Target: target, Key: k, Until: e.until, Source: e.source, Failures: e.failures, Profile: e.profile, Reason: e.reason})
			}
		}
	}
	l.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Until.Equal(out[j].Until) {
			return out[i].Target+out[i].Key < out[j].Target+out[j].Key
		}
		return out[i].Until.Before(out[j].Until)
	})
	return out
}

// SetLockdown switches lockdown on or off; a change is a lockdown event.
func (l *Limiter) SetLockdown(on bool, source string) bool {
	l.mu.Lock()
	changed := l.lockdown != on
	l.lockdown, l.lockSrc = on, source
	l.mu.Unlock()
	if !changed {
		return false
	}
	state := "off"
	if on {
		state = "on"
	}
	l.ev.Emit(events.Event{Event: events.Lockdown, Level: events.LevelHigh, Data: map[string]any{"state": state, "source": source}})
	l.log.Warn("lockdown", "state", state, "source", source)
	return true
}

// Lockdown reports the lockdown state and its source.
func (l *Limiter) Lockdown() (bool, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lockdown, l.lockSrc
}

// SetAttack marks an IP as attacking (tarpit candidate) or clears it.
func (l *Limiter) SetAttack(ip string, on bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if on {
		if len(l.attackIPs) < l.o.MaxEntries {
			l.attackIPs[ip] = struct{}{}
		}
		return
	}
	delete(l.attackIPs, ip)
}

// Attacking reports whether ip is in attack state.
func (l *Limiter) Attacking(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.attackIPs[ip]
	return ok
}

// Sweep drops expired locks (reporting unlock{expiry}), stale failure
// windows, expired negative-cache entries and idle buckets. Call it
// periodically.
func (l *Limiter) Sweep(now time.Time, maxWindow time.Duration) {
	type expired struct{ target, key string }
	var exp []expired
	l.mu.Lock()
	for k, e := range l.ipLocks {
		if !now.Before(e.until) {
			delete(l.ipLocks, k)
			exp = append(exp, expired{TargetIP, k})
		}
	}
	for k, e := range l.acctLocks {
		if !now.Before(e.until) {
			delete(l.acctLocks, k)
			exp = append(exp, expired{TargetAccount, k})
		}
	}
	for _, m := range []map[string]*window{l.ipFails, l.acctFails} {
		for k, w := range m {
			w.prune(now, maxWindow)
			if len(w.ts) == 0 {
				delete(m, k)
			}
		}
	}
	for k, until := range l.negative {
		if !now.Before(until) {
			delete(l.negative, k)
		}
	}
	for k, b := range l.buckets {
		if now.Sub(b.last) > maxWindow {
			delete(l.buckets, k)
		}
	}
	for k, p := range l.pending {
		if p.count(now) == 0 {
			delete(l.pending, k)
		}
	}
	for k, r := range l.relocks {
		if now.After(r.until.Add(relockMemory)) {
			delete(l.relocks, k)
		}
	}
	l.o.Metrics.SetLocks(len(l.ipLocks), len(l.acctLocks))
	l.mu.Unlock()
	for _, e := range exp {
		l.emitUnlock(e.target, e.key, SourceExpiry)
	}
}

// Policy applies one profile's effective [ratelimit] to the shared Limiter.
type Policy struct {
	l             *Limiter
	cfg           config.Ratelimit
	profile       string
	allowNets     []*net.IPNet
	allowAccts    map[string]bool
	lockdownNets  []*net.IPNet
	lockdownAccts map[string]bool
	lockCode      int
	// Sleep performs the delays; replaced in tests.
	Sleep func(time.Duration)
}

// Policy builds the policy of a profile; cfg is the merged configuration
// (config.Ratelimit.With).
func (l *Limiter) Policy(profile string, cfg config.Ratelimit) (*Policy, error) {
	p := &Policy{l: l, cfg: cfg, profile: profile, allowAccts: map[string]bool{}, lockdownAccts: map[string]bool{}, Sleep: time.Sleep}
	var err error
	if p.allowNets, err = parseCIDRs(cfg.AllowCIDRs); err != nil {
		return nil, fmt.Errorf("ratelimit.allow_cidrs: %w", err)
	}
	if p.lockdownNets, err = parseCIDRs(cfg.Lockdown.AllowCIDRs); err != nil {
		return nil, fmt.Errorf("ratelimit.lockdown.allow_cidrs: %w", err)
	}
	for _, a := range cfg.AllowAccounts {
		p.allowAccts[AccountKey(a)] = true
	}
	for _, a := range cfg.Lockdown.AllowAccounts {
		p.lockdownAccts[AccountKey(a)] = true
	}
	p.lockCode = ldap.LDAPResultInvalidCredentials
	if cfg.LockResponse == "busy" {
		p.lockCode = ldap.LDAPResultBusy
	}
	return p, nil
}

func parseCIDRs(list []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, s := range list {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			ip := net.ParseIP(s)
			if ip == nil {
				return nil, fmt.Errorf("%q: %w", s, err)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			n = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		}
		out = append(out, n)
	}
	return out, nil
}

func inNets(nets []*net.IPNet, ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(p) {
			return true
		}
	}
	return false
}

// Limiter returns the shared limiter.
func (p *Policy) Limiter() *Limiter { return p.l }

// Config returns the effective configuration.
func (p *Policy) Config() config.Ratelimit { return p.cfg }

// Exempt reports whether the source IP is in allow_cidrs: no limits keyed
// by the address (IP lock, ip.* rates, tarpit, progressive delay). Account
// locks, the negative cache and lockdown still apply.
func (p *Policy) Exempt(ip string) bool { return inNets(p.allowNets, ip) }

// lockdownBlocks reports whether lockdown refuses this source/account. The
// application servers of ratelimit.allow_cidrs are served during a lockdown
// like lockdown.allow_cidrs: an attacker must not be able to switch a whole
// application off by triggering lockdown.auto.
func (p *Policy) lockdownBlocks(ip, account string) bool {
	on, _ := p.l.Lockdown()
	if !on {
		return false
	}
	if inNets(p.lockdownNets, ip) || inNets(p.allowNets, ip) {
		return false
	}
	return account == "" || !p.lockdownAccts[normAccount(account)]
}

func (p *Policy) refuse(reason string, code int) Verdict {
	return Verdict{Allowed: false, Reason: reason, Code: code}
}

// tarpit takes a tarpit slot for an attacking IP; it returns the delay and
// the release function, or refuses when the slots are exhausted.
func (p *Policy) tarpit(ip string) (Verdict, bool) {
	if !p.cfg.Tarpit.Enabled || !p.l.Attacking(ip) {
		return Verdict{}, false
	}
	l := p.l
	l.mu.Lock()
	if l.tarpitted >= p.cfg.Tarpit.MaxConns {
		l.mu.Unlock()
		return p.refuse(ReasonRateLimited, p.lockCode), true
	}
	l.tarpitted++
	conns := l.tarpitted
	l.mu.Unlock()
	l.ev.Emit(events.Event{Event: events.Tarpit, Level: events.LevelLow, Profile: p.profile, ClientIP: ip, Data: map[string]any{"ip": ip, "conns": conns}})
	var once sync.Once
	return Verdict{Allowed: true, Wait: p.cfg.Tarpit.Delay.D(), Done: func() {
		once.Do(func() {
			l.mu.Lock()
			l.tarpitted--
			l.mu.Unlock()
		})
	}}, true
}

// PreBind decides whether a bind may proceed to the upstream. pwHash is
// Limiter.HashPassword of the presented password.
func (p *Policy) PreBind(ip, account, pwHash string) Verdict {
	if !p.cfg.Enabled {
		return Verdict{Allowed: true}
	}
	now := p.l.now()
	acct := normAccount(account)
	if p.lockdownBlocks(ip, acct) {
		return p.refuse(ReasonLockdown, p.lockCode)
	}
	// allow_cidrs only lifts the limits keyed by the source address (IP
	// lock, ip.* rate, tarpit): an application server binding for many
	// users must not turn into a way around account locks.
	exempt := p.Exempt(ip)
	if _, locked := p.l.IPLocked(ip, now); locked && !exempt {
		return p.refuse(ReasonIPLocked, p.lockCode)
	}
	if acct != "" && !p.allowAccts[acct] {
		if _, locked := p.l.AccountLocked(acct, now); locked {
			return p.refuse(ReasonAccountLocked, p.lockCode)
		}
	}
	if acct != "" && pwHash != "" && p.cfg.NegativeCacheTTL > 0 && p.negativeHit(acct, pwHash, now) {
		return p.refuse(ReasonNegativeCache, ldap.LDAPResultInvalidCredentials)
	}
	if v, ok := p.reserve(ip, acct, pwHash, exempt, now); !ok {
		return v
	}
	if exempt {
		return Verdict{Allowed: true}
	}
	if ip != "" && !p.take("bind:"+ip, now, p.cfg.IP.BindRPS, p.cfg.IP.BindBurst) {
		p.release(ip, acct, pwHash, exempt)
		return p.refuse(ReasonRateLimited, ldap.LDAPResultBusy)
	}
	if v, ok := p.tarpit(ip); ok {
		if !v.Allowed {
			p.release(ip, acct, pwHash, exempt)
		}
		return v
	}
	return Verdict{Allowed: true}
}

// negativeHit reports whether (account, password) failed recently; an
// expired entry is dropped.
func (p *Policy) negativeHit(acct, pwHash string, now time.Time) bool {
	p.l.mu.Lock()
	defer p.l.mu.Unlock()
	until, ok := p.l.negative[acct+"\x00"+pwHash]
	if ok && !now.Before(until) {
		delete(p.l.negative, acct+"\x00"+pwHash)
		return false
	}
	return ok
}

// pendingKeys are the reservation keys of one bind (empty when not kept).
func (p *Policy) pendingKeys(ip, acct, pwHash string, exempt bool) (acctKey, pairKey, ipKey string) {
	if acct != "" && !p.allowAccts[acct] {
		acctKey = "a:" + acct
		if pwHash != "" && p.cfg.NegativeCacheTTL > 0 {
			pairKey = "p:" + acct + "\x00" + pwHash
		}
	}
	if ip != "" && !exempt {
		ipKey = "i:" + ip
	}
	return acctKey, pairKey, ipKey
}

// reserve admits a bind to the upstream only while the failures already
// recorded plus the binds still in flight stay below the budget of the
// account and the source; the same (account, password) pair is admitted
// once at a time. The caller must release the reservation through PostBind
// (or release on a later refusal). It fails closed when the table is full.
func (p *Policy) reserve(ip, acct, pwHash string, exempt bool, now time.Time) (Verdict, bool) {
	acctKey, pairKey, ipKey := p.pendingKeys(ip, acct, pwHash, exempt)
	l := p.l
	l.mu.Lock()
	defer l.mu.Unlock()
	count := func(k string) int {
		if k == "" {
			return 0
		}
		if pe := l.pending[k]; pe != nil {
			return pe.count(now)
		}
		return 0
	}
	if acctKey != "" && p.cfg.Account.MaxFailures > 0 {
		w := l.acctFails[acct]
		if w != nil {
			w.prune(now, p.cfg.Account.Window.D())
		}
		if len(windowTS(w))+count(acctKey) >= p.accountBudget(acct, now) {
			return p.refuse(ReasonRateLimited, p.lockCode), false
		}
	}
	if pairKey != "" && count(pairKey) > 0 {
		return p.refuse(ReasonNegativeCache, ldap.LDAPResultInvalidCredentials), false
	}
	if ipKey != "" && p.cfg.IP.MaxFailures > 0 {
		w := l.ipFails[ip]
		if w != nil {
			w.prune(now, p.cfg.IP.Window.D())
		}
		if len(windowTS(w))+count(ipKey) >= p.cfg.IP.MaxFailures {
			return p.refuse(ReasonRateLimited, p.lockCode), false
		}
	}
	for _, k := range []string{acctKey, pairKey, ipKey} {
		if k == "" {
			continue
		}
		pe := l.pending[k]
		if pe == nil {
			if len(l.pending) >= l.o.MaxEntries {
				for kk, pp := range l.pending {
					if pp.count(now) == 0 {
						delete(l.pending, kk)
					}
				}
				if len(l.pending) >= l.o.MaxEntries {
					// Fail closed: an unknown key with no room is refused.
					l.log.Warn("ratelimit: in-flight table full, bind refused")
					return p.refuse(ReasonRateLimited, p.lockCode), false
				}
			}
			pe = &pending{}
			l.pending[k] = pe
		}
		pe.ts = append(pe.ts, now)
	}
	return Verdict{Allowed: true}, true
}

func windowTS(w *window) []time.Time {
	if w == nil {
		return nil
	}
	return w.ts
}

// release gives back the reservation of one bind; the caller holds no lock.
func (p *Policy) release(ip, acct, pwHash string, exempt bool) {
	acctKey, pairKey, ipKey := p.pendingKeys(ip, acct, pwHash, exempt)
	l := p.l
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range []string{acctKey, pairKey, ipKey} {
		if pe := l.pending[k]; k != "" && pe != nil && len(pe.ts) > 0 {
			pe.ts = pe.ts[1:]
			if len(pe.ts) == 0 {
				delete(l.pending, k)
			}
		}
	}
}

// accountBudget is the number of failures that locks acct now: the
// configured maximum, or one while the account is on probation right after
// a lock expired (2 × lock_duration), so that an attacker who waits for the
// expiry cannot restart with a full budget inside the directory's lockout
// observation window. The caller holds mu.
func (p *Policy) accountBudget(acct string, now time.Time) int {
	if r, ok := p.l.relocks[acct]; ok && now.Before(r.until.Add(2*p.cfg.Account.LockDuration.D())) {
		return 1
	}
	return p.cfg.Account.MaxFailures
}

// Rekey moves the reservation of an admitted bind from the presented
// account key to the resolved one (the directory learns the canonical
// account only after a lookup) and re-checks the lock and the negative
// cache under the resolved key. When it refuses, the reservation is
// released and the caller must not call PostBind.
func (p *Policy) Rekey(ip, from, to, pwHash string) Verdict {
	if !p.cfg.Enabled {
		return Verdict{Allowed: true}
	}
	f, t := normAccount(from), normAccount(to)
	if f == t || t == "" {
		return Verdict{Allowed: true}
	}
	exempt := p.Exempt(ip)
	now := p.l.now()
	p.release("", f, pwHash, exempt)
	refuse := func(v Verdict) Verdict {
		p.release(ip, "", "", exempt)
		return v
	}
	if p.lockdownBlocks(ip, t) {
		return refuse(p.refuse(ReasonLockdown, p.lockCode))
	}
	if !p.allowAccts[t] {
		if _, locked := p.l.AccountLocked(t, now); locked {
			return refuse(p.refuse(ReasonAccountLocked, p.lockCode))
		}
	}
	if pwHash != "" && p.cfg.NegativeCacheTTL > 0 && p.negativeHit(t, pwHash, now) {
		return refuse(p.refuse(ReasonNegativeCache, ldap.LDAPResultInvalidCredentials))
	}
	if v, ok := p.reserve("", t, pwHash, exempt, now); !ok {
		return refuse(v)
	}
	return Verdict{Allowed: true}
}

func (p *Policy) take(key string, now time.Time, rps, burst int) bool {
	if rps <= 0 {
		return true
	}
	if burst <= 0 {
		burst = rps
	}
	l := p.l
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.o.MaxEntries {
			// Make room by dropping the buckets idle the longest; a full
			// table must not switch the limit off.
			evictBatch(l.buckets, func(a, b *bucket) bool { return a.last.Before(b.last) })
		}
		b = &bucket{}
		l.buckets[key] = b
	}
	return b.take(now, rps, burst)
}

// Cacheable bind failure reasons: a retry with the same password cannot
// succeed, so the pair is remembered (SPEC §3.4 negative_cache_ttl). The
// same reasons are the ones counted against the account: the attempt
// reached the directory (or the mock) with a password. An unauthenticated
// bind (reason anonymous) never leaves ALDAP and an upstream outage
// (upstream_error) is not the account's fault, so neither locks it.
var cacheableReasons = map[string]bool{"invalid_password": true, "unknown_account": true, "disabled": true, "locked_in_ad": true, "expired": true, "must_change": true, "not_member": true}

// ReasonUpstreamError is the bind_fail reason of a directory failure.
const reasonUpstreamError = "upstream_error"

// PostBind records the outcome of a bind and returns how long the answer
// must be delayed (progressive delay and constant-time failure); elapsed is
// the time the bind already took. It releases the reservation of PreBind
// (or Rekey), so it must be called exactly once per admitted bind.
func (p *Policy) PostBind(ip, account, pwHash string, ok bool, reason string, elapsed time.Duration) time.Duration {
	if !p.cfg.Enabled {
		return 0
	}
	acct := normAccount(account)
	p.release(ip, acct, pwHash, p.Exempt(ip))
	if ok {
		p.recordSuccess(ip, acct, elapsed)
		return 0
	}
	now := p.l.now()
	ipCount, acctCount, delayN, p95, budget := p.recordFailure(ip, acct, pwHash, reason, now)
	if ipCount >= p.cfg.IP.MaxFailures && p.cfg.IP.MaxFailures > 0 {
		p.l.lock(TargetIP, ip, now.Add(p.cfg.IP.LockDuration.D()), SourceRatelimit, ipCount, p.profile, "")
	}
	if acctCount >= budget && p.cfg.Account.MaxFailures > 0 && cacheableReasons[reason] {
		p.l.lock(TargetAccount, acct, now.Add(p.accountLockDuration(acct, now)), SourceRatelimit, acctCount, p.profile, "")
	}
	return p.failureDelay(delayN, p95, elapsed)
}

// accountLockDuration doubles the configured lock for every lock of the
// account within relockMemory (capped at maxLockDuration) and records it.
func (p *Policy) accountLockDuration(acct string, now time.Time) time.Duration {
	l := p.l
	l.mu.Lock()
	defer l.mu.Unlock()
	d := p.cfg.Account.LockDuration.D()
	r, ok := l.relocks[acct]
	if ok && now.After(r.until.Add(relockMemory)) {
		r, ok = relock{}, false
	}
	if !ok && len(l.relocks) >= l.o.MaxEntries {
		evictBatch(l.relocks, func(a, b relock) bool { return a.until.Before(b.until) })
	}
	for i := 0; i < r.n && d < maxLockDuration; i++ {
		d *= 2
	}
	if d > maxLockDuration {
		d = maxLockDuration
	}
	r.n++
	r.until = now.Add(d)
	l.relocks[acct] = r
	return d
}

// recordSuccess keeps the latency sample and clears the counters of the
// source and the account.
func (p *Policy) recordSuccess(ip, acct string, elapsed time.Duration) {
	l := p.l
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lat.add(elapsed)
	delete(l.delays, ip)
	if acct != "" {
		delete(l.acctFails, acct)
	}
}

// recordFailure updates the failure windows, the progressive-delay counter
// and the negative cache; it returns the counts the caller locks on and the
// account budget in force.
func (p *Policy) recordFailure(ip, acct, pwHash, reason string, now time.Time) (ipCount, acctCount, delayN int, p95 time.Duration, budget int) {
	l := p.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if ip != "" && !p.Exempt(ip) && reason != reasonUpstreamError {
		ipCount = addFailure(l.ipFails, ip, now, p.cfg.IP.Window.D(), l.o.MaxEntries)
		if len(l.delays) >= l.o.MaxEntries {
			if _, ok := l.delays[ip]; !ok {
				evictBatch(l.delays, func(int, int) bool { return true })
			}
		}
		l.delays[ip]++
		delayN = l.delays[ip]
	}
	budget = p.accountBudget(acct, now)
	if acct != "" && !p.allowAccts[acct] && cacheableReasons[reason] {
		acctCount = addFailure(l.acctFails, acct, now, p.cfg.Account.Window.D(), l.o.MaxEntries)
	}
	if acct != "" && pwHash != "" && cacheableReasons[reason] && p.cfg.NegativeCacheTTL > 0 {
		if len(l.negative) >= l.o.MaxEntries {
			evictBatch(l.negative, func(a, b time.Time) bool { return a.Before(b) })
		}
		l.negative[acct+"\x00"+pwHash] = now.Add(p.cfg.NegativeCacheTTL.D())
	}
	return ipCount, acctCount, delayN, l.lat.p95(), budget
}

// addFailure records one failure in the window of key and returns the
// count. A full table drops the windows idle the longest instead of
// forgetting the new failure.
func addFailure(m map[string]*window, key string, now time.Time, span time.Duration, maxEntries int) int {
	w := m[key]
	if w == nil {
		if len(m) >= maxEntries {
			evictBatch(m, func(a, b *window) bool { return windowLast(a).Before(windowLast(b)) })
		}
		w = &window{}
		m[key] = w
	}
	return w.add(now, span)
}

// failureDelay combines the progressive delay with the constant-time pad.
func (p *Policy) failureDelay(delayN int, p95, elapsed time.Duration) time.Duration {
	var wait time.Duration
	if delayN > 0 && p.cfg.Delay.Base > 0 {
		wait = p.cfg.Delay.Base.D() << uint(min(delayN-1, 20))
		if wait > p.cfg.Delay.Max.D() || wait <= 0 {
			wait = p.cfg.Delay.Max.D()
		}
	}
	if p.cfg.ConstantTimeBindFail && p95 > elapsed && p95-elapsed > wait {
		wait = p95 - elapsed
	}
	return wait
}

// Failures returns the current failure counts of an IP and an account.
func (p *Policy) Failures(ip, account string) (ipCount, acctCount int) {
	now := p.l.now()
	p.l.mu.Lock()
	defer p.l.mu.Unlock()
	if w := p.l.ipFails[ip]; w != nil {
		w.prune(now, p.cfg.IP.Window.D())
		ipCount = len(w.ts)
	}
	if w := p.l.acctFails[normAccount(account)]; w != nil {
		w.prune(now, p.cfg.Account.Window.D())
		acctCount = len(w.ts)
	}
	return ipCount, acctCount
}

// PreSearch decides whether a search may proceed; account is the bound
// name (empty for anonymous).
func (p *Policy) PreSearch(ip, account string) Verdict {
	if !p.cfg.Enabled {
		return Verdict{Allowed: true}
	}
	now := p.l.now()
	if p.lockdownBlocks(ip, account) {
		return p.refuse(ReasonLockdown, ldap.LDAPResultUnwillingToPerform)
	}
	if p.Exempt(ip) {
		return Verdict{Allowed: true}
	}
	if _, locked := p.l.IPLocked(ip, now); locked {
		return p.refuse(ReasonIPLocked, ldap.LDAPResultUnwillingToPerform)
	}
	if ip != "" && !p.take("search:"+ip, now, p.cfg.IP.SearchRPS, p.cfg.IP.SearchBurst) {
		return p.refuse(ReasonRateLimited, ldap.LDAPResultBusy)
	}
	if v, ok := p.tarpit(ip); ok {
		if !v.Allowed {
			v.Code = ldap.LDAPResultUnwillingToPerform
		}
		return v
	}
	return Verdict{Allowed: true}
}

// LockResponse returns the configured LDAP code for locked clients.
func (p *Policy) LockResponse() int { return p.lockCode }

// HashPassword delegates to the shared limiter.
func (p *Policy) HashPassword(password []byte) string { return p.l.HashPassword(password) }

// LockIP delegates to the shared limiter (vdir.Guard).
func (p *Policy) LockIP(ip string, until time.Time, source string) { p.l.LockIP(ip, until, source) }

// IPLocked delegates to the shared limiter (vdir.Guard).
func (p *Policy) IPLocked(ip string, now time.Time) (time.Time, bool) { return p.l.IPLocked(ip, now) }
