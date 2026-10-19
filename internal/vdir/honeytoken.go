package vdir

import (
	"strings"
	"sync"
	"time"

	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/ldapfilter"
	"github.com/alstdev/aldap/internal/listener"
	"github.com/alstdev/aldap/internal/profile"
	"github.com/alstdev/aldap/internal/upstream"
)

// Locker records source locks. The rate limiter of Stage 6 implements it;
// until then MemoryLocks is used (docs/DECISIONS.md).
type Locker interface {
	// LockIP locks ip until the given time; source names the cause.
	LockIP(ip string, until time.Time, source string)
	// IPLocked reports whether ip is locked at now and until when.
	IPLocked(ip string, now time.Time) (time.Time, bool)
}

// MemoryLocks is an in-memory Locker shared by every profile of a process.
type MemoryLocks struct {
	mu sync.Mutex
	m  map[string]time.Time
}

// NewMemoryLocks returns an empty lock table.
func NewMemoryLocks() *MemoryLocks { return &MemoryLocks{m: map[string]time.Time{}} }

// LockIP implements Locker; a later expiry replaces an earlier one.
func (l *MemoryLocks) LockIP(ip string, until time.Time, _ string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if cur, ok := l.m[ip]; !ok || until.After(cur) {
		l.m[ip] = until
	}
	if len(l.m) > 100000 {
		for k, v := range l.m {
			if !until.Before(v) {
				delete(l.m, k)
			}
		}
	}
}

// IPLocked implements Locker.
func (l *MemoryLocks) IPLocked(ip string, now time.Time) (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	until, ok := l.m[ip]
	if !ok {
		return time.Time{}, false
	}
	if !now.Before(until) {
		delete(l.m, ip)
		return time.Time{}, false
	}
	return until, true
}

// Locks returns the lock table of the directory.
func (d *Directory) Locks() Locker { return d.o.Locks }

// ipLocked reports whether the connection's source IP is locked.
func (d *Directory) ipLocked(c *listener.Conn) bool {
	ip := c.ClientIP()
	if ip == "" {
		return false
	}
	_, locked := d.o.Locks.IPLocked(ip, d.now())
	return locked
}

// honeytokenHit records a trap hit (SPEC §4.5): a honeytoken event of level
// high and an IP lock for honeytoken_lock, reported as a lock event.
func (d *Directory) honeytokenHit(c *listener.Conn, op, account string) {
	ev := c.Event(events.Honeytoken, events.LevelHigh)
	ev.Account = account
	ev.Upstream = d.upstreamName()
	ev.Data = map[string]any{"account": account, "op": op}
	d.ev.Emit(ev)
	d.log.Warn("honeytoken hit", "conn_id", c.ID(), "client_ip", c.ClientIP(), "account", account, "op", op)
	ip := c.ClientIP()
	if ip == "" {
		return
	}
	until := d.now().Add(d.o.HoneytokenLock)
	d.o.Locks.LockIP(ip, until, "honeytoken")
	lk := c.Event(events.Lock, events.LevelMedium)
	lk.Account = account
	lk.Data = map[string]any{"target": "ip", "key": ip, "until": until.UTC().Format(time.RFC3339Nano), "source": "honeytoken", "failures": 0}
	d.ev.Emit(lk)
}

// honeytokenTarget finds the trap a search targets unambiguously: an
// equality term on an identity attribute, or a single-user base whose RDN
// names it. It returns nil when none.
func (d *Directory) honeytokenTarget(f *ldapfilter.Filter, rdn string) *profile.Honeytoken {
	if len(d.rules.Honeytokens()) == 0 {
		return nil
	}
	if rdn != "" {
		if h := d.rules.MatchHoneytoken(rdn); h != nil {
			return h
		}
	}
	var hit *profile.Honeytoken
	ldapfilter.Walk(f, func(n *ldapfilter.Filter) bool {
		if hit != nil {
			return false
		}
		if n.Kind == ldapfilter.Equality {
			attr := n.Attr
			if i := strings.IndexByte(attr, ';'); i > 0 {
				attr = attr[:i]
			}
			hit = d.rules.HoneytokenValue(d.rules.UpstreamAttr(attr), n.Value)
		}
		return hit == nil
	})
	return hit
}

// honeytokenEntry renders a trap as an upstream entry so that it goes
// through the same transformation as real users.
func honeytokenEntry(h *profile.Honeytoken) upstream.Entry {
	e := upstream.Entry{DN: h.DN, Attrs: make(map[string][]string, len(h.Attrs))}
	for k, v := range h.Attrs {
		e.Attrs[strings.ToLower(k)] = append([]string(nil), v...)
	}
	return e
}
