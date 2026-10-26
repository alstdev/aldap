package vdir

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/ids"
	"github.com/alstdev/aldap/internal/ldapfilter"
	"github.com/alstdev/aldap/internal/listener"
	"github.com/alstdev/aldap/internal/profile"
	"github.com/alstdev/aldap/internal/ratelimit"
	"github.com/alstdev/aldap/internal/upstream"
)

// Guard is the rate limiter in front of the directory (internal/ratelimit
// implements it): source locks, the bind and search gates and the
// post-bind bookkeeping (failure windows, negative cache, delays).
type Guard interface {
	// LockIP locks ip until the given time; source names the cause.
	LockIP(ip string, until time.Time, source string)
	// IPLocked reports whether ip is locked at now and until when.
	IPLocked(ip string, now time.Time) (time.Time, bool)
	// HashPassword returns the salted hash used for negative caching and
	// spray detection; the password itself is never kept.
	HashPassword(password []byte) string
	// PreBind decides whether a bind may go to the upstream.
	PreBind(ip, account, pwHash string) ratelimit.Verdict
	// PostBind records the outcome and returns how long to delay the answer.
	PostBind(ip, account, pwHash string, ok bool, reason string, elapsed time.Duration) time.Duration
	// PreSearch decides whether a search may be served.
	PreSearch(ip, account string) ratelimit.Verdict
	// Exempt reports whether ip is a service source of ratelimit.allow_cidrs.
	Exempt(ip string) bool
}

// Observer receives what the intrusion detectors analyze (internal/ids).
type Observer interface {
	Bind(ids.BindObs)
	Search(ids.SearchObs)
}

// noGuard allows everything and keeps no locks: handler tests and
// `aldap check --as-client`.
type noGuard struct{}

func (noGuard) LockIP(string, time.Time, string)             {}
func (noGuard) IPLocked(string, time.Time) (time.Time, bool) { return time.Time{}, false }
func (noGuard) HashPassword(password []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(password))
}
func (noGuard) PreBind(string, string, string) ratelimit.Verdict {
	return ratelimit.Verdict{Allowed: true}
}
func (noGuard) PostBind(string, string, string, bool, string, time.Duration) time.Duration { return 0 }
func (noGuard) PreSearch(string, string) ratelimit.Verdict                                 { return ratelimit.Verdict{Allowed: true} }
func (noGuard) Exempt(string) bool                                                         { return false }

// Guard returns the guard of the directory.
func (d *Directory) Guard() Guard { return d.o.Guard }

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
	// The guard records the lock and reports the lock event (SPEC §6 lock{source=honeytoken}).
	d.o.Guard.LockIP(ip, d.now().Add(d.o.HoneytokenLock), ratelimit.SourceHoneytoken)
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
