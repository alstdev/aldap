package ids

import (
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/events"
)

// WhatClientIPMasked is insecure_config.what of the masked client address
// detector ([ids.client_ip_masked]).
const WhatClientIPMasked = "client_ip_masked"

const (
	// maskedBuckets is the number of time buckets of the window.
	maskedBuckets = 10
	// maskedMaxIPs bounds the sources tracked per bucket; the rest only
	// count towards the total, which keeps the share honest under a flood.
	maskedMaxIPs = 4096
	// maskedMaxAccounts bounds the accounts kept per source and bucket:
	// the detector only needs to know that there are "several".
	maskedMaxAccounts = 64
)

// cgnat is RFC 6598 shared address space (100.64.0.0/10), used by some
// container and VPN networks as their internal range.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// maskedSource is what one bucket knows about one source address.
type maskedSource struct {
	n        int
	accounts map[string]struct{}
}

type maskedBucket struct {
	start time.Time
	total int
	ips   map[string]*maskedSource
}

// maskedTracker finds a dominant private source address shared by several
// accounts: what clients look like behind a NAT, a userspace port
// forwarder (rootlessport) or a container network gateway. Every request
// then carries the same address, so per-IP rate limits, allow_cidrs and
// the source-based detectors stop working.
type maskedTracker struct {
	mu       sync.Mutex
	buckets  []*maskedBucket // oldest first
	lastEval time.Time
	alerted  map[string]time.Time
}

func newMaskedTracker() *maskedTracker {
	return &maskedTracker{alerted: map[string]time.Time{}}
}

// observe counts one bind or search of account from ip. Known sources
// (KnownSource: the client's own address or an allow_cidrs service source)
// are not counted at all, so a masking address among the rest still stands
// out.
func (m *maskedTracker) observe(cfg config.ClientIPMasked, ip, account string, known bool, now time.Time) {
	if !cfg.Enabled || ip == "" || known {
		return
	}
	width := cfg.Window.D() / maskedBuckets
	if width <= 0 {
		return
	}
	acct := strings.ToLower(strings.TrimSpace(account))
	m.mu.Lock()
	defer m.mu.Unlock()
	var b *maskedBucket
	if n := len(m.buckets); n > 0 && now.Sub(m.buckets[n-1].start) < width {
		b = m.buckets[n-1]
	} else {
		b = &maskedBucket{start: now, ips: map[string]*maskedSource{}}
		m.buckets = append(m.buckets, b)
		m.prune(cfg.Window.D(), now)
	}
	b.total++
	src := b.ips[ip]
	if src == nil {
		if len(b.ips) >= maskedMaxIPs {
			return
		}
		src = &maskedSource{accounts: map[string]struct{}{}}
		b.ips[ip] = src
	}
	src.n++
	if acct != "" && len(src.accounts) < maskedMaxAccounts {
		src.accounts[acct] = struct{}{}
	}
}

// prune drops buckets that ended before the window; the caller holds mu.
func (m *maskedTracker) prune(window time.Duration, now time.Time) {
	i := 0
	for i < len(m.buckets) && now.Sub(m.buckets[i].start) > window {
		i++
	}
	m.buckets = m.buckets[i:]
	for ip, at := range m.alerted {
		if now.Sub(at) > window {
			delete(m.alerted, ip)
		}
	}
}

// maskedFinding is one report of the detector.
type maskedFinding struct {
	ip                 string
	requests, total    int
	accounts, sharePct int
}

// evaluate judges the window at most once per bucket width and returns
// the source to report, if any; a source is reported once per window.
func (m *maskedTracker) evaluate(cfg config.ClientIPMasked, now time.Time) (maskedFinding, bool) {
	if !cfg.Enabled {
		return maskedFinding{}, false
	}
	window := cfg.Window.D()
	m.mu.Lock()
	defer m.mu.Unlock()
	if now.Sub(m.lastEval) < window/maskedBuckets {
		return maskedFinding{}, false
	}
	m.lastEval = now
	m.prune(window, now)
	total := 0
	counts := map[string]int{}
	accounts := map[string]map[string]struct{}{}
	for _, b := range m.buckets {
		total += b.total
		for ip, src := range b.ips {
			counts[ip] += src.n
			set := accounts[ip]
			if set == nil {
				set = map[string]struct{}{}
				accounts[ip] = set
			}
			for a := range src.accounts {
				set[a] = struct{}{}
			}
		}
	}
	if total < cfg.MinRequests {
		return maskedFinding{}, false
	}
	var top string
	for ip, n := range counts {
		if n > counts[top] || (n == counts[top] && ip < top) {
			top = ip
		}
	}
	f := maskedFinding{ip: top, requests: counts[top], total: total, accounts: len(accounts[top]), sharePct: counts[top] * 100 / total}
	if f.sharePct < cfg.MinSharePercent || f.accounts < cfg.MinAccounts || !maskingAddress(top) || ignored(cfg.IgnoreCIDRs, top) {
		return maskedFinding{}, false
	}
	if _, done := m.alerted[top]; done {
		return maskedFinding{}, false
	}
	m.alerted[top] = now
	return f, true
}

// maskingAddress reports whether ip can be the address of a NAT or a
// container network gateway: private (RFC 1918, fc00::/7), shared
// (RFC 6598) or link-local. Loopback is excluded: a local front end is a
// deliberate setup, and every test client is one.
func maskingAddress(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	return !a.IsLoopback() && (a.IsPrivate() || cgnat.Contains(a) || a.IsLinkLocalUnicast())
}

// ignored reports whether ip is inside one of cidrs (addresses or prefixes,
// validated by the configuration).
func ignored(cidrs []string, ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil && p.Contains(a) {
			return true
		}
		if b, err := netip.ParseAddr(c); err == nil && b.Unmap() == a {
			return true
		}
	}
	return false
}

// checkMasked runs the detector (from Tick) and reports a finding as
// insecure_config{what=client_ip_masked} and a WARN log line.
func (e *Engine) checkMasked(cfg config.ClientIPMasked, now time.Time) {
	f, ok := e.masked.evaluate(cfg, now)
	if !ok {
		return
	}
	e.log.Warn("client addresses look masked: most binds and searches come from one private address for several accounts; "+
		"per-IP rate limits, allow_cidrs and the IDS cannot tell clients apart (container network or proxy without the real source IP, see docs/podman.md)",
		"source_ip", f.ip, "share_percent", f.sharePct, "requests", f.requests, "accounts", f.accounts, "window", cfg.Window.D().String())
	e.ev.Emit(events.Event{Event: events.InsecureConfig, Level: events.LevelMedium, ClientIP: f.ip, Data: map[string]any{
		"what": WhatClientIPMasked, "share_percent": f.sharePct, "requests": f.requests, "requests_total": f.total,
		"accounts": f.accounts, "window": cfg.Window.D().String(),
	}})
}
