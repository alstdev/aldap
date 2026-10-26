package ids

import (
	"fmt"
	"testing"
	"time"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/events"
)

// traffic is one source in a masked-address scenario.
type traffic struct {
	ip       string
	accounts int
	requests int
	search   bool
}

func feed(e *Engine, cl *clock, srcs []traffic) {
	for _, s := range srcs {
		for i := range s.requests {
			acct := fmt.Sprintf("user%02d", i%max(s.accounts, 1))
			if s.accounts == 0 {
				acct = ""
			}
			if s.search {
				e.Search(SearchObs{Profile: "p", IP: s.ip, ConnID: "c-1", Account: acct, Base: "ou=users,dc=x", Scope: "sub"})
			} else {
				e.Bind(BindObs{Profile: "p", IP: s.ip, ConnID: "c-1", Account: acct, OK: true})
			}
			cl.add(100 * time.Millisecond)
		}
	}
}

func maskedEvents(ev *sink) []events.Event {
	return ev.find(events.InsecureConfig, func(e events.Event) bool { return e.Data["what"] == WhatClientIPMasked })
}

func TestClientIPMasked_Detects(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*config.ClientIPMasked)
		srcs []traffic
		want string // reported source ("" = none)
	}{
		{"podman custom network gateway", nil, []traffic{{ip: "10.89.0.1", accounts: 5, requests: 60}}, "10.89.0.1"},
		{"searches count too", nil, []traffic{{ip: "10.88.0.1", accounts: 4, requests: 30}, {ip: "10.88.0.1", accounts: 4, requests: 30, search: true}}, "10.88.0.1"},
		{"slirp4netns rootlesskit", nil, []traffic{{ip: "10.0.2.100", accounts: 3, requests: 55}, {ip: "192.0.2.10", accounts: 1, requests: 2}}, "10.0.2.100"},
		{"IPv6 ULA", nil, []traffic{{ip: "fd00::1", accounts: 3, requests: 50}}, "fd00::1"},
		{"CGNAT range", nil, []traffic{{ip: "100.64.0.1", accounts: 3, requests: 50}}, "100.64.0.1"},
		{"real clients spread", nil, []traffic{{ip: "10.1.0.5", accounts: 5, requests: 30}, {ip: "10.1.0.6", accounts: 5, requests: 30}}, ""},
		{"share under the threshold", nil, []traffic{{ip: "10.89.0.1", accounts: 5, requests: 80}, {ip: "10.1.0.6", accounts: 1, requests: 20}}, ""},
		{"too few requests", nil, []traffic{{ip: "10.89.0.1", accounts: 5, requests: 49}}, ""},
		{"one account", nil, []traffic{{ip: "10.89.0.1", accounts: 1, requests: 60}}, ""},
		{"anonymous only", nil, []traffic{{ip: "10.89.0.1", accounts: 0, requests: 60}}, ""},
		{"public address", nil, []traffic{{ip: "198.51.100.7", accounts: 5, requests: 60}}, ""},
		{"loopback", nil, []traffic{{ip: "127.0.0.1", accounts: 5, requests: 60}}, ""},
		{"ignored application server", func(m *config.ClientIPMasked) { m.IgnoreCIDRs = []string{"10.89.0.0/24"} },
			[]traffic{{ip: "10.89.0.1", accounts: 5, requests: 60}}, ""},
		{"ignored single address", func(m *config.ClientIPMasked) { m.IgnoreCIDRs = []string{"10.89.0.1"} },
			[]traffic{{ip: "10.89.0.1", accounts: 5, requests: 60}}, ""},
		{"disabled", func(m *config.ClientIPMasked) { m.Enabled = false }, []traffic{{ip: "10.89.0.1", accounts: 5, requests: 60}}, ""},
		{"custom thresholds", func(m *config.ClientIPMasked) { m.MinRequests, m.MinSharePercent, m.MinAccounts = 10, 70, 2 },
			[]traffic{{ip: "172.18.0.1", accounts: 2, requests: 15}, {ip: "10.1.0.6", accounts: 1, requests: 5}}, "172.18.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, ev, cl, _ := newTest(t, func(c *config.Intrusion) {
				c.Spray.Enabled, c.Enumeration.Enabled = false, false
				if tc.mod != nil {
					tc.mod(&c.ClientIPMasked)
				}
			})
			feed(e, cl, tc.srcs)
			cl.add(time.Minute)
			e.Tick()
			got := maskedEvents(ev)
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("reported %+v", got)
				}
				return
			}
			if len(got) != 1 || got[0].ClientIP != tc.want || got[0].Level != events.LevelMedium {
				t.Fatalf("events = %+v, want one for %s", got, tc.want)
			}
			if got[0].Data["share_percent"].(int) < 70 || got[0].Data["accounts"].(int) < 2 {
				t.Errorf("data = %+v", got[0].Data)
			}
			ev.check(t)
		})
	}
}

// TestClientIPMasked_OncePerWindow: the finding is repeated only after a
// window, and traffic older than the window is forgotten.
func TestClientIPMasked_OncePerWindow(t *testing.T) {
	e, ev, cl, _ := newTest(t, func(c *config.Intrusion) { c.Spray.Enabled, c.Enumeration.Enabled = false, false })
	gw := []traffic{{ip: "10.89.0.1", accounts: 5, requests: 60}}
	feed(e, cl, gw)
	cl.add(time.Minute)
	e.Tick()
	feed(e, cl, gw)
	cl.add(time.Minute)
	e.Tick()
	e.Tick() // within the same bucket: not evaluated again
	if n := len(maskedEvents(ev)); n != 1 {
		t.Fatalf("events within one window = %d", n)
	}
	// Eleven minutes later the old traffic is gone: nothing to report.
	cl.add(11 * time.Minute)
	e.Tick()
	if n := len(maskedEvents(ev)); n != 1 {
		t.Fatalf("stale traffic reported again: %d", n)
	}
	// New traffic in a new window is reported again.
	feed(e, cl, gw)
	cl.add(time.Minute)
	e.Tick()
	if n := len(maskedEvents(ev)); n != 2 {
		t.Fatalf("events after a new window = %d", n)
	}
}

// TestClientIPMasked_Bounds: a flood of distinct sources does not grow the
// tables without bound and still dilutes the share.
func TestClientIPMasked_Bounds(t *testing.T) {
	e, ev, cl, _ := newTest(t, func(c *config.Intrusion) { c.Spray.Enabled, c.Enumeration.Enabled = false, false })
	cfg := config.Default().Intrusion.ClientIPMasked
	for i := range maskedMaxIPs + 100 {
		e.masked.observe(cfg, fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), "u", cl.now())
	}
	for i := range 200 {
		e.masked.observe(cfg, "10.89.0.1", fmt.Sprintf("acct%d", i), cl.now())
	}
	e.masked.mu.Lock()
	b := e.masked.buckets[len(e.masked.buckets)-1]
	ips, accounts := len(b.ips), 0
	if src := b.ips["10.89.0.1"]; src != nil {
		accounts = len(src.accounts)
	}
	e.masked.mu.Unlock()
	if ips > maskedMaxIPs || accounts > maskedMaxAccounts {
		t.Errorf("tables: %d sources, %d accounts", ips, accounts)
	}
	cl.add(time.Minute)
	e.Tick()
	if n := len(maskedEvents(ev)); n != 0 {
		t.Errorf("flood of sources reported as masking: %d", n)
	}
	for _, ip := range []string{"", "not-an-ip"} {
		if maskingAddress(ip) || ignored([]string{"10.0.0.0/8"}, ip) {
			t.Errorf("address %q", ip)
		}
	}
	if !maskingAddress("::ffff:10.0.2.2") || !maskingAddress("169.254.1.1") {
		t.Error("mapped or link-local address")
	}
}
