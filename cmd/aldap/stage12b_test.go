//go:build integration

package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/ids"
	"github.com/alstdev/aldap/internal/listener"
	"github.com/alstdev/aldap/internal/ratelimit"
	"github.com/alstdev/aldap/internal/secret"
	"github.com/alstdev/aldap/internal/testdir"
)

// startDaemonWith renders the test configuration, applies edit and starts
// a daemon with the given inherited sockets.
func startDaemonWith(t *testing.T, extra, virolaExtra string, edit func(body string, ldapsPort int) string, inherited *inheritedSockets) (*running, error) {
	t.Helper()
	dc := testdir.StartFixture(t)
	caDir := filepath.Join(t.TempDir(), "ca")
	path, lp, pp := daemonConfigVirola(t, dc, caDir, extra, virolaExtra)
	if edit != nil {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(edit(string(b), lp)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	logs := &safeBuffer{}
	d, err := loadDaemon(path, true, daemonOptions{LogOut: logs, EventsOut: logs, Secrets: secret.Default, Argon2: fastArgon, Hostname: "aldap-test", Inherited: inherited})
	if err != nil {
		t.Fatalf("loadDaemon: %v", err)
	}
	r := &running{d: d, dc: dc, logs: logs, ldapsAddr: fmt.Sprintf("127.0.0.1:%d", lp), plainAddr: fmt.Sprintf("127.0.0.1:%d", pp), caDir: caDir, path: path}
	if err := d.start(context.Background()); err != nil {
		d.stop()
		return r, err
	}
	t.Cleanup(func() { r.d.stop() })
	return r, nil
}

// systemdListen replaces the listen address of [profile.virola].
func systemdListen(listen string) func(string, int) string {
	return func(body string, lp int) string {
		return strings.Replace(body, fmt.Sprintf(`listen = ["127.0.0.1:%d"]`, lp), `listen = [`+listen+`]`, 1)
	}
}

// ldapsTo dials an ldaps listener at addr and binds as the client.
func (r *running) ldapsTo(t *testing.T, addr string) *ldap.Conn {
	t.Helper()
	c, err := ldap.DialURL("ldaps://"+addr, ldap.DialWithTLSConfig(r.tlsConfig(t)))
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	c.SetTimeout(5 * time.Second)
	t.Cleanup(func() { _ = c.Close() })
	if err := c.Bind(tClientDN, clientPassword); err != nil {
		t.Fatalf("client bind via %s: %v", addr, err)
	}
	return c
}

func loopbackListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

// stillOpen reports whether the inherited socket ln is open (the process
// keeps it across reloads).
func stillOpen(ln net.Listener) bool {
	f, err := ln.(*net.TCPListener).File()
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// TestStage12b_SocketActivation: a profile served on the sockets systemd
// passed under one name; reloads keep them, also when the name is dropped
// and listed again; an unknown name fails start and reload without changes.
func TestStage12b_SocketActivation(t *testing.T) {
	ln1, ln2, spare := loopbackListener(t), loopbackListener(t), loopbackListener(t)
	set := &inheritedSockets{}
	set.add("virola", ln1)
	set.add("virola", ln2)
	set.add("spare", spare)
	r, err := startDaemonWith(t, "", "", systemdListen(`"systemd:virola"`), set)
	if err != nil {
		t.Fatalf("start: %v\n%s", err, r.logs.String())
	}
	addrs := r.d.addrs("virola")
	if len(addrs) != 2 || addrs[0] != ln1.Addr().String() || addrs[1] != ln2.Addr().String() {
		t.Fatalf("addrs = %v", addrs)
	}
	c1 := r.ldapsTo(t, ln1.Addr().String())
	r.ldapsTo(t, ln2.Addr().String())
	if res := search(t, c1, tUsersDN, "(uid=alice.adams)", "mail"); len(res.Entries) != 1 {
		t.Fatalf("search via the inherited socket: %d entries", len(res.Entries))
	}
	if !strings.Contains(r.logs.String(), `"msg":"connection accepted"`) || !strings.Contains(r.logs.String(), `"direct_source":true`) {
		t.Error("connections on inherited sockets are not marked direct_source")
	}
	waitFor(t, func() bool { return strings.Contains(r.logs.String(), `"socket":"systemd:spare"`) })

	// A reload that changes the rules keeps the sockets and the connection.
	r.reloadWith(t, func(s string) string { return strings.Replace(s, `"mail", "objectClass"`, `"objectClass"`, 1) })
	if res := search(t, c1, tUsersDN, "(uid=alice.adams)", "mail"); len(res.Entries) != 1 || res.Entries[0].GetAttributeValue("mail") != "" {
		t.Fatalf("after reload: %+v", res.Entries)
	}
	// Dropping the name stops serving it but keeps the sockets open ...
	port := freePort(t)
	r.reloadWith(t, func(s string) string {
		return strings.Replace(s, `listen = ["systemd:virola"]`, fmt.Sprintf(`listen = ["127.0.0.1:%d"]`, port), 1)
	})
	if !stillOpen(ln1) || !stillOpen(ln2) {
		t.Fatal("reload closed an inherited socket")
	}
	waitFor(t, func() bool { return strings.Contains(r.logs.String(), `"socket":"systemd:virola"`) })
	r.ldapsTo(t, fmt.Sprintf("127.0.0.1:%d", port))
	// ... so listing it again serves it again.
	r.reloadWith(t, func(s string) string {
		return strings.Replace(s, fmt.Sprintf(`listen = ["127.0.0.1:%d"]`, port), `listen = ["systemd:virola"]`, 1)
	})
	c3 := r.ldapsTo(t, ln1.Addr().String())
	if res := search(t, c3, tUsersDN, "(uid=bob.brown)"); len(res.Entries) != 1 {
		t.Fatalf("served again: %d entries", len(res.Entries))
	}
	// An unknown name fails the reload; the running configuration stays.
	b, _ := os.ReadFile(r.path)
	if err := os.WriteFile(r.path, []byte(strings.Replace(string(b), `"systemd:virola"`, `"systemd:virola", "systemd:nope"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	o := r.d.opts
	o.State = r.d.state
	next, err := reload(context.Background(), r.d, r.path, true, o)
	if err == nil || next != r.d || !strings.Contains(err.Error(), "systemd:nope") {
		t.Fatalf("reload with an unknown socket name: %v", err)
	}
	if res := search(t, c3, tUsersDN, "(uid=bob.brown)"); len(res.Entries) != 1 {
		t.Fatal("old configuration stopped after a failed reload")
	}
	r.d.stop()
	if stillOpen(ln1) {
		t.Error("inherited socket open after shutdown")
	}
}

func TestStage12b_SocketActivationUnknownName(t *testing.T) {
	set := &inheritedSockets{}
	set.add("other", loopbackListener(t))
	r, err := startDaemonWith(t, "", "", systemdListen(`"systemd:virola"`), set)
	if err == nil || !strings.Contains(err.Error(), "passed: other") {
		t.Fatalf("start with a missing socket name: %v\n%s", err, r.logs.String())
	}
}

// proxyConfig accepts PROXY headers from 127.0.0.2 only and makes the
// masked-address detector as eager as in internal/ids tests.
const proxyVirola = `proxy_protocol = { enabled = true, trusted_cidrs = ["127.0.0.2/32"] }
`

const proxyExtra = `
[ratelimit]
constant_time_bind_fail = false
negative_cache_ttl = "1s"
[ratelimit.ip]
max_failures = 3
window = "5m"
lock_duration = "1m"
[ratelimit.account]
max_failures = 50
[ratelimit.delay]
base = "1ms"
max = "2ms"

[ids.client_ip_masked]
window = "1m"
min_requests = 10
min_share_percent = 90
min_accounts = 3
`

// proxyHeaderV2 is a v2 PROXY header for a TCP4 client src:port.
func proxyHeaderV2(src string, port uint16) []byte {
	h := append([]byte("\r\n\r\n\x00\r\nQUIT\n"), 0x21, 0x11, 0, 12)
	h = append(h, netip.MustParseAddr(src).AsSlice()...)
	h = append(h, 127, 0, 0, 1)
	h = binary.BigEndian.AppendUint16(h, port)
	return binary.BigEndian.AppendUint16(h, 636)
}

// viaProxy connects from local (the proxy address) to the ldaps profile,
// sends header and returns the LDAP connection over TLS.
func (r *running) viaProxy(t *testing.T, local string, header []byte) (*ldap.Conn, error) {
	t.Helper()
	d := &net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(local)}}
	raw, err := d.DialContext(context.Background(), "tcp", r.ldapsAddr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Write(header); err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(raw, r.tlsConfig(t))
	hctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	c := ldap.NewConn(tc, true)
	c.Start()
	c.SetTimeout(5 * time.Second)
	t.Cleanup(func() { _ = c.Close() })
	return c, nil
}

// TestStage12b_ProxyProtocol: behind a trusted proxy, events, the per-IP
// rate limit and the detectors see the address of the header; a spoofed
// header from elsewhere is cut and reported; the masked-address detector
// stays silent although every connection comes from one proxy address.
func TestStage12b_ProxyProtocol(t *testing.T) {
	r := startDaemonVirola(t, proxyExtra, proxyVirola)
	c, err := r.viaProxy(t, "127.0.0.2", proxyHeaderV2("10.89.0.1", 40001))
	if err != nil {
		t.Fatalf("via the trusted proxy: %v", err)
	}
	// Three failures lock the header address, not the proxy's.
	for i := 0; i < 3; i++ {
		if err := c.Bind(fmt.Sprintf("user%d@test.aldap", i), "wrong"); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			t.Fatalf("failure %d: %v", i, err)
		}
	}
	fail := waitEvents(t, r, "bind_fail with the header address", events.BindFail, nil)
	if fail.ClientIP != "10.89.0.1" || fail.ClientPort != 40001 {
		t.Errorf("bind_fail client %s:%d", fail.ClientIP, fail.ClientPort)
	}
	waitEvents(t, r, "ip lock of the header address", events.Lock, func(e events.Record) bool {
		return e.Data["target"] == "ip" && e.Data["key"] == "10.89.0.1"
	})
	before := r.dc.Calls().Binds
	if err := c.Bind("alice.adams@test.aldap", "alice.adams-pass"); err == nil {
		t.Fatal("locked header address bound")
	}
	if r.dc.Calls().Binds != before {
		t.Error("locked header address reached the upstream")
	}
	// Another client behind the same proxy is not affected.
	c2, err := r.viaProxy(t, "127.0.0.2", []byte("PROXY TCP4 10.89.0.2 127.0.0.1 40002 636\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c2.Bind("alice.adams@test.aldap", "alice.adams-pass"); err != nil {
		t.Fatalf("other client behind the proxy: %v", err)
	}
	// Many accounts through one proxy address: KnownSource, no masking report.
	for i := 0; i < 20; i++ {
		_ = c2.Bind([]string{"bob.brown", "mia.moore", "dan.davis", "frank.foster"}[i%4]+"@test.aldap", []string{"bob.brown", "mia.moore", "dan.davis", "frank.foster"}[i%4]+"-pass")
	}
	// A spoofed header from an address outside trusted_cidrs.
	if _, err := r.viaProxy(t, "127.0.0.1", proxyHeaderV2("192.0.2.66", 1)); err == nil {
		t.Fatal("spoofed header from an untrusted address was served")
	}
	ev := waitEvents(t, r, "insecure_config for the spoofed header", events.InsecureConfig, func(e events.Record) bool {
		return e.Data["what"] == listener.WhatProxyUntrusted
	})
	if ev.ClientIP != "127.0.0.1" || ev.Profile != "virola" {
		t.Errorf("insecure_config %+v", ev)
	}
	if n := len(findEvents(r, events.BindOK, func(e events.Record) bool { return e.ClientIP == "192.0.2.66" })); n != 0 {
		t.Error("spoofed address appears in events")
	}
	// Without a header the untrusted peer is served under its own address.
	r.clientConn(t)
	// The detector judges the window at most every window/10 (6s).
	time.Sleep(7 * time.Second)
	if got := findEvents(r, events.InsecureConfig, func(e events.Record) bool { return e.Data["what"] == ids.WhatClientIPMasked }); len(got) != 0 {
		t.Errorf("client_ip_masked behind a trusted proxy: %+v", got)
	}
}

// virolaAllow is the Virola scenario: every bind comes from one
// application server address in the profile's allow_cidrs.
const virolaAllow = `[profile.virola.ratelimit]
allow_cidrs = ["127.0.0.1/32"]
`

// TestStage12b_VirolaAllowCIDRs: allow_cidrs lifts only the IP limits. A
// brute force on one account through the application server locks that
// account (the next bind does not reach the upstream), other accounts keep
// working, the server's address is never locked, and a spray through it
// still starts an attack.
func TestStage12b_VirolaAllowCIDRs(t *testing.T) {
	r := startDaemonVirola(t, stage6Config, virolaAllow)
	c := bindFrom(t, r, "127.0.0.1")
	for i := 0; i < 3; i++ {
		_ = c.Bind("bob.brown@test.aldap", fmt.Sprintf("guess-%d", i))
	}
	waitEvents(t, r, "account lock through allow_cidrs", events.Lock, func(e events.Record) bool {
		return e.Data["target"] == "account" && e.Data["key"] == "bob.brown"
	})
	before := r.dc.Calls().Binds
	if err := c.Bind("bob.brown@test.aldap", "bob.brown-pass"); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Fatalf("locked account through the application server: %v", err)
	}
	if r.dc.Calls().Binds != before {
		t.Error("locked account reached the upstream")
	}
	waitEvents(t, r, "account_locked", events.BindBlocked, func(e events.Record) bool { return e.Reason == ratelimit.ReasonAccountLocked })
	// Other users of the application keep working; more failures than
	// ip.max_failures (8) never lock the server's address.
	users := []string{"alice.adams", "mia.moore", "dan.davis", "nick.nelson", "frank.foster"}
	for round := 0; round < 2; round++ {
		for _, u := range users {
			_ = c.Bind(u+"@test.aldap", "typo")
		}
	}
	for _, u := range users {
		if err := c.Bind(u+"@test.aldap", u+"-pass"); err != nil {
			t.Fatalf("%s through the application server: %v", u, err)
		}
	}
	if n := len(findEvents(r, events.Lock, func(e events.Record) bool { return e.Data["target"] == "ip" })); n != 0 {
		t.Errorf("allow_cidrs address locked (%d lock events)", n)
	}
	// A spray (one password, five accounts) through the server is detected.
	for _, u := range []string{"grace.green", "hank.hill", "ivy.irwin", "leo.lewis", "kate.king"} {
		_ = c.Bind(u+"@test.aldap", "Winter2026!")
	}
	att := waitEvents(t, r, "spray through allow_cidrs", events.AttackStart, func(e events.Record) bool { return e.Data["kind"] == ids.KindSpray })
	if att.Level != events.LevelHigh && att.Level != events.LevelMedium {
		t.Errorf("attack_start %+v", att)
	}
	// The tarpit (attacking source) does not apply to the server address.
	start := time.Now()
	if err := c.Bind("alice.adams@test.aldap", "alice.adams-pass"); err != nil {
		t.Fatalf("after the spray: %v", err)
	}
	if d := time.Since(start); d > 250*time.Millisecond {
		t.Errorf("allow_cidrs address tarpitted (%v)", d)
	}
}
