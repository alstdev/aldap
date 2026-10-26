package listener

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/events"
)

// proxyV2 builds a v2 header; cmd 0 = LOCAL, 1 = PROXY; fam is the
// family/transport byte (0x11 TCP4, 0x21 TCP6, ...).
func proxyV2(cmd, fam byte, src, dst string, sport, dport uint16, tlv []byte) []byte {
	var body []byte
	if src != "" {
		s, d := netip.MustParseAddr(src), netip.MustParseAddr(dst)
		body = append(body, s.AsSlice()...)
		body = append(body, d.AsSlice()...)
		body = binary.BigEndian.AppendUint16(body, sport)
		body = binary.BigEndian.AppendUint16(body, dport)
	}
	body = append(body, tlv...)
	h := append([]byte{}, proxyV2Sig...)
	h = append(h, 0x20|cmd, fam)
	h = binary.BigEndian.AppendUint16(h, uint16(len(body)))
	return append(h, body...)
}

func TestReadProxyHeader_Cases(t *testing.T) {
	t.Parallel()
	tlv := []byte{0x04, 0x00, 0x02, 'h', 'i'} // PP2_TYPE_NOOP
	tests := []struct {
		name string
		in   []byte
		want string // client address; "" = keep the peer address
		err  string
	}{
		{"v1_tcp4", []byte("PROXY TCP4 203.0.113.7 10.0.0.1 51234 636\r\n"), "203.0.113.7:51234", ""},
		{"v1_tcp6", []byte("PROXY TCP6 2001:db8::7 2001:db8::1 51234 636\r\n"), "[2001:db8::7]:51234", ""},
		{"v1_unknown", []byte("PROXY UNKNOWN ffff::1 ffff::2 1 2\r\n"), "", ""},
		{"v1_unknown_bare", []byte("PROXY UNKNOWN\r\n"), "", ""},
		{"v1_family_mismatch", []byte("PROXY TCP4 2001:db8::7 10.0.0.1 1 2\r\n"), "", "family"},
		{"v1_bad_proto", []byte("PROXY UDP4 203.0.113.7 10.0.0.1 1 2\r\n"), "", "malformed"},
		{"v1_bad_ip", []byte("PROXY TCP4 203.0.113 10.0.0.1 1 2\r\n"), "", "source address"},
		{"v1_bad_dst", []byte("PROXY TCP4 203.0.113.7 x 1 2\r\n"), "", "destination address"},
		{"v1_bad_port", []byte("PROXY TCP4 203.0.113.7 10.0.0.1 70000 2\r\n"), "", "invalid port"},
		{"v1_leading_zero", []byte("PROXY TCP4 203.0.113.7 10.0.0.1 01 2\r\n"), "", "invalid port"},
		{"v1_bad_dport", []byte("PROXY TCP4 203.0.113.7 10.0.0.1 1 x\r\n"), "", "invalid port"},
		{"v1_extra_field", []byte("PROXY TCP4 203.0.113.7 10.0.0.1 1 2 3\r\n"), "", "malformed"},
		{"v1_no_cr", []byte("PROXY TCP4 203.0.113.7 10.0.0.1 1 2\n"), "", "malformed"},
		{"v1_too_long", []byte("PROXY TCP4 " + strings.Repeat("1", 120) + "\r\n"), "", "107"},
		{"v1_eof", []byte("PROXY TCP4 203.0.113.7"), "", "EOF"},
		{"v2_tcp4", proxyV2(1, 0x11, "198.51.100.9", "10.0.0.1", 40000, 636, nil), "198.51.100.9:40000", ""},
		{"v2_tcp4_tlv", proxyV2(1, 0x11, "198.51.100.9", "10.0.0.1", 40000, 636, tlv), "198.51.100.9:40000", ""},
		{"v2_tcp6", proxyV2(1, 0x21, "2001:db8::9", "2001:db8::1", 40000, 636, nil), "[2001:db8::9]:40000", ""},
		{"v2_tcp6_mapped", proxyV2(1, 0x21, "::ffff:198.51.100.9", "::ffff:10.0.0.1", 1, 636, nil), "198.51.100.9:1", ""},
		{"v2_local", proxyV2(0, 0x00, "", "", 0, 0, nil), "", ""},
		{"v2_local_with_addr", proxyV2(0, 0x11, "198.51.100.9", "10.0.0.1", 1, 2, nil), "", ""},
		{"v2_unspec", proxyV2(1, 0x00, "", "", 0, 0, tlv), "", ""},
		{"v2_udp", proxyV2(1, 0x12, "198.51.100.9", "10.0.0.1", 1, 2, nil), "", "not a stream"},
		{"v2_unix", append(proxyV2(1, 0x31, "", "", 0, 0, nil)[:14], 0, 0), "", "not supported"},
		{"v2_short4", append(proxyV2(1, 0x11, "", "", 0, 0, nil)[:14], 0, 4, 1, 2, 3, 4), "", "short IPv4"},
		{"v2_short6", append(proxyV2(1, 0x21, "", "", 0, 0, nil)[:14], 0, 4, 1, 2, 3, 4), "", "short IPv6"},
		{"v2_version", append(append(append([]byte{}, proxyV2Sig...), 0x11, 0x11), 0, 0), "", "version"},
		{"v2_command", append(append(append([]byte{}, proxyV2Sig...), 0x22, 0x11), 0, 0), "", "command"},
		{"v2_oversize", append(append(append([]byte{}, proxyV2Sig...), 0x21, 0x11), 0xff, 0xff), "", "max"},
		{"v2_truncated", proxyV2(1, 0x11, "198.51.100.9", "10.0.0.1", 1, 2, nil)[:20], "", "EOF"},
		{"v2_bad_sig", append([]byte("\r\n\r\n\x00\r\nQUIX\n"), 0x21, 0x11, 0, 0), "", "signature"},
		{"ldap", []byte{0x30, 0x0c}, "", "no PROXY"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			br := bufio.NewReader(bytes.NewReader(append(tt.in, 0x30, 0x01)))
			got, err := readProxyHeader(br)
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("err = %v, want %q", err, tt.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if s := addrString(got); s != tt.want {
				t.Fatalf("addr = %q, want %q", s, tt.want)
			}
			// The bytes after the header stay for the client protocol.
			if b, err := br.ReadByte(); err != nil || b != 0x30 {
				t.Fatalf("next byte = %#x, %v", b, err)
			}
		})
	}
}

func addrString(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

func TestStartsWithProxyHeader(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]bool{
		"PROXY TCP4 ":             true,
		string(proxyV2Sig) + "!!": true,
		"\x30\x0c":                false,
		"\x16\x03\x01":            false,
		"PROXZ ":                  false,
		"\r\n\r\n\x00\r\nQUIX\n":  false,
	} {
		got, err := startsWithProxyHeader(bufio.NewReader(strings.NewReader(in)))
		if err != nil || got != want {
			t.Errorf("%q: %v, %v", in, got, err)
		}
	}
	if _, err := startsWithProxyHeader(bufio.NewReader(strings.NewReader("PRO"))); err == nil {
		t.Error("short signature: no error")
	}
	if _, err := startsWithProxyHeader(bufio.NewReader(strings.NewReader(""))); err == nil {
		t.Error("empty: no error")
	}
}

func TestParseProxyTrusted(t *testing.T) {
	t.Parallel()
	p, err := ParseProxyTrusted([]string{"10.89.0.0/24", "192.0.2.1", "::ffff:198.51.100.1", "fd00::/8"})
	if err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]bool{
		"10.89.0.7:1": true, "10.89.1.7:1": false, "192.0.2.1:1": true, "192.0.2.2:1": false,
		"198.51.100.1:5": true, "[::ffff:10.89.0.3]:1": true, "[fd12::1]:1": true, "[2001:db8::1]:1": false,
	} {
		if got := p.trusts(net.TCPAddrFromAddrPort(netip.MustParseAddrPort(addr))); got != want {
			t.Errorf("%s: %v", addr, got)
		}
	}
	if p.trusts(nil) || p.trusts(stringAddr("not an address")) || !p.trusts(stringAddr("10.89.0.9:7")) {
		t.Error("non-TCP addresses")
	}
	if _, err := ParseProxyTrusted([]string{"bad"}); err == nil {
		t.Error("bad entry accepted")
	}
}

// ipHandler records the client address and DirectSource of every bind.
type ipHandler struct {
	fakeHandler
	mu     sync.Mutex
	ips    []string
	direct []bool
}

func (h *ipHandler) Bind(ctx context.Context, c *Conn, name string, pw []byte) Result {
	h.mu.Lock()
	h.ips = append(h.ips, c.ClientIP())
	h.direct = append(h.direct, c.DirectSource())
	h.mu.Unlock()
	return h.fakeHandler.Bind(ctx, c, name, pw)
}

func (h *ipHandler) last(t *testing.T) (string, bool) {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.ips) == 0 {
		t.Fatal("no bind reached the handler")
	}
	return h.ips[len(h.ips)-1], h.direct[len(h.direct)-1]
}

func proxyServer(t *testing.T, trusted []string, mod func(*Config)) (*testServer, *ipHandler) {
	t.Helper()
	pp, err := ParseProxyTrusted(trusted)
	if err != nil {
		t.Fatal(err)
	}
	h := &ipHandler{}
	cfg := Config{Profile: "p", Handler: h, ProxyProtocol: pp, FirstPacketTimeout: 2 * time.Second}
	if mod != nil {
		mod(&cfg)
	}
	return start(t, cfg), h
}

// bindVia sends header (may be empty) and a bind on a raw connection and
// returns the result code, or -1 when the server closed the connection.
func bindVia(t *testing.T, addr string, header []byte) int64 {
	t.Helper()
	raw, rd := rawConn(t, addr)
	defer raw.Close()
	if _, err := raw.Write(append(append([]byte{}, header...), bindPacket(1, 3, "ok", "pw")...)); err != nil {
		t.Fatal(err)
	}
	raw0, err := readMessage(rd, 0)
	if err != nil {
		return -1
	}
	m, err := parseMessage(raw0)
	if err != nil {
		t.Fatal(err)
	}
	return resultCode(t, m)
}

func TestProxyProtocol_TrustedHeader(t *testing.T) {
	t.Parallel()
	ts, h := proxyServer(t, []string{"127.0.0.1"}, nil)
	for name, hdr := range map[string][]byte{
		"v1": []byte("PROXY TCP4 203.0.113.7 127.0.0.1 51234 389\r\n"),
		"v2": proxyV2(1, 0x21, "2001:db8::7", "2001:db8::1", 4000, 389, nil),
	} {
		if code := bindVia(t, ts.addr, hdr); code != ldap.LDAPResultSuccess {
			t.Fatalf("%s: bind = %d", name, code)
		}
		ip, direct := h.last(t)
		want := map[string]string{"v1": "203.0.113.7", "v2": "2001:db8::7"}[name]
		if ip != want || !direct {
			t.Errorf("%s: client ip %q direct %v, want %q true", name, ip, direct, want)
		}
	}
	// LOCAL (a health check of the proxy itself) keeps the proxy address.
	if code := bindVia(t, ts.addr, proxyV2(0, 0, "", "", 0, 0, nil)); code != ldap.LDAPResultSuccess {
		t.Fatalf("local: bind = %d", code)
	}
	if ip, direct := h.last(t); ip != "127.0.0.1" || direct {
		t.Errorf("local: %q %v", ip, direct)
	}
	// session_summary carries the client address of the header.
	waitFor(t, func() bool {
		for _, e := range ts.ev.find(events.SessionSummary) {
			if e.ClientIP == "203.0.113.7" {
				return true
			}
		}
		return false
	})
}

func TestProxyProtocol_TrustedLDAPS(t *testing.T) {
	t.Parallel()
	ts, h := proxyServer(t, []string{"127.0.0.0/8"}, func(c *Config) { c.Transport = TransportLDAPS })
	raw, _ := rawConn(t, ts.addr)
	if _, err := raw.Write([]byte("PROXY TCP4 198.51.100.20 10.0.0.1 1234 636\r\n")); err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(raw, ts.clientTLS())
	if err := tc.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("handshake after the header: %v", err)
	}
	if _, err := tc.Write(bindPacket(1, 3, "ok", "pw")); err != nil {
		t.Fatal(err)
	}
	if code := resultCode(t, readRaw(t, bufio.NewReader(tc))); code != ldap.LDAPResultSuccess {
		t.Fatalf("bind = %d", code)
	}
	if ip, direct := h.last(t); ip != "198.51.100.20" || !direct {
		t.Errorf("client %q direct %v", ip, direct)
	}
}

func TestProxyProtocol_Untrusted(t *testing.T) {
	t.Parallel()
	ts, h := proxyServer(t, []string{"10.89.0.2"}, nil)
	// A spoofed header from an address outside trusted_cidrs: closed,
	// reported once per minute and address.
	for i := 0; i < 3; i++ {
		if code := bindVia(t, ts.addr, []byte("PROXY TCP4 10.0.0.99 10.0.0.1 1 389\r\n")); code != -1 {
			t.Fatalf("spoofed header served: %d", code)
		}
	}
	if code := bindVia(t, ts.addr, proxyV2(1, 0x11, "10.0.0.99", "10.0.0.1", 1, 389, nil)); code != -1 {
		t.Fatalf("spoofed v2 header served: %d", code)
	}
	waitFor(t, func() bool { return len(ts.ev.find(events.InsecureConfig)) > 0 })
	evs := ts.ev.find(events.InsecureConfig)
	if len(evs) != 1 || evs[0].Data["what"] != WhatProxyUntrusted || evs[0].ClientIP != "127.0.0.1" || evs[0].Profile != "p" {
		t.Fatalf("events = %+v", evs)
	}
	h.mu.Lock()
	n := len(h.ips)
	h.mu.Unlock()
	if n != 0 {
		t.Fatalf("handler saw %d binds from spoofed headers", n)
	}
	// Without a header the peer is served under its own address.
	if code := bindVia(t, ts.addr, nil); code != ldap.LDAPResultSuccess {
		t.Fatalf("direct client: %d", code)
	}
	if ip, direct := h.last(t); ip != "127.0.0.1" || direct {
		t.Errorf("direct client %q %v", ip, direct)
	}
	c := ts.dial(t)
	if err := c.Bind("ok", "pw"); err != nil {
		t.Fatalf("ldap client without a header: %v", err)
	}
}

func TestProxyProtocol_TrustedWithoutHeader(t *testing.T) {
	t.Parallel()
	ts, h := proxyServer(t, []string{"127.0.0.1"}, nil)
	if code := bindVia(t, ts.addr, nil); code != -1 {
		t.Fatalf("trusted proxy without a header served: %d", code)
	}
	if code := bindVia(t, ts.addr, []byte("PROXY TCP4 bad\r\n")); code != -1 {
		t.Fatalf("malformed header served: %d", code)
	}
	// Silence: closed at the first-packet timeout.
	raw, rd := rawConn(t, ts.addr)
	_ = raw
	if err := closed(rd); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.ips) != 0 {
		t.Fatalf("handler reached: %v", h.ips)
	}
	if len(ts.ev.find(events.InsecureConfig)) != 0 {
		t.Error("insecure_config for the trusted proxy")
	}
}

func TestProxyProtocol_PerIPLimitUsesHeader(t *testing.T) {
	t.Parallel()
	ts, _ := proxyServer(t, []string{"127.0.0.1"}, func(c *Config) {
		c.PerIP = NewIPLimiter(1)
		c.Global = NewLimiter(10)
	})
	hold := func(ip string) (net.Conn, *bufio.Reader) {
		raw, rd := rawConn(t, ts.addr)
		if _, err := raw.Write(append([]byte("PROXY TCP4 "+ip+" 127.0.0.1 1 389\r\n"), bindPacket(1, 3, "ok", "pw")...)); err != nil {
			t.Fatal(err)
		}
		return raw, rd
	}
	_, rd1 := hold("192.0.2.1")
	readRaw(t, rd1)
	_, rd2 := hold("192.0.2.2")
	readRaw(t, rd2) // another client behind the same proxy
	_, rd3 := hold("192.0.2.1")
	if err := closed(rd3); err != nil {
		t.Fatalf("second connection of 192.0.2.1: %v", err)
	}
	waitFor(t, func() bool { return len(ts.ev.find(events.RateLimited)) == 1 })
	if e := ts.ev.find(events.RateLimited)[0]; e.ClientIP != "192.0.2.1" || e.Reason != "conn_limit_ip" {
		t.Errorf("rate_limited = %+v", e)
	}
	waitFor(t, func() bool { return ts.current().cfg.PerIP.Count("192.0.2.2") == 1 })
}

func TestProxyProtocol_ShutdownPending(t *testing.T) {
	t.Parallel()
	ts, _ := proxyServer(t, []string{"127.0.0.1"}, func(c *Config) { c.FirstPacketTimeout = time.Minute })
	_, rd := rawConn(t, ts.addr)
	waitFor(t, func() bool {
		ts.mu.Lock()
		defer ts.mu.Unlock()
		return len(ts.pending) == 1
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := ts.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown waited for a pending header: %v", err)
	}
	if err := closed(rd); err != nil {
		t.Fatal(err)
	}
}

func TestDirectSource_Config(t *testing.T) {
	t.Parallel()
	h := &ipHandler{}
	ts := start(t, Config{Profile: "p", Handler: h, DirectSource: true})
	if code := bindVia(t, ts.addr, nil); code != ldap.LDAPResultSuccess {
		t.Fatal(code)
	}
	if ip, direct := h.last(t); ip != "127.0.0.1" || !direct {
		t.Errorf("%q %v", ip, direct)
	}
	if NewConn("c", "p", nil).DirectSource() {
		t.Error("NewConn direct")
	}
}
