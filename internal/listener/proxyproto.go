package listener

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alstdev/aldap/internal/events"
)

// PROXY protocol (haproxy proxy-protocol.txt, versions 1 and 2): a proxy in
// front of the listener sends one header with the client's address before
// the client's own bytes (LDAP or the TLS ClientHello).

const (
	// proxyV1Max is the longest v1 header including CRLF (spec §2.1).
	proxyV1Max = 107
	// proxyV2Max bounds the address and TLV block of a v2 header; real
	// proxies send a few dozen bytes, the format allows 65535.
	proxyV2Max = 4096
	// proxyWarnEvery limits the log lines and events per proxy address.
	proxyWarnEvery = time.Minute
	// proxyWarnMax bounds the addresses remembered for proxyWarnEvery.
	proxyWarnMax = 1024
)

var (
	proxyV1Sig = []byte("PROXY ")
	proxyV2Sig = []byte("\r\n\r\n\x00\r\nQUIT\n")
)

// WhatProxyUntrusted is insecure_config.what of a PROXY protocol header
// sent from an address outside proxy_protocol.trusted_cidrs.
const WhatProxyUntrusted = "proxy_protocol_untrusted"

// errNoProxyHeader means the connection does not start with a header.
var errNoProxyHeader = errors.New("no PROXY protocol header")

// ProxyProtocol accepts PROXY protocol headers from the Trusted networks.
type ProxyProtocol struct {
	Trusted []netip.Prefix
}

// ParseProxyTrusted converts proxy_protocol.trusted_cidrs (addresses or
// prefixes, validated by the configuration) into a ProxyProtocol.
func ParseProxyTrusted(cidrs []string) (*ProxyProtocol, error) {
	p := &ProxyProtocol{}
	for _, c := range cidrs {
		if pr, err := netip.ParsePrefix(c); err == nil {
			p.Trusted = append(p.Trusted, pr.Masked())
			continue
		}
		a, err := netip.ParseAddr(c)
		if err != nil {
			return nil, fmt.Errorf("proxy_protocol.trusted_cidrs: %q is not an IP address or CIDR", c)
		}
		a = a.Unmap()
		p.Trusted = append(p.Trusted, netip.PrefixFrom(a, a.BitLen()))
	}
	return p, nil
}

// trusts reports whether the peer address may send a header.
func (p *ProxyProtocol) trusts(peer net.Addr) bool {
	ap, ok := addrPort(peer)
	if !ok {
		return false
	}
	a := ap.Addr().Unmap()
	for _, pr := range p.Trusted {
		if pr.Contains(a) {
			return true
		}
	}
	return false
}

func addrPort(a net.Addr) (netip.AddrPort, bool) {
	if ta, ok := a.(*net.TCPAddr); ok {
		return ta.AddrPort(), true
	}
	if a == nil {
		return netip.AddrPort{}, false
	}
	ap, err := netip.ParseAddrPort(a.String())
	return ap, err == nil
}

// startsWithProxyHeader reports whether the next bytes are a v1 or v2
// signature, reading no more than needed to tell: LDAP messages start
// with 0x30, TLS records with 0x16.
func startsWithProxyHeader(br *bufio.Reader) (bool, error) {
	b, err := br.Peek(1)
	if err != nil {
		return false, err
	}
	var sig []byte
	switch b[0] {
	case proxyV1Sig[0]:
		sig = proxyV1Sig
	case proxyV2Sig[0]:
		sig = proxyV2Sig
	default:
		return false, nil
	}
	b, err = br.Peek(len(sig))
	if err != nil {
		return false, err
	}
	return bytes.Equal(b, sig), nil
}

// readProxyHeader consumes one header and returns the client address it
// carries; nil means "use the connection's own address" (v1 UNKNOWN, v2
// LOCAL, v2 AF_UNSPEC).
func readProxyHeader(br *bufio.Reader) (net.Addr, error) {
	b, err := br.Peek(1)
	if err != nil {
		return nil, err
	}
	switch b[0] {
	case proxyV1Sig[0]:
		return readProxyV1(br)
	case proxyV2Sig[0]:
		return readProxyV2(br)
	}
	return nil, errNoProxyHeader
}

// readProxyV1 parses "PROXY TCP4|TCP6 src dst sport dport\r\n" or
// "PROXY UNKNOWN ...\r\n".
func readProxyV1(br *bufio.Reader) (net.Addr, error) {
	line := make([]byte, 0, proxyV1Max)
	for {
		c, err := br.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("proxy v1: %w", err)
		}
		line = append(line, c)
		if c == '\n' {
			break
		}
		if len(line) >= proxyV1Max {
			return nil, errors.New("proxy v1: header longer than 107 bytes")
		}
	}
	s, ok := strings.CutSuffix(string(line), "\r\n")
	if !ok || !strings.HasPrefix(s, string(proxyV1Sig)) {
		return nil, errors.New("proxy v1: malformed header")
	}
	f := strings.Split(s, " ")
	if len(f) >= 2 && f[1] == "UNKNOWN" {
		return nil, nil
	}
	if len(f) != 6 || (f[1] != "TCP4" && f[1] != "TCP6") {
		return nil, errors.New("proxy v1: malformed header")
	}
	src, err := netip.ParseAddr(f[2])
	if err != nil {
		return nil, fmt.Errorf("proxy v1: source address: %w", err)
	}
	dst, err := netip.ParseAddr(f[3])
	if err != nil {
		return nil, fmt.Errorf("proxy v1: destination address: %w", err)
	}
	want4 := f[1] == "TCP4"
	if src.Is4() != want4 || dst.Is4() != want4 || src.Zone() != "" {
		return nil, fmt.Errorf("proxy v1: address family does not match %s", f[1])
	}
	port, err := parseProxyPort(f[4])
	if err != nil {
		return nil, err
	}
	if _, err := parseProxyPort(f[5]); err != nil {
		return nil, err
	}
	return net.TCPAddrFromAddrPort(netip.AddrPortFrom(src, port)), nil
}

func parseProxyPort(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil || (len(s) > 1 && s[0] == '0') {
		return 0, fmt.Errorf("proxy v1: invalid port %q", s)
	}
	return uint16(n), nil
}

// readProxyV2 parses the binary header: signature, version/command,
// family/transport, length, addresses and TLVs (ignored).
func readProxyV2(br *bufio.Reader) (net.Addr, error) {
	var hdr [16]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return nil, fmt.Errorf("proxy v2: %w", err)
	}
	if !bytes.Equal(hdr[:12], proxyV2Sig) {
		return nil, errors.New("proxy v2: bad signature")
	}
	if hdr[12]>>4 != 2 {
		return nil, fmt.Errorf("proxy v2: version %d", hdr[12]>>4)
	}
	cmd := hdr[12] & 0x0f
	if cmd > 1 {
		return nil, fmt.Errorf("proxy v2: command %d", cmd)
	}
	n := int(binary.BigEndian.Uint16(hdr[14:16]))
	if n > proxyV2Max {
		return nil, fmt.Errorf("proxy v2: %d bytes of addresses and TLVs (max %d)", n, proxyV2Max)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, fmt.Errorf("proxy v2: %w", err)
	}
	if cmd == 0 {
		// LOCAL: the proxy's own connection (health check); the
		// address block is ignored.
		return nil, nil
	}
	family, transport := hdr[13]>>4, hdr[13]&0x0f
	if family == 0 {
		return nil, nil // AF_UNSPEC: the receiver keeps the real endpoints
	}
	if transport != 1 {
		return nil, fmt.Errorf("proxy v2: transport %d is not a stream", transport)
	}
	switch family {
	case 1: // AF_INET: src(4) dst(4) sport(2) dport(2)
		if n < 12 {
			return nil, errors.New("proxy v2: short IPv4 address block")
		}
		src := netip.AddrFrom4([4]byte(body[0:4]))
		return net.TCPAddrFromAddrPort(netip.AddrPortFrom(src, binary.BigEndian.Uint16(body[8:10]))), nil
	case 2: // AF_INET6: src(16) dst(16) sport(2) dport(2)
		if n < 36 {
			return nil, errors.New("proxy v2: short IPv6 address block")
		}
		src := netip.AddrFrom16([16]byte(body[0:16])).Unmap()
		return net.TCPAddrFromAddrPort(netip.AddrPortFrom(src, binary.BigEndian.Uint16(body[32:34]))), nil
	}
	return nil, fmt.Errorf("proxy v2: address family %d is not supported", family)
}

// bufferedConn reads through the buffer that held the PROXY header, so
// client bytes read along with it are not lost (plain LDAP and TLS alike).
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// proxyWarnings rate-limits the reports of one proxy address; it lives in
// the Server and survives Reconfigure.
type proxyWarnings struct {
	mu   sync.Mutex
	last map[string]time.Time
}

// allow reports whether key may be reported now.
func (w *proxyWarnings) allow(key string, now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.last == nil || len(w.last) >= proxyWarnMax {
		w.last = map[string]time.Time{}
	}
	if t, ok := w.last[key]; ok && now.Sub(t) < proxyWarnEvery {
		return false
	}
	w.last[key] = now
	return true
}

// resolveProxy reads the PROXY header of a connection accepted on a
// listener with proxy_protocol: from a trusted proxy it returns the client
// address of the header (direct=true: the address is the client's own);
// from any other peer the connection is served under its own address
// unless it sends a header, which closes it with insecure_config. ok=false
// means the connection must be closed.
func (s *Server) resolveProxy(g *generation, nc net.Conn, br *bufio.Reader) (remote net.Addr, direct, ok bool) {
	peer := nc.RemoteAddr()
	peerIP, _ := splitHostPort(peer)
	if err := nc.SetReadDeadline(time.Now().Add(g.cfg.FirstPacketTimeout)); err != nil {
		return nil, false, false
	}
	defer nc.SetReadDeadline(time.Time{}) //nolint:errcheck // the read loop sets its own deadline next
	pp := g.cfg.ProxyProtocol
	if !pp.trusts(peer) {
		has, err := startsWithProxyHeader(br)
		if err != nil {
			g.log.Debug("connection closed before its first bytes", "client_ip", peerIP, "err", err)
			return nil, false, false
		}
		if !has {
			return peer, false, true
		}
		if s.proxyWarn.allow("untrusted|"+peerIP, time.Now()) {
			g.log.Warn("PROXY protocol header from an untrusted address, connection closed (spoofed client address or the proxy is missing from proxy_protocol.trusted_cidrs)",
				"client_ip", peerIP)
			g.events.Emit(events.Event{Event: events.InsecureConfig, Level: events.LevelMedium, Profile: g.cfg.Profile, ClientIP: peerIP,
				Data: map[string]any{"what": WhatProxyUntrusted, "peer": peerIP}})
		}
		return nil, false, false
	}
	src, err := readProxyHeader(br)
	if err != nil {
		if s.proxyWarn.allow("trusted|"+peerIP, time.Now()) {
			g.log.Warn("trusted proxy sent no valid PROXY protocol header, connection closed", "proxy_ip", peerIP, "err", err)
		}
		return nil, false, false
	}
	if src == nil {
		return peer, false, true
	}
	g.log.Debug("PROXY protocol header accepted", "proxy_ip", peerIP, "client_ip", src.String())
	return src, true, true
}
