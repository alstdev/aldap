package listener

// Audit 14, area A.3 (protocol and DoS). These tests probe the BER reader,
// the transport limits, StartTLS and the PROXY protocol with hostile input.
// A test that fails on the current code documents a finding (see
// scratchpad/audit/A3.md); nothing here changes production code.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/events"
)

// nestedAndFilter builds (&(&(&...(cn=x)...))) with depth levels of AND.
func nestedAndFilter(depth int) *ber.Packet {
	leaf := ber.Encode(ber.ClassContext, ber.TypeConstructed, ldap.FilterEqualityMatch, nil, "eq")
	leaf.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", "attr"))
	leaf.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "x", "value"))
	f := leaf
	for i := 0; i < depth; i++ {
		and := ber.Encode(ber.ClassContext, ber.TypeConstructed, ldap.FilterAnd, nil, "and")
		and.AppendChild(f)
		f = and
	}
	return f
}

// wideOrFilter builds (|(cn=x)(cn=x)...) with n terms.
func wideOrFilter(n int) *ber.Packet {
	or := ber.Encode(ber.ClassContext, ber.TypeConstructed, ldap.FilterOr, nil, "or")
	for i := 0; i < n; i++ {
		leaf := ber.Encode(ber.ClassContext, ber.TypeConstructed, ldap.FilterEqualityMatch, nil, "eq")
		leaf.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", "attr"))
		leaf.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "x", "value"))
		or.AppendChild(leaf)
	}
	return or
}

// searchWith encodes a subtree search with the given filter packet and attrs.
func searchWith(id int64, filter *ber.Packet, attrs ...string) []byte {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchRequest, nil, "Search")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "dc=x", "base"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 2, "scope"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "deref"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "size"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "time"))
	op.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "typesOnly"))
	op.AppendChild(filter)
	a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attrs")
	for _, s := range attrs {
		a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, s, "attr"))
	}
	op.AppendChild(a)
	return envelope(id, op, nil).Bytes()
}

func parseRaw(data []byte, maxBytes int64) (*message, error) {
	raw, err := readMessage(bufio.NewReader(bytes.NewReader(data)), maxBytes)
	if err != nil {
		return nil, err
	}
	return parseMessage(raw)
}

func heapAlloc() uint64 {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

// ---------------------------------------------------------------- 1. BER

// SPEC §9: "відмова на вкладеність > 64". The listener never sets
// ber.MaxNestingDepth (library default 1000), so a message nested 70 deep
// is decoded and dispatched. FINDING A3-1 (Low): SPEC limit not enforced.
func TestAudit14_A3_BERDepthOver64Refused(t *testing.T) {
	// Envelope (1) + protocolOp (2) + 68 filter levels = 70 BER levels.
	data := searchWith(1, nestedAndFilter(67))
	m, err := parseRaw(data, 1<<20)
	if err != nil {
		return // refused as SPEC requires
	}
	req, err := parseSearch(m.Body)
	if err != nil {
		return
	}
	t.Errorf("SPEC §9 requires refusing BER nesting > 64; a 70-level message was decoded and decompiled to a %d-byte filter (ber.MaxNestingDepth=%d)", len(req.Filter), ber.MaxNestingDepth)
}

// A 10 000-level nested filter must not crash or exhaust the process.
func TestAudit14_A3_BERDepth10000NoCrash(t *testing.T) {
	data := searchWith(1, nestedAndFilter(10000))
	if len(data) > 1<<20 {
		t.Fatalf("test packet too large: %d", len(data))
	}
	before := heapAlloc()
	start := time.Now()
	_, err := parseRaw(data, 1<<20)
	el := time.Since(start)
	after := heapAlloc()
	t.Logf("10000-deep filter (%d bytes): err=%v in %v, heap delta %d KiB", len(data), err, el, int64(after-before)/1024)
	if err == nil {
		t.Error("10000-deep nesting should be refused")
	}
	if el > 2*time.Second {
		t.Errorf("parse took %v", el)
	}
}

// A 1 MiB wide OR filter is decompiled to text before any filter limit is
// checked (max_filter_len applies to the text in vdir only). Measures the
// CPU cost a single request costs the listener.
func TestAudit14_A3_WideORFilterCost(t *testing.T) {
	// Each (cn=x) is 9 bytes on the wire → ~110k terms under 1 MiB.
	data := searchWith(1, wideOrFilter(110000))
	if len(data) > 1<<20 {
		t.Fatalf("packet %d > 1 MiB", len(data))
	}
	start := time.Now()
	m, err := parseRaw(data, 1<<20)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	req, err := parseSearch(m.Body)
	el := time.Since(start)
	if err != nil {
		t.Fatalf("parseSearch: %v", err)
	}
	t.Logf("wide OR: %d wire bytes → %d filter chars in %v", len(data), len(req.Filter), el)
	if el > 3*time.Second {
		t.Errorf("decompile of one 1 MiB filter took %v", el)
	}
}

// Attribute lists and controls are not bounded by count, only by
// max_request_bytes: a 1 MiB request carries ~200k attribute names that
// are all kept in SearchRequest.Attrs (and later in the search event).
func TestAudit14_A3_AttributeListUnbounded(t *testing.T) {
	attrs := make([]string, 150000)
	for i := range attrs {
		attrs[i] = "a"
	}
	filter, _ := ldap.CompileFilter("(cn=*)")
	data := searchWith(1, filter, attrs...)
	if len(data) > 1<<20 {
		t.Fatalf("packet %d > 1 MiB", len(data))
	}
	m, err := parseRaw(data, 1<<20)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	req, err := parseSearch(m.Body)
	if err != nil {
		t.Fatalf("parseSearch: %v", err)
	}
	t.Logf("%d attribute names accepted from one request", len(req.Attrs))
	if len(req.Attrs) != 150000 {
		t.Errorf("attrs = %d", len(req.Attrs))
	}
}

// Length-header edge cases: everything is decided from the header before
// any body byte is buffered.
func TestAudit14_A3_LengthHeaderEdges(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"indefinite", []byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00}, ErrMalformed},
		{"2^31-1", []byte{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff}, ErrTooLarge},
		{"2^32-1", []byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff}, ErrTooLarge},
		{"5 octets (2^39)", []byte{0x30, 0x85, 0x80, 0, 0, 0, 0}, ErrTooLarge},
		{"8 octets (2^63)", []byte{0x30, 0x88, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, ErrTooLarge},
		{"0xff", []byte{0x30, 0xff}, ErrTooLarge},
		{"1MiB exactly over", append([]byte{0x30, 0x83, 0x0f, 0xff, 0xfe}, make([]byte, 10)...), ErrTooLarge}, // 1048574+5 > 1048576
		{"length 4 (too short)", []byte{0x30, 0x04, 0x02, 0x01, 0x01, 0x00}, ErrMalformed},
		{"not ldap", []byte{0x16, 0x03, 0x01}, ErrNotLDAP},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := heapAlloc()
			_, err := readMessage(bufio.NewReader(bytes.NewReader(tc.in)), 1<<20)
			after := heapAlloc()
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
			if after > before+(4<<20) {
				t.Errorf("header rejection allocated %d bytes", after-before)
			}
		})
	}
}

// A declared length just under the limit followed by silence: the body is
// never buffered beyond what arrived and the first-packet deadline ends
// the connection with a Notice of Disconnection.
func TestAudit14_A3_DeclaredLengthThenStall(t *testing.T) {
	ts := start(t, Config{Profile: "p", FirstPacketTimeout: 300 * time.Millisecond, IdleTimeout: 400 * time.Millisecond})
	t.Run("first-packet", func(t *testing.T) {
		raw, rd := rawConn(t, ts.addr)
		// 0x30 0x83 0x0f 0xff 0xfa = 1 MiB - 6 - 5 → total exactly under the default limit.
		if _, err := raw.Write([]byte{0x30, 0x83, 0x0f, 0xff, 0xf0, 0x02, 0x01, 0x01}); err != nil {
			t.Fatal(err)
		}
		startT := time.Now()
		m := readRaw(t, rd)
		if resultCode(t, m) != ldap.LDAPResultUnavailable || time.Since(startT) > 2*time.Second {
			t.Errorf("stalled body → %+v after %v", m, time.Since(startT))
		}
		if err := closed(rd); err != nil {
			t.Errorf("connection not closed: %v", err)
		}
	})
	t.Run("after-first-message", func(t *testing.T) {
		raw, rd := rawConn(t, ts.addr)
		_, _ = raw.Write(bindPacket(1, 3, "ok", "pw"))
		if m := readRaw(t, rd); resultCode(t, m) != 0 {
			t.Fatalf("bind → %d", resultCode(t, m))
		}
		if _, err := raw.Write([]byte{0x30, 0x83, 0x0f, 0xff, 0xf0, 0x02}); err != nil {
			t.Fatal(err)
		}
		startT := time.Now()
		m := readRaw(t, rd)
		if resultCode(t, m) != ldap.LDAPResultUnavailable || time.Since(startT) > 2*time.Second {
			t.Errorf("stalled second message → %+v after %v", m, time.Since(startT))
		}
	})
	t.Run("slowloris-1-byte", func(t *testing.T) {
		raw, rd := rawConn(t, ts.addr)
		pkt := bindPacket(1, 3, "ok", "pw")
		startT := time.Now()
		var done atomic.Bool
		go func() {
			for _, b := range pkt {
				if done.Load() {
					return
				}
				if _, err := raw.Write([]byte{b}); err != nil {
					return
				}
				time.Sleep(60 * time.Millisecond) // whole packet would take > 1 s
			}
		}()
		m := readRaw(t, rd)
		done.Store(true)
		if m.ID != 0 || resultCode(t, m) != ldap.LDAPResultUnavailable {
			t.Errorf("slowloris → %+v", m)
		}
		if el := time.Since(startT); el > 1500*time.Millisecond {
			t.Errorf("deadline is not absolute per message: took %v", el)
		}
	})
}

// An oversize header closes the connection with rate_limited{reason=oversize}
// and the global slot is released.
func TestAudit14_A3_OversizeHeaderClosesConnection(t *testing.T) {
	global := NewLimiter(5)
	ts := start(t, Config{Profile: "p", MaxRequestBytes: 4096, Global: global})
	raw, rd := rawConn(t, ts.addr)
	if _, err := raw.Write([]byte{0x30, 0x82, 0x10, 0x00}); err != nil { // 4096 + 4 > 4096
		t.Fatal(err)
	}
	m := readRaw(t, rd)
	if resultCode(t, m) != ldap.LDAPResultProtocolError {
		t.Errorf("oversize → %+v", m)
	}
	if err := closed(rd); err != nil {
		t.Errorf("not closed: %v", err)
	}
	waitFor(t, func() bool {
		evs := ts.ev.find(events.RateLimited)
		return len(evs) == 1 && evs[0].Reason == "oversize" && evs[0].Data["target"] == "conn"
	})
	waitFor(t, func() bool { return global.Count() == 0 })
}

// ---------------------------------------------------------------- 2. limits

func TestAudit14_A3_PerIP33rdRefused(t *testing.T) {
	perIP := NewIPLimiter(32)
	ts := start(t, Config{Profile: "p", PerIP: perIP})
	var conns []net.Conn
	for i := 0; i < 32; i++ {
		raw, _ := rawConn(t, ts.addr)
		conns = append(conns, raw)
	}
	waitFor(t, func() bool { return perIP.Count("127.0.0.1") == 32 })
	raw, rd := rawConn(t, ts.addr)
	_, _ = raw.Write(bindPacket(1, 3, "ok", "pw"))
	if err := closed(rd); err != nil {
		t.Errorf("33rd connection should be closed: %v", err)
	}
	evs := ts.ev.find(events.RateLimited)
	if len(evs) != 1 || evs[0].Reason != "conn_limit_ip" || evs[0].Data["limit"] != 32 {
		t.Errorf("rate_limited = %+v", evs)
	}
	for _, c := range conns {
		_ = c.Close()
	}
	waitFor(t, func() bool { return perIP.Count("127.0.0.1") == 0 })
}

func TestAudit14_A3_SilentConnectionClosedAfterFirstPacketDeadline(t *testing.T) {
	ts := start(t, Config{Profile: "p", FirstPacketTimeout: 200 * time.Millisecond})
	_, rd := rawConn(t, ts.addr)
	startT := time.Now()
	m := readRaw(t, rd)
	if m.ID != 0 || resultCode(t, m) != ldap.LDAPResultUnavailable {
		t.Errorf("notice = %+v", m)
	}
	if el := time.Since(startT); el > 1500*time.Millisecond {
		t.Errorf("closed after %v", el)
	}
	if err := closed(rd); err != nil {
		t.Errorf("not closed: %v", err)
	}
	waitFor(t, func() bool { return ts.ConnCount() == 0 })
}

// A flood of connections (the per-IP limit is irrelevant here: no PerIP)
// never exceeds the global limit; every excess connection is closed and
// reported.
func TestAudit14_A3_GlobalFloodCapped(t *testing.T) {
	global := NewLimiter(8)
	ts := start(t, Config{Profile: "p", Global: global})
	var peak atomic.Int64
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if n := int64(global.Count()); n > peak.Load() {
				peak.Store(n)
			}
			time.Sleep(200 * time.Microsecond)
		}
	}()
	var wg sync.WaitGroup
	var served, refused atomic.Int64
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			raw, err := net.DialTimeout("tcp", ts.addr, 2*time.Second)
			if err != nil {
				return
			}
			defer raw.Close()
			_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
			rd := bufio.NewReader(raw)
			_, _ = raw.Write(bindPacket(1, 3, "ok", "pw"))
			rawMsg, err := readMessage(rd, 0)
			if err != nil {
				refused.Add(1)
				return
			}
			m, err := parseMessage(rawMsg)
			if err == nil && m.Op == ldap.ApplicationBindResponse {
				served.Add(1)
				time.Sleep(300 * time.Millisecond) // hold the slot
			}
		}()
	}
	wg.Wait()
	close(stop)
	t.Logf("served=%d refused=%d peak=%d", served.Load(), refused.Load(), peak.Load())
	if peak.Load() > 8 {
		t.Errorf("global count peaked at %d > 8", peak.Load())
	}
	if served.Load()+refused.Load() != 40 || refused.Load() == 0 {
		t.Errorf("served=%d refused=%d", served.Load(), refused.Load())
	}
	for _, e := range ts.ev.find(events.RateLimited) {
		if e.Reason != "conn_limit_global" {
			t.Errorf("unexpected reason %q", e.Reason)
		}
	}
	waitFor(t, func() bool { return global.Count() == 0 })
}

// On ldaps the TLS handshake happens on the first read: a peer that never
// sends a ClientHello is counted at accept and cut by the first-packet
// deadline, so a handshake slowloris cannot hold sockets beyond that.
func TestAudit14_A3_TLSHandshakeSlowloris(t *testing.T) {
	global := NewLimiter(3)
	ts := start(t, Config{Profile: "p", Transport: TransportLDAPS, Global: global, FirstPacketTimeout: 300 * time.Millisecond})
	var rds []*bufio.Reader
	for i := 0; i < 3; i++ {
		_, rd := rawConn(t, ts.addr)
		rds = append(rds, rd)
	}
	waitFor(t, func() bool { return global.Count() == 3 }) // counted before any handshake
	// A 4th is refused while the three idle handshakes are pending.
	raw4, rd4 := rawConn(t, ts.addr)
	_, _ = raw4.Write([]byte{0x16, 0x03, 0x01})
	if err := closed(rd4); err != nil {
		t.Errorf("4th connection should be refused: %v", err)
	}
	startT := time.Now()
	for _, rd := range rds {
		if err := closed(rd); err != nil {
			t.Errorf("idle handshake not closed: %v", err)
		}
	}
	if el := time.Since(startT); el > 2*time.Second {
		t.Errorf("handshake slowloris survived %v", el)
	}
	waitFor(t, func() bool { return global.Count() == 0 })
	// Partial ClientHello drip: still bounded by the same deadline.
	raw, rd := rawConn(t, ts.addr)
	_, _ = raw.Write([]byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01})
	startT = time.Now()
	if err := closed(rd); err != nil {
		t.Errorf("partial hello not closed: %v", err)
	}
	if el := time.Since(startT); el > 2*time.Second {
		t.Errorf("partial hello survived %v", el)
	}
}

// ---------------------------------------------------------------- 3. StartTLS

// Plaintext bytes pipelined after the StartTLS request must never be
// executed (STARTTLS command injection, CVE-2021-33515 class).
func TestAudit14_A3_StartTLSPipelinedPDUNotExecuted(t *testing.T) {
	for _, tc := range []struct {
		name string
		pdu  []byte
	}{{"bind", bindPacket(2, 3, "injected", "pw")}, {"search", searchPacket(2)}} {
		t.Run(tc.name, func(t *testing.T) {
			ts := start(t, Config{Profile: "p", Transport: TransportLDAPStartTLS, HandshakeTimeout: 500 * time.Millisecond})
			raw, rd := rawConn(t, ts.addr)
			if _, err := raw.Write(append(append([]byte{}, extendedPacket(1, oidStartTLS)...), tc.pdu...)); err != nil {
				t.Fatal(err)
			}
			m := readRaw(t, rd)
			if m.ID != 1 || m.Op != ldap.ApplicationExtendedResponse {
				t.Fatalf("response = %+v", m)
			}
			// The server must close rather than serve the pipelined PDU, in
			// clear text or as the first "protected" message.
			if resultCode(t, m) == ldap.LDAPResultSuccess {
				tc := tls.Client(raw, ts.clientTLS())
				_ = tc.SetDeadline(time.Now().Add(2 * time.Second))
				if err := tc.Handshake(); err == nil {
					// If the handshake succeeded, make sure nothing was executed.
					_, _ = tc.Write(bindPacket(3, 3, "ok", "pw"))
					_ = readRaw(t, bufio.NewReader(tc))
				}
			}
			ts.h.mu.Lock()
			binds, searches := ts.h.binds, len(ts.h.searches)
			ts.h.mu.Unlock()
			for _, b := range binds {
				if b == "injected" {
					t.Fatalf("pipelined plaintext bind was executed: %v", binds)
				}
			}
			if searches != 0 {
				t.Fatalf("pipelined plaintext search was executed")
			}
		})
	}
}

// Plaintext that arrives after the StartTLS response but before the
// ClientHello is fed to the TLS handshake and fails it; never executed.
func TestAudit14_A3_StartTLSPlaintextAfterResponse(t *testing.T) {
	ts := start(t, Config{Profile: "p", Transport: TransportLDAPStartTLS, HandshakeTimeout: 500 * time.Millisecond})
	raw, rd := rawConn(t, ts.addr)
	_, _ = raw.Write(extendedPacket(1, oidStartTLS))
	if m := readRaw(t, rd); resultCode(t, m) != 0 {
		t.Fatalf("StartTLS → %d", resultCode(t, m))
	}
	_, _ = raw.Write(bindPacket(2, 3, "injected", "pw"))
	if err := closed(rd); err != nil {
		t.Errorf("connection should close after a failed handshake: %v", err)
	}
	ts.h.mu.Lock()
	defer ts.h.mu.Unlock()
	if len(ts.h.binds) != 0 {
		t.Errorf("plaintext bind executed: %v", ts.h.binds)
	}
}

// StartTLS on an ldaps listener and twice on a connection are refused; the
// bound identity survives StartTLS (RFC 4513 §3.1.1 allows either; the
// choice is not recorded in docs/DECISIONS.md — Info).
func TestAudit14_A3_StartTLSStates(t *testing.T) {
	t.Run("ldaps", func(t *testing.T) {
		ts := start(t, Config{Profile: "p", Transport: TransportLDAPS})
		raw, _ := rawConn(t, ts.addr)
		tc := tls.Client(raw, ts.clientTLS())
		if err := tc.Handshake(); err != nil {
			t.Fatal(err)
		}
		rd := bufio.NewReader(tc)
		_, _ = tc.Write(extendedPacket(1, oidStartTLS))
		m := readRaw(t, rd)
		if code := resultCode(t, m); code != ldap.LDAPResultUnwillingToPerform && code != ldap.LDAPResultOperationsError {
			t.Errorf("StartTLS over ldaps → %d", code)
		}
		// The connection stays usable (no downgrade, no crash).
		_, _ = tc.Write(bindPacket(2, 3, "ok", "pw"))
		if m := readRaw(t, rd); resultCode(t, m) != 0 {
			t.Errorf("bind after refused StartTLS → %d", resultCode(t, m))
		}
	})
	t.Run("bound-identity-kept", func(t *testing.T) {
		ts := start(t, Config{Profile: "p", Transport: TransportLDAPStartTLS})
		seen := make(chan Bound, 1)
		ts.h.entries = nil
		c := ts.dial(t)
		if err := c.Bind("ok", "pw"); err != nil {
			t.Fatal(err)
		}
		if err := c.StartTLS(ts.clientTLS()); err != nil {
			t.Fatal(err)
		}
		// Observe the bound state of the server-side connection.
		ts.mu.Lock()
		for sc := range ts.conns {
			seen <- sc.Bound()
		}
		ts.mu.Unlock()
		b := <-seen
		t.Logf("bound after StartTLS: kind=%s name=%q (identity kept; RFC 4513 §3.1.1 MAY reset)", b.Kind, b.Name)
	})
}

// ---------------------------------------------------------------- 4. PROXY

func TestAudit14_A3_ProxyHeaderSplitAcrossSegments(t *testing.T) {
	ts, h := proxyServer(t, []string{"127.0.0.1"}, nil)
	raw, rd := rawConn(t, ts.addr)
	hdr := []byte("PROXY TCP4 203.0.113.9 127.0.0.1 51234 389\r\n")
	for i := 0; i < len(hdr); i += 7 {
		end := min(i+7, len(hdr))
		if _, err := raw.Write(hdr[i:end]); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, _ = raw.Write(bindPacket(1, 3, "ok", "pw"))
	if m := readRaw(t, rd); resultCode(t, m) != 0 {
		t.Fatalf("bind → %d", resultCode(t, m))
	}
	if ip, _ := h.last(t); ip != "203.0.113.9" {
		t.Errorf("client ip %q", ip)
	}
	// v2 split in the middle of the 16-byte fixed header and of the body.
	raw2, rd2 := rawConn(t, ts.addr)
	v2 := proxyV2(1, 0x11, "198.51.100.5", "10.0.0.1", 4000, 389, nil)
	_, _ = raw2.Write(v2[:9])
	time.Sleep(20 * time.Millisecond)
	_, _ = raw2.Write(v2[9:20])
	time.Sleep(20 * time.Millisecond)
	_, _ = raw2.Write(v2[20:])
	_, _ = raw2.Write(bindPacket(1, 3, "ok", "pw"))
	if m := readRaw(t, rd2); resultCode(t, m) != 0 {
		t.Fatalf("v2 split bind → %d", resultCode(t, m))
	}
	if ip, _ := h.last(t); ip != "198.51.100.5" {
		t.Errorf("v2 client ip %q", ip)
	}
}

// Malformed headers from a trusted proxy close the connection, without
// blocking beyond the first-packet deadline.
func TestAudit14_A3_ProxyMalformedHeaders(t *testing.T) {
	ts, _ := proxyServer(t, []string{"127.0.0.1"}, func(c *Config) { c.FirstPacketTimeout = 500 * time.Millisecond })
	tooLongV1 := []byte("PROXY TCP4 " + strings.Repeat("1", 120)) // no CRLF, > 107 bytes
	oversizeV2 := append([]byte{}, proxyV2Sig...)
	oversizeV2 = append(oversizeV2, 0x21, 0x11)
	oversizeV2 = binary.BigEndian.AppendUint16(oversizeV2, 4097)
	hugeTLV := proxyV2(1, 0x11, "198.51.100.5", "10.0.0.1", 1, 2, bytes.Repeat([]byte{0xee}, 4000)) // body 4012 ≤ 4096 with garbage TLVs: accepted
	cases := map[string][]byte{
		"v1-no-crlf-120":  tooLongV1,
		"v2-len-4097":     oversizeV2,
		"v2-af-unix":      proxyV2(1, 0x31, "", "", 0, 0, bytes.Repeat([]byte{0}, 216)),
		"v2-udp":          proxyV2(1, 0x12, "198.51.100.5", "10.0.0.1", 1, 2, nil),
		"v2-short-ipv4":   append(append(append([]byte{}, proxyV2Sig...), 0x21, 0x11), 0x00, 0x04, 1, 2, 3, 4),
		"v2-version-1":    func() []byte { b := proxyV2(1, 0x11, "198.51.100.5", "10.0.0.1", 1, 2, nil); b[12] = 0x11; return b }(),
		"v1-port-99999":   []byte("PROXY TCP4 203.0.113.9 127.0.0.1 99999 389\r\n"),
		"v1-family-mixed": []byte("PROXY TCP4 2001:db8::1 127.0.0.1 1 389\r\n"),
		"stall-5-bytes":   []byte("PROXY"),
		"no-header":       nil,
	}
	for name, hdr := range cases {
		t.Run(name, func(t *testing.T) {
			startT := time.Now()
			code := bindVia(t, ts.addr, hdr)
			if code != -1 {
				t.Errorf("accepted with bind code %d", code)
			}
			if el := time.Since(startT); el > 2*time.Second {
				t.Errorf("took %v", el)
			}
		})
	}
	t.Run("v2-garbage-tlv-accepted", func(t *testing.T) {
		if code := bindVia(t, ts.addr, hugeTLV); code != ldap.LDAPResultSuccess {
			t.Errorf("4000 bytes of TLV garbage within the 4096 bound should be ignored, got %d", code)
		}
	})
}

// A trusted proxy decides the client address: it may name a loopback or
// an allow_cidrs address and the connection is then served as that client
// with DirectSource=true (per-IP limit, ratelimit exemptions and the IDS
// all key on it). Documented trust boundary — a compromised proxy equals
// a client on any address. IPv4-mapped IPv6 is unmapped.
func TestAudit14_A3_ProxyTrustedNamesPrivilegedAddress(t *testing.T) {
	perIP := NewIPLimiter(1)
	ts, h := proxyServer(t, []string{"127.0.0.1"}, func(c *Config) { c.PerIP = perIP })
	for name, tc := range map[string]struct {
		hdr  []byte
		want string
	}{
		"loopback":    {[]byte("PROXY TCP4 127.0.0.1 127.0.0.1 1 389\r\n"), "127.0.0.1"},
		"v4-mapped":   {proxyV2(1, 0x21, "::ffff:10.1.2.3", "::ffff:10.0.0.1", 4000, 389, nil), "10.1.2.3"},
		"unspecified": {[]byte("PROXY TCP4 0.0.0.0 127.0.0.1 1 389\r\n"), "0.0.0.0"},
	} {
		t.Run(name, func(t *testing.T) {
			if code := bindVia(t, ts.addr, tc.hdr); code != ldap.LDAPResultSuccess {
				t.Fatalf("bind = %d", code)
			}
			ip, direct := h.last(t)
			if ip != tc.want || !direct {
				t.Errorf("client %q direct %v, want %q true", ip, direct, tc.want)
			}
			waitFor(t, func() bool { return perIP.Count(tc.want) == 0 })
		})
	}
	// Two connections through the proxy claiming different clients are not
	// limited by the proxy's own address (per-IP limit 1 keyed on the header).
	raw1, rd1 := rawConn(t, ts.addr)
	_, _ = raw1.Write(append([]byte("PROXY TCP4 198.51.100.1 127.0.0.1 1 389\r\n"), bindPacket(1, 3, "ok", "pw")...))
	if m := readRaw(t, rd1); resultCode(t, m) != 0 {
		t.Fatalf("first via proxy → %d", resultCode(t, m))
	}
	raw2, rd2 := rawConn(t, ts.addr)
	_, _ = raw2.Write(append([]byte("PROXY TCP4 198.51.100.2 127.0.0.1 1 389\r\n"), bindPacket(1, 3, "ok", "pw")...))
	if m := readRaw(t, rd2); resultCode(t, m) != 0 {
		t.Fatalf("second via proxy → %d", resultCode(t, m))
	}
	// Same claimed client twice → the second is refused (limit 1).
	raw3, rd3 := rawConn(t, ts.addr)
	_, _ = raw3.Write(append([]byte("PROXY TCP4 198.51.100.1 127.0.0.1 2 389\r\n"), bindPacket(1, 3, "ok", "pw")...))
	if err := closed(rd3); err != nil {
		t.Errorf("per-IP limit on the header address not applied: %v", err)
	}
}

// A trusted proxy that connects and stalls holds a global slot only until
// the first-packet deadline.
func TestAudit14_A3_ProxyStallReleasesGlobal(t *testing.T) {
	global := NewLimiter(2)
	ts, _ := proxyServer(t, []string{"127.0.0.1"}, func(c *Config) { c.Global = global; c.FirstPacketTimeout = 300 * time.Millisecond })
	_, rd := rawConn(t, ts.addr)
	waitFor(t, func() bool { return global.Count() == 1 })
	startT := time.Now()
	if err := closed(rd); err != nil {
		t.Errorf("stalled proxy connection not closed: %v", err)
	}
	if el := time.Since(startT); el > 2*time.Second {
		t.Errorf("stall survived %v", el)
	}
	waitFor(t, func() bool { return global.Count() == 0 })
}

// ---------------------------------------------------------------- fuzz-like

// Random mutations of valid packets must never panic the parser (a quick
// in-process smoke; the real fuzz target is FuzzParseMessage).
func TestAudit14_A3_MutationSmoke(t *testing.T) {
	seeds := [][]byte{bindPacket(1, 3, "cn=x", "pw"), searchPacket(2), extendedPacket(3, oidStartTLS),
		envelope(4, ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchRequest, nil, ""), []ldap.Control{ldap.NewControlPaging(10)}).Bytes()}
	n := 0
	for _, s := range seeds {
		for i := 0; i < len(s); i++ {
			for _, v := range []byte{0x00, 0x80, 0xff, s[i] ^ 0x40} {
				d := append([]byte{}, s...)
				d[i] = v
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Errorf("panic on mutation %d/%d: %v", i, v, r)
						}
					}()
					m, err := parseRaw(d, 1<<16)
					if err != nil {
						return
					}
					switch m.Op {
					case ldap.ApplicationBindRequest:
						_, _ = parseBind(m.Body)
					case ldap.ApplicationSearchRequest:
						_, _ = parseSearch(m.Body)
					case ldap.ApplicationExtendedRequest:
						_, _ = extendedName(m.Body)
					}
					n++
				}()
			}
		}
	}
	t.Logf("%d mutated packets decoded without panic", n)
}

// Sanity: the helpers above produce what the server accepts.
func TestAudit14_A3_HelpersRoundTrip(t *testing.T) {
	ts := start(t, Config{Profile: "p"})
	raw, rd := rawConn(t, ts.addr)
	_, _ = raw.Write(searchWith(1, nestedAndFilter(3), "cn"))
	m := readUntil(t, rd, ldap.ApplicationSearchResultDone)
	if resultCode(t, m) != 0 {
		t.Fatalf("search → %d", resultCode(t, m))
	}
	ts.h.mu.Lock()
	defer ts.h.mu.Unlock()
	if len(ts.h.searches) != 1 || ts.h.searches[0].Filter != "(&(&(&(cn=x))))" {
		t.Errorf("filter = %q", ts.h.searches[0].Filter)
	}
	_ = context.Background
	_ = io.EOF
	_ = fmt.Sprint
}
