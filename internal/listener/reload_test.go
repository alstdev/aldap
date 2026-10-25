package listener

import (
	"bufio"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// searchPacket encodes a subtree search for (cn=*) under dc=x.
func searchPacket(id int64) []byte {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchRequest, nil, "Search")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "dc=x", "base"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 2, "scope"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "deref"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "size"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "time"))
	op.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "typesOnly"))
	filter, _ := ldap.CompileFilter("(cn=*)")
	op.AppendChild(filter)
	op.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attrs"))
	return envelope(id, op, nil).Bytes()
}

// diagnostic returns the diagnostic message of an LDAPResult.
func diagnostic(t *testing.T, m *message) string {
	t.Helper()
	if len(m.Body.Children) < 3 {
		t.Fatalf("no diagnostic in %+v", m)
	}
	s, _ := m.Body.Children[2].Value.(string)
	return s
}

// readUntil reads messages until one with application tag op arrives.
func readUntil(t *testing.T, rd *bufio.Reader, op ber.Tag) *message {
	t.Helper()
	for range 20 {
		if m := readRaw(t, rd); m.Op == op {
			return m
		}
	}
	t.Fatalf("no message with op %d", op)
	return nil
}

func searchCount(h *fakeHandler) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.searches)
}

func TestReconfigure_InFlightKeepsOldHandler(t *testing.T) {
	oldH := &fakeHandler{block: make(chan struct{}), entries: []Entry{{DN: "cn=old,dc=x"}}}
	ts := start(t, Config{Profile: "p", Handler: oldH})
	conn, rd := rawConn(t, ts.addr)
	if _, err := conn.Write(searchPacket(1)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return searchCount(oldH) == 1 })

	newH := &fakeHandler{entries: []Entry{{DN: "cn=new,dc=x"}}}
	wait, err := ts.Reconfigure(Config{Profile: "p", Transport: TransportLDAP, Handler: newH, Events: ts.ev})
	if err != nil {
		t.Fatal(err)
	}
	// The old request is still running: its generation is not drained.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	if err := wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("wait with a request in flight = %v", err)
	}
	cancel()
	close(oldH.block)
	if m := readRaw(t, rd); m.Op != ldap.ApplicationSearchResultEntry || m.Body.Children[0].Data.String() != "cn=old,dc=x" {
		t.Errorf("in-flight search answered by %+v", m)
	}
	if m := readUntil(t, rd, ldap.ApplicationSearchResultDone); resultCode(t, m) != ldap.LDAPResultSuccess {
		t.Errorf("in-flight done = %d", resultCode(t, m))
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := wait(ctx); err != nil {
		t.Errorf("wait after the request = %v", err)
	}
	// The next request on the same connection uses the new handler.
	if _, err := conn.Write(searchPacket(2)); err != nil {
		t.Fatal(err)
	}
	if m := readRaw(t, rd); m.Op != ldap.ApplicationSearchResultEntry || m.Body.Children[0].Data.String() != "cn=new,dc=x" {
		t.Errorf("next search answered by %+v", m)
	}
	readUntil(t, rd, ldap.ApplicationSearchResultDone)
	if searchCount(oldH) != 1 || searchCount(newH) != 1 {
		t.Errorf("searches old=%d new=%d", searchCount(oldH), searchCount(newH))
	}
	if ts.ConnCount() != 1 {
		t.Errorf("connection was cut: %d", ts.ConnCount())
	}
}

func TestReconfigure_TransportChangeEndsOldConnections(t *testing.T) {
	ts := start(t, Config{Profile: "p"})
	conn, rd := rawConn(t, ts.addr)
	if _, err := conn.Write(bindPacket(1, 3, "ok", "pw")); err != nil {
		t.Fatal(err)
	}
	readRaw(t, rd)
	tlsCfg, _ := serverTLS(t)
	if _, err := ts.Reconfigure(Config{Profile: "p", Transport: TransportLDAPS, TLS: tlsCfg, Handler: ts.h, Events: ts.ev}); err != nil {
		t.Fatal(err)
	}
	// The idle plain connection is ended with a notice at once.
	m := readRaw(t, rd)
	if m.ID != 0 || resultCode(t, m) != ldap.LDAPResultUnavailable || diagnostic(t, m) != reasonReconfigured {
		t.Errorf("notice = %+v", m)
	}
	if err := closed(rd); err != nil {
		t.Errorf("plain connection kept on an ldaps listener: %v", err)
	}
	// New connections speak the new transport.
	c, err := ldap.DialURL("ldaps://"+ts.addr, ldap.DialWithTLSConfig(ts.clientTLS()))
	if err != nil {
		t.Fatalf("ldaps after reconfigure: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Bind("ok", "pw"); err != nil {
		t.Errorf("bind over ldaps: %v", err)
	}
	if !ts.RequiresTLS() || ts.OffersStartTLS() {
		t.Error("transport flags after reconfigure")
	}
}

func TestReconfigure_Errors(t *testing.T) {
	ts := start(t, Config{Profile: "p"})
	if _, err := ts.Reconfigure(Config{Profile: "p", Transport: TransportLDAP}); err == nil {
		t.Error("handler required")
	}
	if err := Check(Config{Profile: "p", Transport: TransportLDAPS, Handler: ts.h}); err == nil {
		t.Error("Check: ldaps needs TLS")
	}
	if err := Check(Config{Profile: "p", Transport: TransportLDAP, Handler: ts.h}); err != nil {
		t.Errorf("Check: %v", err)
	}
	ts.Close()
	if _, err := ts.Reconfigure(Config{Profile: "p", Transport: TransportLDAP, Handler: ts.h}); !errors.Is(err, ErrServerClosed) {
		t.Errorf("reconfigure after close = %v", err)
	}
}

// TestShutdown_DrainsActiveRequest: the request in flight is answered,
// then the connection gets the notice and is closed; an idle connection
// is ended at once; Shutdown returns before its deadline.
func TestShutdown_DrainsActiveRequest(t *testing.T) {
	h := &fakeHandler{block: make(chan struct{}), entries: []Entry{{DN: "cn=a,dc=x"}}}
	ts := start(t, Config{Profile: "p", Handler: h})
	idle, idleRd := rawConn(t, ts.addr)
	if _, err := idle.Write(bindPacket(1, 3, "ok", "pw")); err != nil {
		t.Fatal(err)
	}
	readRaw(t, idleRd)
	busy, busyRd := rawConn(t, ts.addr)
	if _, err := busy.Write(searchPacket(5)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return searchCount(h) == 1 })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res := make(chan error, 1)
	go func() { res <- ts.Shutdown(ctx) }()
	if m := readRaw(t, idleRd); resultCode(t, m) != ldap.LDAPResultUnavailable || diagnostic(t, m) != reasonShutdown {
		t.Errorf("idle notice = %+v", m)
	}
	select {
	case err := <-res:
		t.Fatalf("Shutdown returned %v with a request in flight", err)
	case <-time.After(100 * time.Millisecond):
	}
	// New connections are refused while the drain runs.
	if c, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", ts.addr); err == nil {
		_ = c.Close()
		t.Error("listener still accepts during the drain")
	}
	close(h.block)
	if m := readRaw(t, busyRd); m.Op != ldap.ApplicationSearchResultEntry {
		t.Errorf("entry = %+v", m)
	}
	if m := readRaw(t, busyRd); m.Op != ldap.ApplicationSearchResultDone || m.ID != 5 || resultCode(t, m) != ldap.LDAPResultSuccess {
		t.Errorf("in-flight search done = %+v", m)
	}
	if m := readRaw(t, busyRd); m.ID != 0 || resultCode(t, m) != ldap.LDAPResultUnavailable {
		t.Errorf("busy notice = %+v", m)
	}
	if err := closed(busyRd); err != nil {
		t.Errorf("busy connection should be closed: %v", err)
	}
	if err := <-res; err != nil {
		t.Errorf("Shutdown = %v", err)
	}
	h.mu.Lock()
	ctxErr := h.ctxErr
	h.mu.Unlock()
	if ctxErr != nil {
		t.Errorf("drained request was canceled: %v", ctxErr)
	}
}
