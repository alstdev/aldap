package api

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/tlsutil"
)

func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	ca, err := tlsutil.NewCA(tlsutil.ECDSAP256, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c, err := ca.Issue(tlsutil.ParseSANs("127.0.0.1"), tlsutil.ECDSAP256, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return c, pool
}

// sseClient reads the id/event lines of an SSE response.
type sseClient struct {
	resp *http.Response
	ids  chan uint64
	ping chan struct{}
}

func openStream(t *testing.T, url, token string, hdr map[string]string) *sseClient {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req) //nolint:bodyclose // closed by sseClient.close
	if err != nil {
		t.Fatal(err)
	}
	c := &sseClient{resp: resp, ids: make(chan uint64, 10000), ping: make(chan struct{}, 100)}
	if resp.StatusCode != http.StatusOK {
		return c
	}
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "id: "):
				n, _ := strconv.ParseUint(strings.TrimPrefix(line, "id: "), 10, 64)
				c.ids <- n
			case line == ": ping":
				select {
				case c.ping <- struct{}{}:
				default:
				}
			}
		}
		close(c.ids)
	}()
	return c
}

func (c *sseClient) next(t *testing.T) uint64 {
	t.Helper()
	select {
	case id, ok := <-c.ids:
		if !ok {
			t.Fatal("stream closed")
		}
		return id
	case <-time.After(5 * time.Second):
		t.Fatal("no event within 5s")
	}
	return 0
}

func (c *sseClient) close() { _ = c.resp.Body.Close() }

func serveTCP(t *testing.T, e *env) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.s.ServeAPI(ln, nil); err != nil {
		t.Fatal(err)
	}
	return "http://" + ln.Addr().String()
}

func emitN(bus *events.Bus, n int) {
	for i := 0; i < n; i++ {
		bus.Emit(events.Event{Event: events.BindFail, Reason: "invalid_password", ClientIP: "192.0.2.1"})
	}
}

// TestStream_LastEventID is TESTING.md 36: the client drops at seq N and
// reconnects with Last-Event-ID: N; it receives N+1… from the buffer, then
// live events, without gaps or duplicates.
func TestStream_LastEventID(t *testing.T) {
	e := newEnv(t, nil)
	base := serveTCP(t, e)
	emitN(e.bus, 3)
	c := openStream(t, base+"/v1/events/stream", tokEvents, nil)
	if c.resp.StatusCode != http.StatusOK || c.resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("stream: %d %v", c.resp.StatusCode, c.resp.Header)
	}
	for want := uint64(1); want <= 3; want++ {
		if got := c.next(t); got != want {
			t.Fatalf("got %d, want %d", got, want)
		}
	}
	c.close()
	emitN(e.bus, 2) // seq 4, 5 while disconnected
	c = openStream(t, base+"/v1/events/stream", tokEvents, map[string]string{"Last-Event-ID": "3"})
	defer c.close()
	if a, b := c.next(t), c.next(t); a != 4 || b != 5 {
		t.Fatalf("resume: %d %d", a, b)
	}
	emitN(e.bus, 1)
	if got := c.next(t); got != 6 {
		t.Fatalf("live: %d", got)
	}
	// Heartbeat comments keep the connection alive.
	select {
	case <-c.ping:
	case <-time.After(5 * time.Second):
		t.Error("no heartbeat")
	}
}

func TestStream_SinceTypesErrorsAndGaps(t *testing.T) {
	e := newEnv(t, nil)
	base := serveTCP(t, e)
	emitN(e.bus, 2)
	e.bus.Emit(events.Event{Event: events.Lockdown, Data: map[string]any{"state": "on", "source": "api"}}) // seq 3
	c := openStream(t, base+"/v1/events/stream?since=1&types=lockdown", tokEvents, nil)
	if got := c.next(t); got != 3 {
		t.Fatalf("types filter: %d", got)
	}
	c.close()
	bad := openStream(t, base+"/v1/events/stream", tokEvents, map[string]string{"Last-Event-ID": "x"})
	if bad.resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad Last-Event-ID: %d", bad.resp.StatusCode)
	}
	bad.close()
	noScope := openStream(t, base+"/v1/events/stream", tokLocksR, nil)
	if noScope.resp.StatusCode != http.StatusForbidden {
		t.Errorf("stream scope: %d", noScope.resp.StatusCode)
	}
	noScope.close()
	// A subscription queue of 1 drops records under load; the stream
	// backfills them from the ring buffer by seq.
	e.s.Shutdown(context.Background())
	e = newEnvQueue(t, 1)
	base = serveTCP(t, e)
	emitN(e.bus, 3)
	c = openStream(t, base+"/v1/events/stream?since=3", tokEvents, nil)
	defer c.close()
	emitN(e.bus, 1)
	if got := c.next(t); got != 4 {
		t.Fatalf("first live: %d", got)
	}
	emitN(e.bus, 300)
	for want := uint64(5); want <= 304; want++ {
		if got := c.next(t); got != want {
			t.Fatalf("gap: got %d, want %d", got, want)
		}
	}
	// Shutdown ends open streams.
	done := make(chan struct{})
	go func() {
		e.s.Shutdown(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown blocked by the stream")
	}
}

func TestTransport_LoopbackOnlyWithoutTLS(t *testing.T) {
	if err := CheckTransport(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, false); err != nil {
		t.Error(err)
	}
	if err := CheckTransport(&net.TCPAddr{IP: net.IPv6loopback}, false); err != nil {
		t.Error(err)
	}
	for _, a := range []net.Addr{&net.TCPAddr{IP: net.IPv4zero}, &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1)}, &net.TCPAddr{IP: net.IPv6unspecified}} {
		if err := CheckTransport(a, false); err == nil {
			t.Errorf("%s without TLS accepted", a)
		}
		if err := CheckTransport(a, true); err != nil {
			t.Errorf("%s with TLS refused: %v", a, err)
		}
	}
	e := newEnv(t, nil)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.s.ServeAPI(ln, nil); err == nil {
		t.Fatal("wildcard listener without TLS accepted")
	}
	if _, err := ln.Accept(); err == nil {
		t.Error("refused listener left open")
	}
	ln2, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.s.ServeMetrics(ln2, nil); err == nil {
		t.Error("wildcard metrics listener without TLS accepted")
	}
	tcp, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.s.ServeIPC(tcp); err == nil {
		t.Error("TCP listener accepted as IPC")
	}
	// TLS listener: the handshake is served.
	ln3, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cert, pool := selfSigned(t)
	if err := e.s.ServeAPI(ln3, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}); err != nil {
		t.Fatal(err)
	}
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	hreq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, fmt.Sprintf("https://%s/healthz", ln3.Addr()), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cl.Do(hreq)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("tls healthz: %d", resp.StatusCode)
	}
}

// pipeListener reports the address of a go-winio named pipe listener.
type pipeListener struct{ net.Listener }

type pipeAddr string

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return string(a) }

func (l pipeListener) Addr() net.Addr { return pipeAddr(`\\.\pipe\aldap-test`) }

func TestServeIPC_NamedPipeAddress(t *testing.T) {
	e := newEnv(t, nil)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckTransport(pipeAddr("x"), false); err != nil {
		t.Errorf("pipe refused: %v", err)
	}
	if err := e.s.ServeIPC(pipeListener{ln}); err != nil {
		t.Fatalf("named pipe refused as IPC: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	e.s.Shutdown(ctx)
}
