package listener

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	ber "github.com/go-asn1-ber/asn1-ber"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/events"
)

// BindKind classifies an authenticated connection.
type BindKind string

// Bind kinds (SPEC §6 bind_ok.bind_kind).
const (
	BindAnonymous BindKind = "anonymous"
	BindClient    BindKind = "client"
	BindUser      BindKind = "user"
)

// Bound is the authorization state of a connection as set by the Handler.
type Bound struct {
	Kind BindKind
	// Name is the bind name as presented by the client ("" for anonymous).
	Name string
	// UpstreamDN is the real DN that authenticated (user binds), never shown to clients.
	UpstreamDN string
}

// Conn is the per-connection state a Handler sees.
type Conn struct {
	id        string
	remote    net.Addr
	direct    bool
	profile   string
	transport string
	opened    time.Time

	nc     net.Conn
	rd     *bufio.Reader
	wmu    sync.Mutex
	tls    atomic.Bool
	closed atomic.Bool

	mu    sync.Mutex
	bound Bound
	store map[string]any
	tlsFP string
	fp    string

	cancel context.CancelFunc
	// kicked holds the Notice of Disconnection text once the connection
	// must end after its current request (shutdown, reconfigured listener).
	kicked atomic.Pointer[string]

	// Session counters (SPEC §6 session_summary).
	bindsOK, bindsFail, searches, results, denied atomic.Int64
	bytesIn, bytesOut                             atomic.Int64
}

// Fingerprinter receives the fingerprint of a connection once its first
// packet is read (internal/ids implements it).
type Fingerprinter interface {
	Fingerprint(profile, ip, connID, fp string)
}

// HelloFingerprint hashes the negotiable parts of a TLS ClientHello
// (JA3-like: versions, cipher suites, curves, point formats, signature
// schemes and ALPN) into 16 hex characters.
func HelloFingerprint(h *tls.ClientHelloInfo) string {
	var b strings.Builder
	write := func(prefix string, vals []uint16) {
		b.WriteString(prefix)
		for i, v := range vals {
			if i > 0 {
				b.WriteByte('-')
			}
			b.WriteString(strconv.Itoa(int(v)))
		}
		b.WriteByte(';')
	}
	write("v:", h.SupportedVersions)
	write("c:", h.CipherSuites)
	curves := make([]uint16, len(h.SupportedCurves))
	for i, c := range h.SupportedCurves {
		curves[i] = uint16(c)
	}
	write("e:", curves)
	points := make([]uint16, len(h.SupportedPoints))
	for i, p := range h.SupportedPoints {
		points[i] = uint16(p)
	}
	write("p:", points)
	sigs := make([]uint16, len(h.SignatureSchemes))
	for i, s := range h.SignatureSchemes {
		sigs[i] = uint16(s)
	}
	write("s:", sigs)
	b.WriteString("a:" + strings.Join(h.SupportedProtos, ","))
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:8])
}

func (c *Conn) setTLSFingerprint(fp string) {
	c.mu.Lock()
	c.tlsFP = fp
	c.mu.Unlock()
}

// Fingerprint returns the connection fingerprint ("" before the first packet).
func (c *Conn) Fingerprint() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fp
}

// firstPacketFingerprint combines the TLS hash with the LDAP first packet:
// operation, LDAP version for binds, number of controls and a size bucket.
func (c *Conn) firstPacketFingerprint(m *message, size int) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	bucket := 0
	for n := size; n > 16; n >>= 1 {
		bucket++
	}
	var ver int64
	if m.Op == ldap.ApplicationBindRequest {
		if req, err := parseBind(m.Body); err == nil {
			ver = req.Version
			wipe(req.Password)
		}
	}
	c.fp = fmt.Sprintf("tls:%s|ldap:%d/%d/%d/%d", orDash(c.tlsFP), m.Op, ver, len(m.Controls), bucket)
	return c.fp
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// NewConn builds a detached connection record (no socket) for handlers
// that are driven outside the listener: `aldap check --as-client`, the
// profile test API and handler tests. Writes through it are not possible.
func NewConn(id, profile string, remote net.Addr) *Conn {
	return &Conn{id: id, profile: profile, remote: remote, opened: time.Now()}
}

// ID returns the connection id used in events ("c-00000001").
func (c *Conn) ID() string { return c.id }

// Profile returns the profile name of the listener.
func (c *Conn) Profile() string { return c.profile }

// RemoteAddr returns the client address (see ClientIP).
func (c *Conn) RemoteAddr() net.Addr { return c.remote }

// DirectSource reports whether the client address is known to be the
// client's own: the connection came through a socket inherited from systemd
// or its address was taken from a trusted PROXY protocol header. The
// masked-address detector skips such connections.
func (c *Conn) DirectSource() bool { return c.direct }

// ClientIP returns the client IP as text ("" when unknown): the peer, or
// the source of a trusted PROXY protocol header.
func (c *Conn) ClientIP() string {
	ip, _ := splitHostPort(c.remote)
	return ip
}

// ClientPort returns the peer port (0 when unknown).
func (c *Conn) ClientPort() int {
	_, port := splitHostPort(c.remote)
	return port
}

func splitHostPort(a net.Addr) (string, int) {
	if a == nil {
		return "", 0
	}
	if ta, ok := a.(*net.TCPAddr); ok {
		return ta.IP.String(), ta.Port
	}
	h, p, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String(), 0
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return h, 0
	}
	return h, port
}

// TLS reports whether the connection is encrypted (ldaps or after StartTLS).
func (c *Conn) TLS() bool { return c.tls.Load() }

// Bound returns the current authorization state.
func (c *Conn) Bound() Bound {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bound
}

// SetBound records the authorization state after a Bind.
func (c *Conn) SetBound(b Bound) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bound = b
}

// Store keeps a per-connection value (paged results state); nil deletes.
func (c *Conn) Store(key string, v any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if v == nil {
		delete(c.store, key)
		return
	}
	if c.store == nil {
		c.store = map[string]any{}
	}
	c.store[key] = v
}

// Load returns a value kept with Store.
func (c *Conn) Load(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.store[key]
	return v, ok
}

// Event pre-fills the connection fields of an event.
func (c *Conn) Event(kind, level string) events.Event {
	return events.Event{Event: kind, Level: level, Profile: c.profile, ConnID: c.id,
		ClientIP: c.ClientIP(), ClientPort: c.ClientPort(), TLS: events.Bool(c.TLS()), Account: c.Bound().Name}
}

// write sends one encoded message; writes are serialized per connection.
func (c *Conn) write(b []byte, timeout time.Duration) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if timeout > 0 {
		if err := c.nc.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
	}
	n, err := c.nc.Write(b)
	c.bytesOut.Add(int64(n))
	return err
}

// writeQuietly sends a message whose delivery is best effort (notices,
// final responses before a close); a failure is logged at debug level.
func (c *Conn) writeQuietly(log *slog.Logger, b []byte, timeout time.Duration) {
	if err := c.write(b, timeout); err != nil && log != nil {
		log.Debug("write failed", "conn_id", c.id, "err", err)
	}
}

// close shuts the transport down once.
func (c *Conn) close() {
	if c.closed.Swap(true) {
		return
	}
	if c.cancel != nil {
		c.cancel()
	}
	if err := c.nc.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		slog.Default().Debug("close failed", "conn_id", c.id, "err", err)
	}
}

// kick ends the connection once its current request is answered: the
// request loop sees the mark before its next read, and a read already
// waiting is woken by an expired deadline. The loop sets its own deadline
// before it checks the mark, so either it sees the mark or this deadline
// lands after its own. The deadline is set on its own goroutine: the
// transport is guarded by the write lock, which a slow response may hold
// for up to the write timeout, and a drain must not wait for it per
// connection.
func (c *Conn) kick(reason string) {
	if !c.kicked.CompareAndSwap(nil, &reason) {
		return
	}
	go func() {
		c.wmu.Lock()
		nc := c.nc
		c.wmu.Unlock()
		if err := nc.SetReadDeadline(time.Now()); err != nil && !errors.Is(err, net.ErrClosed) {
			slog.Default().Debug("set deadline failed", "conn_id", c.id, "err", err)
		}
	}()
}

// kickReason returns the notice text of a kicked connection ("" = not kicked).
func (c *Conn) kickReason() string {
	if r := c.kicked.Load(); r != nil {
		return *r
	}
	return ""
}

// entryWriter streams SearchResultEntry messages for one search.
type entryWriter struct {
	c         *Conn
	id        int64
	typesOnly bool
	timeout   time.Duration
	n         int
}

// Entry sends one entry to the client.
func (w *entryWriter) Entry(e Entry) error {
	w.n++
	return w.c.write(encodeEntry(w.id, e, w.typesOnly), w.timeout)
}

// EntryWriter streams search entries to the client.
type EntryWriter interface {
	Entry(Entry) error
}

// Handler serves the operations the proxy allows. Every other operation is
// refused by the listener itself. Handlers are called sequentially per
// connection; a Handler must not retain req.Password (the listener zeroes it).
type Handler interface {
	Bind(ctx context.Context, c *Conn, name string, password []byte) Result
	Search(ctx context.Context, c *Conn, req *SearchRequest, w EntryWriter) Result
}

// serve runs the request loop of one connection until it ends. Every
// request runs under the configuration current when it was read.
func (s *Server) serve(ctx context.Context, c *Conn) {
	defer c.close()
	defer func() {
		if r := recover(); r != nil {
			// Never print the recovered value: it may hold a request with a password.
			s.current().log.Error("panic while serving connection", "conn_id", c.id, "client_ip", c.ClientIP(), "panic", fmt.Sprintf("%T", r))
		}
	}()
	ctx, c.cancel = context.WithCancel(ctx)
	defer c.cancel()
	first := true
	for {
		g := s.current()
		timeout := g.cfg.IdleTimeout
		if first {
			timeout = g.cfg.FirstPacketTimeout
		}
		var deadline time.Time
		if timeout > 0 {
			deadline = time.Now().Add(timeout)
		}
		c.wmu.Lock()
		err := c.nc.SetReadDeadline(deadline)
		c.wmu.Unlock()
		if err != nil {
			return
		}
		if reason := c.kickReason(); reason != "" {
			g.disconnect(c, reason)
			return
		}
		raw, err := readMessage(c.rd, g.cfg.MaxRequestBytes)
		if err != nil {
			if reason := c.kickReason(); reason != "" {
				g.disconnect(c, reason)
				return
			}
			g.readFailed(c, err)
			return
		}
		c.bytesIn.Add(int64(len(raw)))
		if !s.handle(ctx, c, raw, first) {
			return
		}
		first = false
	}
}

// handle parses and dispatches one request under the current
// configuration; it returns false when the connection must end.
func (s *Server) handle(ctx context.Context, c *Conn, raw []byte, first bool) bool {
	g := s.acquire()
	defer g.done()
	msg, err := parseMessage(raw)
	if err != nil {
		g.log.Debug("malformed request", "conn_id", c.id, "err", err)
		c.writeQuietly(g.log, encodeNotice(ldap.LDAPResultProtocolError, "malformed request"), g.cfg.WriteTimeout)
		return false
	}
	if first {
		fp := c.firstPacketFingerprint(msg, len(raw))
		if g.cfg.Fingerprints != nil {
			g.cfg.Fingerprints.Fingerprint(c.profile, c.ClientIP(), c.id, fp)
		}
	}
	if c.profile != g.cfg.Profile || c.transport != g.cfg.Transport {
		// Read just before a reconfiguration that changed what this
		// listener serves: never answer it under the new profile.
		g.disconnect(c, reasonReconfigured)
		return false
	}
	// The raw message and the decoded BER tree may hold a password; both
	// are zeroed once handled (SPEC §9), together with the copy the bind
	// handler wipes.
	defer wipeMessage(raw, msg)
	return g.dispatch(ctx, c, msg)
}

// wipeMessage zeroes the wire bytes of a message and every value buffer of
// its decoded BER tree.
func wipeMessage(raw []byte, m *message) {
	wipe(raw)
	if m != nil {
		wipePacket(m.Body)
	}
}

func wipePacket(p *ber.Packet) {
	if p == nil {
		return
	}
	if p.Data != nil {
		wipe(p.Data.Bytes())
	}
	for _, c := range p.Children {
		wipePacket(c)
	}
}

// disconnect sends the Notice of Disconnection (unavailable) of a kicked
// connection; the caller closes it.
func (g *generation) disconnect(c *Conn, reason string) {
	g.log.Debug("connection ended", "conn_id", c.id, "client_ip", c.ClientIP(), "reason", reason)
	c.writeQuietly(g.log, encodeNotice(ldap.LDAPResultUnavailable, reason), g.cfg.WriteTimeout)
}

// readFailed handles the end of the read loop: EOF is a normal close, a
// deadline is an idle timeout, an oversized or non-LDAP message is reported.
func (g *generation) readFailed(c *Conn, err error) {
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed), errors.Is(err, io.ErrUnexpectedEOF):
		return
	case errors.Is(err, os.ErrDeadlineExceeded):
		g.log.Debug("idle timeout", "conn_id", c.id, "client_ip", c.ClientIP())
		c.writeQuietly(g.log, encodeNotice(ldap.LDAPResultUnavailable, "idle timeout"), g.cfg.WriteTimeout)
	case errors.Is(err, ErrTooLarge):
		g.log.Warn("request too large, closing connection", "conn_id", c.id, "client_ip", c.ClientIP(), "err", err)
		ev := c.Event(events.RateLimited, events.LevelLow)
		ev.Reason = "oversize"
		ev.Data = map[string]any{"target": "conn", "key": c.ClientIP(), "limit": g.cfg.MaxRequestBytes}
		g.events.Emit(ev)
		c.writeQuietly(g.log, encodeNotice(ldap.LDAPResultProtocolError, "request too large"), g.cfg.WriteTimeout)
	case errors.Is(err, ErrNotLDAP), errors.Is(err, ErrMalformed):
		g.log.Debug("not an LDAP message", "conn_id", c.id, "client_ip", c.ClientIP(), "err", err)
	default:
		g.log.Debug("read failed", "conn_id", c.id, "err", err)
	}
}

// dispatch handles one message; it returns false when the connection must end.
func (g *generation) dispatch(ctx context.Context, c *Conn, m *message) bool {
	switch m.Op {
	case ldap.ApplicationUnbindRequest:
		return false
	case ldap.ApplicationAbandonRequest:
		// Requests are processed sequentially, so there is nothing in flight
		// to abandon; RFC 4511 §4.11 allows ignoring it.
		return true
	case ldap.ApplicationBindRequest:
		return g.handleBind(ctx, c, m)
	case ldap.ApplicationSearchRequest:
		return g.handleSearch(ctx, c, m)
	case ldap.ApplicationExtendedRequest:
		return g.handleExtended(ctx, c, m)
	case ldap.ApplicationModifyRequest, ldap.ApplicationAddRequest, ldap.ApplicationDelRequest,
		ldap.ApplicationModifyDNRequest, ldap.ApplicationCompareRequest:
		return g.deny(c, m, "")
	default:
		c.writeQuietly(g.log, encodeNotice(ldap.LDAPResultProtocolError, "unknown protocol operation"), g.cfg.WriteTimeout)
		return false
	}
}

// deny refuses a write, compare or extended operation (SPEC §4.2 and
// docs/DECISIONS.md): compare → compareFalse, the rest → unwillingToPerform;
// every refusal is an op_denied event.
func (g *generation) deny(c *Conn, m *message, oid string) bool {
	app, _ := responseTag(m.Op)
	op := deniedOp(m.Op)
	code := ldap.LDAPResultUnwillingToPerform
	if m.Op == ldap.ApplicationCompareRequest {
		code = ldap.LDAPResultCompareFalse
	}
	c.denied.Add(1)
	ev := c.Event(events.OpDenied, events.LevelMedium)
	ev.Data = map[string]any{"op": op}
	if oid != "" {
		ev.Data["oid"] = oid
	}
	g.events.Emit(ev)
	g.log.Info("operation denied", "conn_id", c.id, "client_ip", c.ClientIP(), "op", op, "oid", oid)
	var b []byte
	if m.Op == ldap.ApplicationExtendedRequest {
		b = encodeExtended(m.ID, Result{Code: code}, "")
	} else {
		b = encodeResult(m.ID, app, Result{Code: code})
	}
	return c.write(b, g.cfg.WriteTimeout) == nil
}

func (g *generation) handleBind(ctx context.Context, c *Conn, m *message) bool {
	req, err := parseBind(m.Body)
	if err != nil {
		c.writeQuietly(g.log, encodeNotice(ldap.LDAPResultProtocolError, "malformed bind request"), g.cfg.WriteTimeout)
		return false
	}
	defer wipe(req.Password)
	var res Result
	switch {
	case req.Version != ldapVersion3:
		res = Result{Code: ldap.LDAPResultProtocolError, Diagnostic: "only LDAPv3 is supported"}
	case req.SASL:
		res = Result{Code: ldap.LDAPResultAuthMethodNotSupported, Diagnostic: "only simple bind is supported"}
	case g.requireTLS && !c.TLS():
		res = Result{Code: ldap.LDAPResultConfidentialityRequired, Diagnostic: "StartTLS required"}
	default:
		// A new bind resets the authorization state (RFC 4511 §4.2.1).
		c.SetBound(Bound{Kind: BindAnonymous})
		res = g.cfg.Handler.Bind(ctx, c, req.Name, req.Password)
	}
	if res.Code == ldap.LDAPResultSuccess {
		c.bindsOK.Add(1)
	} else {
		c.bindsFail.Add(1)
	}
	return c.write(encodeResult(m.ID, ldap.ApplicationBindResponse, res), g.cfg.WriteTimeout) == nil
}

// wipe zeroes a password buffer (SPEC §9).
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (g *generation) handleSearch(ctx context.Context, c *Conn, m *message) bool {
	req, err := parseSearch(m.Body)
	if err != nil {
		c.writeQuietly(g.log, encodeNotice(ldap.LDAPResultProtocolError, "malformed search request"), g.cfg.WriteTimeout)
		return false
	}
	req.Controls = m.Controls
	var res Result
	rootDSE := req.Base == "" && req.Scope == ScopeBase
	if g.requireTLS && !c.TLS() && !rootDSE {
		// The root DSE stays readable so clients can discover StartTLS.
		res = Result{Code: ldap.LDAPResultConfidentialityRequired, Diagnostic: "StartTLS required"}
	} else {
		w := &entryWriter{c: c, id: m.ID, typesOnly: req.TypesOnly, timeout: g.cfg.WriteTimeout}
		res = g.cfg.Handler.Search(ctx, c, req, w)
		c.results.Add(int64(w.n))
	}
	c.searches.Add(1)
	return c.write(encodeResult(m.ID, ldap.ApplicationSearchResultDone, res), g.cfg.WriteTimeout) == nil
}

func (g *generation) handleExtended(ctx context.Context, c *Conn, m *message) bool {
	name, err := extendedName(m.Body)
	if err != nil {
		c.writeQuietly(g.log, encodeNotice(ldap.LDAPResultProtocolError, "malformed extended request"), g.cfg.WriteTimeout)
		return false
	}
	if name != oidStartTLS {
		return g.deny(c, m, name)
	}
	return g.startTLS(ctx, c, m)
}

// startTLS answers a StartTLS request and upgrades the connection (RFC 4511
// §4.14). The response is written before the handshake; any failure ends
// the connection — there is no clear-text fallback.
func (g *generation) startTLS(ctx context.Context, c *Conn, m *message) bool {
	switch {
	case !g.offersStartTLS:
		return c.write(encodeExtended(m.ID, Result{Code: ldap.LDAPResultUnwillingToPerform, Diagnostic: "StartTLS not available on this listener"}, oidStartTLS), g.cfg.WriteTimeout) == nil
	case c.TLS():
		return c.write(encodeExtended(m.ID, Result{Code: ldap.LDAPResultOperationsError, Diagnostic: "TLS already established"}, oidStartTLS), g.cfg.WriteTimeout) == nil
	}
	if err := c.write(encodeExtended(m.ID, Success, oidStartTLS), g.cfg.WriteTimeout); err != nil {
		return false
	}
	if c.rd.Buffered() > 0 {
		// Data pipelined after the StartTLS request is a protocol violation.
		g.log.Debug("data after StartTLS request", "conn_id", c.id)
		return false
	}
	hctx, cancel := context.WithTimeout(ctx, g.cfg.HandshakeTimeout)
	defer cancel()
	tc := tls.Server(c.nc, g.tlsFor(c))
	if err := tc.HandshakeContext(hctx); err != nil {
		g.log.Debug("StartTLS handshake failed", "conn_id", c.id, "client_ip", c.ClientIP(), "err", err)
		return false
	}
	c.wmu.Lock()
	c.nc = tc
	c.rd = bufio.NewReaderSize(tc, readBufferSize)
	c.wmu.Unlock()
	c.tls.Store(true)
	g.log.Debug("StartTLS established", "conn_id", c.id, "client_ip", c.ClientIP(), "version", tlsVersion(tc))
	return true
}

func tlsVersion(c *tls.Conn) string {
	switch c.ConnectionState().Version {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	default:
		return "unknown"
	}
}
