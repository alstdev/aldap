package listener

import (
	"bufio"
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/events"
)

// Audit 14 / A.6 (5): what the listener actually zeroes. parseBind copies
// the password out of the BER tree (append([]byte(nil), ...)); wipe() only
// clears that copy. The wire buffer returned by readMessage and the
// *ber.Packet tree (auth.Data) keep the clear-text password until the GC
// reuses the memory.
func TestAudit14_A6_WireBufferNotZeroed(t *testing.T) {
	const pw = "S3CR3T-wire-0badc0de"
	raw, err := readMessage(bufio.NewReader(bytes.NewReader(bindPacket(1, 3, "cn=u", pw))), 0)
	if err != nil {
		t.Fatal(err)
	}
	m, err := parseMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	req, err := parseBind(m.Body)
	if err != nil {
		t.Fatal(err)
	}
	wipe(req.Password)  // what handleBind does (defer wipe(req.Password))
	wipeMessage(raw, m) // what handle does once the request was dispatched
	if bytes.Contains(req.Password, []byte(pw)) {
		t.Fatal("the copy itself was not zeroed")
	}
	if bytes.Contains(raw, []byte(pw)) {
		t.Errorf("FINDING(low): wire buffer still holds the password after wipe(req.Password)")
	}
	if bytes.Contains(m.Body.Children[2].Data.Bytes(), []byte(pw)) || bytes.Contains(m.Body.Bytes(), []byte(pw)) {
		t.Errorf("FINDING(low): ber.Packet tree still holds the password after wipe(req.Password)")
	}
}

// a6PanicHandler panics inside Bind with the password in the panic value and
// in a local variable, the way a bug in vdir/profile code could.
type a6PanicHandler struct{}

func (a6PanicHandler) Bind(_ context.Context, _ *Conn, _ string, password []byte) Result {
	local := "pw=" + string(password)
	panic(local)
}

func (a6PanicHandler) Search(context.Context, *Conn, *SearchRequest, EntryWriter) Result {
	return Result{Code: ldap.LDAPResultUnwillingToPerform}
}

// TestAudit14_A6_PanicOutputNoPassword: the recover wrapper in serve must
// not print the recovered value (coverage for check 4, panic/recover output).
func TestAudit14_A6_PanicOutputNoPassword(t *testing.T) {
	const pw = "S3CR3T-panic-c0ffee"
	logs := &syncBuffer{}
	s, err := New(Config{Profile: "p", Transport: TransportLDAP, Handler: a6PanicHandler{},
		Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})), Events: events.Discard,
		IdleTimeout: 2 * time.Second, FirstPacketTimeout: 2 * time.Second, WriteTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	}()
	c, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(bindPacket(1, 3, "cn=u", pw)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	_, _ = c.Read(buf) // connection closes after the panic
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(logs.String(), "panic while serving") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	out := logs.String()
	if !strings.Contains(out, "panic while serving") {
		t.Fatalf("panic not logged:\n%s", out)
	}
	if strings.Contains(out, pw) || strings.Contains(out, "pw=") {
		t.Errorf("FINDING: password in the panic log:\n%s", out)
	}
}

// syncBuffer is a bytes.Buffer safe for a writer goroutine and a reading test.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}
