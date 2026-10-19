package events

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func rec(i int) Record {
	return Record{Schema: SchemaID, TS: "2026-10-19T10:00:00.000Z", ID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Seq: uint64(i), Event: Search, Level: LevelLow, Host: "h", Data: map[string]any{"i": i}}
}

func TestFileSink_Rotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	fs, err := NewFileSink(path, 0, 2, true)
	if err != nil {
		t.Fatal(err)
	}
	fs.MaxBytes = 300 // ~2 records per file
	for i := 0; i < 9; i++ {
		if err := fs.Write(context.Background(), []Record{rec(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) != 3 {
		t.Fatalf("files %v, want current + 2 rotated", names)
	}
	for _, n := range []string{"events.jsonl.1.gz", "events.jsonl.2.gz"} {
		raw, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		data, _ := io.ReadAll(zr)
		if !strings.Contains(string(data), `"event":"search"`) {
			t.Errorf("%s content %q", n, data)
		}
	}
	// Newest rotated file holds the most recent records before the current one.
	cur, _ := os.ReadFile(path)
	if !strings.Contains(string(cur), `"i":8`) {
		t.Errorf("current file %q", cur)
	}
	// Reopen appends; plain rotation without compression.
	fs2, err := NewFileSink(path, 1, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	fs2.MaxBytes = 200
	for i := 0; i < 4; i++ {
		_ = fs2.Write(context.Background(), []Record{rec(i)})
	}
	_ = fs2.Close()
	_ = fs2.Close()
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("plain rotation: %v", err)
	}
	if _, err := NewFileSink(filepath.Join(dir, "missing", "x"), 1, 1, false); err == nil {
		t.Error("missing directory accepted")
	}
	if err := gzipFile(filepath.Join(dir, "nope"), filepath.Join(dir, "nope.gz")); err == nil {
		t.Error("gzip of missing file")
	}
}

func TestWriterSink_Lines(t *testing.T) {
	var buf bytes.Buffer
	s := &WriterSink{W: &buf}
	if err := s.Write(context.Background(), []Record{rec(1), rec(2)}); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSpace(buf.String()), "\n"); len(lines) != 2 || !strings.HasPrefix(lines[0], `{"schema":"aldap.event.v1"`) {
		t.Errorf("output %q", buf.String())
	}
	if s.Close() != nil {
		t.Error("close")
	}
	// Unserializable data falls back to an error note instead of failing.
	r := rec(3)
	r.Data["bad"] = make(chan int)
	if out := string(r.JSON()); !strings.Contains(out, "unserializable") {
		t.Errorf("fallback: %s", out)
	}
}

func TestSyslogSink_Cases(t *testing.T) {
	if _, err := NewSyslogSink("http", "x", "auth"); err == nil {
		t.Error("bad network accepted")
	}
	if _, err := NewSyslogSink("udp", "", "auth"); err == nil {
		t.Error("empty address accepted")
	}
	if _, err := NewSyslogSink("udp", "x", "fac"); err == nil {
		t.Error("bad facility accepted")
	}
	pc, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	s, err := NewSyslogSink("udp", pc.LocalAddr().String(), "local3")
	if err != nil {
		t.Fatal(err)
	}
	r := rec(7)
	r.Level = LevelHigh
	if err := s.Write(context.Background(), []Record{r}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	msg := string(buf[:n])
	// local3 = 19 → 19*8 + warning(4) = 156
	if !strings.HasPrefix(msg, "<156>1 2026-10-19T10:00:00.000Z h aldap ") || !strings.Contains(msg, " search - {\"schema\"") || !strings.HasSuffix(msg, "\n") {
		t.Errorf("message %q", msg)
	}
	if err := s.Close(); err != nil {
		t.Error(err)
	}
	// Reconnect after a write failure, then give up.
	var dials atomic.Int32
	s.Dial = func(string, string, time.Duration) (net.Conn, error) {
		dials.Add(1)
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	}
	if err := s.Write(context.Background(), []Record{r}); err == nil {
		t.Error("write on closed pipe succeeded")
	}
	if dials.Load() != 2 {
		t.Errorf("dials = %d, want 2 (initial + reconnect)", dials.Load())
	}
	s.Dial = func(string, string, time.Duration) (net.Conn, error) { return nil, io.ErrClosedPipe }
	if err := s.Write(context.Background(), []Record{r}); err == nil {
		t.Error("connect failure not reported")
	}
	_ = s.Close()
}

func TestWebhookSink_Cases(t *testing.T) {
	var calls atomic.Int32
	var gotSig, gotBody atomic.Value
	status := atomic.Int32{}
	status.Store(http.StatusOK)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		gotBody.Store(body)
		gotSig.Store(r.Header.Get(SignatureHeader))
		if r.Header.Get("X-Extra") != "1" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("User-Agent") != "aldap-test" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()
	var slept []time.Duration
	s, err := NewWebhookSink(WebhookOptions{URL: srv.URL, Headers: map[string]string{"X-Extra": "1"}, Key: []byte("k"), Retries: 2,
		Backoff: 10 * time.Millisecond, MaxBackoff: 15 * time.Millisecond, UserAgent: "aldap-test"})
	if err != nil {
		t.Fatal(err)
	}
	s.Sleep = func(_ context.Context, d time.Duration) { slept = append(slept, d) }
	if err := s.Write(context.Background(), []Record{rec(1), rec(2)}); err != nil {
		t.Fatal(err)
	}
	body := gotBody.Load().([]byte)
	if !VerifySignature([]byte("k"), body, gotSig.Load().(string)) || VerifySignature([]byte("other"), body, gotSig.Load().(string)) {
		t.Error("signature")
	}
	if !strings.HasPrefix(string(body), `[{"schema"`) || !strings.Contains(string(body), `"seq":2`) {
		t.Errorf("body %s", body)
	}
	// 500 → retried with doubling backoff capped at MaxBackoff, then fails.
	status.Store(http.StatusInternalServerError)
	calls.Store(0)
	if err := s.Write(context.Background(), []Record{rec(3)}); err == nil {
		t.Error("5xx reported as success")
	}
	if calls.Load() != 3 || len(slept) != 2 || slept[0] != 10*time.Millisecond || slept[1] != 15*time.Millisecond {
		t.Errorf("calls %d slept %v", calls.Load(), slept)
	}
	// 4xx → no retry.
	status.Store(http.StatusForbidden)
	calls.Store(0)
	if err := s.Write(context.Background(), []Record{rec(4)}); err == nil || calls.Load() != 1 {
		t.Errorf("4xx: %v calls %d", err, calls.Load())
	}
	// Canceled context stops retries; network errors are retried.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	status.Store(http.StatusInternalServerError)
	calls.Store(0)
	if err := s.Write(ctx, []Record{rec(5)}); err == nil {
		t.Error("canceled context")
	}
	if calls.Load() > 1 {
		t.Errorf("retried after cancel: %d", calls.Load())
	}
	if s.Close() != nil {
		t.Error("close")
	}
	dead, _ := NewWebhookSink(WebhookOptions{URL: "http://127.0.0.1:1/", Retries: 1, Timeout: 200 * time.Millisecond})
	dead.Sleep = func(context.Context, time.Duration) {}
	if err := dead.Write(context.Background(), []Record{rec(6)}); err == nil {
		t.Error("dead endpoint")
	}
	// Real sleep path with a tiny backoff.
	dead2, _ := NewWebhookSink(WebhookOptions{URL: "http://127.0.0.1:1/", Retries: 1, Backoff: time.Millisecond, MaxBackoff: time.Millisecond})
	if err := dead2.Write(context.Background(), []Record{rec(6)}); err == nil {
		t.Error("dead endpoint")
	}
	// Options: empty URL, bad CA file.
	if _, err := NewWebhookSink(WebhookOptions{}); err == nil {
		t.Error("empty url")
	}
	if _, err := NewWebhookSink(WebhookOptions{URL: "http://x", TLSCAFile: filepath.Join(t.TempDir(), "nope")}); err == nil {
		t.Error("missing CA")
	}
	notPEM := filepath.Join(t.TempDir(), "ca.pem")
	_ = os.WriteFile(notPEM, []byte("junk"), 0o600)
	if _, err := NewWebhookSink(WebhookOptions{URL: "http://x", TLSCAFile: notPEM}); err == nil {
		t.Error("junk CA")
	}
	// A valid CA bundle is accepted (the test server's certificate).
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer tlsSrv.Close()
	caPath := filepath.Join(t.TempDir(), "srv.pem")
	_ = os.WriteFile(caPath, pemOf(t, tlsSrv), 0o600)
	tsink, err := NewWebhookSink(WebhookOptions{URL: tlsSrv.URL, TLSCAFile: caPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := tsink.Write(context.Background(), []Record{rec(7)}); err != nil {
		t.Errorf("tls webhook: %v", err)
	}
}
