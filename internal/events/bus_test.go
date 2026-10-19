package events

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alstdev/aldap/internal/config"
)

func TestNewULID_Format(t *testing.T) {
	ts := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	id, err := NewULID(ts, strings.NewReader("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`).MatchString(id) {
		t.Fatalf("ulid %q", id)
	}
	// The first 10 characters encode the timestamp: same ms → same prefix.
	id2, _ := NewULID(ts, strings.NewReader("fedcba9876543210"))
	if id[:10] != id2[:10] || id == id2 {
		t.Fatalf("time prefix: %s vs %s", id, id2)
	}
	later, _ := NewULID(ts.Add(time.Second), nil)
	if later[:10] <= id[:10] {
		t.Fatalf("ulid not sortable by time: %s vs %s", id, later)
	}
	if _, err := NewULID(ts, strings.NewReader("short")); err == nil {
		t.Fatal("short random source accepted")
	}
}

func TestRedactFilter_Cases(t *testing.T) {
	cases := map[string]string{
		"(userPassword=secret)":                             "(userPassword=***)",
		"(|(uid=a)(unicodePwd=S3CR*))":                      "(|(uid=a)(unicodePwd=***))",
		"(&(cn=x)(userpassword>=abc)(unicodepwd;binary=z))": "(&(cn=x)(userpassword>=***)(unicodepwd;binary=***))",
		"(userPassword:caseExactMatch:=pw)":                 "(userPassword:caseExactMatch:=***)",
		"(mail=userPassword=notanattr)":                     "(mail=userPassword=notanattr)",
	}
	for in, want := range cases {
		if got := RedactFilter(in); got != want {
			t.Errorf("RedactFilter(%q) = %q, want %q", in, got, want)
		}
	}
}

func fixedNow(ts time.Time) func() time.Time { return func() time.Time { return ts } }

func TestBus_WrapAndRing(t *testing.T) {
	ts := time.Date(2026, 10, 19, 10, 21, 33, 412000000, time.UTC)
	b := NewBus(Options{Host: "h1", BufferSize: 3, Now: fixedNow(ts), Logger: slog.New(slog.DiscardHandler)})
	e := Event{Event: BindFail, Level: LevelLow, Profile: "p", ConnID: "c-1", ClientIP: "10.0.0.1", ClientPort: 5, TLS: Bool(true),
		Account: "alice", Reason: "invalid_password", Failures: 2, Upstream: "ad", UpstreamServer: "ldaps://dc", Duration: 42 * time.Millisecond,
		Data: map[string]any{"filter_norm": "(userPassword=x)", "k": 1}}
	r := b.Wrap(e)
	var got map[string]any
	if err := json.Unmarshal(r.JSON(), &got); err != nil {
		t.Fatal(err)
	}
	if got["schema"] != SchemaID || got["ts"] != "2026-10-19T10:21:33.412Z" || got["seq"] != float64(1) || got["host"] != "h1" ||
		got["event"] != BindFail || got["account"] != "alice" || got["failures"] != float64(2) || got["duration_ms"] != float64(42) ||
		got["tls"] != true || got["client_port"] != float64(5) {
		t.Errorf("record %s", r.JSON())
	}
	if d := got["data"].(map[string]any); d["filter_norm"] != "(userPassword=***)" || d["k"] != float64(1) {
		t.Errorf("data %v", d)
	}
	if e.Data["filter_norm"] != "(userPassword=x)" {
		t.Error("producer data mutated")
	}
	// Empty level defaults to low; no data → {}.
	r2 := b.Wrap(Event{Event: Startup})
	if r2.Level != LevelLow || !strings.Contains(string(r2.JSON()), `"data":{}`) {
		t.Errorf("defaults: %s", r2.JSON())
	}
	// Ring buffer keeps the last BufferSize records.
	for i := 0; i < 5; i++ {
		b.Emit(Event{Event: Search, Data: map[string]any{"i": i}})
	}
	last := b.Last(10)
	if len(last) != 3 || last[0].Data["i"] != 2 || last[2].Data["i"] != 4 || b.Seq() != 7 {
		t.Errorf("last = %+v seq=%d", last, b.Seq())
	}
	since := b.Since(last[0].Seq, 1)
	if len(since) != 1 || since[0].Data["i"] != 3 {
		t.Errorf("since = %+v", since)
	}
	if len(b.Since(100, 0)) != 0 || len(b.Last(0)) != 0 {
		t.Error("empty results expected")
	}
}

func TestBus_FiltersHashingSubscriptions(t *testing.T) {
	b := NewBus(Options{Host: "h", Include: []string{BindOK, BindFail}, Exclude: []string{BindFail}, HashAccounts: true, Salt: []byte("salt")})
	sub := b.Subscribe(1)
	defer sub.Close()
	b.Emit(Event{Event: Search})
	b.Emit(Event{Event: BindFail})
	b.Emit(Event{Event: BindOK, Account: "alice"})
	b.Emit(Event{Event: BindOK, Account: "bob"})
	if b.Seq() != 2 {
		t.Fatalf("filtered events wrapped: seq=%d", b.Seq())
	}
	r := <-sub.C
	if r.Account != "" || r.AccountHash != HashAccount([]byte("salt"), "alice") || len(r.AccountHash) != 64 {
		t.Errorf("hash: %+v", r)
	}
	if sub.Dropped() != 1 {
		t.Errorf("dropped = %d", sub.Dropped())
	}
	sub.Close()
	sub.Close()
	b.Emit(Event{Event: BindOK})
	if sub.Dropped() != 1 {
		t.Error("closed subscription still counted")
	}
	if !b.Accepts(BindOK) || b.Accepts(BindFail) || b.Accepts(Search) {
		t.Error("Accepts")
	}
	if h, _ := os.Hostname(); NewBus(Options{}).Host() != h {
		t.Error("default host")
	}
}

// memSink records batches.
type memSink struct {
	mu      sync.Mutex
	batches [][]Record
	err     error
	closed  bool
	wait    chan struct{}
}

func (m *memSink) Write(_ context.Context, batch []Record) error {
	if m.wait != nil {
		<-m.wait
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := append([]Record(nil), batch...)
	m.batches = append(m.batches, cp)
	return m.err
}

func (m *memSink) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *memSink) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, b := range m.batches {
		n += len(b)
	}
	return n
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

func TestBus_SinkBatching(t *testing.T) {
	b := NewBus(Options{Host: "h", Logger: slog.New(slog.DiscardHandler)})
	ms := &memSink{}
	b.AddSink(ms, SinkOptions{Name: "m", Kinds: []string{Search}, BatchSize: 2, BatchInterval: 20 * time.Millisecond})
	b.Emit(Event{Event: BindOK}) // filtered by kinds
	b.Emit(Event{Event: Search})
	b.Emit(Event{Event: Search})
	waitFor(t, func() bool { return ms.count() == 2 })
	ms.mu.Lock()
	full := len(ms.batches) == 1 && len(ms.batches[0]) == 2
	ms.mu.Unlock()
	if !full {
		t.Errorf("batches %+v", ms.batches)
	}
	b.Emit(Event{Event: Search}) // partial batch flushed by the interval
	waitFor(t, func() bool { return ms.count() == 3 })
	// Flush is a barrier: everything emitted before it is written on return.
	for i := 0; i < 5; i++ {
		b.Emit(Event{Event: Search})
	}
	b.Flush()
	if ms.count() != 8 {
		t.Errorf("after Flush: %d records written", ms.count())
	}
	b.Flush()
	// Failures count as dropped; Close flushes.
	ms.err = errors.New("boom")
	b.Emit(Event{Event: Search})
	b.Emit(Event{Event: Search})
	b.Close()
	if d := b.Dropped(); d["m"] != 2 {
		t.Errorf("dropped = %v", d)
	}
	if !ms.closed {
		t.Error("sink not closed")
	}
	if len(b.sinks) != 0 {
		t.Error("sinks remain after Close")
	}
}

func TestBus_Overflow(t *testing.T) {
	b := NewBus(Options{Host: "h", Logger: slog.New(slog.DiscardHandler)})
	gate := make(chan struct{})
	ms := &memSink{wait: gate}
	b.AddSink(ms, SinkOptions{Name: "slow", QueueSize: 2, OnOverflow: "drop_oldest"})
	for i := 0; i < 6; i++ {
		b.Emit(Event{Event: Search, Data: map[string]any{"i": i}})
	}
	close(gate)
	b.Close()
	if d := b.Dropped()["slow"]; d < 2 {
		t.Errorf("dropped = %d, want >= 2 (queue 2)", d)
	}
	// The newest record survives drop_oldest.
	ms.mu.Lock()
	lastBatch := ms.batches[len(ms.batches)-1]
	ms.mu.Unlock()
	if lastBatch[len(lastBatch)-1].Data["i"] != 5 {
		t.Errorf("newest record lost: %+v", lastBatch)
	}
	// block: Emit waits for room, nothing is dropped.
	b2 := NewBus(Options{Host: "h", Logger: slog.New(slog.DiscardHandler)})
	gate2 := make(chan struct{})
	ms2 := &memSink{wait: gate2}
	b2.AddSink(ms2, SinkOptions{Name: "block", QueueSize: 1, OnOverflow: "block"})
	done := make(chan struct{})
	go func() {
		for i := 0; i < 4; i++ {
			b2.Emit(Event{Event: Search})
		}
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("Emit did not block on a full queue")
	case <-time.After(50 * time.Millisecond):
	}
	close(gate2)
	<-done
	b2.Close()
	if ms2.count() != 4 || b2.Dropped()["block"] != 0 {
		t.Errorf("block policy: delivered %d dropped %v", ms2.count(), b2.Dropped())
	}
	// Records offered to a closed sink are counted as dropped, never panic.
	r := newRunner(&memSink{}, SinkOptions{Name: "x"}, slog.New(slog.DiscardHandler), nil)
	r.close()
	r.offer(Record{Event: Search})
	if r.dropped.Load() != 1 {
		t.Error("offer after close")
	}
}

func TestBus_SetSinksReplaces(t *testing.T) {
	b := NewBus(Options{Host: "h", Logger: slog.New(slog.DiscardHandler)})
	first := &memSink{}
	b.SetSinks([]SinkSpec{{Sink: first, Options: SinkOptions{Name: "a"}}})
	b.Emit(Event{Event: Search})
	second := &memSink{}
	b.SetSinks([]SinkSpec{{Sink: second, Options: SinkOptions{Name: "b"}}})
	if !first.closed || first.count() != 1 {
		t.Error("first sink not flushed and closed")
	}
	b.Emit(Event{Event: Search})
	b.Close()
	if second.count() != 1 {
		t.Error("second sink missed the record")
	}
}

func TestBusFromConfig_Cases(t *testing.T) {
	cfg := config.Default().Events
	cfg.HashAccounts = true
	cfg.SaltFile = filepath.Join(t.TempDir(), "salt")
	if _, err := BusFromConfig(cfg, Options{Host: "h"}); err == nil {
		t.Fatal("missing salt file accepted")
	}
	if err := os.WriteFile(cfg.SaltFile, []byte("pepper"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := BusFromConfig(cfg, Options{Host: "h"})
	if err != nil {
		t.Fatal(err)
	}
	if r := b.Wrap(Event{Event: BindOK, Account: "a"}); r.AccountHash != HashAccount([]byte("pepper"), "a") {
		t.Error("salt file not used")
	}
	cfg.SaltFile = ""
	b2, err := BusFromConfig(cfg, Options{Host: "h", Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	if r := b2.Wrap(Event{Event: BindOK, Account: "a"}); r.AccountHash == "" || r.AccountHash == HashAccount(nil, "a") {
		t.Error("random salt expected")
	}
	// Configure: stdout + file + webhook; syslog/webhook/file errors surface.
	var out strings.Builder
	cfg = config.Default().Events
	cfg.File.Enabled, cfg.File.Path = true, filepath.Join(t.TempDir(), "ev.jsonl")
	cfg.Webhooks = []config.Webhook{{Name: "w", URL: "http://127.0.0.1:1/x", Timeout: config.Duration(time.Second)}}
	if err := b.Configure(cfg, ConfigureOptions{Stdout: &out}); err != nil {
		t.Fatal(err)
	}
	b.Emit(Event{Event: Startup})
	b.Close()
	if !strings.Contains(out.String(), `"event":"startup"`) {
		t.Errorf("stdout sink: %q", out.String())
	}
	if data, _ := os.ReadFile(cfg.File.Path); !strings.Contains(string(data), `"event":"startup"`) {
		t.Errorf("file sink: %q", data)
	}
	bad := config.Default().Events
	bad.Syslog.Enabled, bad.Syslog.Network, bad.Syslog.Address, bad.Syslog.Facility = true, "udp", "127.0.0.1:514", "nope"
	if err := b.Configure(bad, ConfigureOptions{}); err == nil {
		t.Error("bad facility accepted")
	}
	bad = config.Default().Events
	bad.Webhooks = []config.Webhook{{URL: ""}}
	if err := b.Configure(bad, ConfigureOptions{}); err == nil {
		t.Error("empty webhook url accepted")
	}
	bad = config.Default().Events
	bad.Webhooks = []config.Webhook{{URL: "http://x", HMACSecretFile: filepath.Join(t.TempDir(), "missing")}}
	if err := b.Configure(bad, ConfigureOptions{}); err == nil {
		t.Error("missing hmac file accepted")
	}
	bad = config.Default().Events
	bad.File.Enabled, bad.File.Path = true, filepath.Join(t.TempDir(), "nodir", "x")
	if err := b.Configure(bad, ConfigureOptions{}); err == nil {
		t.Error("unwritable file accepted")
	}
	bad = config.Default().Events
	bad.Stdout.Enabled = false
	if err := b.Configure(bad, ConfigureOptions{}); err != nil || len(b.sinks) != 0 {
		t.Errorf("no sinks: %v %v", err, b.sinks)
	}
}
