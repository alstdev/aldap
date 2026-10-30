package events

// Audit 14, area A.3: resource bounds of the event bus.

import (
	"context"
	"log/slog"
	"runtime"
	"strings"
	"testing"
	"time"
)

func heapInUse() uint64 {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

// The ring never holds more than buffer_size records, whatever the
// emission rate; a lagging subscriber and a full sink queue drop instead
// of growing.
func TestAudit14_A3_RingNeverExceedsBufferSize(t *testing.T) {
	b := NewBus(Options{BufferSize: 100, Logger: slog.New(slog.DiscardHandler)})
	sub := b.Subscribe(4)
	defer sub.Close()
	sink := newBlockingSink()
	b.AddSink(sink, SinkOptions{Name: "slow", QueueSize: 8, OnOverflow: "drop_oldest"})
	for i := 0; i < 1000; i++ {
		b.Emit(Event{Event: Search, Level: LevelLow, Profile: "p", Data: map[string]any{"i": i}})
	}
	b.mu.Lock()
	n, capRing := b.n, cap(b.ring)
	b.mu.Unlock()
	if n != 100 || capRing > 100 {
		t.Errorf("ring n=%d cap=%d, want 100/≤100", n, capRing)
	}
	if last := b.Last(1000); len(last) != 100 || last[99].Seq != 1000 || last[0].Seq != 901 {
		t.Errorf("Last = %d records, seq %d..%d", len(last), last[0].Seq, last[len(last)-1].Seq)
	}
	if sub.Dropped() < 900 {
		t.Errorf("subscriber dropped %d, want ≥ 900", sub.Dropped())
	}
	if len(sub.C) > 4 {
		t.Errorf("subscriber queue %d > 4", len(sub.C))
	}
	close(sink.release)
	b.Close()
	if d := b.Dropped()["slow"]; d == 0 {
		t.Error("full sink queue must drop")
	}
}

// Record fields are stored as the producer gave them: there is no size
// cap, so buffer_size × (client-controlled field size) is the ring's real
// bound. FINDING A3-3 (with the vdir test that shows the client-controlled
// producers).
func TestAudit14_A3_RecordFieldSizeUnbounded(t *testing.T) {
	b := NewBus(Options{BufferSize: 10, Logger: slog.New(slog.DiscardHandler)})
	big := strings.Repeat("a", 1<<20)
	before := heapInUse()
	for i := 0; i < 10; i++ {
		b.Emit(Event{Event: Search, Level: LevelLow, Profile: "p", Account: big, Data: map[string]any{"base": big, "filter_norm": "(x=y)"}})
	}
	after := heapInUse()
	last := b.Last(1)
	stored, _ := last[0].Data["base"].(string)
	t.Logf("10 records with 1 MiB base + 1 MiB account: heap +%d MiB; stored base = %d bytes; ×100000 buffer_size = %d GiB",
		int64(after-before)>>20, len(stored), int64(len(stored)+len(last[0].Account))*100000>>30)
	if len(stored) > 64<<10 || len(last[0].Account) > 64<<10 {
		t.Errorf("record fields are not capped: base %d bytes, account %d bytes", len(stored), len(last[0].Account))
	}
}

// on_overflow = block stalls the emitting goroutine (the client connection)
// while the destination is down — by configuration, documented here.
func TestAudit14_A3_BlockOverflowStallsEmitter(t *testing.T) {
	b := NewBus(Options{BufferSize: 10, Logger: slog.New(slog.DiscardHandler)})
	sink := newBlockingSink()
	b.AddSink(sink, SinkOptions{Name: "block", QueueSize: 2, OnOverflow: "block"})
	done := make(chan struct{})
	go func() {
		for i := 0; i < 5; i++ { // 1 in Write + 2 queued + the 4th blocks
			b.Emit(Event{Event: Search, Level: LevelLow})
		}
		close(done)
	}()
	select {
	case <-done:
		t.Error("Emit did not block with on_overflow=block and a stuck sink")
	case <-time.After(300 * time.Millisecond):
	}
	close(sink.release)
	<-done
	b.Close()
}

// blockingSink blocks every Write until release is closed.
type blockingSink struct {
	release chan struct{}
}

func newBlockingSink() *blockingSink { return &blockingSink{release: make(chan struct{})} }

func (s *blockingSink) Write(context.Context, []Record) error {
	<-s.release
	return nil
}

func (s *blockingSink) Close() error { return nil }
