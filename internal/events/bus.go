package events

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alstdev/aldap/internal/metrics"
)

// Options tune a Bus.
type Options struct {
	// Host is the host field of every record (default os.Hostname).
	Host string
	// BufferSize is the ring buffer capacity (default 100000).
	BufferSize int
	// Include keeps only these kinds (empty = all); Exclude drops these kinds.
	Include, Exclude []string
	// HashAccounts replaces account by sha256(Salt || account) in hex.
	HashAccounts bool
	Salt         []byte
	Now          func() time.Time
	Logger       *slog.Logger
	// Metrics counts emitted and dropped records (nil = none).
	Metrics *metrics.Metrics
}

// RecordSink receives wrapped records in batches from the bus. Write is
// called from the sink's own goroutine; a returned error counts the batch
// as dropped. Close flushes and releases resources.
type RecordSink interface {
	Write(ctx context.Context, batch []Record) error
	Close() error
}

// SinkOptions describe how the bus feeds one sink.
type SinkOptions struct {
	// Name identifies the sink in logs and drop counters.
	Name string
	// Kinds limits the delivered event types (empty = all).
	Kinds []string
	// QueueSize bounds the pending records (default 10000).
	QueueSize int
	// OnOverflow is drop_oldest (default) or block.
	OnOverflow string
	// BatchSize and BatchInterval group records per Write (default 1 record,
	// no wait); a partial batch is written after BatchInterval.
	BatchSize     int
	BatchInterval time.Duration
}

// Bus is the process-wide event hub: it wraps events into records, keeps
// the last BufferSize records for the API and fans them out to sinks and
// subscribers without blocking producers.
type Bus struct {
	o       Options
	include map[string]bool
	exclude map[string]bool
	seq     atomic.Uint64
	log     *slog.Logger

	mu    sync.Mutex
	ring  []Record
	head  int // index of the oldest record
	n     int
	sinks []*runner
	subs  map[*Subscription]struct{}
	// dropped accumulates the counters of sinks that were replaced.
	dropped map[string]uint64
}

// NewBus creates a bus without sinks; records are kept in the ring buffer.
func NewBus(o Options) *Bus {
	if o.Host == "" {
		if h, err := os.Hostname(); err == nil {
			o.Host = h
		} else {
			o.Host = "aldap"
		}
	}
	if o.BufferSize <= 0 {
		o.BufferSize = 100000
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	b := &Bus{o: o, log: o.Logger, ring: make([]Record, 0, min(o.BufferSize, 1024)), subs: map[*Subscription]struct{}{}, dropped: map[string]uint64{}}
	b.include = set(o.Include)
	b.exclude = set(o.Exclude)
	return b
}

func set(ks []string) map[string]bool {
	if len(ks) == 0 {
		return nil
	}
	m := make(map[string]bool, len(ks))
	for _, k := range ks {
		m[k] = true
	}
	return m
}

// Host returns the host field used by the bus.
func (b *Bus) Host() string { return b.o.Host }

// Seq returns the sequence number of the last emitted record.
func (b *Bus) Seq() uint64 { return b.seq.Load() }

// Wrap builds the record of e without storing or delivering it: the
// envelope fields are filled, the account hashed and password values in
// filters redacted. The sequence number advances.
func (b *Bus) Wrap(e Event) Record {
	ts := b.o.Now()
	id, err := NewULID(ts, nil)
	if err != nil {
		// crypto/rand failures are fatal elsewhere; the record keeps going without an id.
		b.log.Error("ulid generation failed", "err", err)
	}
	r := newRecord(e, ts, id, b.seq.Add(1), b.o.Host)
	redactData(r.Data)
	clipRecord(&r)
	if b.o.HashAccounts && r.Account != "" {
		r.AccountHash = HashAccount(b.o.Salt, r.Account)
		r.Account = ""
	}
	return r
}

// HashAccount returns hex(sha256(salt || account)) (events.hash_accounts).
func HashAccount(salt []byte, account string) string {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(account))
	return hex.EncodeToString(h.Sum(nil))
}

// Accepts reports whether the include/exclude filter keeps the kind.
func (b *Bus) Accepts(kind string) bool {
	if b.include != nil && !b.include[kind] {
		return false
	}
	return !b.exclude[kind]
}

// Emit implements Sink: the event is wrapped, stored and delivered.
func (b *Bus) Emit(e Event) {
	if !b.Accepts(e.Event) {
		return
	}
	r := b.Wrap(e)
	b.o.Metrics.Event(r.Event)
	b.mu.Lock()
	b.store(r)
	sinks := b.sinks
	for s := range b.subs {
		s.offer(r)
	}
	b.mu.Unlock()
	for _, s := range sinks {
		s.offer(r)
	}
}

// store appends r to the ring buffer; the caller holds mu.
func (b *Bus) store(r Record) {
	if len(b.ring) < b.o.BufferSize {
		b.ring = append(b.ring, r)
		b.n = len(b.ring)
		return
	}
	b.ring[b.head] = r
	b.head = (b.head + 1) % len(b.ring)
}

// Since returns up to limit records with Seq > seq, oldest first (limit <= 0
// = all). The ring is ordered by seq, so the start is found by binary
// search and only the records returned are copied.
func (b *Bus) Since(seq uint64, limit int) []Record {
	var out []Record
	b.Each(seq, func(r Record) bool {
		out = append(out, r)
		return limit <= 0 || len(out) < limit
	})
	return out
}

// Each calls fn for every record with Seq > seq, oldest first, under the
// bus lock, until fn returns false; fn must be quick and must not call
// back into the bus.
func (b *Bus) Each(seq uint64, fn func(Record) bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	at := func(i int) Record { return b.ring[(b.head+i)%b.n] }
	start := sort.Search(b.n, func(i int) bool { return at(i).Seq > seq })
	for i := start; i < b.n; i++ {
		if !fn(at(i)) {
			return
		}
	}
}

// Count returns how many buffered records have Seq > seq.
func (b *Bus) Count(seq uint64) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	at := func(i int) Record { return b.ring[(b.head+i)%b.n] }
	return b.n - sort.Search(b.n, func(i int) bool { return at(i).Seq > seq })
}

// Last returns the newest n records, oldest first.
func (b *Bus) Last(n int) []Record {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n > b.n {
		n = b.n
	}
	out := make([]Record, 0, n)
	for i := b.n - n; i < b.n; i++ {
		out = append(out, b.ring[(b.head+i)%b.n])
	}
	return out
}

// Subscription delivers records to one consumer (API streams, notify).
type Subscription struct {
	C       chan Record
	bus     *Bus
	dropped atomic.Uint64
	closed  atomic.Bool
}

// Subscribe registers a consumer with a queue of size n; records are
// dropped (and counted) when the consumer lags.
func (b *Bus) Subscribe(n int) *Subscription {
	if n <= 0 {
		n = 256
	}
	s := &Subscription{C: make(chan Record, n), bus: b}
	b.mu.Lock()
	b.subs[s] = struct{}{}
	b.mu.Unlock()
	return s
}

func (s *Subscription) offer(r Record) {
	if s.closed.Load() {
		return
	}
	select {
	case s.C <- r:
	default:
		s.dropped.Add(1)
	}
}

// Dropped returns the records dropped because the consumer lagged.
func (s *Subscription) Dropped() uint64 { return s.dropped.Load() }

// Close unregisters the subscription; C is not closed so a concurrent
// reader never sees a closed channel racing with offer.
func (s *Subscription) Close() {
	if s.closed.Swap(true) {
		return
	}
	s.bus.mu.Lock()
	delete(s.bus.subs, s)
	s.bus.mu.Unlock()
}

// AddSink attaches a sink with its own queue and goroutine.
func (b *Bus) AddSink(sink RecordSink, o SinkOptions) {
	r := newRunner(sink, o, b.log, b.o.Metrics)
	b.mu.Lock()
	b.sinks = append(b.sinks, r)
	b.mu.Unlock()
}

// SetSinks replaces the sinks; the previous ones are flushed and closed.
func (b *Bus) SetSinks(sinks []SinkSpec) {
	rs := make([]*runner, 0, len(sinks))
	for _, s := range sinks {
		rs = append(rs, newRunner(s.Sink, s.Options, b.log, b.o.Metrics))
	}
	b.mu.Lock()
	old := b.sinks
	b.sinks = rs
	b.mu.Unlock()
	for _, r := range old {
		r.close()
	}
	b.mu.Lock()
	for _, r := range old {
		b.dropped[r.o.Name] += r.dropped.Load()
	}
	b.mu.Unlock()
}

// SinkSpec pairs a sink with its delivery options.
type SinkSpec struct {
	Sink    RecordSink
	Options SinkOptions
}

// Dropped returns the records dropped per sink name (queue overflow or
// delivery failure), replaced sinks included.
func (b *Bus) Dropped() map[string]uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[string]uint64, len(b.dropped)+len(b.sinks))
	for k, v := range b.dropped {
		out[k] = v
	}
	for _, r := range b.sinks {
		out[r.o.Name] += r.dropped.Load()
	}
	return out
}

// Flush blocks until every record emitted so far has been handed to the
// sinks (written, or dropped by a failing sink).
func (b *Bus) Flush() {
	b.mu.Lock()
	sinks := b.sinks
	b.mu.Unlock()
	for _, r := range sinks {
		r.flush()
	}
}

// Close flushes and closes every sink.
func (b *Bus) Close() {
	b.SetSinks(nil)
}

// runner feeds one sink from a bounded queue.
type runner struct {
	o       SinkOptions
	sink    RecordSink
	kinds   map[string]bool
	ch      chan Record
	dropped atomic.Uint64
	log     *slog.Logger
	done    chan struct{}
	once    sync.Once
	// mu guards closed: offer holds it shared so close never races a send.
	mu     sync.RWMutex
	closed bool
	m      *metrics.Metrics
}

func newRunner(sink RecordSink, o SinkOptions, log *slog.Logger, m *metrics.Metrics) *runner {
	if o.QueueSize <= 0 {
		o.QueueSize = 10000
	}
	if o.BatchSize <= 0 {
		o.BatchSize = 1
	}
	if o.OnOverflow == "" {
		o.OnOverflow = "drop_oldest"
	}
	r := &runner{o: o, sink: sink, kinds: set(o.Kinds), ch: make(chan Record, o.QueueSize), log: log.With("sink", o.Name), done: make(chan struct{}), m: m}
	go r.loop()
	return r
}

func (r *runner) offer(rec Record) {
	if r.kinds != nil && !r.kinds[rec.Event] {
		return
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		r.drop(1)
		return
	}
	if r.o.OnOverflow == "block" {
		r.ch <- rec
		return
	}
	for {
		select {
		case r.ch <- rec:
			return
		default:
		}
		// Full: drop the oldest pending record and retry.
		select {
		case <-r.ch:
			r.drop(1)
		default:
		}
	}
}

func (r *runner) loop() {
	defer close(r.done)
	var batch []Record
	var timer *time.Timer
	var timerC <-chan time.Time
	flush := func() {
		if timer != nil {
			timer.Stop()
			timer, timerC = nil, nil
		}
		if len(batch) == 0 {
			return
		}
		if err := r.sink.Write(context.Background(), batch); err != nil {
			r.drop(len(batch))
			r.log.Warn("event sink write failed", "records", len(batch), "err", err)
		}
		batch = nil
	}
	for {
		select {
		case rec, ok := <-r.ch:
			if !ok {
				flush()
				return
			}
			if rec.flush != nil {
				flush()
				close(rec.flush)
				continue
			}
			batch = append(batch, rec)
			if len(batch) >= r.o.BatchSize {
				flush()
				continue
			}
			if r.o.BatchInterval > 0 {
				if timerC == nil {
					timer = time.NewTimer(r.o.BatchInterval)
					timerC = timer.C
				}
				continue
			}
			// No interval: take what is already queued, then write.
			for len(batch) < r.o.BatchSize {
				select {
				case more, ok := <-r.ch:
					if !ok {
						flush()
						return
					}
					if more.flush != nil {
						flush()
						close(more.flush)
						continue
					}
					batch = append(batch, more)
					continue
				default:
				}
				break
			}
			flush()
		case <-timerC:
			flush()
		}
	}
}

// drop counts n dropped records.
func (r *runner) drop(n int) {
	if n <= 0 {
		return
	}
	r.dropped.Add(uint64(n))
	r.m.Dropped(r.o.Name, float64(n))
}

// flush waits until the records queued before the call are written.
func (r *runner) flush() {
	done := make(chan struct{})
	r.mu.RLock()
	if r.closed {
		r.mu.RUnlock()
		return
	}
	r.ch <- Record{flush: done}
	r.mu.RUnlock()
	<-done
}

// close stops the runner after delivering what is queued.
func (r *runner) close() {
	r.once.Do(func() {
		r.mu.Lock()
		r.closed = true
		close(r.ch)
		r.mu.Unlock()
		<-r.done
		if err := r.sink.Close(); err != nil {
			r.log.Warn("event sink close failed", "err", err)
		}
	})
}
