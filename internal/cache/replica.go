package cache

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/upstream"
)

// retryAfterFailure bounds the wait before the next attempt after a
// failed sync (the regular interval applies when it is shorter).
const retryAfterFailure = 30 * time.Second

// ReplicaOptions configure a replica (profile cache.mode = replica).
type ReplicaOptions struct {
	// Profile and Upstream name the profile in events and logs.
	Profile, Upstream string
	// Interval is cache.sync_interval; Jitter (0..1) spreads it by ±Jitter.
	Interval time.Duration
	Jitter   float64
	Events   events.Sink
	Logger   *slog.Logger
	// Now and Rand ([0,1)) are the clock and the jitter source (tests).
	Now  func() time.Time
	Rand func() float64
}

// Snapshot is one synced copy of a profile. Data belongs to the caller
// (the directory); Entries counts its users.
type Snapshot struct {
	Data    any
	Entries int
	At      time.Time
}

// SyncFunc fetches a complete copy of the profile from the upstream.
type SyncFunc func(ctx context.Context) (data any, entries int, err error)

// Replica keeps the last complete copy of a profile in memory and renews
// it in the background (SPEC §5.1 replica). A failed sync keeps the copy
// it has and emits replica_sync_failed. It outlives reloads that leave the
// profile unchanged; Run is started by each daemon generation.
type Replica struct {
	o      ReplicaOptions
	snap   atomic.Pointer[Snapshot]
	syncMu sync.Mutex
	force  chan struct{}

	mu          sync.Mutex
	lastAttempt time.Time
	lastFailed  bool
}

// NewReplica builds an empty replica.
func NewReplica(o ReplicaOptions) *Replica {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Rand == nil {
		o.Rand = rand.Float64
	}
	if o.Events == nil {
		o.Events = events.Discard
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Interval <= 0 {
		o.Interval = 5 * time.Minute
	}
	return &Replica{o: o, force: make(chan struct{}, 1)}
}

// Current returns the synced copy, if any.
func (r *Replica) Current() (data any, at time.Time, ok bool) {
	s := r.snap.Load()
	if s == nil {
		return nil, time.Time{}, false
	}
	return s.Data, s.At, true
}

// Stats returns the age and the entry count of the copy (ok = synced once).
func (r *Replica) Stats() (age time.Duration, entries int, ok bool) {
	s := r.snap.Load()
	if s == nil {
		return 0, 0, false
	}
	return r.o.Now().Sub(s.At), s.Entries, true
}

// Trigger asks the running loop for a sync now (aldapctl sync,
// POST /v1/profiles/{name}/sync); a request already pending absorbs it.
func (r *Replica) Trigger() {
	select {
	case r.force <- struct{}{}:
	default:
	}
}

// Sync fetches a new copy now. Syncs are serialized; the copy is replaced
// only by a complete successful fetch.
func (r *Replica) Sync(ctx context.Context, fn SyncFunc) error {
	r.syncMu.Lock()
	defer r.syncMu.Unlock()
	start := r.o.Now()
	data, n, err := fn(ctx)
	r.mu.Lock()
	r.lastAttempt, r.lastFailed = r.o.Now(), err != nil
	r.mu.Unlock()
	prev := r.snap.Load()
	ageS := 0
	if prev != nil {
		ageS = int(r.o.Now().Sub(prev.At) / time.Second)
	}
	ev := events.Event{Profile: r.o.Profile, Upstream: r.o.Upstream, Duration: r.o.Now().Sub(start)}
	if err != nil {
		kept := 0
		if prev != nil {
			kept = prev.Entries
		}
		ev.Event, ev.Level, ev.Reason = events.ReplicaSyncFailed, events.LevelMedium, syncReason(err)
		ev.Data = map[string]any{"age_s": ageS, "entries": kept}
		r.o.Events.Emit(ev)
		r.o.Logger.Warn("replica sync failed, keeping the last copy", "profile", r.o.Profile, "age_s", ageS, "entries", kept, "err", err)
		return err
	}
	r.snap.Store(&Snapshot{Data: data, Entries: n, At: r.o.Now()})
	ev.Event, ev.Level = events.ReplicaSynced, events.LevelLow
	ev.Data = map[string]any{"age_s": ageS, "entries": n}
	r.o.Events.Emit(ev)
	r.o.Logger.Info("replica synced", "profile", r.o.Profile, "entries", n)
	return nil
}

func syncReason(err error) string {
	switch {
	case errors.Is(err, upstream.ErrUnavailable), errors.Is(err, upstream.ErrClosed), errors.Is(err, upstream.ErrPoolExhausted):
		return "upstream_unavailable"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "canceled"
	}
	return "upstream_error"
}

// delay is the wait before the next sync: none without a copy or after a
// trigger, the jittered interval after the last success, at most
// retryAfterFailure after a failure.
func (r *Replica) delay() time.Duration {
	r.mu.Lock()
	last, failed := r.lastAttempt, r.lastFailed
	r.mu.Unlock()
	s := r.snap.Load()
	if last.IsZero() && s != nil {
		last = s.At // a copy kept across a reload
	}
	if last.IsZero() {
		return 0
	}
	j := min(max(r.o.Jitter, 0), 1)
	interval := time.Duration(float64(r.o.Interval) * (1 + j*(2*r.o.Rand()-1)))
	if failed {
		interval = min(interval, retryAfterFailure)
	}
	return max(interval-r.o.Now().Sub(last), 0)
}

// Run syncs at once when there is no copy, then every jittered interval
// or on Trigger, until ctx ends.
func (r *Replica) Run(ctx context.Context, fn SyncFunc) {
	for {
		t := time.NewTimer(r.delay())
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		case <-r.force:
			t.Stop()
		}
		_ = r.Sync(ctx, fn) //nolint:errcheck // reported by event and log
	}
}
