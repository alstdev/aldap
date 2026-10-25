package record

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/listener"
	"github.com/alstdev/aldap/internal/vdir"
)

// MaxShadowSamples bounds the DNs listed per side of a shadow_diff (SPEC §6).
const MaxShadowSamples = 20

// Evaluator runs a search under the shadow rules: the shadow directory of
// the profile (*vdir.Directory without events, guard or observer).
type Evaluator interface {
	Evaluate(ctx context.Context, req vdir.TestRequest) (listener.Result, []listener.Entry)
}

// ShadowOptions configure a Shadow.
type ShadowOptions struct {
	// MaxParallel bounds the shadow searches running at once (default 4);
	// a client search arriving when all are busy is not shadowed.
	MaxParallel int
	// Timeout bounds one shadow search (default 10 s); a shadow search
	// that times out is not reported.
	Timeout time.Duration
	Events  events.Sink
	Logger  *slog.Logger
	Now     func() time.Time
}

// Shadow evaluates the shadow rules of a profile (SPEC §3.4 shadow.filter,
// shadow.bases) for every client search in the background and reports a
// different answer as shadow_diff. It implements vdir.Tap: the client
// already has its answer when Search is called, Search never waits (a busy
// limit skips the search) and a shadow search never touches the client
// connection.
type Shadow struct {
	ev  Evaluator
	o   ShadowOptions
	log *slog.Logger
	sem chan struct{}

	ctx    context.Context
	cancel context.CancelFunc
	life   sync.RWMutex
	closed bool
	wg     sync.WaitGroup

	skipped, timeouts, diffs atomic.Uint64
}

var _ vdir.Tap = (*Shadow)(nil)

// NewShadow builds the background runner over the shadow directory.
func NewShadow(ev Evaluator, o ShadowOptions) *Shadow {
	if o.MaxParallel <= 0 {
		o.MaxParallel = 4
	}
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	if o.Events == nil {
		o.Events = events.Discard
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	s := &Shadow{ev: ev, o: o, log: o.Logger, sem: make(chan struct{}, o.MaxParallel)}
	if s.log == nil {
		s.log = slog.Default()
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	return s
}

// Stats returns the searches skipped (limit busy), timed out and reported.
func (s *Shadow) Stats() (skipped, timeouts, diffs uint64) {
	return s.skipped.Load(), s.timeouts.Load(), s.diffs.Load()
}

// Search implements vdir.Tap.
func (s *Shadow) Search(t vdir.TapSearch) {
	if t.Local || t.Filter == nil {
		return
	}
	select {
	case s.sem <- struct{}{}:
	default:
		s.skipped.Add(1)
		return
	}
	s.life.RLock()
	if s.closed {
		s.life.RUnlock()
		<-s.sem
		return
	}
	s.wg.Add(1)
	s.life.RUnlock()
	// The connection context is read here, on the connection goroutine.
	ev := t.Conn.Event(events.ShadowDiff, events.LevelLow)
	go s.run(ev, t)
}

// Close cancels the running shadow searches and waits for them.
func (s *Shadow) Close() {
	s.life.Lock()
	s.closed = true
	s.life.Unlock()
	s.cancel()
	s.wg.Wait()
}

func (s *Shadow) run(ev events.Event, t vdir.TapSearch) {
	defer func() {
		if p := recover(); p != nil {
			s.log.Error("shadow search failed", "profile", ev.Profile, "conn_id", ev.ConnID, "panic", "recovered")
		}
		<-s.sem
		s.wg.Done()
	}()
	ctx, cancel := context.WithTimeout(s.ctx, s.o.Timeout)
	defer cancel()
	start := s.o.Now()
	res, entries := s.ev.Evaluate(ctx, vdir.TestRequest{Base: t.Base, Scope: t.Scope, Filter: t.RawFilter, Attrs: t.Attrs, SizeLimit: t.SizeLimit})
	if ctx.Err() != nil {
		s.timeouts.Add(1)
		s.log.Debug("shadow search not completed", "profile", ev.Profile, "conn_id", ev.ConnID, "err", ctx.Err())
		return
	}
	added, removed := diffEntries(t.Entries, entries)
	if len(added) == 0 && len(removed) == 0 && res.Code == t.Result.Code {
		return
	}
	s.diffs.Add(1)
	ev.Duration = s.o.Now().Sub(start)
	ev.Data = map[string]any{
		"base": t.Base, "scope": t.Scope.String(), "filter_norm": RedactFilter(t.Filter.Normalize()),
		"added": sample(added), "removed": sample(removed), "added_count": len(added), "removed_count": len(removed),
		"results": len(t.Entries), "shadow_results": len(entries),
		"result_code": t.Result.Code, "shadow_result_code": res.Code,
	}
	s.o.Events.Emit(ev)
}

// diffEntries returns the DNs only the shadow answer has (added) and those
// only the client answer has (removed), compared case-insensitively.
func diffEntries(main, shadow []listener.Entry) (added, removed []string) {
	removed, added = DiffDNList(dnList(main), dnList(shadow))
	return added, removed
}

func dnList(es []listener.Entry) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.DN)
	}
	return out
}

func sample(dns []string) []string {
	if len(dns) > MaxShadowSamples {
		dns = dns[:MaxShadowSamples]
	}
	if dns == nil {
		return []string{}
	}
	return dns
}
