package cache

import (
	"container/list"
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alstdev/aldap/internal/ldapfilter"
	"github.com/alstdev/aldap/internal/upstream"
)

// Source is the search side of an upstream (*upstream.Upstream).
type Source interface {
	Search(ctx context.Context, req upstream.SearchRequest) (*upstream.Result, error)
}

// statusReporter is implemented by *upstream.Upstream.
type statusReporter interface {
	Status() []upstream.ServerStatus
}

// allDown reports whether the upstream marks every server down (unknown,
// e.g. before the first health check, is not down).
func allDown(src Source) bool {
	sr, ok := src.(statusReporter)
	if !ok {
		return false
	}
	st := sr.Status()
	for _, s := range st {
		if s.State != upstream.StateDown {
			return false
		}
	}
	return len(st) > 0
}

// TTLOptions configure a TTL cache (profile cache.mode = ttl).
type TTLOptions struct {
	// TTL is how long a result is served without asking the upstream.
	TTL time.Duration
	// MaxEntries bounds the directory entries kept over all results; the
	// least recently used results are evicted first. A single result
	// larger than the bound is not cached.
	MaxEntries int
	// StaleWhileDown serves expired results up to StaleMax old while every
	// upstream server is down.
	StaleWhileDown bool
	StaleMax       time.Duration
	// Now is the clock (tests).
	Now func() time.Time
}

// TTL caches upstream search results (SPEC §5.1 ttl). The key is the
// whole request after the profile rewrote it: base, scope, filter,
// attributes and size limit, so one store serves one profile. It is safe
// for concurrent use and outlives the upstream it wraps (reload).
type TTL struct {
	o TTLOptions

	mu    sync.Mutex
	items map[string]*list.Element
	lru   *list.List // front = most recently used
	size  int        // directory entries held
}

type ttlItem struct {
	key  string
	res  upstream.Result
	at   time.Time
	cost int
}

// NewTTL builds an empty TTL cache.
func NewTTL(o TTLOptions) *TTL {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.MaxEntries <= 0 {
		o.MaxEntries = 10000
	}
	return &TTL{o: o, items: map[string]*list.Element{}, lru: list.New()}
}

// Wrap returns a Source that answers from the cache and asks up on a miss.
func (t *TTL) Wrap(up Source) Source { return &ttlSource{t: t, up: up} }

// Len returns the number of directory entries held (cache_entries).
func (t *TTL) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.size
}

// Purge drops every result.
func (t *TTL) Purge() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.items = map[string]*list.Element{}
	t.lru.Init()
	t.size = 0
}

// Sweep drops the results that can no longer be served, fresh or stale.
func (t *TTL) Sweep() {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.o.Now()
	for el := t.lru.Back(); el != nil; {
		prev := el.Prev()
		if it := itemOf(el); now.Sub(it.at) > t.retention() {
			t.remove(el)
		}
		el = prev
	}
}

// retention is how long a result is kept: its TTL, or the stale window
// when stale results may be served.
func (t *TTL) retention() time.Duration {
	if t.o.StaleWhileDown && t.o.StaleMax > t.o.TTL {
		return t.o.StaleMax
	}
	return t.o.TTL
}

// itemOf returns the item an element of the LRU list holds.
func itemOf(el *list.Element) *ttlItem {
	if it, ok := el.Value.(*ttlItem); ok {
		return it
	}
	return &ttlItem{}
}

func (t *TTL) remove(el *list.Element) {
	it := itemOf(el)
	t.lru.Remove(el)
	delete(t.items, it.key)
	t.size -= it.cost
}

// lookup returns a copy of the cached result and its age.
func (t *TTL) lookup(key string) (upstream.Result, time.Duration, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	el, ok := t.items[key]
	if !ok {
		return upstream.Result{}, 0, false
	}
	it := itemOf(el)
	age := t.o.Now().Sub(it.at)
	if age > t.retention() {
		t.remove(el)
		return upstream.Result{}, 0, false
	}
	t.lru.MoveToFront(el)
	return it.res, age, true
}

func (t *TTL) store(key string, res *upstream.Result) {
	cost := max(len(res.Entries), 1)
	if cost > t.o.MaxEntries {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if el, ok := t.items[key]; ok {
		t.remove(el)
	}
	it := &ttlItem{key: key, res: *res, at: t.o.Now(), cost: cost}
	it.res.Cached, it.res.Stale, it.res.Age = false, false, 0
	t.items[key] = t.lru.PushFront(it)
	t.size += cost
	for t.size > t.o.MaxEntries {
		t.remove(t.lru.Back())
	}
}

type ttlSource struct {
	t  *TTL
	up Source
}

// Search serves a fresh cached result, else asks the upstream and caches
// the answer. When the upstream is unavailable (every server down) an
// expired result within stale_max is served instead, marked Stale.
func (s *ttlSource) Search(ctx context.Context, req upstream.SearchRequest) (*upstream.Result, error) {
	key := Key(req)
	cached, age, ok := s.t.lookup(key)
	if ok && age < s.t.o.TTL {
		return hit(cached, age, false), nil
	}
	stale := ok && s.t.o.StaleWhileDown && age <= s.t.o.StaleMax
	if stale && allDown(s.up) {
		return hit(cached, age, true), nil
	}
	res, err := s.up.Search(ctx, req)
	if err != nil {
		if stale && (errors.Is(err, upstream.ErrUnavailable) || errors.Is(err, upstream.ErrPoolExhausted)) {
			return hit(cached, age, true), nil
		}
		return nil, err
	}
	s.t.store(key, res)
	return res, nil
}

func hit(r upstream.Result, age time.Duration, stale bool) *upstream.Result {
	r.Cached, r.Stale, r.Age = true, stale, age
	return &r
}

// Key identifies a search request: canonical base, scope, normalized
// filter, lower-cased sorted attributes and size limit. The time limit is
// not part of it (it does not change the answer of a complete search).
func Key(req upstream.SearchRequest) string {
	base := strings.ToLower(req.Base)
	if dn, err := ldapfilter.ParseDN(req.Base); err == nil {
		base = dn.Canonical()
	}
	f := "(objectClass=*)"
	if req.Filter != nil {
		f = req.Filter.Normalize().String()
	}
	attrs := make([]string, len(req.Attrs))
	for i, a := range req.Attrs {
		attrs[i] = strings.ToLower(a)
	}
	slices.Sort(attrs)
	attrs = slices.Compact(attrs)
	var b strings.Builder
	b.WriteString(base)
	b.WriteByte(0)
	b.WriteString(strconv.Itoa(int(req.Scope)))
	b.WriteByte(0)
	b.WriteString(f)
	b.WriteByte(0)
	b.WriteString(strings.Join(attrs, ","))
	b.WriteByte(0)
	b.WriteString(strconv.Itoa(req.SizeLimit))
	return b.String()
}
