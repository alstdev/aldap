package upstream

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// pool is a bounded LIFO pool of connections to one server. Get blocks until
// a slot is free or ctx ends; Put returns a healthy connection for reuse or
// closes a broken one. Idle connections older than maxIdle are closed lazily.
type pool struct {
	size    int
	maxIdle time.Duration
	dial    func(ctx context.Context) (ldapConn, error)
	now     func() time.Time
	log     *slog.Logger
	sem     chan struct{}

	mu     sync.Mutex
	idle   []idleConn
	closed bool
	active int
}

type idleConn struct {
	c     ldapConn
	since time.Time
}

func newPool(size int, maxIdle time.Duration, now func() time.Time, log *slog.Logger, dial func(ctx context.Context) (ldapConn, error)) *pool {
	if size < 1 {
		size = 1
	}
	return &pool{size: size, maxIdle: maxIdle, dial: dial, now: now, log: log, sem: make(chan struct{}, size)}
}

// get returns a connection; the caller must put it back.
func (p *pool) get(ctx context.Context) (ldapConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPoolExhausted, err)
	}
	select {
	case p.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %w", ErrPoolExhausted, ctx.Err())
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		<-p.sem
		return nil, ErrClosed
	}
	now := p.now()
	for len(p.idle) > 0 {
		ic := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]
		if ic.c.IsClosing() || (p.maxIdle > 0 && now.Sub(ic.since) > p.maxIdle) {
			closeQuietly(ic.c, p.log)
			continue
		}
		p.active++
		p.mu.Unlock()
		return ic.c, nil
	}
	p.active++
	p.mu.Unlock()
	c, err := p.dial(ctx)
	if err != nil {
		p.mu.Lock()
		p.active--
		p.mu.Unlock()
		<-p.sem
		return nil, fmt.Errorf("%w: %w", ErrConnect, err)
	}
	return c, nil
}

// put returns a connection; healthy ones go back to the idle stack.
func (p *pool) put(c ldapConn, healthy bool) {
	p.mu.Lock()
	p.active--
	if healthy && !p.closed && !c.IsClosing() {
		p.idle = append(p.idle, idleConn{c: c, since: p.now()})
		p.mu.Unlock()
		<-p.sem
		return
	}
	p.mu.Unlock()
	closeQuietly(c, p.log)
	<-p.sem
}

// reap closes idle connections older than maxIdle.
func (p *pool) reap() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.maxIdle <= 0 {
		return
	}
	now := p.now()
	kept := p.idle[:0]
	for _, ic := range p.idle {
		if now.Sub(ic.since) > p.maxIdle || ic.c.IsClosing() {
			closeQuietly(ic.c, p.log)
			continue
		}
		kept = append(kept, ic)
	}
	p.idle = kept
}

// drain closes every idle connection (e.g. after the server went down).
func (p *pool) drain() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, ic := range p.idle {
		closeQuietly(ic.c, p.log)
	}
	p.idle = nil
}

// close drains the pool and refuses further gets.
func (p *pool) close() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	p.drain()
}

// stats returns the idle and active connection counts.
func (p *pool) stats() (idle, active int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.idle), p.active
}
