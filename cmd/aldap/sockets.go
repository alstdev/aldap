package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/alstdev/aldap/internal/listener"
)

// socketSpec is one listen address of a daemon generation.
type socketSpec struct {
	key     string
	addr    string
	profile *servedProfile
}

// socketKey identifies a listening socket across reloads: the configured
// address, so an address that stays in the configuration keeps its socket
// and its connections even when it moves to another profile. Ephemeral
// ports (":0", tests) are never shared, so their key also names the
// profile and the occurrence.
func socketKey(profile, addr string, seen map[string]int) string {
	key := addr
	if _, port, err := net.SplitHostPort(addr); err == nil && port == "0" {
		key = profile + "|" + addr
	}
	n := seen[key]
	seen[key] = n + 1
	if n > 0 {
		key += "#" + strconv.Itoa(n)
	}
	return key
}

// sockets lists the listen addresses of the generation in profile order.
func (d *daemon) sockets() []socketSpec {
	seen := map[string]int{}
	var out []socketSpec
	for _, sp := range d.profiles {
		for _, addr := range sp.addrs {
			out = append(out, socketSpec{key: socketKey(sp.name, addr, seen), addr: addr, profile: sp})
		}
	}
	return out
}

// socketPool holds the listening sockets and their servers. It outlives
// daemon generations: a reload reconfigures the server of every address
// that stays, opens the added ones and drains the removed ones, so
// clients on unchanged addresses keep their connections (SPEC §3.6).
type socketPool struct {
	mu      sync.Mutex
	entries map[string]*socketEntry
	// serving counts the Serve goroutines; bg counts drains and
	// generation retirements running in the background.
	serving sync.WaitGroup
	bg      sync.WaitGroup
	closed  bool
}

// socketEntry is one listening socket; srv is nil until the first apply.
type socketEntry struct {
	addr    string
	profile string
	ln      net.Listener
	srv     *listener.Server
}

func newSocketPool() *socketPool {
	return &socketPool{entries: map[string]*socketEntry{}}
}

// open binds the addresses of specs that have no socket yet. On failure
// the sockets it opened are closed again and the pool is unchanged.
func (p *socketPool) open(ctx context.Context, specs []socketSpec) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return errors.New("listeners already shut down")
	}
	lc := net.ListenConfig{}
	var opened []string
	for _, s := range specs {
		if _, ok := p.entries[s.key]; ok {
			continue
		}
		ln, err := lc.Listen(ctx, "tcp", s.addr)
		if err != nil {
			for _, k := range opened {
				_ = p.entries[k].ln.Close() //nolint:errcheck // undoing a failed open
				delete(p.entries, k)
			}
			return fmt.Errorf("profile.%s: listen %s: %w", s.profile.name, s.addr, err)
		}
		p.entries[s.key] = &socketEntry{addr: s.addr, ln: ln}
		opened = append(opened, s.key)
	}
	return nil
}

// apply makes the generation d serve every socket of specs: a running
// server is reconfigured (requests in flight finish under the previous
// configuration), a new socket gets a server, and sockets not in specs are
// drained and closed in the background within the shutdown timeout. It
// returns the waits for the requests still running under the previous
// configurations.
func (p *socketPool) apply(d *daemon, specs []socketSpec) []func(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var waits []func(context.Context) error
	keep := make(map[string]bool, len(specs))
	for _, s := range specs {
		keep[s.key] = true
		e := p.entries[s.key]
		if e == nil {
			// open ran under the same lock order before apply; a missing
			// socket here means the pool was shut down in between.
			continue
		}
		e.profile = s.profile.name
		if e.srv != nil {
			wait, err := e.srv.Reconfigure(s.profile.lcfg)
			if err != nil {
				d.log.Error("listener not reconfigured", "profile", s.profile.name, "addr", e.ln.Addr().String(), "err", err)
				continue
			}
			waits = append(waits, wait)
			continue
		}
		srv, err := listener.New(s.profile.lcfg)
		if err != nil {
			// buildProfile checked the configuration; never reached.
			d.log.Error("listener not started", "profile", s.profile.name, "addr", e.ln.Addr().String(), "err", err)
			_ = e.ln.Close() //nolint:errcheck // the socket has no server
			delete(p.entries, s.key)
			continue
		}
		e.srv = srv
		p.serve(d.log, e)
	}
	timeout := d.cfg.Server.ShutdownTimeout.D()
	for key, e := range p.entries {
		if keep[key] {
			continue
		}
		delete(p.entries, key)
		d.log.Info("listener removed, draining", "profile", e.profile, "addr", e.ln.Addr().String())
		p.drain(e, timeout)
	}
	return waits
}

// serve runs the accept loop of e; the caller holds p.mu.
func (p *socketPool) serve(log *slog.Logger, e *socketEntry) {
	srv, ln, profile := e.srv, e.ln, e.profile
	p.serving.Add(1)
	go func() {
		defer p.serving.Done()
		if err := srv.Serve(ln); err != nil && !errors.Is(err, listener.ErrServerClosed) {
			log.Error("listener stopped", "profile", profile, "addr", ln.Addr().String(), "err", err)
		}
	}()
}

// drain shuts the server of a removed socket down in the background.
func (p *socketPool) drain(e *socketEntry, timeout time.Duration) {
	p.bg.Add(1)
	go func() {
		defer p.bg.Done()
		if e.srv == nil {
			_ = e.ln.Close() //nolint:errcheck // never served
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		_ = e.srv.Shutdown(ctx) //nolint:errcheck // a cut drain is logged by the caller of shutdown, not here
	}()
}

// background runs f as part of the pool's background work, which
// shutdown waits for.
func (p *socketPool) background(f func()) {
	p.bg.Add(1)
	go func() {
		defer p.bg.Done()
		f()
	}()
}

// addrs returns the bound addresses of specs (port 0 resolved).
func (p *socketPool) addrs(specs []socketSpec) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(specs))
	for _, s := range specs {
		if e := p.entries[s.key]; e != nil {
			out = append(out, e.ln.Addr().String())
		}
	}
	return out
}

// shutdown drains every server in parallel within ctx (SPEC §5.3) and
// waits for the background drains and retirements; connections still
// busy at the deadline are cut and logged.
func (p *socketPool) shutdown(ctx context.Context, log *slog.Logger) {
	p.mu.Lock()
	p.closed = true
	entries := p.entries
	p.entries = map[string]*socketEntry{}
	p.mu.Unlock()
	var wg sync.WaitGroup
	for _, e := range entries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e.srv == nil {
				_ = e.ln.Close() //nolint:errcheck // never served
				return
			}
			if err := e.srv.Shutdown(ctx); err != nil {
				log.Warn("connections cut at shutdown timeout", "profile", e.profile, "addr", e.addr)
			}
		}()
	}
	wg.Wait()
	p.serving.Wait()
	p.bg.Wait()
}
