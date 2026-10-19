package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/ids"
	"github.com/alstdev/aldap/internal/listener"
	"github.com/alstdev/aldap/internal/metrics"
	"github.com/alstdev/aldap/internal/profile"
	"github.com/alstdev/aldap/internal/ratelimit"
	"github.com/alstdev/aldap/internal/secret"
	"github.com/alstdev/aldap/internal/tlsutil"
	"github.com/alstdev/aldap/internal/upstream"
	"github.com/alstdev/aldap/internal/vdir"
)

// certCheckInterval is how often server certificates are checked for
// renewal and expiry.
const certCheckInterval = time.Hour

// sweepInterval is how often expired locks and attack timers are checked.
const sweepInterval = time.Second

// runtimeState is what survives a reload: the event bus (seq, ring buffer),
// the rate-limit tables and the detector state. serve creates one per
// process; tests may pass their own through daemonOptions.
type runtimeState struct {
	bus          *events.Bus
	limiter      *ratelimit.Limiter
	ids          *ids.Engine
	metrics      *metrics.Metrics
	lockdownAuto atomic.Bool
}

// newRuntimeState builds the process-wide state from the first configuration.
func newRuntimeState(cfg *config.Config, log *slog.Logger, host string) (*runtimeState, error) {
	m := metrics.New(version, commit, date)
	bus, err := events.BusFromConfig(cfg.Events, events.Options{Host: host, Logger: log, Metrics: m})
	if err != nil {
		return nil, err
	}
	rs := &runtimeState{bus: bus, metrics: m}
	rs.limiter = ratelimit.New(ratelimit.Options{Events: rs, Logger: log, Metrics: m})
	rs.ids = ids.New(cfg.Intrusion, ids.Options{Events: rs, Logger: log, OnAttack: rs.onAttack, OnAttackEnd: rs.onAttackEnd, Metrics: m})
	return rs, nil
}

// Emit implements events.Sink: every event reaches the bus and the
// indicator scoring of the detectors.
func (r *runtimeState) Emit(e events.Event) {
	r.bus.Emit(e)
	r.ids.Note(e)
}

// onAttack marks the sources for the tarpit and enters lockdown when
// [ratelimit.lockdown].auto is set and the attack is high level.
func (r *runtimeState) onAttack(a ids.Attack) {
	for _, ip := range a.IPs {
		r.limiter.SetAttack(ip, true)
	}
	if a.Level == events.LevelHigh && r.lockdownAuto.Load() {
		r.limiter.SetLockdown(true, ratelimit.SourceIDs)
	}
}

func (r *runtimeState) onAttackEnd(a ids.Attack) {
	for _, ip := range a.IPs {
		r.limiter.SetAttack(ip, false)
	}
}

// daemonOptions tune a daemon build (tests inject writers and clocks).
type daemonOptions struct {
	// LogOut receives slog output and events (default stderr).
	LogOut io.Writer
	// Secrets resolves passwords (default secret.Default).
	Secrets secret.Resolver
	// Argon2 overrides the client_bind hash cost (tests).
	Argon2 profile.Argon2Params
	// NoPersistCerts keeps issued certificates in memory (tests).
	NoPersistCerts bool
	// Hostname overrides os.Hostname for certificate SANs.
	Hostname string
	// EventsOut receives the stdout event sink (default os.Stdout).
	EventsOut io.Writer
	// State is the process-wide runtime state (nil = created by buildDaemon).
	State *runtimeState
}

// daemon is one built configuration: upstreams, profiles and listeners.
type daemon struct {
	cfg    *config.Config
	log    *slog.Logger
	events events.Sink
	opts   daemonOptions

	upstreams map[string]*upstream.Upstream
	profiles  []*servedProfile
	global    *listener.Limiter
	state     *runtimeState

	mu       sync.Mutex
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	started  bool
	stopOnce sync.Once
}

// servedProfile is one [profile.<name>] with its listeners.
type servedProfile struct {
	name      string
	cfg       *config.Profile
	tls       *tlsutil.Manager
	dir       *vdir.Directory
	servers   []*listener.Server
	addrs     []string
	listeners []net.Listener
}

// newLogger builds the process logger from [server].
func newLogger(s config.Server, out io.Writer) *slog.Logger {
	lvl := slog.LevelInfo
	switch s.LogLevel {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}
	ho := &slog.HandlerOptions{Level: lvl}
	if s.LogFormat == "json" {
		return slog.New(slog.NewJSONHandler(out, ho))
	}
	return slog.New(slog.NewTextHandler(out, ho))
}

// buildDaemon validates cfg (strict files) and constructs every component
// without opening sockets or touching the upstreams.
func buildDaemon(cfg *config.Config, o daemonOptions) (*daemon, error) {
	if o.LogOut == nil {
		o.LogOut = os.Stderr
	}
	rep := config.Validator{StrictFiles: true, Secrets: o.Secrets}.Validate(cfg)
	if !rep.OK() {
		return nil, fmt.Errorf("configuration invalid:\n%s", rep.Error())
	}
	log := newLogger(cfg.Server, o.LogOut)
	for _, w := range rep.Warnings {
		log.Warn("configuration warning", "key", w.Path, "msg", w.Msg)
	}
	host := o.Hostname
	if host == "" {
		if h, err := os.Hostname(); err == nil {
			host = h
		}
	}
	state := o.State
	if state == nil {
		var err error
		if state, err = newRuntimeState(cfg, log, host); err != nil {
			return nil, err
		}
	} else {
		state.ids.Reconfigure(cfg.Intrusion)
	}
	state.lockdownAuto.Store(cfg.Ratelimit.Lockdown.Auto)
	if err := state.bus.Configure(cfg.Events, events.ConfigureOptions{Stdout: o.EventsOut, Secrets: o.Secrets, UserAgent: "aldap/" + version}); err != nil {
		return nil, err
	}
	d := &daemon{cfg: cfg, log: log, events: state, opts: o, upstreams: map[string]*upstream.Upstream{},
		global: listener.NewLimiter(cfg.Server.MaxConnections), state: state}
	if err := d.buildUpstreams(); err != nil {
		return nil, err
	}
	if err := d.buildProfiles(); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *daemon) buildUpstreams() error {
	for _, name := range sortedKeys(d.cfg.Upstreams) {
		ucfg := d.cfg.Upstreams[name]
		pw, warns, err := d.opts.Secrets.Resolve(ucfg.BindPasswordSource())
		if err != nil {
			return fmt.Errorf("upstream.%s.bind_password: %w", name, err)
		}
		for _, w := range warns {
			d.log.Warn("secret warning", "key", "upstream."+name+".bind_password", "msg", w.Msg)
		}
		u, err := upstream.New(name, ucfg, pw.Reveal(), upstream.Options{Logger: d.log, Events: upstream.EventFunc(d.upstreamEvent), Metrics: d.state.metrics})
		if err != nil {
			return err
		}
		d.upstreams[name] = u
	}
	return nil
}

// upstreamEvent adapts package-local upstream events to the event stream.
func (d *daemon) upstreamEvent(e upstream.Event) {
	d.events.Emit(events.Event{Event: e.Kind, Level: e.Level, Upstream: e.Upstream, UpstreamServer: e.Server, Data: e.Data})
}

func (d *daemon) buildProfiles() error {
	for _, name := range sortedKeys(d.cfg.Profiles) {
		sp, err := d.buildProfile(name, d.cfg.Profiles[name])
		if err != nil {
			return err
		}
		d.profiles = append(d.profiles, sp)
	}
	if len(d.profiles) == 0 {
		return errors.New("no profile to serve")
	}
	return nil
}

// profileSearcher picks the data source of a profile: the upstream for
// proxy, a Mock for mock, nothing for honeypot (SPEC §3.4 mode).
func (d *daemon) profileSearcher(name string, pcfg *config.Profile) (vdir.Searcher, error) {
	switch pcfg.Mode {
	case "mock":
		base := ""
		if len(pcfg.Bases) > 0 {
			base = pcfg.Bases[0]
		}
		m, err := vdir.LoadMock(pcfg.Mock.File, base)
		if err != nil {
			return nil, fmt.Errorf("profile.%s.mock.file: %w", name, err)
		}
		if len(pcfg.Bases) == 0 {
			pcfg.Bases = []string{m.BaseDN()}
		}
		d.log.Info("mock profile loaded", "profile", name, "file", pcfg.Mock.File, "entries", m.Len())
		return m, nil
	case "honeypot":
		d.log.Warn("honeypot profile: every bind and search is reported as a honeytoken hit", "profile", name)
		return nil, nil
	}
	up, ok := d.upstreams[pcfg.Upstream]
	if !ok {
		return nil, fmt.Errorf("profile.%s.upstream: unknown upstream %q", name, pcfg.Upstream)
	}
	return up, nil
}

func (d *daemon) buildProfile(name string, pcfg *config.Profile) (*servedProfile, error) {
	up, err := d.profileSearcher(name, pcfg)
	if err != nil {
		return nil, err
	}
	clientPW := ""
	if pcfg.ClientBind.DN != "" && pcfg.ClientBind.PasswordHash == "" {
		pw, warns, err := d.opts.Secrets.Resolve(pcfg.ClientBind.PasswordSource())
		if err != nil {
			return nil, fmt.Errorf("profile.%s.client_bind.password: %w", name, err)
		}
		for _, w := range warns {
			d.log.Warn("secret warning", "key", "profile."+name+".client_bind.password", "msg", w.Msg)
		}
		clientPW = pw.Reveal()
	}
	rules, err := profile.Compile(name, pcfg, d.cfg.Upstreams[pcfg.Upstream], profile.Options{ClientPassword: clientPW, Argon2: d.opts.Argon2})
	if err != nil {
		return nil, err
	}
	sp := &servedProfile{name: name, cfg: pcfg, addrs: pcfg.Listen}
	offersStartTLS := pcfg.Transport == listener.TransportStartTLS || pcfg.Transport == listener.TransportLDAPStartTLS
	guard, err := d.state.limiter.Policy(name, d.cfg.Ratelimit.With(pcfg.Ratelimit))
	if err != nil {
		return nil, fmt.Errorf("profile.%s: %w", name, err)
	}
	honeyLock := d.cfg.Intrusion.Honeytoken.LockDuration.D()
	if !d.cfg.Intrusion.Honeytoken.Enabled {
		honeyLock = 0
	}
	sp.dir = vdir.New(rules, up, vdir.Options{Logger: d.log, Events: d.events, Version: version, StartTLS: offersStartTLS,
		Guard: guard, Observer: d.state.ids, HoneytokenLock: honeyLock, Metrics: d.state.metrics})
	lcfg := listener.Config{
		Profile: name, Transport: pcfg.Transport, StartTLSRequired: pcfg.StartTLSRequired, Handler: sp.dir, Fingerprints: d.state.ids, Metrics: d.state.metrics,
		MaxRequestBytes: int64(pcfg.Limits.MaxRequestBytes), IdleTimeout: pcfg.Limits.IdleTimeout.D(),
		PerIP: listener.NewIPLimiter(pcfg.Limits.MaxConnsPerIP), Global: d.global, Logger: d.log, Events: d.events,
	}
	if pcfg.Transport != listener.TransportLDAP {
		sp.tls, err = d.buildTLS(name, pcfg)
		if err != nil {
			return nil, err
		}
		lcfg.TLS = sp.tls.Config()
	}
	for range pcfg.Listen {
		s, err := listener.New(lcfg)
		if err != nil {
			return nil, fmt.Errorf("profile.%s: %w", name, err)
		}
		sp.servers = append(sp.servers, s)
	}
	return sp, nil
}

// effectiveTLS merges [profile.<name>.tls] over [tls].
func effectiveTLS(global config.TLS, o config.TLSOverride) config.TLS {
	t := global
	if o.Mode != nil {
		t.Mode = *o.Mode
	}
	if o.CADir != nil {
		t.CADir = *o.CADir
	}
	if o.AutoInit != nil {
		t.AutoInit = *o.AutoInit
	}
	if o.Cert != nil {
		t.Cert = *o.Cert
	}
	if o.Key != nil {
		t.Key = *o.Key
	}
	if o.AutoRenewBefore != nil {
		t.AutoRenewBefore = *o.AutoRenewBefore
	}
	if o.ExpiryAlertBefore != nil {
		t.ExpiryAlertBefore = *o.ExpiryAlertBefore
	}
	if o.SAN != nil {
		t.SAN = *o.SAN
	}
	if o.KeyType != nil {
		t.KeyType = *o.KeyType
	}
	if o.MinVersion != nil {
		t.MinVersion = *o.MinVersion
	}
	if o.ClientAuth != nil {
		t.ClientAuth = *o.ClientAuth
	}
	if o.ClientCA != nil {
		t.ClientCA = *o.ClientCA
	}
	return t
}

// certSANs lists the names a profile's certificate must cover: the listen
// hosts (or the host name and loopback for wildcard addresses) plus tls.san.
func certSANs(listen, extra []string, hostname string) tlsutil.SANs {
	names := make([]string, 0, len(listen)+len(extra))
	for _, addr := range listen {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		if host == "" || host == "0.0.0.0" || host == "::" {
			names = append(names, hostname, "localhost", "127.0.0.1", "::1")
			continue
		}
		names = append(names, host)
	}
	names = append(names, extra...)
	return tlsutil.ParseSANs(names...)
}

func (d *daemon) buildTLS(name string, pcfg *config.Profile) (*tlsutil.Manager, error) {
	t := effectiveTLS(d.cfg.TLS, pcfg.TLS)
	hostname := d.opts.Hostname
	if hostname == "" {
		h, err := os.Hostname()
		if err != nil {
			d.log.Warn("hostname unavailable, certificate gets no host name SAN", "err", err)
			h = ""
		}
		hostname = h
	}
	m, err := tlsutil.New(tlsutil.Options{
		Profile: name, Mode: t.Mode, CADir: t.CADir, AutoInit: t.AutoInit, Cert: t.Cert, Key: t.Key, KeyType: tlsutil.KeyType(t.KeyType),
		SANs: certSANs(pcfg.Listen, t.SAN, hostname), AutoRenewBefore: t.AutoRenewBefore.D(), ExpiryAlertBefore: t.ExpiryAlertBefore.D(),
		MinVersion: t.MinVersion, ClientAuth: t.ClientAuth, ClientCA: t.ClientCA, NoPersist: d.opts.NoPersistCerts, Metrics: d.state.metrics,
		Logger: d.log, Events: d.events,
	})
	if err != nil {
		return nil, fmt.Errorf("profile.%s.tls: %w", name, err)
	}
	return m, nil
}

// start opens every listener (failing fast when one address cannot be
// bound), starts the upstream health loops and the certificate checks.
func (d *daemon) start(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.started {
		return errors.New("daemon already started")
	}
	ctx, d.cancel = context.WithCancel(ctx)
	lc := net.ListenConfig{}
	for _, sp := range d.profiles {
		for _, addr := range sp.addrs {
			ln, err := lc.Listen(ctx, "tcp", addr)
			if err != nil {
				d.closeListeners()
				d.cancel()
				return fmt.Errorf("profile.%s: listen %s: %w", sp.name, addr, err)
			}
			sp.listeners = append(sp.listeners, ln)
		}
	}
	d.started = true
	for _, u := range d.upstreams {
		u.Start(ctx)
	}
	names := make([]string, 0, len(d.profiles))
	for _, sp := range d.profiles {
		names = append(names, sp.name)
		for i, ln := range sp.listeners {
			srv := sp.servers[i]
			d.wg.Add(1)
			go func() {
				defer d.wg.Done()
				if err := srv.Serve(ln); err != nil && !errors.Is(err, listener.ErrServerClosed) {
					d.log.Error("listener stopped", "profile", sp.name, "addr", ln.Addr().String(), "err", err)
				}
			}()
		}
		if sp.tls != nil {
			d.wg.Add(1)
			go func() {
				defer d.wg.Done()
				d.certLoop(ctx, sp.tls)
			}()
		}
	}
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.sweepLoop(ctx)
	}()
	d.events.Emit(events.Event{Event: events.Startup, Level: events.LevelLow, Data: map[string]any{"version": version, "profiles": names}})
	d.log.Info("aldap started", "version", version, "profiles", names)
	return nil
}

func (d *daemon) certLoop(ctx context.Context, m *tlsutil.Manager) {
	m.Check()
	t := time.NewTicker(certCheckInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Check()
		}
	}
}

// sweepLoop expires locks and drives the attack timers of the detectors.
func (d *daemon) sweepLoop(ctx context.Context) {
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	window := d.cfg.Ratelimit.IP.Window.D()
	if w := d.cfg.Ratelimit.Account.Window.D(); w > window {
		window = w
	}
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			d.state.limiter.Sweep(now, window)
			d.state.ids.Tick()
		}
	}
}

func (d *daemon) closeListeners() {
	for _, sp := range d.profiles {
		for _, ln := range sp.listeners {
			_ = ln.Close() //nolint:errcheck // best effort during start failure
		}
		sp.listeners = nil
	}
}

// addrs returns the bound addresses of a profile (after start).
func (d *daemon) addrs(profileName string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, sp := range d.profiles {
		if sp.name == profileName {
			out := make([]string, 0, len(sp.listeners))
			for _, ln := range sp.listeners {
				out = append(out, ln.Addr().String())
			}
			return out
		}
	}
	return nil
}

// stop drains the listeners within shutdown_timeout, closes the upstreams
// and emits shutdown (SPEC §5.3).
func (d *daemon) stop() {
	d.stopOnce.Do(func() {
		d.mu.Lock()
		started := d.started
		d.mu.Unlock()
		if started {
			ctx, cancel := context.WithTimeout(context.Background(), d.cfg.Server.ShutdownTimeout.D())
			defer cancel()
			var wg sync.WaitGroup
			for _, sp := range d.profiles {
				for _, s := range sp.servers {
					wg.Add(1)
					go func() {
						defer wg.Done()
						if err := s.Shutdown(ctx); err != nil {
							d.log.Warn("connections cut at shutdown timeout", "profile", sp.name)
						}
					}()
				}
			}
			wg.Wait()
			d.cancel()
			d.wg.Wait()
		}
		for _, u := range d.upstreams {
			u.Close()
		}
		if started {
			d.events.Emit(events.Event{Event: events.Shutdown, Level: events.LevelLow, Data: map[string]any{"version": version}})
			d.log.Info("aldap stopped")
		}
		d.state.bus.Flush()
	})
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// loadDaemon reads and builds the configuration at path.
func loadDaemon(path string, required bool, o daemonOptions) (*daemon, error) {
	cfg, err := config.LoadFile(path, required)
	if err != nil {
		return nil, err
	}
	return buildDaemon(cfg, o)
}

// describeListen formats the listen addresses for log lines.
func describeListen(d *daemon) string {
	parts := make([]string, 0, len(d.profiles))
	for _, sp := range d.profiles {
		parts = append(parts, sp.name+"="+strings.Join(sp.addrs, ","))
	}
	return strings.Join(parts, " ")
}
