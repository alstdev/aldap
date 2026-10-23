package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/alstdev/aldap/internal/api"
	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/tlsutil"
	"github.com/alstdev/aldap/internal/upstream"
	"github.com/alstdev/aldap/internal/vdir"
)

// backupLayout names aldap.toml.bak.<ts> (UTC).
const backupLayout = "20060102T150405Z"

// reloadRequest asks the serve loop for a reload and waits for the outcome.
type reloadRequest struct {
	done chan error
}

// controller is the api.Backend of the process: it follows the current
// daemon across reloads, routes reloads through the serve loop (which owns
// the daemon) and serializes configuration changes.
type controller struct {
	path     string
	required bool
	o        daemonOptions
	now      func() time.Time

	cur  atomic.Pointer[daemon]
	reqs chan reloadRequest
	// cfgMu serializes PUT /v1/config (validate, write, reload, rollback).
	cfgMu sync.Mutex
}

func newController(path string, required bool, o daemonOptions, d *daemon) *controller {
	c := &controller{path: path, required: required, o: o, now: time.Now, reqs: make(chan reloadRequest)}
	c.cur.Store(d)
	return c
}

func (c *controller) daemon() *daemon { return c.cur.Load() }

// Profiles implements api.Backend.
func (c *controller) Profiles() []api.ProfileInfo {
	d := c.daemon()
	out := make([]api.ProfileInfo, 0, len(d.cfg.Profiles))
	for _, name := range sortedKeys(d.cfg.Profiles) {
		p := d.cfg.Profiles[name]
		out = append(out, api.ProfileInfo{Name: name, Mode: p.Mode, Transport: p.Transport, Listen: p.Listen, Upstream: p.Upstream,
			VirtualBase: p.VirtualBase, Bases: p.Bases, Cache: p.Cache.Mode})
	}
	return out
}

// Upstreams implements api.Backend.
func (c *controller) Upstreams() map[string][]upstream.ServerStatus {
	d := c.daemon()
	out := make(map[string][]upstream.ServerStatus, len(d.upstreams))
	for name, u := range d.upstreams {
		out[name] = u.Status()
	}
	return out
}

// Ready implements api.Backend: every proxy profile needs an upstream
// server up (SPEC §7 /readyz).
func (c *controller) Ready() bool {
	d := c.daemon()
	for _, sp := range d.profiles {
		if sp.cfg.Mode != "proxy" {
			continue
		}
		u, ok := d.upstreams[sp.cfg.Upstream]
		if !ok || !u.Healthy() {
			return false
		}
	}
	return true
}

// Test implements api.Backend.
func (c *controller) Test(ctx context.Context, profile string, req vdir.TestRequest) (vdir.TestResult, error) {
	for _, sp := range c.daemon().profiles {
		if sp.name == profile {
			return sp.dir.Test(ctx, req), nil
		}
	}
	return vdir.TestResult{}, fmt.Errorf("profile %q: %w", profile, api.ErrNotFound)
}

// Sync implements api.Backend; the replica cache comes with Stage 9.
func (c *controller) Sync(_ context.Context, profile string) error {
	p, ok := c.daemon().cfg.Profiles[profile]
	if !ok {
		return fmt.Errorf("profile %q: %w", profile, api.ErrNotFound)
	}
	if p.Cache.Mode != "replica" {
		return fmt.Errorf("profile %q: %w", profile, api.ErrNotReplica)
	}
	return fmt.Errorf("replica sync: %w (Stage 9)", api.ErrNotImplemented)
}

// ConfigTOML implements api.Backend: the effective configuration (file,
// includes, environment, defaults) with every secret.Inline rendered "***".
func (c *controller) ConfigTOML() ([]byte, error) {
	cfg := c.daemon().cfg
	var b bytes.Buffer
	enc := toml.NewEncoder(&b)
	if err := enc.Encode(cfg); err != nil {
		return nil, fmt.Errorf("encode configuration: %w", err)
	}
	// The named tables are decoded on their own (toml:"-" in config.Config).
	named := map[string]any{"upstream": cfg.Upstreams, "profile": cfg.Profiles}
	if err := enc.Encode(named); err != nil {
		return nil, fmt.Errorf("encode configuration: %w", err)
	}
	return b.Bytes(), nil
}

// Reload implements api.Backend through the serve loop.
func (c *controller) Reload(ctx context.Context) error {
	req := reloadRequest{done: make(chan error, 1)}
	select {
	case c.reqs <- req:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-req.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// validate loads body as if it were the configuration file (includes and
// environment apply) and runs the strict validator without touching disk.
func (c *controller) validate(body []byte) error {
	l := config.Loader{ReadFile: func(p string) ([]byte, error) {
		if p == c.path {
			return body, nil
		}
		return os.ReadFile(p)
	}}
	cfg, err := l.Load(c.path, true)
	if err != nil {
		return fmt.Errorf("%w: %v", api.ErrInvalidConfig, err) //nolint:errorlint // one sentinel, the cause as text
	}
	if rep := (config.Validator{StrictFiles: true, Secrets: c.o.Secrets}).Validate(cfg); !rep.OK() {
		return fmt.Errorf("%w:\n%s", api.ErrInvalidConfig, rep.Error())
	}
	return nil
}

// ApplyConfig implements api.Backend (SPEC §7 PUT /v1/config): validate in
// memory, back the current file up as aldap.toml.bak.<ts>, write the new
// one atomically, reload; a failed reload restores the previous file.
func (c *controller) ApplyConfig(ctx context.Context, body []byte) (api.ApplyResult, error) {
	if c.path == "" {
		return api.ApplyResult{}, api.ErrNoConfigFile
	}
	c.cfgMu.Lock()
	defer c.cfgMu.Unlock()
	if err := c.validate(body); err != nil {
		return api.ApplyResult{}, err
	}
	mode := fs.FileMode(0o600)
	prev, err := os.ReadFile(c.path)
	switch {
	case err == nil:
		if fi, serr := os.Stat(c.path); serr == nil {
			mode = fi.Mode().Perm()
		}
	case errors.Is(err, fs.ErrNotExist):
		prev = nil
	default:
		return api.ApplyResult{}, fmt.Errorf("read %s: %w", c.path, err)
	}
	res := api.ApplyResult{}
	if prev != nil {
		if res.Backup, err = c.backup(prev, mode); err != nil {
			return api.ApplyResult{}, err
		}
	}
	if err := writeFileAtomic(c.path, body, mode); err != nil {
		return api.ApplyResult{}, err
	}
	if err := c.Reload(ctx); err != nil {
		if rerr := c.rollback(prev, mode); rerr != nil {
			return api.ApplyResult{}, fmt.Errorf("reload failed: %w; restoring the previous file failed too: %v", err, rerr) //nolint:errorlint // the reload error decides the status
		}
		return api.ApplyResult{}, fmt.Errorf("reload failed, previous file restored: %w", err)
	}
	return res, nil
}

// backup writes prev to <path>.bak.<ts> without overwriting an older backup.
func (c *controller) backup(prev []byte, mode fs.FileMode) (string, error) {
	base := c.path + ".bak." + c.now().UTC().Format(backupLayout)
	name := base
	for i := 1; ; i++ {
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if errors.Is(err, fs.ErrExist) && i < 100 {
			name = fmt.Sprintf("%s.%d", base, i)
			continue
		}
		if err != nil {
			return "", fmt.Errorf("backup: %w", err)
		}
		_, werr := f.Write(prev)
		serr := f.Sync()
		cerr := f.Close()
		if err := errors.Join(werr, serr, cerr); err != nil {
			return "", fmt.Errorf("backup %s: %w", name, err)
		}
		return name, nil
	}
}

// rollback puts the previous file back after a failed reload; a file that
// did not exist before is removed again.
func (c *controller) rollback(prev []byte, mode fs.FileMode) error {
	if prev == nil {
		return os.Remove(c.path)
	}
	return writeFileAtomic(c.path, prev, mode)
}

// writeFileAtomic writes data to a temporary file in the same directory,
// syncs it and renames it over path, so readers see the old or the new
// content, never a mix.
func writeFileAtomic(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	serr := f.Sync()
	merr := f.Chmod(mode)
	cerr := f.Close()
	if err := errors.Join(werr, serr, merr, cerr); err != nil {
		_ = os.Remove(tmp) //nolint:errcheck // our own temporary file
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp) //nolint:errcheck // our own temporary file
		return fmt.Errorf("write %s: %w", path, err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()  //nolint:errcheck // not supported everywhere
		_ = d.Close() //nolint:errcheck // read-only handle
	}
	return nil
}

// apiRuntime is the process-level API: it outlives reloads so a PUT
// /v1/config can wait for the reload it triggered.
type apiRuntime struct {
	srv    *api.Server
	tls    *tlsutil.Manager
	cancel context.CancelFunc
	wg     sync.WaitGroup
	// listen is the [api] transport the listeners were opened with.
	listen apiListen
}

// apiListen are the [api] keys that need a restart to change.
type apiListen struct {
	Enabled       bool
	Listen        string
	MetricsListen string
	TLS           config.APITLS
	ClientAuth    string
	ClientCA      string
	IPC           string
}

func apiListenOf(cfg *config.Config) apiListen {
	a := cfg.API
	return apiListen{Enabled: a.Enabled, Listen: a.Listen, MetricsListen: a.Metrics.Listen, TLS: a.TLS, ClientAuth: a.ClientAuth, ClientCA: a.ClientCA, IPC: cfg.Server.IPCSocket}
}

// startAPI opens the IPC socket, the API listener ([api].enabled) and the
// separate metrics listener ([api.metrics].listen).
func startAPI(ctx context.Context, d *daemon, ctl *controller) (*apiRuntime, error) {
	st := d.state
	rt := &apiRuntime{listen: apiListenOf(d.cfg)}
	rt.srv = api.New(api.Options{Backend: ctl, Bus: st.bus, Limiter: st.limiter, IDs: st.ids, Metrics: st.metrics, Events: st, Logger: d.log, Version: version})
	if err := rt.srv.Configure(d.cfg.API, d.opts.Secrets); err != nil {
		return nil, err
	}
	ctx, rt.cancel = context.WithCancel(ctx)
	if err := rt.open(ctx, d); err != nil {
		rt.stop()
		return nil, err
	}
	return rt, nil
}

func (rt *apiRuntime) open(ctx context.Context, d *daemon) error {
	ipc, err := api.ListenIPC(d.cfg.Server.IPCSocket)
	switch {
	case errors.Is(err, api.ErrIPCUnsupported):
		d.log.Warn("IPC socket unavailable on this platform, aldapctl needs --url and a token", "err", err)
	case err != nil:
		return fmt.Errorf("server.ipc_socket: %w", err)
	default:
		if err := rt.srv.ServeIPC(ipc); err != nil {
			return fmt.Errorf("server.ipc_socket: %w", err)
		}
	}
	a := d.cfg.API
	if !a.Enabled && (!a.Metrics.Enabled || a.Metrics.Listen == "") {
		return nil
	}
	tlsCfg, err := rt.buildTLS(d)
	if err != nil {
		return err
	}
	lc := net.ListenConfig{}
	if a.Enabled {
		ln, err := lc.Listen(ctx, "tcp", a.Listen)
		if err != nil {
			return fmt.Errorf("api.listen: %w", err)
		}
		if err := rt.srv.ServeAPI(ln, tlsCfg); err != nil {
			return fmt.Errorf("api.listen: %w", err)
		}
	}
	if a.Metrics.Enabled && a.Metrics.Listen != "" && (!a.Enabled || a.Metrics.Listen != a.Listen) {
		ln, err := lc.Listen(ctx, "tcp", a.Metrics.Listen)
		if err != nil {
			return fmt.Errorf("api.metrics.listen: %w", err)
		}
		if err := rt.srv.ServeMetrics(ln, tlsCfg); err != nil {
			return fmt.Errorf("api.metrics.listen: %w", err)
		}
	}
	if rt.tls != nil {
		rt.wg.Add(1)
		go func() {
			defer rt.wg.Done()
			d.certLoop(ctx, rt.tls)
		}()
	}
	return nil
}

// buildTLS returns the API TLS configuration: the built-in CA (tls.builtin),
// an external pair (tls.cert/key) or none (loopback only, enforced by
// api.CheckTransport on the bound address).
func (rt *apiRuntime) buildTLS(d *daemon) (*tls.Config, error) {
	a := d.cfg.API
	o := tlsutil.Options{Profile: "api", KeyType: tlsutil.KeyType(d.cfg.TLS.KeyType), MinVersion: d.cfg.TLS.MinVersion, ClientAuth: a.ClientAuth, ClientCA: a.ClientCA,
		AutoRenewBefore: d.cfg.TLS.AutoRenewBefore.D(), ExpiryAlertBefore: d.cfg.TLS.ExpiryAlertBefore.D(), NoPersist: true, Metrics: d.state.metrics, Logger: d.log, Events: d.events}
	switch {
	case a.TLS.Builtin:
		o.Mode, o.CADir, o.AutoInit = "builtin-ca", d.cfg.TLS.CADir, d.cfg.TLS.AutoInit
		o.SANs = certSANs([]string{a.Listen, a.Metrics.Listen}, d.cfg.TLS.SAN, d.hostname())
	case a.TLS.Cert != "":
		o.Mode, o.Cert, o.Key = "external", a.TLS.Cert, a.TLS.Key
	default:
		if a.ClientAuth == "require" {
			return nil, errors.New("api.client_auth = require needs api.tls")
		}
		return nil, nil
	}
	m, err := tlsutil.New(o)
	if err != nil {
		return nil, fmt.Errorf("api.tls: %w", err)
	}
	rt.tls = m
	return m.Config(), nil
}

// reconfigure applies the reloaded [api] tokens, scopes, limits and
// metrics settings; listener changes need a restart (Stage 12).
func (rt *apiRuntime) reconfigure(d *daemon) {
	if err := rt.srv.Configure(d.cfg.API, d.opts.Secrets); err != nil {
		d.log.Error("api tokens not reloaded, keeping the previous ones", "err", err)
	}
	if apiListenOf(d.cfg) != rt.listen {
		d.log.Warn("api listen, tls, client_auth or ipc_socket changed: takes effect after a restart")
	}
}

func (rt *apiRuntime) stop() {
	if rt.cancel != nil {
		rt.cancel()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rt.srv.Shutdown(ctx)
	rt.wg.Wait()
}

// hostname is the host name used for certificate SANs.
func (d *daemon) hostname() string {
	if d.opts.Hostname != "" {
		return d.opts.Hostname
	}
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}
