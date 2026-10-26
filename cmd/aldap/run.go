package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/alstdev/aldap/internal/api"
	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/secret"
)

// runRun is `aldap run`: build, start, serve until SIGINT/SIGTERM, reload
// on SIGHUP (SPEC §3.6, §5.3). Exit codes: 0 clean stop, 1 start failure,
// 2 usage error.
func runRun(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "configuration file (default $"+config.EnvConfigPath+" or "+config.DefaultConfigPath+")")
	fs.Usage = func() {
		fmt.Fprint(stderr, "Usage: aldap run [--config FILE]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "aldap run: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	path, required := config.ResolvePath(*cfgPath, os.LookupEnv)
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	return serve(context.Background(), path, required, daemonOptions{LogOut: stderr, Secrets: secret.Default}, sigs, stdout)
}

// serve runs the daemon life cycle: start, the API and IPC socket, handle
// signals and API reloads, stop. It is separate from runRun so tests can
// drive it with a fake signal channel.
func serve(ctx context.Context, path string, required bool, o daemonOptions, sigs <-chan os.Signal, stdout io.Writer) int {
	if o.Inherited == nil {
		// Socket activation: the descriptors are passed once, at start.
		inherited, err := inheritSystemdSockets(os.Getenv, os.Getpid())
		if err != nil {
			fmt.Fprintf(o.LogOut, "aldap run: %v\n", err)
			return 1
		}
		o.Inherited = inherited
	}
	d, err := loadDaemon(path, required, o)
	if err != nil {
		fmt.Fprintf(o.LogOut, "aldap run: %v\n", err)
		return 1
	}
	// The bus, locks and detector state outlive reloads (SPEC §6 seq is
	// monotonic per process; lock state is kept across configuration changes).
	o.State = d.state
	defer d.state.close()
	if err := d.start(ctx); err != nil {
		fmt.Fprintf(o.LogOut, "aldap run: %v\n", err)
		d.stop()
		return 1
	}
	ctl := newController(path, required, o, d)
	rt, err := startAPI(ctx, d, ctl)
	if err != nil {
		fmt.Fprintf(o.LogOut, "aldap run: %v\n", err)
		d.stop()
		return 1
	}
	fmt.Fprintf(stdout, "aldap %s listening: %s\n", version, describeListen(d))
	notifyManager(d.log, "READY=1\nSTATUS=serving "+describeListen(d))
	if o.Ready != nil {
		o.Ready()
	}
	stop := func() {
		notifyManager(ctl.cur.Load().log, "STOPPING=1")
		rt.stop()
		ctl.cur.Load().stop()
	}
	doReload := func() error {
		notifyManager(ctl.cur.Load().log, "RELOADING=1")
		next, err := reload(ctx, ctl.cur.Load(), path, required, o)
		ctl.cur.Store(next)
		if err == nil {
			rt.reconfigure(next)
		}
		notifyManager(next.log, "READY=1\nSTATUS=serving "+describeListen(next))
		return err
	}
	for {
		select {
		case <-ctx.Done():
			stop()
			return 0
		case req := <-ctl.reqs:
			req.done <- doReload()
		case sig := <-sigs:
			switch sig {
			case syscall.SIGHUP:
				_ = doReload() //nolint:errcheck // reload logs and emits config_reload itself
			default:
				ctl.cur.Load().log.Info("signal received, shutting down", "signal", sig.String())
				stop()
				return 0
			}
		}
	}
}

// reload builds the new configuration; on failure the old daemon keeps
// running and config_reload{ok=false} is emitted. On success the new
// generation takes the listeners over without closing the addresses that
// stay (SPEC §3.6): requests in flight finish under the old rules, every
// later request uses the new ones; added addresses are opened, removed
// ones drained. It returns the daemon now serving and the error of a
// failed reload (api.ErrInvalidConfig when the new configuration does not
// load or validate).
func reload(ctx context.Context, old *daemon, path string, required bool, o daemonOptions) (*daemon, error) {
	old.log.Info("reload requested")
	next, err := loadDaemon(path, required, o)
	if err != nil {
		old.log.Error("reload failed, keeping the running configuration", "err", err)
		old.events.Emit(events.Event{Event: events.ConfigReload, Level: events.LevelHigh, Data: map[string]any{"ok": false, "errors": []string{err.Error()}}})
		return old, fmt.Errorf("%w: %v", api.ErrInvalidConfig, err) //nolint:errorlint // one sentinel, the cause as text
	}
	old.mu.Lock()
	pool := old.pool
	old.mu.Unlock()
	if pool == nil {
		pool = newSocketPool(o.Inherited)
	}
	if err := next.takeOver(ctx, pool, old); err != nil {
		// Nothing changed: the old generation keeps every listener.
		next.log.Error("new configuration failed to start, keeping the running one", "err", err)
		next.release()
		old.events.Emit(events.Event{Event: events.ConfigReload, Level: events.LevelHigh, Data: map[string]any{"ok": false, "errors": []string{err.Error()}}})
		return old, fmt.Errorf("start: %w", err)
	}
	next.events.Emit(events.Event{Event: events.ConfigReload, Level: events.LevelLow, Data: map[string]any{"ok": true, "errors": []string{}}})
	next.log.Info("configuration reloaded", "listen", describeListen(next))
	return next, nil
}

// notifyManager reports the daemon state to systemd; a failure is only logged.
func notifyManager(log *slog.Logger, state string) {
	if err := sdNotify(state); err != nil {
		log.Warn("service manager notification failed", "err", err)
	}
}
