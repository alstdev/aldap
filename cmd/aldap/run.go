package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

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

// serve runs the daemon life cycle: start, handle signals, stop. It is
// separate from runRun so tests can drive it with a fake signal channel.
func serve(ctx context.Context, path string, required bool, o daemonOptions, sigs <-chan os.Signal, stdout io.Writer) int {
	d, err := loadDaemon(path, required, o)
	if err != nil {
		fmt.Fprintf(o.LogOut, "aldap run: %v\n", err)
		return 1
	}
	if err := d.start(ctx); err != nil {
		fmt.Fprintf(o.LogOut, "aldap run: %v\n", err)
		d.stop()
		return 1
	}
	fmt.Fprintf(stdout, "aldap %s listening: %s\n", version, describeListen(d))
	for {
		select {
		case <-ctx.Done():
			d.stop()
			return 0
		case sig := <-sigs:
			switch sig {
			case syscall.SIGHUP:
				d = reload(ctx, d, path, required, o)
			default:
				d.log.Info("signal received, shutting down", "signal", sig.String())
				d.stop()
				return 0
			}
		}
	}
}

// reload builds the new configuration; on failure the old daemon keeps
// running and config_reload{ok=false} is emitted. On success the old
// listeners are drained and the new ones started (full restart of the
// listeners is acceptable in Stage 4, TASKS.md).
func reload(ctx context.Context, old *daemon, path string, required bool, o daemonOptions) *daemon {
	old.log.Info("reload requested")
	next, err := loadDaemon(path, required, o)
	if err != nil {
		old.log.Error("reload failed, keeping the running configuration", "err", err)
		old.events.Emit(events.Event{Event: events.ConfigReload, Level: events.LevelHigh, Data: map[string]any{"ok": false, "errors": []string{err.Error()}}})
		return old
	}
	old.stop()
	if err := next.start(ctx); err != nil {
		// The old listeners are gone; try to bring them back.
		next.log.Error("new configuration failed to start, restarting the previous one", "err", err)
		next.stop()
		prev, perr := loadDaemon(path, required, o)
		if perr == nil {
			perr = prev.start(ctx)
		}
		if perr != nil {
			old.log.Error("previous configuration could not be restarted either", "err", perr)
			old.events.Emit(events.Event{Event: events.ConfigReload, Level: events.LevelHigh, Data: map[string]any{"ok": false, "errors": []string{err.Error(), perr.Error()}}})
			return old
		}
		prev.events.Emit(events.Event{Event: events.ConfigReload, Level: events.LevelHigh, Data: map[string]any{"ok": false, "errors": []string{err.Error()}}})
		return prev
	}
	next.events.Emit(events.Event{Event: events.ConfigReload, Level: events.LevelLow, Data: map[string]any{"ok": true, "errors": []string{}}})
	next.log.Info("configuration reloaded")
	return next
}
