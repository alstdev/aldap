package main

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/kardianos/service"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/secret"
)

// systemdUnit is deploy/aldap.service with the ExecStart line of the
// kardianos/service template (TestSystemdUnitInSync keeps them equal).
//
//go:embed aldap.service.tmpl
var systemdUnit string

const (
	serviceUsage = `Usage: aldap service <action> [options]

Actions:
  install    register aldap with the service manager (systemd, Windows SCM)
  uninstall  remove the registration
  start      start the installed service
  stop       stop it (graceful drain, SPEC §5.3)
  restart    stop and start it
  status     print running, stopped or not installed
  run        serve under the service manager (what install registers on Windows)

Options:
`
	defaultServiceName = "aldap"
	// serviceStartWait bounds how long the service manager waits for the
	// listeners before the start is reported as failed.
	serviceStartWait = 60 * time.Second
)

// newService creates the platform service; tests replace it.
var newService = service.New

// serviceOptions are the flags of `aldap service`.
type serviceOptions struct {
	name    string
	config  string
	logFile string
}

// serviceConfig describes the service to the service manager. On Windows
// the SCM starts `aldap service run`, which logs to the Event Log and the
// log file; elsewhere the unit runs `aldap run` (systemd Type=notify) and
// uses the hardened unit of deploy/aldap.service.
func serviceConfig(o serviceOptions, goos string) *service.Config {
	c := &service.Config{
		Name:        o.name,
		DisplayName: "ALDAP",
		Description: "LDAP proxy with a virtual directory, brute-force protection and IDS telemetry",
		Option:      service.KeyValue{},
	}
	if goos == "windows" {
		c.Arguments = []string{"service", "run", "--name", o.name, "--config", o.config}
		if o.logFile != "" {
			c.Arguments = append(c.Arguments, "--log-file", o.logFile)
		}
		// Option names of kardianos/service on Windows (service_windows.go).
		c.Option["StartType"] = "automatic"
		c.Option["OnFailure"] = "restart"
		c.Option["OnFailureDelayDuration"] = "5s"
		return c
	}
	c.Arguments = []string{"run", "--config", o.config}
	c.Option["SystemdScript"] = systemdUnit
	return c
}

// defaultLogFile is the log file of a Windows service next to the
// configuration (the SCM gives the process no console).
func defaultLogFile(goos, cfg string) string {
	if goos != "windows" || cfg == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(cfg), "aldap.log")
}

// runService is `aldap service <action>` (SPEC §10.4, §10.5). Exit codes:
// 0 done (status: running), 1 the action failed, 2 usage error, 3 status:
// stopped or not installed.
func runService(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("service", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o serviceOptions
	fs.StringVar(&o.name, "name", defaultServiceName, "service name")
	fs.StringVar(&o.config, "config", "", "configuration file (install, run; default $"+config.EnvConfigPath+" or "+config.DefaultConfigPath+")")
	fs.StringVar(&o.logFile, "log-file", "", "log file of the Windows service (install, run; default aldap.log next to the configuration)")
	fs.Usage = func() {
		fmt.Fprint(stderr, serviceUsage)
		fs.PrintDefaults()
	}
	if len(args) == 0 {
		fs.Usage()
		return 2
	}
	action := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "aldap service: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if o.name == "" {
		fmt.Fprintln(stderr, "aldap service: --name must not be empty")
		return 2
	}
	path, required := config.ResolvePath(o.config, os.LookupEnv)
	if action == "install" || action == "run" {
		abs, err := filepath.Abs(path)
		if err != nil {
			fmt.Fprintf(stderr, "aldap service: config path: %v\n", err)
			return 1
		}
		o.config = abs
		if o.logFile == "" {
			o.logFile = defaultLogFile(runtime.GOOS, o.config)
		}
	}
	switch action {
	case "run":
		return serviceRun(o, required, stdout, stderr)
	case "status":
		return serviceStatus(o, stdout, stderr)
	case "install", "uninstall", "start", "stop", "restart":
		if action == "install" {
			// Refuse to register a configuration that would not start.
			if _, err := config.LoadFile(o.config, true); err != nil {
				fmt.Fprintf(stderr, "aldap service install: %v\n", err)
				return 1
			}
		}
		s, err := newService(&program{}, serviceConfig(o, runtime.GOOS))
		if err != nil {
			fmt.Fprintf(stderr, "aldap service: %v\n", err)
			return 1
		}
		if err := service.Control(s, action); err != nil {
			fmt.Fprintf(stderr, "aldap service %s: %v\n", action, err)
			return 1
		}
		fmt.Fprintf(stdout, "aldap service %s: %s done (%s)\n", o.name, action, s.Platform())
		return 0
	default:
		fmt.Fprintf(stderr, "aldap service: unknown action %q\n\n", action)
		fs.Usage()
		return 2
	}
}

// serviceStatus prints running (exit 0), stopped or not installed (3).
func serviceStatus(o serviceOptions, stdout, stderr io.Writer) int {
	s, err := newService(&program{}, serviceConfig(o, runtime.GOOS))
	if err != nil {
		fmt.Fprintf(stderr, "aldap service: %v\n", err)
		return 1
	}
	st, err := s.Status()
	switch {
	case errors.Is(err, service.ErrNotInstalled):
		fmt.Fprintln(stdout, "not installed")
		return 3
	case err != nil:
		fmt.Fprintf(stderr, "aldap service status: %v\n", err)
		return 1
	case st == service.StatusRunning:
		fmt.Fprintln(stdout, "running")
		return 0
	case st == service.StatusStopped:
		fmt.Fprintln(stdout, "stopped")
		return 3
	default:
		fmt.Fprintln(stdout, "unknown")
		return 1
	}
}

// serviceRun serves under the service manager: the SCM (or a console,
// interactively) drives start and stop; warnings and errors also go to the
// system log (Event Log on Windows).
func serviceRun(o serviceOptions, required bool, stdout, stderr io.Writer) int {
	p := &program{path: o.config, required: required, stdout: stdout,
		sigs: make(chan os.Signal, 2), done: make(chan int, 1), ready: make(chan struct{})}
	s, err := newService(p, serviceConfig(o, runtime.GOOS))
	if err != nil {
		fmt.Fprintf(stderr, "aldap service run: %v\n", err)
		return 1
	}
	logOut := stderr
	if o.logFile != "" {
		f, err := os.OpenFile(o.logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			fmt.Fprintf(stderr, "aldap service run: log file: %v\n", err)
			return 1
		}
		defer f.Close() //nolint:errcheck // log lines are written unbuffered
		logOut = f
	}
	// The stdout event sink follows the log: a service has no console.
	p.opts = daemonOptions{LogOut: logOut, EventsOut: logOut, Secrets: secret.Default}
	if !service.Interactive() {
		if sys, err := s.Logger(nil); err == nil {
			p.opts.SystemLog = sys
		}
	}
	if err := s.Run(); err != nil {
		fmt.Fprintf(stderr, "aldap service run: %v\n", err)
		if p.opts.SystemLog != nil {
			_ = p.opts.SystemLog.Error("aldap service run: " + err.Error()) //nolint:errcheck // nothing left to report to
		}
		return 1
	}
	select {
	case code := <-p.done:
		return code
	default:
		return 0
	}
}

// program adapts the daemon life cycle to service.Interface.
type program struct {
	path     string
	required bool
	opts     daemonOptions
	stdout   io.Writer
	sigs     chan os.Signal
	done     chan int
	ready    chan struct{}
}

// Start runs the daemon and returns once it serves; a configuration that
// does not start fails the service start.
func (p *program) Start(service.Service) error {
	opts := p.opts
	opts.Ready = func() { close(p.ready) }
	exited := make(chan int, 1)
	go func() {
		code := serve(context.Background(), p.path, p.required, opts, p.sigs, p.stdout)
		exited <- code
		p.done <- code
	}()
	select {
	case <-p.ready:
		return nil
	case code := <-exited:
		return fmt.Errorf("aldap did not start (exit code %d), see the log", code)
	case <-time.After(serviceStartWait):
		return errors.New("aldap did not start within " + serviceStartWait.String())
	}
}

// Stop drains the daemon (SPEC §5.3) and waits for it to finish.
func (p *program) Stop(service.Service) error {
	select {
	case p.sigs <- syscall.SIGTERM:
	default:
	}
	code := <-p.done
	p.done <- code
	if code != 0 {
		return fmt.Errorf("aldap stopped with exit code %d", code)
	}
	return nil
}
