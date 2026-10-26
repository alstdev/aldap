package main

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kardianos/service"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/testdir"
)

// fakeService records the actions of `aldap service` and, for run, drives
// the program like a service manager: Start, then Stop.
type fakeService struct {
	mu      sync.Mutex
	prg     service.Interface
	cfg     *service.Config
	actions []string
	status  service.Status
	statErr error
	failOn  string
	// stopAfter is how long Run serves before it stops the program.
	stopAfter time.Duration
	runErr    error
}

func (f *fakeService) act(a string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.actions = append(f.actions, a)
	if a == f.failOn {
		return errors.New(a + " refused")
	}
	return nil
}

func (f *fakeService) Run() error {
	if err := f.prg.Start(f); err != nil {
		f.runErr = err
		return err
	}
	time.Sleep(f.stopAfter)
	return f.prg.Stop(f)
}
func (f *fakeService) Start() error     { return f.act("start") }
func (f *fakeService) Stop() error      { return f.act("stop") }
func (f *fakeService) Restart() error   { return f.act("restart") }
func (f *fakeService) Install() error   { return f.act("install") }
func (f *fakeService) Uninstall() error { return f.act("uninstall") }
func (f *fakeService) Logger(chan<- error) (service.Logger, error) {
	return service.ConsoleLogger, nil
}
func (f *fakeService) SystemLogger(chan<- error) (service.Logger, error) {
	return service.ConsoleLogger, nil
}
func (f *fakeService) String() string                  { return f.cfg.Name }
func (f *fakeService) Platform() string                { return "fake" }
func (f *fakeService) Status() (service.Status, error) { return f.status, f.statErr }

func useFakeService(t *testing.T, f *fakeService) {
	t.Helper()
	prev := newService
	newService = func(i service.Interface, c *service.Config) (service.Service, error) {
		f.prg, f.cfg = i, c
		return f, nil
	}
	t.Cleanup(func() { newService = prev })
}

// TestSystemdUnitInSync: the unit `aldap service install` writes is
// deploy/aldap.service with the installed command line.
func TestSystemdUnitInSync(t *testing.T) {
	deployed, err := os.ReadFile(filepath.Join("..", "..", "deploy", "aldap.service"))
	if err != nil {
		t.Fatal(err)
	}
	unit := strings.Replace(systemdUnit, "ExecStart={{Path | cmdEscape}}{{range Arguments}} {{. | cmd}}{{end}}",
		"ExecStart=/usr/local/bin/aldap run --config /etc/aldap/aldap.toml", 1)
	if unit != string(deployed) {
		t.Error("cmd/aldap/aldap.service.tmpl differs from deploy/aldap.service: keep them equal except ExecStart")
	}
	for _, want := range []string{"Type=notify", "DynamicUser=yes", "NoNewPrivileges=yes", "ExecReload=/bin/kill -HUP $MAINPID"} {
		if !strings.Contains(systemdUnit, want) {
			t.Errorf("unit lacks %s", want)
		}
	}
}

func TestServiceConfig_Platforms(t *testing.T) {
	o := serviceOptions{name: "aldap", config: `C:\ProgramData\ALDAP\aldap.toml`, logFile: `C:\ProgramData\ALDAP\aldap.log`}
	w := serviceConfig(o, "windows")
	if strings.Join(w.Arguments, " ") != `service run --name aldap --config C:\ProgramData\ALDAP\aldap.toml --log-file C:\ProgramData\ALDAP\aldap.log` {
		t.Errorf("windows arguments = %q", w.Arguments)
	}
	if w.Option["StartType"] != "automatic" || w.Option["OnFailure"] != "restart" || w.Option["SystemdScript"] != nil {
		t.Errorf("windows options = %v", w.Option)
	}
	o.logFile = ""
	if args := serviceConfig(o, "windows").Arguments; strings.Contains(strings.Join(args, " "), "--log-file") {
		t.Errorf("log file without a path: %q", args)
	}
	l := serviceConfig(serviceOptions{name: "aldap", config: "/etc/aldap/aldap.toml"}, "linux")
	if strings.Join(l.Arguments, " ") != "run --config /etc/aldap/aldap.toml" || l.Option["SystemdScript"] != systemdUnit {
		t.Errorf("linux config = %q %v", l.Arguments, l.Option)
	}
	if got := defaultLogFile("windows", `/x/aldap.toml`); got != filepath.Join("/x", "aldap.log") {
		t.Errorf("default log file = %q", got)
	}
	if defaultLogFile("linux", "/etc/aldap/aldap.toml") != "" || defaultLogFile("windows", "") != "" {
		t.Error("default log file outside windows")
	}
}

func TestRunService_Actions(t *testing.T) {
	dc := testdir.StartFixture(t)
	path, _, _ := daemonConfig(t, dc, filepath.Join(t.TempDir(), "ca"), "")
	bad := filepath.Join(t.TempDir(), "bad.toml")
	if err := os.WriteFile(bad, []byte("[server]\nbogus = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		args   []string
		fake   *fakeService
		code   int
		out    string
		action string
	}{
		{"install", []string{"install", "--config", path}, &fakeService{}, 0, "install done", "install"},
		{"install invalid config", []string{"install", "--config", bad}, &fakeService{}, 1, "bogus", ""},
		{"install refused", []string{"install", "--config", path}, &fakeService{failOn: "install"}, 1, "install refused", "install"},
		{"uninstall", []string{"uninstall", "--name", "aldap2"}, &fakeService{}, 0, "aldap2: uninstall done", "uninstall"},
		{"start", []string{"start"}, &fakeService{}, 0, "start done", "start"},
		{"stop", []string{"stop"}, &fakeService{}, 0, "stop done", "stop"},
		{"restart", []string{"restart"}, &fakeService{}, 0, "restart done", "restart"},
		{"status running", []string{"status"}, &fakeService{status: service.StatusRunning}, 0, "running", ""},
		{"status stopped", []string{"status"}, &fakeService{status: service.StatusStopped}, 3, "stopped", ""},
		{"status not installed", []string{"status"}, &fakeService{statErr: service.ErrNotInstalled}, 3, "not installed", ""},
		{"status error", []string{"status"}, &fakeService{statErr: errors.New("no systemd")}, 1, "no systemd", ""},
		{"status unknown", []string{"status"}, &fakeService{status: service.StatusUnknown}, 1, "unknown", ""},
		{"no action", nil, &fakeService{}, 2, "Usage: aldap service", ""},
		{"unknown action", []string{"enable"}, &fakeService{}, 2, `unknown action "enable"`, ""},
		{"extra argument", []string{"start", "now"}, &fakeService{}, 2, "unexpected argument", ""},
		{"bad flag", []string{"start", "--bogus"}, &fakeService{}, 2, "", ""},
		{"empty name", []string{"start", "--name", ""}, &fakeService{}, 2, "--name", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.fake
			useFakeService(t, f)
			var stdout, stderr bytes.Buffer
			code := run(append([]string{"service"}, tc.args...), &stdout, &stderr)
			if code != tc.code || !strings.Contains(stdout.String()+stderr.String(), tc.out) {
				t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, tc.code, stdout.String(), stderr.String())
			}
			if tc.action != "" && (len(f.actions) != 1 || f.actions[0] != tc.action) {
				t.Errorf("actions = %v", f.actions)
			}
			if tc.action == "install" && f.cfg != nil && !filepath.IsAbs(f.cfg.Arguments[len(f.cfg.Arguments)-1]) && f.cfg.Option["SystemdScript"] != nil {
				t.Errorf("install config path not absolute: %q", f.cfg.Arguments)
			}
		})
	}
}

// TestServiceRun: under a service manager the program starts the daemon,
// reports it ready, drains it on stop and logs to the log file.
func TestServiceRun(t *testing.T) {
	dc := testdir.StartFixture(t)
	path, lp, _ := daemonConfig(t, dc, filepath.Join(t.TempDir(), "ca"), "")
	logFile := filepath.Join(t.TempDir(), "aldap.log")
	f := &fakeService{stopAfter: 200 * time.Millisecond}
	useFakeService(t, f)
	served := make(chan error, 1)
	go func() {
		// While Run serves, the listener accepts connections.
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			c, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", "127.0.0.1:"+strconv.Itoa(lp))
			if err == nil {
				_ = c.Close()
				served <- nil
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		served <- errors.New("listener never accepted")
	}()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"service", "run", "--config", path, "--log-file", logFile}, &stdout, &stderr); code != 0 {
		t.Fatalf("service run exit %d: %s", code, stderr.String())
	}
	if err := <-served; err != nil {
		t.Error(err)
	}
	b, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"aldap started", `"event":"shutdown"`, "aldap stopped"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("log file lacks %s", want)
		}
	}
	if st, err := os.Stat(logFile); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("log file mode: %v %v", st.Mode(), err)
	}
	// A configuration that does not start fails the service start.
	bad := filepath.Join(t.TempDir(), "none.toml")
	f2 := &fakeService{}
	useFakeService(t, f2)
	stderr.Reset()
	if code := run([]string{"service", "run", "--config", bad, "--log-file", logFile}, &stdout, &stderr); code != 1 || f2.runErr == nil {
		t.Errorf("start failure: exit %d, run error %v", code, f2.runErr)
	}
	// An unwritable log file is refused before anything starts.
	if code := run([]string{"service", "run", "--config", path, "--log-file", filepath.Join(t.TempDir(), "no", "dir", "x.log")}, &stdout, &stderr); code != 1 {
		t.Errorf("bad log file exit %d", code)
	}
}

func TestSDNotify(t *testing.T) {
	dir, err := os.MkdirTemp("", "sd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "notify")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Skipf("unixgram: %v", err)
	}
	defer func() { _ = conn.Close() }()
	t.Setenv("NOTIFY_SOCKET", sock)
	if err := sdNotify("READY=1"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := conn.ReadFromUnix(buf)
	if err != nil || string(buf[:n]) != "READY=1" {
		t.Errorf("datagram %q, %v", buf[:n], err)
	}
	for _, addr := range []string{"vsock:2:1234", filepath.Join(dir, "missing")} {
		t.Setenv("NOTIFY_SOCKET", addr)
		if err := sdNotify("READY=1"); err == nil {
			t.Errorf("NOTIFY_SOCKET=%s accepted", addr)
		}
	}
	t.Setenv("NOTIFY_SOCKET", "@aldap-test-abstract-"+strconv.Itoa(os.Getpid()))
	_ = sdNotify("READY=1") // abstract namespace: nobody listens, only the address form matters
	t.Setenv("NOTIFY_SOCKET", "")
	if err := sdNotify("READY=1"); err != nil {
		t.Errorf("without NOTIFY_SOCKET: %v", err)
	}
	// The daemon reports READY, RELOADING and STOPPING (systemd Type=notify).
	t.Setenv("NOTIFY_SOCKET", sock)
	var logs bytes.Buffer
	notifyManager(slog.New(slog.NewTextHandler(&logs, nil)), "STOPPING=1")
	n, _, err = conn.ReadFromUnix(buf)
	if err != nil || string(buf[:n]) != "STOPPING=1" {
		t.Errorf("STOPPING datagram %q, %v", buf[:n], err)
	}
	t.Setenv("NOTIFY_SOCKET", "vsock:1")
	notifyManager(slog.New(slog.NewTextHandler(&logs, nil)), "READY=1")
	if !strings.Contains(logs.String(), "service manager notification failed") {
		t.Error("notification failure not logged")
	}
}

type recordingSysLog struct {
	mu   sync.Mutex
	errs []string
	warn []string
	fail bool
}

func (r *recordingSysLog) Error(v ...any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errs = append(r.errs, v[0].(string))
	if r.fail {
		return errors.New("event log full")
	}
	return nil
}

func (r *recordingSysLog) Warning(v ...any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.warn = append(r.warn, v[0].(string))
	return nil
}

func TestSystemLog_WarningsAndErrors(t *testing.T) {
	sys := &recordingSysLog{}
	var out bytes.Buffer
	log := newLogger(config.Server{LogLevel: "debug", LogFormat: "json"}, &out, sys).With("profile", "virola").WithGroup("g")
	log.Debug("debug line")
	log.Info("info line")
	log.Warn("warn line", "k", "v")
	log.Error("error line")
	if strings.Count(out.String(), "\n") != 4 {
		t.Errorf("main log:\n%s", out.String())
	}
	if len(sys.warn) != 1 || !strings.Contains(sys.warn[0], "warn line") || !strings.Contains(sys.warn[0], "profile=virola") || !strings.Contains(sys.warn[0], "g.k=v") {
		t.Errorf("system log warnings = %q", sys.warn)
	}
	if len(sys.errs) != 1 || !strings.Contains(sys.errs[0], "error line") {
		t.Errorf("system log errors = %q", sys.errs)
	}
	sys.fail = true
	log.Error("second error")
	if !strings.Contains(out.String(), "second error") {
		t.Error("a failing system log must not lose the main log line")
	}
	if newLogger(config.Server{LogLevel: "info"}, &out, nil).Handler().Enabled(t.Context(), slog.LevelDebug) {
		t.Error("level without a system log")
	}
	if !(teeHandler{slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelError})}).Enabled(t.Context(), slog.LevelError) {
		t.Error("tee enabled")
	}
}

// TestPodmanQuadlet keeps the hardening and the network mode of
// deploy/podman/aldap.container (docs/podman.md): the client IP is only
// preserved with pasta and no custom network.
func TestPodmanQuadlet(t *testing.T) {
	keys := unitKeys(t, "aldap.container")
	checkQuadletHardening(t, keys)
	if len(keys["[Container]PublishPort"]) == 0 || len(keys["[Container]HealthCmd"]) != 0 {
		t.Errorf("ports %q, HealthCmd %q (the image HEALTHCHECK is used)", keys["[Container]PublishPort"], keys["[Container]HealthCmd"])
	}
}

// TestPodmanSocketActivation keeps the socket-activated pair: the socket
// names its descriptors "virola" (listen = ["systemd:virola"]), the
// container is started by it, publishes no port for it and runs ALDAP as
// PID 1 (Podman sets LISTEN_PID=1).
func TestPodmanSocketActivation(t *testing.T) {
	sock := unitKeys(t, "aldap-virola.socket")
	if got := sock["[Socket]FileDescriptorName"]; len(got) != 1 || got[0] != "virola" {
		t.Errorf("FileDescriptorName = %q", got)
	}
	if len(sock["[Socket]ListenStream"]) == 0 || len(sock["[Socket]Accept"]) != 1 || sock["[Socket]Accept"][0] != "no" {
		t.Errorf("ListenStream %q, Accept %q", sock["[Socket]ListenStream"], sock["[Socket]Accept"])
	}
	keys := unitKeys(t, "aldap-virola.container")
	checkQuadletHardening(t, keys)
	if got := keys["[Unit]Requires"]; len(got) != 1 || got[0] != "aldap-virola.socket" {
		t.Errorf("Requires = %q", got)
	}
	if len(keys["[Container]PublishPort"]) != 0 || len(keys["[Container]RunInit"]) != 0 {
		t.Errorf("PublishPort %q, RunInit %q", keys["[Container]PublishPort"], keys["[Container]RunInit"])
	}
	if got := keys["[Service]ExecReload"]; len(got) != 1 || !strings.HasSuffix(got[0], " aldap-virola") {
		t.Errorf("ExecReload = %q", got)
	}
}

// unitKeys parses a systemd unit of deploy/podman into "[Section]Key" → values.
func unitKeys(t *testing.T, name string) map[string][]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "podman", name))
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string][]string{}
	section := ""
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "["):
			section = line
		default:
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				t.Fatalf("%s: not a key: %q", name, line)
			}
			keys[section+k] = append(keys[section+k], v)
		}
	}
	return keys
}

// checkQuadletHardening checks the keys every ALDAP Quadlet unit shares.
func checkQuadletHardening(t *testing.T, keys map[string][]string) {
	t.Helper()
	want := map[string]string{
		"[Container]Network": "pasta", "[Container]ReadOnly": "true", "[Container]DropCapability": "all",
		"[Container]NoNewPrivileges": "true", "[Container]UserNS": "keep-id:uid=65532,gid=65532",
		"[Container]Sysctl": "net.ipv4.ip_unprivileged_port_start=0", "[Install]WantedBy": "default.target",
	}
	for k, v := range want {
		if got := keys[k]; len(got) != 1 || got[0] != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	confDir := false
	for _, v := range keys["[Container]Volume"] {
		if strings.HasSuffix(strings.SplitN(v, ":", 2)[0], ".toml") {
			t.Errorf("single-file configuration mount %q", v)
		}
		if strings.Contains(v, ":/etc/aldap:ro") {
			confDir = true
		}
	}
	if !confDir {
		t.Error("configuration directory not mounted read-only at /etc/aldap")
	}
	for _, v := range keys["[Container]Secret"] {
		if !strings.Contains(v, "mode=0400") || !strings.Contains(v, "uid=65532") {
			t.Errorf("secret %q readable beyond the ALDAP user", v)
		}
	}
}
