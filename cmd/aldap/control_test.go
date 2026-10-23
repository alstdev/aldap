package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alstdev/aldap/internal/api"
	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/listener"
	"github.com/alstdev/aldap/internal/secret"
	"github.com/alstdev/aldap/internal/testdir"
	"github.com/alstdev/aldap/internal/vdir"
)

// testController wires a controller to a started daemon; reloads are
// answered by a goroutine that plays the serve loop.
func testController(t *testing.T, reloadErr func() error) (*controller, *running, string) {
	t.Helper()
	r := startDaemon(t, "")
	path := filepath.Join(t.TempDir(), "aldap.toml")
	src, err := os.ReadFile(r.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, src, 0o640); err != nil {
		t.Fatal(err)
	}
	ctl := newController(path, true, daemonOptions{Secrets: secret.Default}, r.d)
	ctl.now = func() time.Time { return time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC) }
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case req := <-ctl.reqs:
				req.done <- reloadErr()
			}
		}
	}()
	return ctl, r, path
}

func TestController_Views(t *testing.T) {
	ctl, r, _ := testController(t, func() error { return nil })
	ps := ctl.Profiles()
	if len(ps) != 2 || ps[0].Name != "plain" || ps[1].Name != "virola" || ps[1].Transport != "ldaps" || ps[1].Cache != "none" {
		t.Errorf("profiles = %+v", ps)
	}
	if us := ctl.Upstreams(); len(us["ad"]) != 1 {
		t.Errorf("upstreams = %+v", us)
	}
	waitFor(t, ctl.Ready)
	res, err := ctl.Test(context.Background(), "virola", vdir.TestRequest{Base: tUsersDN, Scope: listener.ScopeSub, Filter: "(sAMAccountName=alice.adams)"})
	if err != nil || len(res.Entries) != 1 {
		t.Errorf("test: %v %+v", err, res)
	}
	if _, err := ctl.Test(context.Background(), "nope", vdir.TestRequest{}); !errors.Is(err, api.ErrNotFound) {
		t.Errorf("test unknown: %v", err)
	}
	if err := ctl.Sync(context.Background(), "nope"); !errors.Is(err, api.ErrNotFound) {
		t.Errorf("sync unknown: %v", err)
	}
	if err := ctl.Sync(context.Background(), "virola"); !errors.Is(err, api.ErrNotReplica) {
		t.Errorf("sync non-replica: %v", err)
	}
	// A replica profile is synced on request: cmd/aldap/stage9_test.go.
	b, err := ctl.ConfigTOML()
	if err != nil || !strings.Contains(string(b), "[profile.virola]") || strings.Contains(string(b), clientPassword) {
		t.Errorf("config toml: %v %v %v", err, strings.Contains(string(b), "[profile.virola]"), strings.Contains(string(b), clientPassword))
	}
	// The rendering loads back (secrets aside, it is the same configuration).
	back := filepath.Join(t.TempDir(), "back.toml")
	if err := os.WriteFile(back, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if cfg, err := config.LoadFile(back, true); err != nil || len(cfg.Profiles) != 2 || cfg.Upstreams["ad"] == nil {
		t.Errorf("rendered configuration does not load: %v\n%s", err, b)
	}
	// A proxy profile without a healthy upstream makes the process not ready.
	sp := r.d.profiles[1]
	sp.cfg.Upstream = "missing"
	if ctl.Ready() {
		t.Error("ready without upstream")
	}
	sp.cfg.Upstream = "ad"
}

func TestController_ApplyConfig(t *testing.T) {
	var reloadErr error
	ctl, _, path := testController(t, func() error { return reloadErr })
	orig, _ := os.ReadFile(path)
	ctx := context.Background()
	// Invalid: TOML syntax, validation, unknown key.
	for _, bad := range []string{"[server", "[server]\nlog_level = \"loud\"\n", "[nope]\n"} {
		if _, err := ctl.ApplyConfig(ctx, []byte(bad)); !errors.Is(err, api.ErrInvalidConfig) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if now, _ := os.ReadFile(path); string(now) != string(orig) {
		t.Fatal("file changed by an invalid body")
	}
	next := strings.Replace(string(orig), `log_level = "debug"`, `log_level = "warn"`, 1)
	res, err := ctl.ApplyConfig(ctx, []byte(next))
	if err != nil || res.Backup != path+".bak.20261023T120000Z" {
		t.Fatalf("apply: %v %+v", err, res)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o640 {
		t.Errorf("mode not kept: %v", fi.Mode())
	}
	if b, _ := os.ReadFile(res.Backup); string(b) != string(orig) {
		t.Error("backup content")
	}
	// Same second: the backup gets a suffix instead of overwriting.
	res, err = ctl.ApplyConfig(ctx, []byte(next))
	if err != nil || res.Backup != path+".bak.20261023T120000Z.1" {
		t.Errorf("second backup: %v %+v", err, res)
	}
	// Reload failure: the previous file is restored.
	reloadErr = errors.New("listen: address in use")
	other := strings.Replace(next, `log_level = "warn"`, `log_level = "error"`, 1)
	if _, err := ctl.ApplyConfig(ctx, []byte(other)); err == nil || !strings.Contains(err.Error(), "previous file restored") {
		t.Errorf("rollback: %v", err)
	}
	if now, _ := os.ReadFile(path); string(now) != next {
		t.Error("file not restored")
	}
	// A file that did not exist before is removed again on rollback.
	if err := os.Rename(path, path+".moved"); err != nil {
		t.Fatal(err)
	}
	if _, err := ctl.ApplyConfig(ctx, []byte(next)); err == nil {
		t.Error("reload error lost")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("new file kept after rollback: %v", err)
	}
	reloadErr = nil
	if res, err := ctl.ApplyConfig(ctx, []byte(next)); err != nil || res.Backup != "" {
		t.Errorf("apply without previous file: %v %+v", err, res)
	}
	// No configuration file at all (environment only).
	envOnly := newController("", false, daemonOptions{Secrets: secret.Default}, ctl.daemon())
	if _, err := envOnly.ApplyConfig(ctx, []byte(next)); !errors.Is(err, api.ErrNoConfigFile) {
		t.Errorf("env only: %v", err)
	}
	// Reload honors the context.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := envOnly.Reload(cctx); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled reload: %v", err)
	}
	// Unwritable directory: the write error is reported, nothing reloaded.
	if err := writeFileAtomic(filepath.Join(t.TempDir(), "missing", "x.toml"), []byte("x"), 0o600); err == nil {
		t.Error("write into a missing directory")
	}
}

// TestServe_APIRuntime runs serve with the API over TLS (built-in CA), a
// separate metrics listener and the IPC socket; it reloads through the IPC
// socket and SIGHUP and checks that listener changes are reported.
func TestServe_APIRuntime(t *testing.T) {
	dc := testdir.StartFixture(t)
	caDir := filepath.Join(t.TempDir(), "ca")
	apiPort, metricsPort := freePort(t), freePort(t)
	t.Setenv("ALDAP_TEST_API_TOKEN", "S3CR3T-api-token-0123456789abcdef0123456")
	apiTable := fmt.Sprintf("[api]\nenabled = true\nlisten = \"127.0.0.1:%d\"\n[api.tls]\nbuiltin = true\n[api.metrics]\nlisten = \"127.0.0.1:%d\"\npublic = true\n"+
		"[[api.token]]\nname = \"ops\"\ntoken_env = \"ALDAP_TEST_API_TOKEN\"\nscopes = [\"status:read\"]\n", apiPort, metricsPort)
	path, _, _ := daemonConfig(t, dc, caDir, apiTable)
	src, _ := os.ReadFile(path)
	ipc := ""
	for _, line := range strings.Split(string(src), "\n") {
		if v, ok := strings.CutPrefix(line, "ipc_socket = "); ok {
			ipc, _ = strconv.Unquote(v)
		}
	}
	logs, stdout := &safeBuffer{}, &safeBuffer{}
	sigs := make(chan os.Signal, 1)
	done := make(chan int, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		done <- serve(ctx, path, true, daemonOptions{LogOut: logs, EventsOut: io.Discard, Secrets: secret.Default, Argon2: fastArgon, NoPersistCerts: true, Hostname: "aldap-test"}, sigs, stdout)
	}()
	waitFor(t, func() bool { return strings.Contains(stdout.String(), "listening") || len(done) > 0 })
	if len(done) > 0 {
		t.Fatalf("serve exited:\n%s", logs.String())
	}
	pem, err := os.ReadFile(filepath.Join(caDir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	get := func(c *http.Client, url, token string) int {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	https := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	if code := get(https, fmt.Sprintf("https://127.0.0.1:%d/v1/status", apiPort), "S3CR3T-api-token-0123456789abcdef0123456"); code != http.StatusOK {
		t.Errorf("https status: %d", code)
	}
	if code := get(https, fmt.Sprintf("https://127.0.0.1:%d/metrics", metricsPort), ""); code != http.StatusOK {
		t.Errorf("public metrics listener: %d", code)
	}
	if code := get(https, fmt.Sprintf("https://127.0.0.1:%d/v1/status", metricsPort), ""); code != http.StatusNotFound {
		t.Errorf("metrics listener serves the API: %d", code)
	}
	unix := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", ipc)
	}}}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://aldap/v1/reload", nil)
	resp, err := unix.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ipc reload: %d\n%s", resp.StatusCode, logs.String())
	}
	// A changed API port is reported, the running listener stays.
	moved := strings.Replace(string(src), fmt.Sprintf("listen = \"127.0.0.1:%d\"\n[api.tls]", apiPort), fmt.Sprintf("listen = \"127.0.0.1:%d\"\n[api.tls]", freePort(t)), 1)
	if err := os.WriteFile(path, []byte(moved), 0o600); err != nil {
		t.Fatal(err)
	}
	sigs <- syscall.SIGHUP
	waitFor(t, func() bool { return strings.Contains(logs.String(), "takes effect after a restart") })
	if code := get(https, fmt.Sprintf("https://127.0.0.1:%d/healthz", apiPort), ""); code != http.StatusOK {
		t.Errorf("api after reload: %d", code)
	}
	// A broken file is refused by a reload request.
	if err := os.WriteFile(path, []byte("[server]\nlog_level = \"loud\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	req, _ = http.NewRequestWithContext(context.Background(), http.MethodPost, "http://aldap/v1/reload", nil)
	if resp, err = unix.Do(req); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("reload of a broken file: %d", resp.StatusCode)
	}
	sigs <- syscall.SIGTERM
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop")
	}
	if _, err := os.Lstat(ipc); !os.IsNotExist(err) {
		t.Errorf("ipc socket left: %v", err)
	}
	if strings.Contains(logs.String(), "S3CR3T") {
		t.Error("token in logs")
	}
}

func TestServe_APIStartFailures(t *testing.T) {
	dc := testdir.StartFixture(t)
	caDir := filepath.Join(t.TempDir(), "ca")
	busy, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	_, port, _ := net.SplitHostPort(busy.Addr().String())
	cases := map[string]string{
		"api port busy":     "[api]\nenabled = true\nlisten = \"127.0.0.1:" + port + "\"\n",
		"metrics port busy": "[api.metrics]\nlisten = \"127.0.0.1:" + port + "\"\n",
		"mtls without tls":  "[api]\nenabled = true\nlisten = \"127.0.0.1:" + strconv.Itoa(freePort(t)) + "\"\nclient_auth = \"require\"\nclient_ca = \"/nonexistent/ca.pem\"\n",
		"external tls":      "[api]\nenabled = true\nlisten = \"127.0.0.1:" + strconv.Itoa(freePort(t)) + "\"\n[api.tls]\ncert = \"/nonexistent/a.crt\"\nkey = \"/nonexistent/a.key\"\n",
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			path, _, _ := daemonConfig(t, dc, caDir, extra)
			logs := &safeBuffer{}
			if code := serve(context.Background(), path, true, daemonOptions{LogOut: logs, EventsOut: io.Discard, Secrets: secret.Default, Argon2: fastArgon, NoPersistCerts: true}, make(chan os.Signal), &safeBuffer{}); code != 1 {
				t.Errorf("exit %d\n%s", code, logs.String())
			}
		})
	}
	// The IPC path is occupied by a regular file.
	path, _, _ := daemonConfig(t, dc, caDir, "")
	src, _ := os.ReadFile(path)
	for _, line := range strings.Split(string(src), "\n") {
		if v, ok := strings.CutPrefix(line, "ipc_socket = "); ok {
			p, _ := strconv.Unquote(v)
			if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	logs := &safeBuffer{}
	if code := serve(context.Background(), path, true, daemonOptions{LogOut: logs, EventsOut: io.Discard, Secrets: secret.Default, Argon2: fastArgon, NoPersistCerts: true}, make(chan os.Signal), &safeBuffer{}); code != 1 || !strings.Contains(logs.String(), "ipc_socket") {
		t.Errorf("ipc occupied: exit %d\n%s", code, logs.String())
	}
}
