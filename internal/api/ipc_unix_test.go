//go:build !windows

package api

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// shortDir keeps socket paths below the 104/108-byte sun_path limit.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "aldap")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

func ipcClient(path string) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}}
}

// TestIPC_Socket covers the socket life cycle: mode 0600, a live socket is
// refused, a stale one replaced, a regular file kept; requests need no token.
func TestIPC_Socket(t *testing.T) {
	path := filepath.Join(shortDir(t), "run", "aldap.sock")
	ln, err := ListenIPC(path)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode: %v %v", fi.Mode(), err)
	}
	if _, err := ListenIPC(path); err == nil {
		t.Error("second listener on a live socket")
	}
	e := newEnv(t, nil)
	if err := e.s.ServeIPC(ln); err != nil {
		t.Fatal(err)
	}
	e.lim.LockIP("192.0.2.9", e.clk.now().Add(time.Hour), "ratelimit")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodDelete, "http://ipc/v1/locks/ip/192.0.2.9", nil)
	resp, err := ipcClient(path).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || len(e.lim.Locks()) != 0 {
		t.Fatalf("ipc unlock: %d", resp.StatusCode)
	}
	e.s.Shutdown(context.Background())
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("socket left after shutdown: %v", err)
	}
	// Stale socket (no listener) is replaced.
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	_ = stale.Close()
	ln, err = ListenIPC(path)
	if err != nil {
		t.Fatalf("stale socket: %v", err)
	}
	_ = ln.Close()
	// A regular file is never removed.
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenIPC(path); err == nil {
		t.Error("regular file replaced")
	}
	if b, _ := os.ReadFile(path); string(b) != "keep" {
		t.Error("regular file changed")
	}
	if _, err := ListenIPC(filepath.Join(path, "sub", "x.sock")); err == nil {
		t.Error("socket below a file")
	}
}
