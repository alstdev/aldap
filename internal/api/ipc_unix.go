//go:build !windows

package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// ErrIPCUnsupported is returned where the IPC channel is not available.
var ErrIPCUnsupported = errors.New("ipc: not supported on this platform")

// ListenIPC opens the unix socket at path with mode 0600. The socket is
// bound under a temporary name, restricted and renamed into place, so it is
// never reachable with wider permissions. A stale socket left by a crashed
// process is replaced; a live one (another daemon) or a non-socket file is
// an error.
func ListenIPC(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("ipc: %w", err)
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("ipc: %s exists and is not a socket", path)
		}
		if c, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "unix", path); err == nil {
			_ = c.Close() //nolint:errcheck // probe only
			return nil, fmt.Errorf("ipc: %s is in use by another process", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("ipc: remove stale socket: %w", err)
		}
	}
	tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	_ = os.Remove(tmp) //nolint:errcheck // leftover of this pid only
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: tmp, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("ipc: %w", err)
	}
	ln.SetUnlinkOnClose(false)
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = ln.Close()     //nolint:errcheck // cleanup
		_ = os.Remove(tmp) //nolint:errcheck // cleanup
		return nil, fmt.Errorf("ipc: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = ln.Close()     //nolint:errcheck // cleanup
		_ = os.Remove(tmp) //nolint:errcheck // cleanup
		return nil, fmt.Errorf("ipc: %w", err)
	}
	return &ipcListener{UnixListener: ln, path: path}, nil
}

// ipcListener removes the socket file on Close and reports the final path.
type ipcListener struct {
	*net.UnixListener
	path string
}

func (l *ipcListener) Addr() net.Addr { return &net.UnixAddr{Name: l.path, Net: "unix"} }

func (l *ipcListener) Close() error {
	err := l.UnixListener.Close()
	_ = os.Remove(l.path) //nolint:errcheck // already gone is fine
	return err
}
