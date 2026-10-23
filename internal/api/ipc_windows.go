//go:build windows

package api

import (
	"errors"
	"net"
)

// ErrIPCUnsupported is returned where the IPC channel is not available.
var ErrIPCUnsupported = errors.New("ipc: named pipes are not implemented yet (docs/DECISIONS.md); use the HTTP API")

// ListenIPC is not available on Windows yet: a named pipe with an
// owner-only ACL needs a dependency outside SPEC §2.2, and an AF_UNIX
// socket cannot be restricted to the owner without it.
func ListenIPC(string) (net.Listener, error) { return nil, ErrIPCUnsupported }
