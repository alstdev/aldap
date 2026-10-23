//go:build windows

package api

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/Microsoft/go-winio"
)

// ErrIPCUnsupported is returned where the IPC channel is not available.
var ErrIPCUnsupported = errors.New("ipc: not supported on this platform")

// pipeSDDL grants access to SYSTEM and the built-in Administrators group
// only (SPEC §10.5); "P" protects the DACL from inherited entries.
const pipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"

const pipePrefix = `\\.\pipe\`

// ListenIPC opens the named pipe at path (`\\.\pipe\<name>`) with an ACL
// restricted to SYSTEM and Administrators. Remote clients are rejected by
// go-winio (FILE_PIPE_REJECT_REMOTE_CLIENTS); a pipe already served by
// another process is an error.
func ListenIPC(path string) (net.Listener, error) {
	if !strings.HasPrefix(strings.ToLower(path), pipePrefix) || len(path) == len(pipePrefix) {
		return nil, fmt.Errorf("ipc: %q is not a named pipe path (%s<name>)", path, pipePrefix)
	}
	ln, err := winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: pipeSDDL})
	if err != nil {
		return nil, fmt.Errorf("ipc: %w", err)
	}
	return ln, nil
}
