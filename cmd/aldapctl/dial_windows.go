//go:build windows

package main

import (
	"context"
	"net"

	"github.com/Microsoft/go-winio"
)

// dialIPC connects to the daemon's named pipe (SYSTEM and Administrators
// only, so aldapctl runs elevated for the IPC channel).
func dialIPC(ctx context.Context, path string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, path)
}
