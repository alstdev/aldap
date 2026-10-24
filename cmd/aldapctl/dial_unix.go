//go:build !windows

package main

import (
	"context"
	"net"
)

// dialIPC connects to the daemon's unix socket.
func dialIPC(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", path)
}
