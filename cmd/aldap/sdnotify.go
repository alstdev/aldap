package main

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// sdNotify reports a state to the service manager (sd_notify(3)): the
// systemd unit is Type=notify, so start-up completes only with READY=1.
// Without $NOTIFY_SOCKET (not started by systemd) it does nothing.
func sdNotify(state string) error {
	addr := os.Getenv("NOTIFY_SOCKET")
	switch {
	case addr == "":
		return nil
	case strings.HasPrefix(addr, "@"):
		addr = "\x00" + addr[1:] // abstract namespace
	case !strings.HasPrefix(addr, "/"):
		return fmt.Errorf("NOTIFY_SOCKET %q: only unix sockets are supported", addr)
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("sd_notify: %w", err)
	}
	defer c.Close() //nolint:errcheck // datagram already sent or failed
	if _, err := c.Write([]byte(state)); err != nil {
		return fmt.Errorf("sd_notify: %w", err)
	}
	return nil
}
