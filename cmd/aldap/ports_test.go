package main

import (
	"context"
	"net"
	"sync"
	"testing"
)

var (
	portsMu   sync.Mutex
	portsUsed = map[int]bool{}
)

// freePort returns a loopback TCP port chosen by the kernel at run time.
// The kernel may hand a just-closed port out again, so a port is never
// returned twice within the test binary: two profiles of one configuration
// cannot collide. Nothing listens on the port when it is returned, so it
// also serves as a dead upstream address.
func freePort(t *testing.T) int {
	t.Helper()
	portsMu.Lock()
	defer portsMu.Unlock()
	var held []net.Listener
	defer func() {
		for _, ln := range held {
			_ = ln.Close()
		}
	}()
	for range 64 {
		ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, ln)
		port := ln.Addr().(*net.TCPAddr).Port
		if !portsUsed[port] {
			portsUsed[port] = true
			return port
		}
	}
	t.Fatal("no unused loopback port")
	return 0
}

func TestFreePort_Unique(t *testing.T) {
	seen := map[int]bool{}
	for range 200 {
		p := freePort(t)
		if seen[p] {
			t.Fatalf("port %d returned twice", p)
		}
		seen[p] = true
	}
}
