//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// passFDs duplicates files onto consecutive descriptors from base, the way
// systemd lays them out from 3, and returns base.
func passFDs(t *testing.T, files ...*os.File) int {
	t.Helper()
	const base = 700
	for i, f := range files {
		if err := syscall.Dup3(int(f.Fd()), base+i, syscall.O_CLOEXEC); err != nil {
			t.Fatalf("dup3: %v", err)
		}
		_ = f.Close()
	}
	return base
}

func tcpFile(t *testing.T) (*os.File, string) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	f, err := ln.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	return f, ln.Addr().String()
}

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestInheritFDs_Names(t *testing.T) {
	f1, a1 := tcpFile(t)
	f2, a2 := tcpFile(t)
	base := passFDs(t, f1, f2)
	pid := os.Getpid()
	set, err := inheritFDs(envOf(map[string]string{
		"LISTEN_PID": strconv.Itoa(pid), "LISTEN_FDS": "2", "LISTEN_FDNAMES": "virola:virola",
	}), pid, base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(set.close)
	if got := set.names(); len(got) != 1 || got[0] != "virola" {
		t.Fatalf("names = %v", got)
	}
	lns, err := set.lease("virola")
	if err != nil || len(lns) != 2 {
		t.Fatalf("lease: %v %v", lns, err)
	}
	got := []string{lns[0].Addr().String(), lns[1].Addr().String()}
	if got[0] != a1 || got[1] != a2 {
		t.Errorf("addrs = %v, want %s %s", got, a1, a2)
	}
	if _, err := set.lease("other"); err == nil || !strings.Contains(err.Error(), "passed: virola") {
		t.Errorf("unknown name: %v", err)
	}
	// The original descriptors are released; the duplicates stay.
	if err := syscall.Close(base); !errors.Is(err, syscall.EBADF) {
		t.Errorf("descriptor %d still open: %v", base, err)
	}
	for _, k := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		if _, ok := os.LookupEnv(k); ok {
			t.Errorf("%s left in the environment", k)
		}
	}
}

func TestInheritFDs_DefaultNamesAndOtherPID(t *testing.T) {
	f, _ := tcpFile(t)
	base := passFDs(t, f)
	pid := os.Getpid()
	// Another process's sockets (LISTEN_PID differs): nothing inherited.
	set, err := inheritFDs(envOf(map[string]string{"LISTEN_PID": strconv.Itoa(pid + 1), "LISTEN_FDS": "1"}), pid, base)
	if err != nil || len(set.names()) != 0 {
		t.Fatalf("foreign LISTEN_PID: %v %v", set.names(), err)
	}
	set, err = inheritFDs(envOf(map[string]string{}), pid, base)
	if err != nil || len(set.names()) != 0 {
		t.Fatalf("no socket activation: %v %v", set.names(), err)
	}
	set, err = inheritFDs(envOf(map[string]string{"LISTEN_PID": strconv.Itoa(pid), "LISTEN_FDS": "1"}), pid, base)
	if err != nil {
		t.Fatal(err)
	}
	defer set.close()
	if got := set.names(); len(got) != 1 || got[0] != "unknown" {
		t.Errorf("default name: %v", got)
	}
}

func TestInheritFDs_Errors(t *testing.T) {
	pid := strconv.Itoa(os.Getpid())
	for name, env := range map[string]map[string]string{
		"bad count":   {"LISTEN_PID": pid, "LISTEN_FDS": "x"},
		"negative":    {"LISTEN_PID": pid, "LISTEN_FDS": "-1"},
		"names count": {"LISTEN_PID": pid, "LISTEN_FDS": "2", "LISTEN_FDNAMES": "a"},
	} {
		if _, err := inheritFDs(envOf(env), os.Getpid(), 700); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// A datagram socket and a regular file are refused; the sockets taken
	// before the failure are closed again.
	ftcp, addr := tcpFile(t)
	udp, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fudp, err := udp.(*net.UDPConn).File()
	_ = udp.Close()
	if err != nil {
		t.Fatal(err)
	}
	base := passFDs(t, ftcp, fudp)
	_, err = inheritFDs(envOf(map[string]string{"LISTEN_PID": pid, "LISTEN_FDS": "2", "LISTEN_FDNAMES": "a:b"}), os.Getpid(), base)
	if err == nil || !strings.Contains(err.Error(), "(b)") {
		t.Fatalf("udp socket: %v", err)
	}
	if c, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", addr); err == nil {
		_ = c.Close()
		t.Error("socket taken before the failure still accepts")
	}
	reg, err := os.CreateTemp(t.TempDir(), "f")
	if err != nil {
		t.Fatal(err)
	}
	base = passFDs(t, reg)
	if _, err := inheritFDs(envOf(map[string]string{"LISTEN_PID": pid, "LISTEN_FDS": "1"}), os.Getpid(), base); err == nil {
		t.Error("regular file accepted as a socket")
	}
}

// TestSocketLease: a lease accepts through the shared accept goroutine;
// closing it keeps the socket for the next lease, closing the set ends it.
func TestSocketLease(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	set := &inheritedSockets{}
	set.add("s", ln)
	dial := func() net.Conn {
		c, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	lns, err := set.lease("s")
	if err != nil {
		t.Fatal(err)
	}
	first := lns[0]
	dial()
	if c, err := first.Accept(); err != nil {
		t.Fatal(err)
	} else {
		_ = c.Close()
	}
	_ = first.Close()
	_ = first.Close() // idempotent
	if _, err := first.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("closed lease: %v", err)
	}
	// Connections made while no lease serves wait for the next one.
	dial()
	lns, _ = set.lease("s")
	done := make(chan error, 1)
	go func() {
		c, err := lns[0].Accept()
		if err == nil {
			_ = c.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("waiting connection not handed to the next lease")
	}
	set.close()
	set.close()
	if _, err := lns[0].Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("after close: %v", err)
	}
	if _, err := set.lease("s"); err == nil {
		t.Error("lease after close")
	}
	var none *inheritedSockets
	if _, err := none.lease("s"); err == nil || none.names() != nil {
		t.Error("nil set")
	}
	none.close()
}
