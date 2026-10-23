//go:build windows

package api

import (
	"context"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
)

func TestListenIPC_BadPath(t *testing.T) {
	for _, p := range []string{`C:\aldap.sock`, `\\.\pipe\`, `/run/aldap/aldap.sock`} {
		if _, err := ListenIPC(p); err == nil {
			t.Errorf("ListenIPC(%q): want error", p)
		}
	}
}

func TestListenIPC_Pipe(t *testing.T) {
	path := `\\.\pipe\aldap-test-` + time.Now().Format("150405.000000")
	ln, err := ListenIPC(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if _, err := ListenIPC(path); err == nil {
		t.Fatal("second listener on the same pipe: want error")
	}
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := winio.DialPipeContext(ctx, path)
	if err != nil {
		t.Skipf("dial (the test needs an elevated shell, ACL is SYSTEM+Administrators): %v", err)
	}
	_ = c.Close()
}
