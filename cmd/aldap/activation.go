package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/alstdev/aldap/internal/config"
)

// listenFDsStart is the first file descriptor systemd passes
// (SD_LISTEN_FDS_START, sd_listen_fds(3)).
const listenFDsStart = 3

// inheritedSockets are the listening sockets the service manager passed at
// start (socket activation: $LISTEN_PID, $LISTEN_FDS, $LISTEN_FDNAMES). A
// profile serves them with listen = ["systemd:<name>"]. They belong to the
// process, not to a configuration: a reload that drops a name stops serving
// it but keeps the socket, so a later reload can serve it again — the
// process cannot reopen a socket it did not bind.
type inheritedSockets struct {
	mu      sync.Mutex
	sockets []*inheritedSocket
	closed  bool
}

// inheritedSocket accepts on one passed socket for the lease currently
// serving it. The accept goroutine runs for the life of the process;
// connections wait in the kernel backlog while no lease is active.
type inheritedSocket struct {
	name  string
	ln    net.Listener
	conns chan net.Conn
	errs  chan error
	once  sync.Once
}

// inheritSystemdSockets takes over the sockets passed to this process:
// getenv/pid stand for os.Getenv/os.Getpid. Without $LISTEN_PID, or when
// it names another process, nothing was passed. The variables are removed
// from the environment so nothing started later inherits them.
func inheritSystemdSockets(getenv func(string) string, pid int) (*inheritedSockets, error) {
	return inheritFDs(getenv, pid, listenFDsStart)
}

// inheritFDs is inheritSystemdSockets with the first descriptor as a
// parameter (tests pass descriptors they opened).
func inheritFDs(getenv func(string) string, pid, start int) (*inheritedSockets, error) {
	set := &inheritedSockets{}
	pidVar, fdsVar, namesVar := getenv("LISTEN_PID"), getenv("LISTEN_FDS"), getenv("LISTEN_FDNAMES")
	for _, k := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		_ = os.Unsetenv(k) //nolint:errcheck // best effort, the values are already read
	}
	if pidVar == "" || pidVar != strconv.Itoa(pid) {
		return set, nil
	}
	n, err := strconv.Atoi(fdsVar)
	if err != nil || n < 0 {
		return nil, fmt.Errorf("socket activation: LISTEN_FDS=%q is not a count", fdsVar)
	}
	names := make([]string, n)
	for i := range names {
		names[i] = "unknown" // sd_listen_fds_with_names(3) default
	}
	if namesVar != "" {
		got := strings.Split(namesVar, ":")
		if len(got) != n {
			return nil, fmt.Errorf("socket activation: LISTEN_FDNAMES has %d names for LISTEN_FDS=%d", len(got), n)
		}
		names = got
	}
	for i := 0; i < n; i++ {
		f := os.NewFile(uintptr(start+i), names[i])
		ln, err := net.FileListener(f)
		// FileListener works on a duplicate; the original descriptor is not needed.
		_ = f.Close() //nolint:errcheck // the duplicate keeps the socket
		if err == nil {
			if _, tcp := ln.(*net.TCPListener); !tcp {
				_ = ln.Close() //nolint:errcheck // refused below
				err = errors.New("not a TCP stream socket (use ListenStream= with an address)")
			}
		}
		if err != nil {
			set.close()
			return nil, fmt.Errorf("socket activation: descriptor %d (%s): %w", start+i, names[i], err)
		}
		set.add(names[i], ln)
	}
	return set, nil
}

// add registers an inherited listener under name (also used by tests).
func (s *inheritedSockets) add(name string, ln net.Listener) {
	is := &inheritedSocket{name: name, ln: ln, conns: make(chan net.Conn), errs: make(chan error, 1)}
	s.mu.Lock()
	s.sockets = append(s.sockets, is)
	s.mu.Unlock()
}

// names lists the distinct socket names.
func (s *inheritedSockets) names() []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, is := range s.sockets {
		if !seen[is.name] {
			seen[is.name] = true
			out = append(out, is.name)
		}
	}
	sort.Strings(out)
	return out
}

// lease returns one listener per socket passed under name; closing a
// lease stops it accepting but keeps the socket.
func (s *inheritedSockets) lease(name string) ([]net.Listener, error) {
	if s == nil {
		return nil, fmt.Errorf("%s%s: no sockets were passed by systemd (socket activation)", config.ListenSystemdPrefix, name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("inherited sockets already closed")
	}
	var out []net.Listener
	for _, is := range s.sockets {
		if is.name == name {
			is.start()
			out = append(out, &socketLease{s: is, done: make(chan struct{})})
		}
	}
	if len(out) == 0 {
		have := "none"
		if len(s.sockets) > 0 {
			var names []string
			seen := map[string]bool{}
			for _, is := range s.sockets {
				if !seen[is.name] {
					seen[is.name] = true
					names = append(names, is.name)
				}
			}
			have = strings.Join(names, ", ")
		}
		return nil, fmt.Errorf("%s%s: systemd passed no socket with that FileDescriptorName= (passed: %s)", config.ListenSystemdPrefix, name, have)
	}
	return out, nil
}

// close closes the inherited sockets for good (process shutdown).
func (s *inheritedSockets) close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	for _, is := range s.sockets {
		_ = is.ln.Close() //nolint:errcheck // shutting down
	}
}

// start runs the accept goroutine once.
func (is *inheritedSocket) start() {
	is.once.Do(func() {
		go func() {
			for {
				c, err := is.ln.Accept()
				if err != nil {
					var ne net.Error
					if errors.As(err, &ne) && ne.Timeout() {
						continue
					}
					is.errs <- err
					close(is.conns)
					return
				}
				is.conns <- c
			}
		}()
	})
}

// socketLease is the net.Listener a listener.Server serves on an
// inherited socket.
type socketLease struct {
	s    *inheritedSocket
	done chan struct{}
	once sync.Once
}

func (l *socketLease) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		return nil, net.ErrClosed
	case c, ok := <-l.s.conns:
		if !ok {
			err := net.ErrClosed
			select {
			case e := <-l.s.errs:
				l.s.errs <- e // for the other leases of the socket
				if !errors.Is(e, net.ErrClosed) {
					err = e
				}
			default:
			}
			return nil, err
		}
		return c, nil
	}
}

// Close ends the lease; the socket stays open for the next one.
func (l *socketLease) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *socketLease) Addr() net.Addr { return l.s.ln.Addr() }
