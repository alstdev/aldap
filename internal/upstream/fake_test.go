package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/config"
)

// fakeServer is an in-memory stand-in for one LDAP server.
type fakeServer struct {
	mu       sync.Mutex
	alive    bool
	dials    int
	binds    int
	searches int
	open     int
	entries  []*ldap.Entry
	// passwords maps bind DN → password; a missing DN yields data 525.
	passwords map[string]string
	bindErr   error
	searchErr error
	referrals []string
	noPaging  bool
	startTLS  error
	lastReq   *ldap.SearchRequest
	reqs      []*ldap.SearchRequest
}

func newFakeServer(n int) *fakeServer {
	fs := &fakeServer{alive: true, passwords: map[string]string{"cn=svc,dc=x": "svc-pw", "cn=user,dc=x": "user-pw"}}
	for i := 0; i < n; i++ {
		fs.entries = append(fs.entries, ldap.NewEntry(fmt.Sprintf("cn=e%03d,dc=x", i), map[string][]string{"CN": {fmt.Sprintf("e%03d", i)}}))
	}
	return fs
}

func (f *fakeServer) setAlive(v bool) {
	f.mu.Lock()
	f.alive = v
	f.mu.Unlock()
}

func (f *fakeServer) counts() (dials, binds, searches int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dials, f.binds, f.searches
}

var errNet = ldap.NewError(ldap.ErrorNetwork, errors.New("connection refused"))

type fakeConn struct {
	srv    *fakeServer
	closed atomic.Bool
	bound  string
}

func (c *fakeConn) dead() bool {
	c.srv.mu.Lock()
	defer c.srv.mu.Unlock()
	return !c.srv.alive
}

func (c *fakeConn) Bind(username, password string) error {
	if c.closed.Load() || c.dead() {
		return errNet
	}
	c.srv.mu.Lock()
	c.srv.binds++
	berr := c.srv.bindErr
	pw, ok := c.srv.passwords[username]
	c.srv.mu.Unlock()
	if berr != nil {
		return berr
	}
	if !ok {
		return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 525, v4563"))
	}
	if pw != password {
		return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 52e, v4563"))
	}
	c.bound = username
	return nil
}

func (c *fakeConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if c.closed.Load() || c.dead() {
		return nil, errNet
	}
	c.srv.mu.Lock()
	defer c.srv.mu.Unlock()
	c.srv.searches++
	c.srv.lastReq = req
	c.srv.reqs = append(c.srv.reqs, req)
	if c.srv.searchErr != nil {
		return nil, c.srv.searchErr
	}
	if req.BaseDN == "" && req.Scope == ldap.ScopeBaseObject {
		return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry("", map[string][]string{
			"defaultNamingContext": {"dc=x"}, "supportedControl": {ldap.ControlTypePaging},
		})}}, nil
	}
	entries := c.srv.entries
	res := &ldap.SearchResult{Referrals: c.srv.referrals}
	ctl, _ := ldap.FindControl(req.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
	if ctl == nil || c.srv.noPaging {
		res.Entries = entries
		return res, nil
	}
	offset := 0
	if len(ctl.Cookie) > 0 {
		offset, _ = strconv.Atoi(string(ctl.Cookie))
	}
	if ctl.PagingSize == 0 {
		return res, nil
	}
	end := offset + int(ctl.PagingSize)
	resp := ldap.NewControlPaging(0)
	if end < len(entries) {
		resp.SetCookie([]byte(strconv.Itoa(end)))
	} else {
		end = len(entries)
	}
	res.Entries = entries[offset:end]
	res.Controls = []ldap.Control{resp}
	if req.SizeLimit > 0 && len(res.Entries) > req.SizeLimit {
		res.Entries = res.Entries[:req.SizeLimit]
		return res, ldap.NewError(ldap.LDAPResultSizeLimitExceeded, errors.New("size limit"))
	}
	return res, nil
}

func (c *fakeConn) StartTLS(*tls.Config) error { return c.srv.startTLS }
func (c *fakeConn) SetTimeout(time.Duration)   {}
func (c *fakeConn) IsClosing() bool            { return c.closed.Load() }
func (c *fakeConn) Close() error {
	if !c.closed.Swap(true) {
		c.srv.mu.Lock()
		c.srv.open--
		c.srv.mu.Unlock()
	}
	return nil
}

// fakeNet routes dials by server URL.
type fakeNet struct {
	mu      sync.Mutex
	servers map[string]*fakeServer
}

func (n *fakeNet) dial(_ context.Context, srv ServerURL) (ldapConn, error) {
	n.mu.Lock()
	fs := n.servers[srv.String()]
	n.mu.Unlock()
	if fs == nil {
		return nil, fmt.Errorf("no fake server for %s", srv)
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.dials++
	if !fs.alive {
		return nil, fmt.Errorf("connect %s: %w", srv, errNet)
	}
	fs.open++
	return &fakeConn{srv: fs}, nil
}

type eventLog struct {
	mu     sync.Mutex
	events []Event
}

func (l *eventLog) Emit(e Event) {
	l.mu.Lock()
	l.events = append(l.events, e)
	l.mu.Unlock()
}

func (l *eventLog) kinds() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, 0, len(l.events))
	for _, e := range l.events {
		out = append(out, e.Kind)
	}
	return out
}

func (l *eventLog) count(kind string) int {
	n := 0
	for _, k := range l.kinds() {
		if k == kind {
			n++
		}
	}
	return n
}

func testConfig(urls ...string) *config.Upstream {
	cfg := config.DefaultUpstream()
	cfg.Servers = urls
	cfg.BindDN = "cn=svc,dc=x"
	cfg.BaseDN = "dc=x"
	cfg.HealthInterval = config.Duration(20 * time.Millisecond)
	cfg.Timeouts = config.Timeouts{Connect: config.Duration(200 * time.Millisecond), Bind: config.Duration(200 * time.Millisecond), Search: config.Duration(200 * time.Millisecond)}
	cfg.Failover.FailThreshold = 2
	cfg.Failover.RecoverThreshold = 2
	cfg.PageSize = 4
	cfg.AuditServiceAccount = false
	return cfg
}

// newFake builds an Upstream over fake servers; the returned servers are in
// list order.
func newFake(t *testing.T, cfg *config.Upstream, sizes ...int) (*Upstream, []*fakeServer, *eventLog) {
	t.Helper()
	n := &fakeNet{servers: map[string]*fakeServer{}}
	fss := make([]*fakeServer, 0, len(cfg.Servers))
	for i, raw := range cfg.Servers {
		su, err := ParseServerURL(raw)
		if err != nil {
			t.Fatal(err)
		}
		size := 0
		if i < len(sizes) {
			size = sizes[i]
		}
		fs := newFakeServer(size)
		n.servers[su.String()] = fs
		fss = append(fss, fs)
	}
	ev := &eventLog{}
	u, err := New("test", cfg, "svc-pw", Options{Events: ev, dial: n.dial, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(u.Close)
	return u, fss, ev
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}
