//go:build integration

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/ratelimit"
)

// pagedPage runs one page of a paged search on c.
func pagedPage(t *testing.T, c *ldap.Conn, cookie []byte, attrs ...string) (*ldap.SearchResult, []byte) {
	t.Helper()
	ctl := ldap.NewControlPaging(1)
	ctl.SetCookie(cookie)
	res, err := c.Search(ldap.NewSearchRequest(tUsersDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=user)", attrs, []ldap.Control{ctl}))
	if err != nil {
		t.Fatalf("paged search: %v", err)
	}
	var next []byte
	if p, ok := ldap.FindControl(res.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging); ok {
		next = p.Cookie
	}
	return res, next
}

func hasMail(res *ldap.SearchResult) bool {
	for _, e := range res.Entries {
		if e.GetAttributeValue("mail") != "" {
			return true
		}
	}
	return false
}

// TestStage12_ReloadDuringPagedSearch is the Stage 12 acceptance test: a
// reload that changes attrs.allow while a paged search is running — the
// running search finishes under the old rules, the next one uses the new
// rules, and the client connection is never cut.
func TestStage12_ReloadDuringPagedSearch(t *testing.T) {
	r := startDaemon(t, "")
	c := r.clientConn(t)
	res, cookie := pagedPage(t, c, nil, "mail", "sAMAccountName")
	if len(res.Entries) != 1 || !hasMail(res) || len(cookie) == 0 {
		t.Fatalf("first page: %d entries, mail=%v, cookie=%q", len(res.Entries), hasMail(res), cookie)
	}
	pages := 1
	addrs := r.d.addrs("virola")

	r.reloadWith(t, func(s string) string {
		return strings.Replace(s, `allow = ["userPrincipalName", "sAMAccountName", "displayName", "mail", "objectClass", "objectGUID"]`,
			`allow = ["userPrincipalName", "sAMAccountName", "displayName", "objectClass", "objectGUID"]`, 1)
	})
	if got := r.d.addrs("virola"); len(got) != 1 || got[0] != addrs[0] {
		t.Errorf("listener changed on reload: %v → %v", addrs, got)
	}
	// The running paged search continues on the same connection under the
	// rules it started with.
	for len(cookie) > 0 {
		res, cookie = pagedPage(t, c, cookie, "mail", "sAMAccountName")
		pages++
		if len(res.Entries) > 0 && !hasMail(res) {
			t.Fatalf("page %d after the reload lost mail: the running search switched rules", pages)
		}
		if pages > 100 {
			t.Fatal("paging does not end")
		}
	}
	if pages < 2 {
		t.Fatalf("pages = %d, the reload did not land inside the paged search", pages)
	}
	// The next search on the same connection uses the new rules.
	res, _ = pagedPage(t, c, nil, "mail", "sAMAccountName")
	if len(res.Entries) != 1 || hasMail(res) || res.Entries[0].GetAttributeValue("sAMAccountName") == "" {
		t.Errorf("new search after reload: %+v", res.Entries)
	}
	if ok := findEvents(r, events.ConfigReload, func(e events.Record) bool { return e.Data["ok"] == true }); len(ok) != 1 {
		t.Errorf("config_reload ok events = %d", len(ok))
	}
}

// TestStage12_ListenAddRemove: a reload opens an added address and drains
// a removed one without touching the connections of other listeners.
func TestStage12_ListenAddRemove(t *testing.T) {
	r := startDaemon(t, "")
	keep := r.clientConn(t)
	oldPlain := r.plain(t)
	if err := oldPlain.StartTLS(r.tlsConfig(t)); err != nil {
		t.Fatalf("starttls: %v", err)
	}
	newPort := freePort(t)
	newAddr := fmt.Sprintf("127.0.0.1:%d", newPort)
	r.reloadWith(t, func(s string) string {
		return strings.Replace(s, fmt.Sprintf("listen = [%q]\ntransport = \"ldap+starttls\"", r.plainAddr),
			fmt.Sprintf("listen = [%q, %q]\ntransport = \"ldap+starttls\"", r.plainAddr, newAddr), 1)
	})
	if got := r.d.addrs("plain"); len(got) != 2 || got[1] != newAddr {
		t.Fatalf("plain addrs after adding = %v", got)
	}
	added, err := ldap.DialURL("ldap://" + newAddr)
	if err != nil {
		t.Fatalf("dial added listener: %v", err)
	}
	defer func() { _ = added.Close() }()
	if err := added.StartTLS(r.tlsConfig(t)); err != nil {
		t.Errorf("starttls on the added listener: %v", err)
	}
	// Remove the original plain address.
	r.reloadWith(t, func(s string) string {
		return strings.Replace(s, fmt.Sprintf("listen = [%q, %q]", r.plainAddr, newAddr), fmt.Sprintf("listen = [%q]", newAddr), 1)
	})
	if got := r.d.addrs("plain"); len(got) != 1 || got[0] != newAddr {
		t.Fatalf("plain addrs after removing = %v", got)
	}
	waitFor(t, func() bool {
		c, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", r.plainAddr)
		if err == nil {
			_ = c.Close()
		}
		return err != nil
	})
	// The connection on the removed address was ended; the others work.
	if _, err := oldPlain.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil, nil)); err == nil {
		t.Error("connection on the removed listener still served")
	}
	if res := search(t, keep, tUsersDN, aliceFilter, "mail"); len(res.Entries) != 1 {
		t.Errorf("virola connection after two reloads: %d entries", len(res.Entries))
	}
	if _, err := added.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil, nil)); err != nil {
		t.Errorf("added listener after the second reload: %v", err)
	}
}

// TestStage12_ReloadKeepsRateLimitState: an account lock outlives a reload
// (SPEC §3.6: the rate limit state is not reset).
func TestStage12_ReloadKeepsRateLimitState(t *testing.T) {
	r := startDaemon(t, strings.Replace(stage6Config, `lock_duration = "1500ms"`, `lock_duration = "10m"`, 1))
	c := r.ldaps(t)
	for i := range 3 {
		_ = c.Bind("bob.brown@test.aldap", fmt.Sprintf("wrong-%d", i))
	}
	waitEvents(t, r, "account lock", events.Lock, func(e events.Record) bool { return e.Data["key"] == "bob.brown" })
	r.reloadWith(t, func(s string) string { return strings.Replace(s, `log_level = "debug"`, `log_level = "info"`, 1) })
	before := r.dc.Calls().Binds
	if err := c.Bind("bob.brown@test.aldap", "bob.brown-pass"); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Fatalf("locked account after reload: %v", err)
	}
	if r.dc.Calls().Binds != before {
		t.Error("locked account reached the upstream after reload")
	}
	waitEvents(t, r, "still locked", events.BindBlocked, func(e events.Record) bool { return e.Reason == ratelimit.ReasonAccountLocked })
}

// TestStage12_DrainActiveRequest: on stop the search in flight is answered,
// then the connection gets the notice of disconnection; new connections
// are refused during the drain.
func TestStage12_DrainActiveRequest(t *testing.T) {
	r := startDaemon(t, "")
	c := r.clientConn(t)
	idle := r.clientConn(t)
	r.dc.SetDelay(800 * time.Millisecond)
	type result struct {
		res *ldap.SearchResult
		err error
	}
	got := make(chan result, 1)
	go func() {
		res, err := c.Search(ldap.NewSearchRequest(tUsersDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, aliceFilter, []string{"mail"}, nil))
		got <- result{res, err}
	}()
	waitFor(t, func() bool { return r.dc.Calls().Searches > 0 && r.dc.OpenConns() > 0 })
	time.Sleep(100 * time.Millisecond) // the search is waiting on the delayed upstream
	stopped := make(chan struct{})
	start := time.Now()
	go func() {
		r.d.stop()
		close(stopped)
	}()
	waitFor(t, func() bool {
		conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", r.ldapsAddr)
		if err == nil {
			_ = conn.Close()
		}
		return err != nil
	})
	out := <-got
	if out.err != nil || len(out.res.Entries) != 1 {
		t.Fatalf("search in flight during the drain: %v", out.err)
	}
	<-stopped
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("drain took %v (shutdown_timeout 2s): the finished connections were not released", d)
	}
	// Both connections were ended by the server.
	for name, conn := range map[string]*ldap.Conn{"busy": c, "idle": idle} {
		_, err := conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil, nil))
		if err == nil {
			t.Errorf("%s connection still open after stop", name)
		}
		var le *ldap.Error
		if errors.As(err, &le) && le.ResultCode != ldap.ErrorNetwork && le.ResultCode != ldap.LDAPResultUnavailable {
			t.Errorf("%s connection: %v", name, err)
		}
	}
	if len(findEvents(r, events.Shutdown, nil)) != 1 {
		t.Error("shutdown event")
	}
}
