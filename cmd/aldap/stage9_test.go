//go:build integration

package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/events/schematest"
)

const (
	stage9TTL     = "[profile.virola.cache]\nmode = \"ttl\"\nttl = \"%s\"\nstale_while_down = %s\n"
	stage9Replica = "[profile.virola.cache]\nmode = \"replica\"\nsync_interval = \"1h\"\n"
	aliceFilter   = "(sAMAccountName=alice.adams)"
)

func ttlConfig(ttl string, staleWhileDown bool) string {
	swd := "false"
	if staleWhileDown {
		swd = "true"
	}
	return strings.Replace(strings.Replace(stage9TTL, "%s", ttl, 1), "%s", swd, 1)
}

// clientSearches counts the searches the test directory served except the
// root DSE reads of the health checks.
func (r *running) clientSearches() int64 {
	c := r.dc.Calls()
	return c.Searches - c.RootDSE
}

func (r *running) clientConn(t *testing.T) *ldap.Conn {
	t.Helper()
	c := r.ldaps(t)
	if err := c.Bind(tClientDN, clientPassword); err != nil {
		t.Fatalf("client bind: %v", err)
	}
	return c
}

// reloadWith rewrites the configuration file with edit and reloads.
func (r *running) reloadWith(t *testing.T, edit func(string) string) {
	t.Helper()
	b, err := os.ReadFile(r.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.path, []byte(edit(string(b))), 0o600); err != nil {
		t.Fatal(err)
	}
	o := r.d.opts
	o.State = r.d.state
	next, err := reload(context.Background(), r.d, r.path, true, o)
	if err != nil {
		t.Fatalf("reload: %v\n%s", err, r.logs.String())
	}
	r.d = next
	t.Cleanup(next.stop)
}

// TESTING.md 21: ttl — the second identical search does not go to the
// upstream (counter); after the ttl it does.
func TestStage9_TTL(t *testing.T) {
	r := startDaemonVirola(t, "", ttlConfig("1s", false))
	c := r.clientConn(t)
	n0 := r.clientSearches()
	if res := search(t, c, tUsersDN, aliceFilter, "mail"); len(res.Entries) != 1 {
		t.Fatalf("first search: %d", len(res.Entries))
	}
	n1 := r.clientSearches()
	if n1 == n0 {
		t.Fatal("first search did not reach the upstream")
	}
	if res := search(t, c, tUsersDN, aliceFilter, "mail"); len(res.Entries) != 1 || res.Entries[0].GetAttributeValue("mail") != "alice.adams@test.aldap" {
		t.Fatalf("second search: %v", res.Entries)
	}
	if n := r.clientSearches(); n != n1 {
		t.Errorf("second identical search reached the upstream (%d queries)", n-n1)
	}
	hits := findEvents(r, events.Search, func(e events.Record) bool { return e.Data["cache_hit"] == true })
	if len(hits) != 1 || hits[0].Data["upstream_queries"] != float64(0) {
		t.Errorf("cache_hit events = %+v", hits)
	}
	// A different request is a miss.
	search(t, c, tUsersDN, "(sAMAccountName=bob.brown)", "mail")
	n2 := r.clientSearches()
	if n2 == n1 {
		t.Error("different request served from the cache")
	}
	waitFor(t, func() bool {
		search(t, c, tUsersDN, aliceFilter, "mail")
		return r.clientSearches() > n2
	})
}

// TESTING.md 22: every upstream down + stale_while_down → answer with
// stale_served; without it → unavailable.
func TestStage9_StaleWhileDown(t *testing.T) {
	for _, swd := range []bool{true, false} {
		r := startDaemonVirola(t, "", ttlConfig("200ms", swd))
		c := r.clientConn(t)
		if res := search(t, c, tUsersDN, aliceFilter, "mail"); len(res.Entries) != 1 {
			t.Fatalf("warm-up: %d", len(res.Entries))
		}
		r.dc.Kill()
		time.Sleep(300 * time.Millisecond) // the result expires
		res, err := c.Search(ldap.NewSearchRequest(tUsersDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, aliceFilter, []string{"mail"}, nil))
		if !swd {
			if !ldap.IsErrorWithCode(err, ldap.LDAPResultUnavailable) {
				t.Errorf("without stale_while_down: %v %v", res, err)
			}
			if len(findEvents(r, events.StaleServed, nil)) != 0 {
				t.Error("stale_served without stale_while_down")
			}
			continue
		}
		if err != nil || len(res.Entries) != 1 || res.Entries[0].GetAttributeValue("mail") != "alice.adams@test.aldap" {
			t.Fatalf("stale answer: %v %v", res, err)
		}
		st := waitEvents(t, r, "stale", events.StaleServed, nil)
		if st.Profile != "virola" || st.Data["entries"] != float64(1) || st.Level != events.LevelMedium {
			t.Errorf("stale_served = %+v", st)
		}
		schematest.Check(t, eventsOf(r)...)
	}
}

// TESTING.md 23: replica — with the upstream off after a sync, search
// works and a user bind is unavailable; a forced sync fails, keeps the
// copy and reports replica_sync_failed; an unchanged reload keeps the copy.
func TestStage9_Replica(t *testing.T) {
	r := startDaemonVirola(t, "", stage9Replica)
	synced := waitEvents(t, r, "first sync", events.ReplicaSynced, nil)
	if synced.Data["entries"] != float64(19) {
		t.Fatalf("replica_synced = %+v", synced)
	}
	c := r.clientConn(t)
	n0 := r.clientSearches()
	all := search(t, c, tUsersDN, "(objectClass=*)", "mail")
	if len(all.Entries) != 19 || r.clientSearches() != n0 {
		t.Fatalf("replica search: %d entries, %d upstream queries", len(all.Entries), r.clientSearches()-n0)
	}
	binds := r.dc.Calls().Binds
	u := r.ldaps(t)
	if err := u.Bind("alice.adams@test.aldap", "alice.adams-pass"); err != nil {
		t.Fatalf("user bind with the upstream up: %v", err)
	}
	if r.dc.Calls().Binds == binds {
		t.Error("user bind did not reach the upstream")
	}

	r.dc.Kill()
	if res := search(t, c, tUsersDN, aliceFilter, "mail"); len(res.Entries) != 1 || res.Entries[0].GetAttributeValue("mail") != "alice.adams@test.aldap" {
		t.Fatalf("search with the upstream off: %v", res.Entries)
	}
	u2 := r.ldaps(t)
	if err := u2.Bind("bob.brown@test.aldap", "bob.brown-pass"); !ldap.IsErrorWithCode(err, ldap.LDAPResultUnavailable) {
		t.Errorf("user bind with the upstream off: %v", err)
	}

	ctl := newController(r.path, true, r.d.opts, r.d)
	if err := ctl.Sync(context.Background(), "virola"); err != nil {
		t.Fatalf("forced sync: %v", err)
	}
	failed := waitEvents(t, r, "forced sync", events.ReplicaSyncFailed, nil)
	if failed.Data["entries"] != float64(19) || failed.Reason != "upstream_unavailable" {
		t.Errorf("replica_sync_failed = %+v", failed)
	}
	if res := search(t, c, tUsersDN, "(objectClass=*)"); len(res.Entries) != 19 {
		t.Errorf("after the failed sync: %d", len(res.Entries))
	}
	if err := ctl.Sync(context.Background(), "plain"); err == nil {
		t.Error("sync of a profile without replica accepted")
	}

	// An unchanged reload keeps the copy: still served with the upstream off.
	r.reloadWith(t, func(s string) string { return s })
	c = r.clientConn(t)
	if res := search(t, c, tUsersDN, "(objectClass=*)"); len(res.Entries) != 19 {
		t.Errorf("after an unchanged reload: %d", len(res.Entries))
	}
	// A changed profile invalidates it: nothing to serve until a sync.
	r.reloadWith(t, func(s string) string { return strings.Replace(s, `"objectGUID"]`, `"objectGUID", "givenName"]`, 1) })
	c = r.clientConn(t)
	_, err := c.Search(ldap.NewSearchRequest(tUsersDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil, nil))
	if !ldap.IsErrorWithCode(err, ldap.LDAPResultUnavailable) {
		t.Errorf("after a profile change with the upstream off: %v", err)
	}
	schematest.Check(t, eventsOf(r)...)
}

// Reload of a changed profile invalidates the ttl cache; an unchanged
// reload keeps it.
func TestStage9_ReloadInvalidatesCache(t *testing.T) {
	r := startDaemonVirola(t, "", ttlConfig("1h", true))
	c := r.clientConn(t)
	search(t, c, tUsersDN, aliceFilter, "mail")
	n1 := r.clientSearches()

	r.reloadWith(t, func(s string) string { return s })
	c = r.clientConn(t)
	search(t, c, tUsersDN, aliceFilter, "mail")
	if n := r.clientSearches(); n != n1 {
		t.Errorf("unchanged reload dropped the cache (%d queries)", n-n1)
	}

	r.reloadWith(t, func(s string) string { return strings.Replace(s, `ttl = "1h"`, `ttl = "2h"`, 1) })
	c = r.clientConn(t)
	search(t, c, tUsersDN, aliceFilter, "mail")
	n2 := r.clientSearches()
	if n2 == n1 {
		t.Error("changed profile served from the old cache")
	}
	if !strings.Contains(r.logs.String(), "profile changed, cache invalidated") {
		t.Error("no invalidation log")
	}
	search(t, c, tUsersDN, aliceFilter, "mail")
	if r.clientSearches() != n2 {
		t.Error("new cache not used after the reload")
	}
}
