package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/api"
	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/listener"
	"github.com/alstdev/aldap/internal/record"
	"github.com/alstdev/aldap/internal/secret"
	"github.com/alstdev/aldap/internal/vdir"
)

const (
	recFilterPW = "S3CR3T-recfilter-4444"
	recUserPW   = "S3CR3T-recuser-5555"
)

// pagedSearch pages through a search by hand and returns every entry and
// the cookies the server handed out.
func pagedSearch(t *testing.T, c *ldap.Conn, filter string, size uint32) ([]*ldap.Entry, [][]byte) {
	t.Helper()
	var all []*ldap.Entry
	var cookies [][]byte
	var cookie []byte
	for {
		ctl := ldap.NewControlPaging(size)
		ctl.SetCookie(cookie)
		res, err := c.Search(ldap.NewSearchRequest(tUsersDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, filter, []string{"mail"}, []ldap.Control{ctl}))
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, res.Entries...)
		p, _ := ldap.FindControl(res.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
		if p == nil || len(p.Cookie) == 0 {
			return all, cookies
		}
		cookie = p.Cookie
		cookies = append(cookies, p.Cookie)
	}
}

// replayAll replays a recording through the profile like aldapctl replay
// (POST /v1/profiles/{name}/test) and counts the differences.
func replayAll(t *testing.T, ctl *controller, recs []record.Search) int {
	t.Helper()
	n := 0
	for _, r := range recs {
		scope := map[string]listener.Scope{"base": listener.ScopeBase, "one": listener.ScopeOne, "sub": listener.ScopeSub}[r.Scope]
		res, err := ctl.Test(context.Background(), r.Profile, vdir.TestRequest{Base: r.Base, Scope: scope, Filter: r.Filter, Attrs: r.Attrs, SizeLimit: r.SizeLimit})
		if err != nil {
			t.Fatal(err)
		}
		dns := make([]string, 0, len(res.Entries))
		for _, e := range res.Entries {
			dns = append(dns, e.DN)
		}
		if _, differs := record.Compare(r, res.Result.Code, dns); differs {
			n++
		}
	}
	return n
}

// TestStage11_RecordReplayShadow: a recording holds every client search
// (a paged one once, with all DNs) but no password, bind data or paging
// cookie, is 0600; replaying it gives 0 differences before and n after a
// filter change; the shadow bases report shadow_diff while the client
// answer is the one of the main rules.
func TestStage11_RecordReplayShadow(t *testing.T) {
	recFile := filepath.Join(t.TempDir(), "virola.jsonl")
	virolaExtra := fmt.Sprintf("[profile.virola.record]\nenabled = true\nfile = %q\n[profile.virola.shadow]\nbases = [\"OU=Office,DC=test,DC=aldap\"]\n", recFile)
	r := startDaemonVirola(t, "", virolaExtra)
	c := r.ldaps(t)
	if err := c.Bind(tClientDN, clientPassword); err != nil {
		t.Fatal(err)
	}
	one := search(t, c, tUsersDN, "(sAMAccountName=alice.adams)", "mail")
	withPW := search(t, c, tUsersDN, "(|(sAMAccountName=alice.adams)(userPassword="+recFilterPW+"))", "mail")
	paged, cookies := pagedSearch(t, c, "(objectClass=*)", 2)
	if len(one.Entries) != 1 || len(withPW.Entries) != 1 || len(cookies) == 0 || len(paged) < 4 {
		t.Fatalf("searches: %d %d %d pages, %d entries", len(one.Entries), len(withPW.Entries), len(cookies), len(paged))
	}
	_ = c.Bind("alice.adams@test.aldap", recUserPW)
	_ = c.Bind(tClientDN, clientPassword)
	ctl := newController(r.path, true, daemonOptions{}, r.d)
	if err := ctl.Record(context.Background(), "virola", false); err != nil { // flushes
		t.Fatal(err)
	}
	if err := ctl.Record(context.Background(), "plain", true); !errors.Is(err, api.ErrNoRecordFile) {
		t.Errorf("plain has no record.file: %v", err)
	}
	raw, err := os.ReadFile(recFile)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(recFile); fi.Mode().Perm() != 0o600 {
			t.Errorf("mode %v", fi.Mode().Perm())
		}
	}
	text := string(raw)
	for _, s := range []string{clientPassword, tSvcPW, recFilterPW, recUserPW, "S3CR3T"} {
		if strings.Contains(text, s) {
			t.Errorf("the recording holds %q:\n%s", s, text)
		}
	}
	for _, ck := range cookies {
		for _, form := range []string{string(ck), base64.StdEncoding.EncodeToString(ck), fmt.Sprintf("%x", ck)} {
			if strings.Contains(text, form) {
				t.Errorf("the recording holds a paging cookie %q", form)
			}
		}
	}
	recs, _, err := record.Read(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 || len(recs[2].DNList) != len(paged) || recs[0].Profile != "virola" || !strings.Contains(recs[1].Filter, `userPassword=\2a\2a\2a`) {
		t.Fatalf("records (want 3, the paged search once with %d DNs):\n%s", len(paged), text)
	}

	// Replay before a change: no difference.
	if n := replayAll(t, ctl, recs); n != 0 {
		t.Errorf("replay before the change: %d differences", n)
	}

	// Shadow: the Office base alone drops the Branch users of the paged search.
	waitFor(t, func() bool { return strings.Contains(r.logs.String(), `"event":"shadow_diff"`) })
	if !strings.Contains(r.logs.String(), `"removed_count"`) {
		t.Errorf("shadow_diff without counts:\n%s", r.logs.String())
	}

	// A filter change: every search that returned alice.adams differs.
	body, err := os.ReadFile(r.path)
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(body), "rdn_attr = \"sAMAccountName\"\n", "rdn_attr = \"sAMAccountName\"\nfilter = \"(&"+config.DefaultADFilter+"(!(sAMAccountName=alice.adams)))\"\n", 1)
	if err := os.WriteFile(r.path, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := daemonOptions{LogOut: r.logs, EventsOut: r.logs, Secrets: secret.Default, Argon2: fastArgon, Hostname: "aldap-test", State: r.d.state}
	next, err := reload(context.Background(), r.d, r.path, true, opts)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	t.Cleanup(next.stop)
	ctl2 := newController(r.path, true, opts, next)
	want := 0
	for _, rec := range recs {
		for _, dn := range rec.DNList {
			if strings.HasPrefix(dn, "sAMAccountName=alice.adams,") || strings.HasPrefix(strings.ToLower(dn), "cn=alice.adams,") {
				want++
				break
			}
		}
	}
	if n := replayAll(t, ctl2, recs); n != want || n == 0 {
		t.Errorf("replay after the filter change: %d differences, want %d", n, want)
	}
	// The record section did not change: the recorder (stopped) is kept
	// and starts again on request.
	if err := ctl2.Record(context.Background(), "virola", true); err != nil {
		t.Fatal(err)
	}
	r.d.state.recorders.closeAll()
}
