package record

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/events/schematest"
	"github.com/alstdev/aldap/internal/listener"
	"github.com/alstdev/aldap/internal/profile"
	"github.com/alstdev/aldap/internal/upstream"
	"github.com/alstdev/aldap/internal/vdir"
)

const (
	dirVB    = "ou=virola,dc=aldap"
	dirUsers = "ou=users," + dirVB
)

// mockFile writes a mock directory: 12 users, every third one in IT.
func mockFile(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("base_dn = \"ou=people,dc=mock\"\n")
	for i := range 12 {
		dept := "Sales"
		if i%3 == 0 {
			dept = "IT"
		}
		fmt.Fprintf(&b, "[[users]]\ncn = \"User %02d\"\nsAMAccountName = \"u%02d\"\nmail = \"u%02d@mock.local\"\ndepartment = %q\nuserPassword = \"S3CR3T-u%02d\"\n", i, i, i, dept, i)
	}
	p := filepath.Join(t.TempDir(), "mock.toml")
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func mockProfile(filter string) *config.Profile {
	p := config.DefaultProfile()
	p.Mode, p.Upstream = "mock", ""
	p.VirtualBase = dirVB
	p.Bases = []string{"ou=people,dc=mock"}
	p.Filter = filter
	p.RDNAttr = "sAMAccountName"
	p.Attrs.Allow = []string{"sAMAccountName", "mail", "department", "cn"}
	return p
}

func mockDir(t *testing.T, filter string, src vdir.Searcher, o vdir.Options) *vdir.Directory {
	t.Helper()
	rules, err := profile.Compile("virola", mockProfile(filter), nil, profile.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return vdir.New(rules, src, o)
}

// gate blocks every search of the wrapped directory until it is opened.
type gate struct {
	vdir.Searcher
	open chan struct{}
	mu   sync.Mutex
	n    int
}

func (g *gate) Search(ctx context.Context, req upstream.SearchRequest) (*upstream.Result, error) {
	g.mu.Lock()
	g.n++
	g.mu.Unlock()
	select {
	case <-g.open:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return g.Searcher.Search(ctx, req)
}

func (g *gate) calls() int { g.mu.Lock(); defer g.mu.Unlock(); return g.n }

type collect struct{ es []listener.Entry }

func (c *collect) Entry(e listener.Entry) error { c.es = append(c.es, e); return nil }

func clientSearch(t *testing.T, d *vdir.Directory, filter string, attrs ...string) (listener.Result, []listener.Entry, time.Duration) {
	t.Helper()
	c := listener.NewConn("c-9", "virola", &net.TCPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 5000})
	w := &collect{}
	start := time.Now()
	res := d.Search(context.Background(), c, &listener.SearchRequest{Base: dirUsers, Scope: listener.ScopeSub, Filter: filter, Attrs: attrs}, w)
	return res, w.es, time.Since(start)
}

// TestShadow_DirectoryAnswerUnchanged runs real directories (mock mode):
// with a recorder and a shadow whose every search hangs, the client gets
// the same answer as without taps and no slower than the hang allows;
// once the shadow directory answers, shadow_diff lists the users the
// shadow filter drops.
func TestShadow_DirectoryAnswerUnchanged(t *testing.T) {
	m, err := vdir.LoadMock(mockFile(t), "")
	if err != nil {
		t.Fatal(err)
	}
	plain := mockDir(t, "(objectClass=*)", m, vdir.Options{})
	wantRes, want, _ := clientSearch(t, plain, "(objectClass=*)", "mail", "cn")
	if wantRes.Code != ldap.LDAPResultSuccess || len(want) != 12 {
		t.Fatalf("baseline: %v %d", wantRes, len(want))
	}

	g := &gate{Searcher: m, open: make(chan struct{})}
	ev := &sink{}
	shadow := NewShadow(mockDir(t, "(department=IT)", g, vdir.Options{Events: events.Discard}), ShadowOptions{Events: ev, MaxParallel: 2, Timeout: time.Minute})
	recPath := filepath.Join(t.TempDir(), "rec.jsonl")
	rec := NewRecorder(RecorderOptions{Profile: "virola", Path: recPath, Logger: slog.New(slog.DiscardHandler)})
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}
	main := mockDir(t, "(objectClass=*)", m, vdir.Options{Taps: []vdir.Tap{shadow, rec}})
	var worst time.Duration
	for range 50 {
		res, got, took := clientSearch(t, main, "(objectClass=*)", "mail", "cn")
		if !reflect.DeepEqual(res, wantRes) || !reflect.DeepEqual(got, want) {
			t.Fatalf("the answer changed with shadow rules: %v, %d entries", res, len(got))
		}
		worst = max(worst, took)
	}
	if worst > 500*time.Millisecond {
		t.Errorf("slowest client search %s while every shadow search hangs", worst)
	}
	waitFor(t, func() bool { return g.calls() == 2 })
	if skipped, _, _ := shadow.Stats(); skipped != 48 {
		t.Errorf("skipped %d, want 48 (max_parallel 2)", skipped)
	}
	close(g.open)
	waitFor(t, func() bool { _, _, d := shadow.Stats(); return d == 2 })
	shadow.Close()
	rec.Stop()

	es := ev.all()
	if len(es) != 2 {
		t.Fatalf("%d shadow_diff events", len(es))
	}
	d := es[0].Data
	if d["removed_count"] != 8 || d["added_count"] != 0 || d["shadow_results"] != 4 || d["results"] != 12 || es[0].ClientIP != "10.0.0.9" {
		t.Errorf("shadow_diff: %v", d)
	}
	schematest.CheckEvents(t, es...)

	recs, _, err := Read(strings.NewReader(readFile(t, recPath)))
	if err != nil || len(recs) != 50 {
		t.Fatalf("recording: %d %v", len(recs), err)
	}
	// Replaying the recording against the unchanged profile: no difference;
	// against the shadow rules: every search differs.
	itOnly := mockDir(t, "(department=IT)", m, vdir.Options{})
	for _, tc := range []struct {
		dir   *vdir.Directory
		diffs int
	}{{plain, 0}, {itOnly, 50}} {
		n := 0
		for _, r := range recs {
			res := tc.dir.Test(context.Background(), vdir.TestRequest{Base: r.Base, Scope: listener.ScopeSub, Filter: r.Filter, Attrs: r.Attrs, SizeLimit: r.SizeLimit})
			if _, differs := Compare(r, res.Result.Code, dnList(res.Entries)); differs {
				n++
			}
		}
		if n != tc.diffs {
			t.Errorf("replay: %d differences, want %d", n, tc.diffs)
		}
	}
}
