package record

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/events/schematest"
	"github.com/alstdev/aldap/internal/ldapfilter"
	"github.com/alstdev/aldap/internal/listener"
	"github.com/alstdev/aldap/internal/vdir"
)

func mustFilter(t *testing.T, s string) *ldapfilter.Filter {
	t.Helper()
	f, err := ldapfilter.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func entries(dns ...string) []listener.Entry {
	out := make([]listener.Entry, 0, len(dns))
	for _, d := range dns {
		out = append(out, listener.Entry{DN: d, Attrs: []listener.Attribute{{Name: "mail", Values: []string{"x@example.org"}}}})
	}
	return out
}

func tap(t *testing.T, filter string, dns ...string) vdir.TapSearch {
	t.Helper()
	c := listener.NewConn("c-1", "virola", &net.TCPAddr{IP: net.IPv4(10, 0, 0, 7), Port: 4000})
	return vdir.TapSearch{Conn: c, Base: "ou=users,dc=aldap", Scope: listener.ScopeSub, RawFilter: filter, Filter: mustFilter(t, filter),
		Attrs: []string{"mail"}, Result: listener.Result{Code: ldap.LDAPResultSuccess}, Entries: entries(dns...)}
}

func TestIsSecretAttr(t *testing.T) {
	for _, a := range []string{"userPassword", "unicodePwd", "UNICODEPWD", "dBCSPwd", "ntPwdHistory", "ms-Mcs-AdmPwd", "msLAPS-Password",
		"supplementalCredentials", "userPassword;binary", "clientSecret"} {
		if !IsSecretAttr(a) {
			t.Errorf("%s not secret", a)
		}
	}
	for _, a := range []string{"uid", "mail", "cn", "objectClass", "sAMAccountName", "pwdLastSet", "badPwdCount", "badPasswordTime", "pwdChangedTime;x"} {
		if IsSecretAttr(a) {
			t.Errorf("%s secret", a)
		}
	}
}

func TestRedactFilter(t *testing.T) {
	for in, want := range map[string]string{
		"(uid=jdoe)":                                      "(uid=jdoe)",
		"(userPassword=S3cret)":                           `(userPassword=\2a\2a\2a)`,
		"(&(uid=a)(unicodePwd=S3cret*))":                  `(&(uid=a)(unicodePwd=\2a\2a\2a))`,
		"(|(userPassword>=S3cret)(userPassword~=S3cret))": `(|(userPassword>=\2a\2a\2a)(userPassword~=\2a\2a\2a))`,
		"(userPassword:caseExactMatch:=S3cret)":           `(userPassword:caseExactMatch:=\2a\2a\2a)`,
		"(:dn:2.5.13.5:=S3cret)":                          `(:dn:2.5.13.5:=\2a\2a\2a)`,
		"(!(userPassword=*))":                             "(!(userPassword=*))",
		"(ms-Mcs-AdmPwd=*S3cret*)":                        `(ms-Mcs-AdmPwd=\2a\2a\2a)`,
	} {
		f := mustFilter(t, in)
		before := f.String()
		if got := RedactFilter(f); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
		if f.String() != before {
			t.Errorf("%s: the input filter was changed", in)
		}
		if _, err := ldapfilter.Parse(RedactFilter(f)); err != nil {
			t.Errorf("%s: redacted filter does not parse: %v", in, err)
		}
	}
	if RedactFilter(nil) != "" {
		t.Error("nil")
	}
}

func TestLineAndRead_RoundTrip(t *testing.T) {
	ts := time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
	tp := tap(t, "(&(uid=jdoe)(userPassword=S3cret))", "cn=jdoe,ou=users,dc=aldap", "cn=jane,ou=users,dc=aldap")
	tp.SizeLimit = 5
	line := Line("virola", ts, tp)
	if bytes.Contains(line, []byte("S3cret")) || !bytes.HasSuffix(line, []byte("\n")) {
		t.Fatalf("line: %s", line)
	}
	empty := tap(t, "(uid=nobody)")
	empty.Attrs = nil
	in := "# a comment\n\n" + string(line) + string(Line("virola", ts, empty))
	recs, lines, err := Read(strings.NewReader(in))
	if err != nil || len(recs) != 2 || lines[0] != 3 || lines[1] != 4 {
		t.Fatalf("read: %v %v %v", recs, lines, err)
	}
	r := recs[0]
	if r.Profile != "virola" || r.Base != "ou=users,dc=aldap" || r.Scope != "sub" || r.SizeLimit != 5 || *r.ResultCode != 0 || *r.Entries != 2 ||
		len(r.DNList) != 2 || r.TS != "2026-10-25T09:00:00Z" || len(r.Attrs) != 1 {
		t.Errorf("record: %+v", r)
	}
	if recs[1].DNList == nil || len(recs[1].DNList) != 0 || recs[1].Attrs == nil {
		t.Errorf("an empty answer must record dns: [] (compared as a set): %+v", recs[1])
	}
	// Compare: the same answer, a changed one.
	if _, differs := Compare(r, 0, []string{"CN=JANE,ou=users,dc=aldap", "cn=jdoe,ou=users,dc=aldap"}); differs {
		t.Error("same DN set differs")
	}
	d, differs := Compare(r, 4, []string{"cn=jdoe,ou=users,dc=aldap", "cn=new,ou=users,dc=aldap"})
	if !differs || d.ResultCode[1] != 4 || len(d.Missing) != 1 || len(d.Extra) != 1 || d.Entries != nil {
		t.Errorf("diff: %+v", d)
	}
	n := 3
	if d, differs := Compare(Search{Filter: "(x=1)", Entries: &n}, 0, []string{"a"}); !differs || d.Entries[0] != 3 {
		t.Errorf("count only: %+v", d)
	}
	if _, differs := Compare(Search{Filter: "(x=1)"}, 32, nil); differs {
		t.Error("nothing recorded but the filter: no difference")
	}
	for name, bad := range map[string]string{"json": "{", "no filter": `{"base":"x"}`, "negative size": `{"filter":"(a=1)","size_limit":-1}`,
		"too long": `{"filter":"` + strings.Repeat("a", MaxLine) + `"}`} {
		if _, _, err := Read(strings.NewReader(bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestLine_TooManyDNs(t *testing.T) {
	dns := make([]string, 0, 30000)
	for i := range 30000 {
		dns = append(dns, "cn=user-with-a-long-name-"+strings.Repeat("x", 20)+"-"+string(rune('a'+i%26))+",ou=users,dc=aldap")
	}
	line := Line("p", time.Now(), tap(t, "(objectClass=*)", dns...))
	if len(line) > MaxLine {
		t.Fatalf("line %d bytes", len(line))
	}
	recs, _, err := Read(bytes.NewReader(line))
	if err != nil || recs[0].DNList != nil || *recs[0].Entries != 30000 {
		t.Fatalf("dns must be dropped, entries kept: %v", err)
	}
}

func newRecorder(t *testing.T, o RecorderOptions) *Recorder {
	t.Helper()
	if o.Path == "" {
		o.Path = filepath.Join(t.TempDir(), "rec.jsonl")
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	r := NewRecorder(o)
	t.Cleanup(r.Stop)
	return r
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRecorder_StartStopAndMode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rec.jsonl")
	// An existing, too permissive file is narrowed to 0600.
	if err := os.WriteFile(p, []byte("# old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := newRecorder(t, RecorderOptions{Profile: "virola", Path: p})
	r.Search(tap(t, "(uid=before-start)"))
	if r.On() {
		t.Fatal("on before Start")
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(); err != nil || !r.On() {
		t.Fatalf("second Start: %v", err)
	}
	r.Search(tap(t, "(uid=jdoe)", "cn=jdoe,ou=users,dc=aldap"))
	r.Search(vdir.TapSearch{RawFilter: "(userPassword=S3cret", Result: listener.Result{Code: ldap.LDAPResultProtocolError}})
	r.Stop()
	r.Stop()
	r.Search(tap(t, "(uid=after-stop)"))
	got := readFile(t, p)
	if strings.Contains(got, "before-start") || strings.Contains(got, "after-stop") || strings.Contains(got, "S3cret") || !strings.Contains(got, `"filter":"(uid=jdoe)"`) {
		t.Errorf("recording:\n%s", got)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(p); fi.Mode().Perm() != FileMode {
			t.Errorf("mode %v", fi.Mode().Perm())
		}
	}
	// A new file is created 0600; recording resumes after Stop.
	q := filepath.Join(dir, "new.jsonl")
	r2 := newRecorder(t, RecorderOptions{Path: q})
	if err := r2.Start(); err != nil {
		t.Fatal(err)
	}
	r2.Search(tap(t, "(uid=a)"))
	r2.Stop()
	if err := r2.Start(); err != nil {
		t.Fatal(err)
	}
	r2.Search(tap(t, "(uid=b)"))
	r2.Stop()
	if s := readFile(t, q); strings.Count(s, "\n") != 2 {
		t.Errorf("two lines expected:\n%s", s)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(q); fi.Mode().Perm() != FileMode {
			t.Errorf("mode %v", fi.Mode().Perm())
		}
	}
}

func TestRecorder_RefusesSymlinkAndDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{link, dir} {
		if err := newRecorder(t, RecorderOptions{Path: p}).Start(); !errors.Is(err, ErrNotRegular) {
			t.Errorf("%s: %v", p, err)
		}
	}
	if err := newRecorder(t, RecorderOptions{Path: filepath.Join(dir, "missing", "x")}).Start(); err == nil {
		t.Error("unwritable path accepted")
	}
}

func TestRecorder_Rotation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rec.jsonl")
	at := time.Date(2026, 10, 25, 9, 0, 0, 123000000, time.UTC) // equal lines
	line := Line("p", at, tap(t, "(uid=0000)", "cn=x,ou=users,dc=aldap"))
	r := newRecorder(t, RecorderOptions{Profile: "p", Path: p, MaxBytes: int64(len(line)) * 3, MaxFiles: 2, Now: func() time.Time { return at }})
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	for range 10 {
		r.Search(tap(t, "(uid=0000)", "cn=x,ou=users,dc=aldap"))
	}
	r.Stop()
	for _, f := range []string{p, Rotated(p, 1), Rotated(p, 2)} {
		fi, err := os.Stat(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if fi.Size() > int64(len(line))*3 {
			t.Errorf("%s: %d bytes over the limit", f, fi.Size())
		}
		if runtime.GOOS != "windows" && fi.Mode().Perm() != FileMode {
			t.Errorf("%s: mode %v", f, fi.Mode().Perm())
		}
		if _, _, err := Read(strings.NewReader(readFile(t, f))); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	if _, err := os.Stat(Rotated(p, 3)); !os.IsNotExist(err) {
		t.Errorf("only max_files rotated files are kept: %v", err)
	}
	total := 0
	for _, f := range []string{p, Rotated(p, 1), Rotated(p, 2)} {
		total += strings.Count(readFile(t, f), "\n")
	}
	if total != 7 { // 3 + 3 + 1: the oldest file (3 lines) went
		t.Errorf("%d lines kept, want 7", total)
	}
}

// TestRecorder_NeverBlocks: a full queue drops searches instead of making
// the connection wait.
func TestRecorder_NeverBlocks(t *testing.T) {
	r := newRecorder(t, RecorderOptions{Path: filepath.Join(t.TempDir(), "rec.jsonl"), Queue: 1})
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	tp := tap(t, "(uid=x)", "cn=x,ou=users,dc=aldap")
	start := time.Now()
	for range 20000 {
		r.Search(tp)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("20000 searches took %s", el)
	}
	r.Stop()
	if r.Dropped() == 0 {
		t.Log("no search dropped (fast disk); the queue bound is still exercised by Queue: 1")
	}
}

type fakeEval struct {
	mu      sync.Mutex
	res     listener.Result
	dns     []string
	block   chan struct{}
	started chan struct{}
	calls   atomic.Int32
	panics  bool
	reqs    []vdir.TestRequest
}

func (f *fakeEval) Evaluate(ctx context.Context, req vdir.TestRequest) (listener.Result, []listener.Entry) {
	f.calls.Add(1)
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	f.mu.Unlock()
	if f.started != nil {
		f.started <- struct{}{}
	}
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return listener.Result{Code: ldap.LDAPResultUnavailable}, nil
		}
	}
	if f.panics {
		panic("boom")
	}
	return f.res, entries(f.dns...)
}

type sink struct {
	mu sync.Mutex
	es []events.Event
}

func (s *sink) Emit(e events.Event) { s.mu.Lock(); s.es = append(s.es, e); s.mu.Unlock() }
func (s *sink) all() []events.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]events.Event(nil), s.es...)
}

func TestShadow_Diff(t *testing.T) {
	ev := &sink{}
	fe := &fakeEval{res: listener.Result{Code: ldap.LDAPResultSuccess}, dns: []string{"cn=a,ou=users,dc=aldap", "CN=B,ou=users,dc=aldap", "cn=new,ou=users,dc=aldap"}}
	s := NewShadow(fe, ShadowOptions{Events: ev})
	main := tap(t, "(&(uid=*)(userPassword=S3cret))", "cn=a,ou=users,dc=aldap", "cn=b,ou=users,dc=aldap", "cn=gone,ou=users,dc=aldap")
	main.SizeLimit = 9
	s.Search(main)
	same := tap(t, "(uid=*)", "cn=a,ou=users,dc=aldap", "cn=b,ou=users,dc=aldap", "cn=new,ou=users,dc=aldap")
	s.Search(same)
	local := tap(t, "(objectClass=*)")
	local.Local = true
	s.Search(local)
	s.Search(vdir.TapSearch{RawFilter: "(", Conn: main.Conn})
	waitFor(t, func() bool { return fe.calls.Load() == 2 && len(s.sem) == 0 })
	s.Close()
	es := ev.all()
	if len(es) != 1 || fe.calls.Load() != 2 {
		t.Fatalf("events %d, evaluations %d", len(es), fe.calls.Load())
	}
	e := es[0]
	d := e.Data
	if e.Event != events.ShadowDiff || e.Level != events.LevelLow || e.ConnID != "c-1" || e.ClientIP != "10.0.0.7" || e.Profile != "virola" {
		t.Errorf("event: %+v", e)
	}
	if d["added_count"] != 1 || d["removed_count"] != 1 || d["added"].([]string)[0] != "cn=new,ou=users,dc=aldap" || d["removed"].([]string)[0] != "cn=gone,ou=users,dc=aldap" {
		t.Errorf("data: %v", d)
	}
	if strings.Contains(d["filter_norm"].(string), "S3cret") {
		t.Errorf("filter not redacted: %v", d["filter_norm"])
	}
	found := false
	for _, r := range fe.reqs {
		found = found || r.Filter == main.RawFilter && r.SizeLimit == 9 && r.Base == main.Base && r.Scope == main.Scope
	}
	if !found {
		t.Errorf("shadow requests: %+v", fe.reqs)
	}
	schematest.CheckEvents(t, es...)
}

func TestShadow_SamplesAndCodes(t *testing.T) {
	ev := &sink{}
	dns := make([]string, 0, 30)
	for i := range 30 {
		dns = append(dns, "cn=u"+string(rune('a'+i%26))+string(rune('a'+i/26))+",ou=users,dc=aldap")
	}
	s := NewShadow(&fakeEval{res: listener.Result{Code: ldap.LDAPResultSuccess}, dns: dns}, ShadowOptions{Events: ev})
	s.Search(tap(t, "(uid=*)"))
	waitFor(t, func() bool { _, _, d := s.Stats(); return d == 1 && len(s.sem) == 0 })
	s.Close()
	s2 := NewShadow(&fakeEval{res: listener.Result{Code: ldap.LDAPResultNoSuchObject}}, ShadowOptions{Events: ev})
	s2.Search(tap(t, "(uid=*)"))
	waitFor(t, func() bool { _, _, d := s2.Stats(); return d == 1 && len(s2.sem) == 0 })
	s2.Close()
	es := ev.all()
	if len(es) != 2 || len(es[0].Data["added"].([]string)) != MaxShadowSamples || es[0].Data["added_count"] != 30 {
		t.Fatalf("samples: %+v", es)
	}
	if es[1].Data["shadow_result_code"] != ldap.LDAPResultNoSuchObject || es[1].Data["added_count"] != 0 {
		t.Errorf("result code difference: %v", es[1].Data)
	}
	schematest.CheckEvents(t, es...)
}

// TestShadow_NeverDelaysTheClient: Search returns at once even when every
// shadow search hangs; beyond max_parallel searches are skipped; a timed
// out shadow search is not reported; Close cancels the hanging ones.
func TestShadow_NeverDelaysTheClient(t *testing.T) {
	ev := &sink{}
	fe := &fakeEval{res: listener.Result{Code: ldap.LDAPResultSuccess}, block: make(chan struct{}), started: make(chan struct{}, 100)}
	s := NewShadow(fe, ShadowOptions{Events: ev, MaxParallel: 2, Timeout: time.Hour})
	tp := tap(t, "(uid=x)", "cn=x,ou=users,dc=aldap")
	start := time.Now()
	for range 1000 {
		s.Search(tp)
	}
	if el := time.Since(start); el > time.Second {
		t.Errorf("1000 shadowed searches took %s with hanging shadows", el)
	}
	<-fe.started
	<-fe.started
	if skipped, _, _ := s.Stats(); skipped != 998 || fe.calls.Load() != 2 {
		t.Errorf("skipped %d, running %d", skipped, fe.calls.Load())
	}
	done := make(chan struct{})
	go func() { s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not cancel the hanging shadow searches")
	}
	if _, timeouts, diffs := s.Stats(); timeouts != 2 || diffs != 0 || len(ev.all()) != 0 {
		t.Errorf("timeouts %d diffs %d events %d", timeouts, diffs, len(ev.all()))
	}
	s.Search(tp) // after Close: ignored
	if fe.calls.Load() != 2 {
		t.Error("search shadowed after Close")
	}
	// Timeout: the shadow search is abandoned and not reported.
	fe2 := &fakeEval{block: make(chan struct{})}
	s2 := NewShadow(fe2, ShadowOptions{Events: ev, Timeout: 20 * time.Millisecond})
	s2.Search(tp)
	waitFor(t, func() bool { _, to, _ := s2.Stats(); return to == 1 })
	s2.Close()
	if len(ev.all()) != 0 {
		t.Error("a timed out shadow search was reported")
	}
}

func TestShadow_PanicRecovered(t *testing.T) {
	ev := &sink{}
	var logs bytes.Buffer
	s := NewShadow(&fakeEval{panics: true}, ShadowOptions{Events: ev, MaxParallel: 1, Logger: newTextLogger(&logs)})
	s.Search(tap(t, "(uid=x)"))
	waitFor(t, func() bool { return len(s.sem) == 0 })
	s.Close()
	s.Search(tap(t, "(uid=x)"))
	if !strings.Contains(logs.String(), "shadow search failed") || len(ev.all()) != 0 {
		t.Errorf("logs: %s", logs.String())
	}
	// The slot was released: a new runner with the same limit still works.
	if len(s.sem) != 0 {
		t.Error("semaphore slot leaked")
	}
}

func newTextLogger(w *bytes.Buffer) *slog.Logger { return slog.New(slog.NewTextHandler(w, nil)) }

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timeout")
}

func TestSearchJSON(t *testing.T) {
	// The format keys of docs/aldapctl.md.
	code, n := 0, 1
	b, err := json.Marshal(Search{Profile: "virola", Base: "b", Scope: "sub", Filter: "(uid=jdoe)", Attrs: []string{"mail"}, ResultCode: &code, Entries: &n, DNList: []string{"d"}})
	if err != nil || string(b) != `{"profile":"virola","base":"b","scope":"sub","filter":"(uid=jdoe)","attrs":["mail"],"result_code":0,"entries":1,"dns":["d"]}` {
		t.Errorf("%s %v", b, err)
	}
}
