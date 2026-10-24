package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/alstdev/aldap/internal/events"
)

// fakeTUI implements tuiAPI with fixtures and records every action.
type fakeTUI struct {
	mu       sync.Mutex
	calls    []string
	lockdown bool
	putErr   error
	stream   []events.Record
}

func (f *fakeTUI) record(s string) {
	f.mu.Lock()
	f.calls = append(f.calls, s)
	f.mu.Unlock()
}

func (f *fakeTUI) callList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeTUI) Status(context.Context) (statusView, error) {
	return statusView{Version: "1.4.0", GoVersion: "go1.26.10", UptimeS: 3600, Lockdown: f.lockdown, Profiles: []string{"virola", "app"}, EventsSeq: 900,
		LocksActive: 2, Upstreams: map[string][]upstreamBrief{"ad": {{URL: "ldaps://dc1.corp.example:636", State: "up", LatencyP50MS: 2}}}}, nil
}

func (f *fakeTUI) Upstreams(context.Context) (map[string][]serverView, error) {
	return map[string][]serverView{"ad": {
		{URL: "ldaps://dc1.corp.example:636", State: "up", P50: int64(2 * time.Millisecond)},
		{URL: "ldaps://dc2.corp.example:636", State: "down", ConsecutiveFail: 3, LastError: "dial tcp 192.0.2.2:636: connect: connection refused after a very long wait"},
	}}, nil
}

func (f *fakeTUI) Profiles(context.Context) ([]profileView, error) {
	return []profileView{{Name: "virola", Mode: "proxy", Transport: "ldaps", Listen: []string{":636"}, Upstream: "ad", VirtualBase: "dc=aldap", Cache: "replica"},
		{Name: "app", Mode: "mock", Transport: "ldap", Listen: []string{"127.0.0.1:1389"}, VirtualBase: "dc=app", Cache: "none"}}, nil
}

func (f *fakeTUI) Locks(context.Context) ([]lockView, error) {
	return []lockView{
		{Target: "ip", Key: "192.0.2.10", Until: fixedNow.Add(15 * time.Minute), Failures: 5, Source: "ratelimit", Profile: "virola"},
		{Target: "account", Key: "jdoe", Until: fixedNow.Add(time.Hour), Source: "api", Reason: "ticket 42 with a reason long enough to need cutting at eighty columns"},
	}, nil
}

func (f *fakeTUI) Indicators(context.Context) ([]indicatorView, error) {
	return []indicatorView{{Target: "ip", Key: "203.0.113.5", Score: 8.5, Reasons: []string{"spray"}, LastSeen: fixedNow}}, nil
}

func (f *fakeTUI) ConfigGet(context.Context) (string, error) {
	var b strings.Builder
	b.WriteString("[server]\nlog_level = \"info\"\n")
	for i := range 40 {
		fmt.Fprintf(&b, "# line %d of a long configuration %s\n", i, strings.Repeat("x", 90))
	}
	return b.String(), nil
}

func (f *fakeTUI) ConfigPut(_ context.Context, body string, dry bool) (applyResult, error) {
	f.record(fmt.Sprintf("put dry=%v %q", dry, body))
	if f.putErr != nil {
		return applyResult{}, f.putErr
	}
	return applyResult{OK: true, DryRun: dry, Backup: map[bool]string{false: "/etc/aldap/aldap.toml.bak.1"}[dry]}, nil
}

func (f *fakeTUI) Lock(_ context.Context, target, key string, d time.Duration, reason string) (lockView, error) {
	f.record(fmt.Sprintf("lock %s %s %s %q", target, key, d, reason))
	return lockView{Target: target, Key: key, Until: fixedNow.Add(d)}, nil
}

func (f *fakeTUI) Unlock(_ context.Context, target, key string) error {
	f.record("unlock " + target + " " + key)
	return nil
}

func (f *fakeTUI) Lockdown(_ context.Context, on bool) (bool, error) {
	f.record(fmt.Sprintf("lockdown %v", on))
	f.lockdown = on
	return on, nil
}

func (f *fakeTUI) Reload(context.Context) error {
	f.record("reload")
	return nil
}

func (f *fakeTUI) Sync(_ context.Context, p string) error {
	f.record("sync " + p)
	return nil
}

func (f *fakeTUI) Learn(_ context.Context, p string, d time.Duration) (learnResult, error) {
	f.record(fmt.Sprintf("learn %s %s", p, d))
	return learnResult{Learning: true, Until: fixedNow.Add(d), Scope: "process"}, nil
}

func (f *fakeTUI) Stream(ctx context.Context, since uint64, _ []string, fn func(events.Record) error, _ func(error)) error {
	f.record(fmt.Sprintf("stream since=%d", since))
	for _, r := range f.stream {
		if err := fn(r); err != nil {
			return err
		}
	}
	<-ctx.Done()
	return nil
}

// tuiEnv drives a model synchronously: commands that the test wants run
// are executed and their messages fed back.
type tuiEnv struct {
	t   *testing.T
	m   *model
	api *fakeTUI
}

func newTUI(t *testing.T, w, h int) *tuiEnv {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	api := &fakeTUI{}
	m := newModel(ctx, api, tuiOptions{color: true, now: func() time.Time { return fixedNow }})
	e := &tuiEnv{t: t, m: m, api: api}
	e.send(tea.WindowSizeMsg{Width: w, Height: h})
	e.run(m.fetch(tabStatus))
	return e
}

func (e *tuiEnv) send(msg tea.Msg) tea.Cmd {
	_, cmd := e.m.Update(msg)
	return cmd
}

// run executes cmd (batches included) and feeds the messages back.
func (e *tuiEnv) run(cmd tea.Cmd) {
	if cmd == nil {
		return
	}
	msg := cmd()
	switch msg := msg.(type) {
	case nil:
	case tea.BatchMsg:
		for _, c := range msg {
			e.run(c)
		}
	default:
		e.run(e.send(msg))
	}
}

func (e *tuiEnv) key(keys ...string) tea.Cmd {
	var last tea.Cmd
	for _, k := range keys {
		var msg tea.KeyMsg
		switch k {
		case "tab":
			msg = tea.KeyMsg{Type: tea.KeyTab}
		case "shift+tab":
			msg = tea.KeyMsg{Type: tea.KeyShiftTab}
		case "left":
			msg = tea.KeyMsg{Type: tea.KeyLeft}
		case "right":
			msg = tea.KeyMsg{Type: tea.KeyRight}
		case "up":
			msg = tea.KeyMsg{Type: tea.KeyUp}
		case "down":
			msg = tea.KeyMsg{Type: tea.KeyDown}
		case "enter":
			msg = tea.KeyMsg{Type: tea.KeyEnter}
		case "esc":
			msg = tea.KeyMsg{Type: tea.KeyEsc}
		case "space":
			msg = tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
		case "ctrl+c":
			msg = tea.KeyMsg{Type: tea.KeyCtrlC}
		default:
			msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
		}
		last = e.send(msg)
	}
	return last
}

// press sends keys and runs the resulting command.
func (e *tuiEnv) press(keys ...string) {
	for _, k := range keys {
		e.run(e.key(k))
	}
}

// typeText types into the input line.
func (e *tuiEnv) typeText(s string) {
	for _, r := range s {
		e.send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
}

func (e *tuiEnv) view() string { return e.m.View() }

// checkFits asserts the screen is at most w×h cells.
func (e *tuiEnv) checkFits(w, h int, what string) {
	e.t.Helper()
	lines := strings.Split(e.view(), "\n")
	if len(lines) > h {
		e.t.Errorf("%s: %d lines > %d", what, len(lines), h)
	}
	for i, l := range lines {
		if lw := lipgloss.Width(l); lw > w {
			e.t.Errorf("%s: line %d is %d cells > %d: %q", what, i, lw, w, l)
		}
	}
}

// TestTUI_Fits80x24 renders every tab, the help and the prompts at 80×24.
func TestTUI_Fits80x24(t *testing.T) {
	e := newTUI(t, 80, 24)
	e.api.stream = nil
	for i := range 50 {
		e.send(streamEventMsg{events.Record{Seq: uint64(i + 1), TS: "2026-10-23T11:00:00Z", Event: "bind_fail", Level: "medium", Profile: "virola",
			ClientIP: "192.0.2.10", Account: strings.Repeat("a", 60), Data: map[string]any{"note": strings.Repeat("y", 100)}}})
	}
	for t2 := range numTabs {
		e.press(fmt.Sprint(int(t2) + 1))
		if e.m.tab != t2 {
			t.Fatalf("key %d: tab %v", t2+1, e.m.tab)
		}
		e.checkFits(80, 24, t2.String())
		if lines := strings.Split(e.view(), "\n"); len(lines) != 24 {
			t.Errorf("%s: %d lines, want the full 24", t2, len(lines))
		}
	}
	e.press("?")
	e.checkFits(80, 24, "help")
	e.press("esc", "4", "u")
	e.checkFits(80, 24, "confirm")
	e.press("n", "l")
	e.checkFits(80, 24, "input")
	// Smaller than 80×24 still renders without overflowing the width.
	e.send(tea.WindowSizeMsg{Width: 40, Height: 10})
	e.press("esc")
	for t2 := range numTabs {
		e.press(fmt.Sprint(int(t2) + 1))
		e.checkFits(40, 10, "small "+t2.String())
	}
}

// TestTUI_HelpListsEveryKey: ? shows all hot keys at 80×24.
func TestTUI_HelpListsEveryKey(t *testing.T) {
	e := newTUI(t, 80, 24)
	e.press("?")
	v := e.view()
	for _, k := range helpKeys() {
		h := k.Help()
		if !strings.Contains(v, h.Desc) || !strings.Contains(v, h.Key) {
			t.Errorf("help lacks %q %q", h.Key, h.Desc)
		}
	}
	for _, ks := range tabKeys {
		for _, k := range ks {
			if !strings.Contains(v, k.Help().Desc) {
				t.Errorf("help lacks tab key %q", k.Help().Desc)
			}
		}
	}
	for _, t2 := range tabNames {
		if !strings.Contains(v, t2) {
			t.Errorf("help lacks the %s section or tab", t2)
		}
	}
	// Keys do nothing while the help is shown; ? closes it.
	e.press("2", "?")
	if e.m.help || e.m.tab != tabStatus {
		t.Errorf("help %v tab %v", e.m.help, e.m.tab)
	}
}

func TestTUI_Navigation(t *testing.T) {
	e := newTUI(t, 80, 24)
	steps := []struct {
		key  string
		want tab
	}{
		{"tab", tabUpstreams}, {"right", tabProfiles}, {"shift+tab", tabUpstreams}, {"left", tabStatus},
		{"left", tabConfig}, {"tab", tabStatus}, {"5", tabEvents}, {"7", tabConfig}, {"9", tabConfig}, {"1", tabStatus},
	}
	for _, s := range steps {
		e.press(s.key)
		if e.m.tab != s.want {
			t.Fatalf("after %s: tab %v, want %v", s.key, e.m.tab, s.want)
		}
	}
	if !strings.Contains(e.view(), "[Status]") {
		t.Error("active tab not bracketed")
	}
	// Lists: the cursor stays inside the rows.
	e.press("4", "down", "down", "down")
	if e.m.cursor[tabLocks] != 1 || !strings.Contains(e.view(), "> account") {
		t.Errorf("locks cursor %d\n%s", e.m.cursor[tabLocks], e.view())
	}
	if v := e.view(); !strings.Contains(v, "reason: ticket 42") || !strings.Contains(v, "eighty columns") {
		t.Errorf("no detail of the selected lock:\n%s", e.view())
	}
	e.press("g")
	if e.m.cursor[tabLocks] != 0 {
		t.Error("g: top")
	}
	e.press("2", "down")
	if v := e.view(); !strings.Contains(v, "last error:") || !strings.Contains(v, "very long wait") {
		t.Errorf("no detail of the selected upstream:\n%s", e.view())
	}
	// Config scrolls.
	e.press("7", "down", "down")
	if e.m.offset[tabConfig] != 2 || strings.Contains(e.view(), "[server]") {
		t.Errorf("config offset %d", e.m.offset[tabConfig])
	}
	e.press("q")
	if !e.m.quitting || e.view() != "" {
		t.Error("q does not quit")
	}
}

// TestTUI_UnlockConfirm: u asks y/n; n sends nothing, y unlocks the
// selected lock.
func TestTUI_UnlockConfirm(t *testing.T) {
	e := newTUI(t, 80, 24)
	e.press("4", "down", "u")
	if e.m.confirm == nil || !strings.Contains(e.view(), "Unlock account jdoe? [y/n]") {
		t.Fatalf("no prompt:\n%s", e.view())
	}
	e.press("x") // other keys keep the prompt
	if e.m.confirm == nil {
		t.Fatal("prompt dismissed by an unrelated key")
	}
	e.press("n")
	if e.m.confirm != nil || len(e.api.callList()) != 0 && strings.Contains(strings.Join(e.api.callList(), ","), "unlock") {
		t.Fatalf("n: %v", e.api.callList())
	}
	e.press("u")
	e.press("esc")
	e.press("u", "y")
	calls := strings.Join(e.api.callList(), ",")
	if strings.Count(calls, "unlock") != 1 || !strings.Contains(calls, "unlock account jdoe") {
		t.Fatalf("calls %v", calls)
	}
	if !strings.Contains(e.view(), "unlocked account jdoe") {
		t.Errorf("no result line:\n%s", e.view())
	}
}

func TestTUI_LockInputAndActions(t *testing.T) {
	e := newTUI(t, 80, 24)
	// l on Locks: input, then confirmation.
	e.press("4", "l")
	if e.m.inKind != inputLock {
		t.Fatal("no input")
	}
	e.typeText("198.51.100.7 2h port scan")
	e.press("enter")
	if e.m.confirm == nil || !strings.Contains(e.m.confirm.prompt, "Lock ip 198.51.100.7 for 2h0m0s?") {
		t.Fatalf("prompt %+v", e.m.confirm)
	}
	e.press("y")
	// Esc cancels an input; a bad duration is an error, nothing sent.
	e.press("l")
	e.typeText("x")
	e.press("esc")
	e.press("l")
	e.typeText("jdoe soon")
	e.press("enter")
	if e.m.confirm != nil || !strings.Contains(e.view(), "! duration") {
		t.Errorf("bad duration:\n%s", e.view())
	}
	// Indicators: l locks the selected key.
	e.press("6", "l")
	e.press("enter", "y")
	// Status: d switches lockdown; R reloads (global).
	e.press("1", "d", "y", "R", "y")
	// Profiles: s sync and b learn the selected profile.
	e.press("3", "down", "s", "y", "b")
	e.press("enter", "y")
	want := []string{`lock ip 198.51.100.7 2h0m0s "port scan"`, `lock ip 203.0.113.5 1h0m0s "aldapctl: indicator"`, "lockdown true", "reload", "sync app", "learn app 24h0m0s"}
	calls := e.api.callList()
	got := []string{}
	for _, c := range calls {
		if !strings.HasPrefix(c, "stream") {
			got = append(got, c)
		}
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("calls\n%v\nwant\n%v", got, want)
	}
	if !e.m.status.Lockdown || !strings.Contains(e.m.tabBar(80), "LOCKDOWN") {
		t.Error("lockdown not shown after refresh")
	}
}

func TestParseLockInput(t *testing.T) {
	for _, tc := range []struct {
		in, target, key string
		d               time.Duration
		reason          string
		err             bool
	}{
		{in: "192.0.2.1", target: "ip", key: "192.0.2.1", d: time.Hour},
		{in: "jdoe 30m too many failures", target: "account", key: "jdoe", d: 30 * time.Minute, reason: "too many failures"},
		{in: "account 10.0.0.1 1h", target: "account", key: "10.0.0.1", d: time.Hour},
		{in: "ip jdoe", err: true},
		{in: "", err: true},
		{in: "jdoe -1h", err: true},
	} {
		target, key, d, reason, err := parseLockInput(tc.in)
		if (err != nil) != tc.err || (!tc.err && (target != tc.target || key != tc.key || d != tc.d || reason != tc.reason)) {
			t.Errorf("%q: %s %s %s %q %v", tc.in, target, key, d, reason, err)
		}
	}
}

func TestTUI_EventsFilterPauseSearch(t *testing.T) {
	e := newTUI(t, 80, 24)
	add := func(seq uint64, kind, profile, ip string) {
		e.send(streamEventMsg{events.Record{Seq: seq, TS: "2026-10-23T11:00:00Z", Event: kind, Level: "low", Profile: profile, ClientIP: ip}})
	}
	add(1, "bind_ok", "virola", "192.0.2.1")
	add(2, "bind_fail", "virola", "192.0.2.2")
	add(3, "search", "app", "192.0.2.3")
	add(2, "bind_fail", "virola", "192.0.2.2") // repeated after a reconnect
	e.press("5")
	if !strings.Contains(e.view(), "Events 3/3  live") {
		t.Fatalf("view:\n%s", e.view())
	}
	e.press("f")
	e.typeText("type=bind_fail,bind_ok profile=virola")
	e.press("enter")
	if v := e.view(); !strings.Contains(v, "Events 2/3") || strings.Contains(v, " search ") {
		t.Errorf("filter:\n%s", v)
	}
	e.press("/")
	e.typeText("192.0.2.2")
	e.press("enter")
	if v := e.view(); !strings.Contains(v, "Events 1/3") || !strings.Contains(v, "bind_fail") {
		t.Errorf("search:\n%s", v)
	}
	e.press("c")
	e.press("space")
	add(4, "lock", "virola", "192.0.2.2")
	if v := e.view(); !strings.Contains(v, "PAUSED (+1 new)") || strings.Contains(v, " lock ") {
		t.Errorf("pause:\n%s", v)
	}
	e.press("p")
	if v := e.view(); !strings.Contains(v, "Events 4/4  live") {
		t.Errorf("resume:\n%s", v)
	}
	e.press("f")
	e.typeText("shade=red")
	e.press("enter")
	if !strings.Contains(e.view(), "! filter key") {
		t.Errorf("bad filter:\n%s", e.view())
	}
	// A broken stream is shown and cleared by the next event.
	e.send(streamStateMsg{err: errors.New("connection reset")})
	if !strings.Contains(e.view(), "disconnected: connection reset") {
		t.Error("stream state not shown")
	}
	add(5, "bind_ok", "virola", "192.0.2.1")
	if strings.Contains(e.view(), "disconnected") {
		t.Error("stream state not cleared")
	}
	// The ring keeps the newest maxEvents.
	for i := range maxEvents + 10 {
		add(uint64(10+i), "search", "app", "192.0.2.9")
	}
	if len(e.m.evts) != maxEvents || e.m.evts[len(e.m.evts)-1].Seq != uint64(maxEvents+19) {
		t.Errorf("ring %d", len(e.m.evts))
	}
}

func TestTUI_StreamStartsFromBacklog(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	api := &fakeTUI{stream: []events.Record{{Seq: 401, Event: "bind_ok"}}}
	m := newModel(ctx, api, tuiOptions{})
	go m.runStream()
	msg := m.waitStream()()
	cancel()
	if ev, ok := msg.(streamEventMsg); !ok || ev.rec.Seq != 401 {
		t.Fatalf("msg %#v", msg)
	}
	if c := api.callList(); len(c) == 0 || c[0] != fmt.Sprintf("stream since=%d", 900-eventBacklog) {
		t.Errorf("calls %v", c)
	}
}

// TestTUI_ConfigEditValidateApply drives e (editor), v and a with confirmation.
func TestTUI_ConfigEditValidateApply(t *testing.T) {
	e := newTUI(t, 80, 24)
	var edited string
	e.m.edit = func(path string) tea.Cmd {
		edited = path
		return func() tea.Msg {
			if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
				return editorDoneMsg{fmt.Errorf("draft file %v: %w", fi, err)}
			}
			return editorDoneMsg{os.WriteFile(path, []byte("[server]\nlog_level = \"warn\"\n"), 0o600)}
		}
	}
	e.press("7", "v")
	if !strings.Contains(e.view(), "no draft") {
		t.Errorf("v without draft:\n%s", e.view())
	}
	e.press("e")
	if !e.m.draftDirty || !strings.Contains(e.view(), "DRAFT") || !strings.Contains(e.view(), `log_level = "warn"`) {
		t.Fatalf("draft:\n%s", e.view())
	}
	if _, err := os.Stat(edited); !os.IsNotExist(err) {
		t.Errorf("temporary file left: %v", err)
	}
	e.press("v")
	e.press("a")
	if e.m.confirm == nil {
		t.Fatal("apply without confirmation")
	}
	e.press("n")
	e.press("a", "y")
	calls := e.api.callList()
	want := []string{`put dry=true "[server]\nlog_level = \"warn\"\n"`, `put dry=false "[server]\nlog_level = \"warn\"\n"`}
	var got []string
	for _, c := range calls {
		if strings.HasPrefix(c, "put") {
			got = append(got, c)
		}
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("calls %v", got)
	}
	if e.m.draftDirty || !strings.Contains(e.view(), "backup /etc/aldap/aldap.toml.bak.1") {
		t.Errorf("after apply:\n%s", e.view())
	}
	// A failed validation shows the daemon's message; x discards the draft.
	e.press("e")
	e.api.putErr = errors.New("API: configuration invalid:\nupstream.ad.bind_password: is the masked placeholder")
	e.press("v")
	if v := e.view(); !strings.Contains(v, "! API: configuration invalid") {
		t.Errorf("validation error:\n%s", v)
	}
	e.press("x")
	if e.m.draftDirty {
		t.Error("x kept the draft")
	}
	// An editor failure keeps no draft and reports the error.
	e.m.edit = func(string) tea.Cmd { return func() tea.Msg { return editorDoneMsg{errors.New("exit status 1")} } }
	e.press("e")
	if e.m.draftDirty || !strings.Contains(e.view(), "! editor: exit status 1") {
		t.Errorf("editor failure:\n%s", e.view())
	}
}

func TestTUI_NoColor(t *testing.T) {
	s := newStyles(false)
	for name, st := range map[string]lipgloss.Style{"err": s.err, "ok": s.ok, "warn": s.warn, "header": s.header} {
		if _, ok := st.GetForeground().(lipgloss.NoColor); !ok {
			t.Errorf("%s has a color without color support", name)
		}
	}
	c := newStyles(true)
	for name, st := range map[string]lipgloss.Style{"err": c.err, "ok": c.ok, "warn": c.warn, "header": c.header} {
		ac, ok := st.GetForeground().(lipgloss.AdaptiveColor)
		if !ok {
			t.Errorf("%s: not adaptive", name)
			continue
		}
		// Only the 16 ANSI colors: no 256-color or true-color values.
		for _, v := range []string{ac.Light, ac.Dark} {
			var n int
			if _, err := fmt.Sscanf(v, "%d", &n); err != nil || n < 0 || n > 15 {
				t.Errorf("%s: color %q is not one of the 16 ANSI colors", name, v)
			}
		}
	}
	// Selection and the active tab read without any styling.
	e := newTUI(t, 80, 24)
	e.m.st = newStyles(false)
	e.press("4")
	if v := e.view(); !strings.Contains(v, "[Locks]") || !strings.Contains(v, "> ip") {
		t.Errorf("markers:\n%s", v)
	}
}

func TestTUI_CtrlCAlwaysQuits(t *testing.T) {
	e := newTUI(t, 80, 24)
	e.press("4", "u")
	if cmd := e.key("ctrl+c"); cmd == nil || !e.m.quitting {
		t.Error("ctrl+c during a prompt")
	}
}

func TestRunTUI_Interactive(t *testing.T) {
	f := newFakeAPI(t)
	var got tuiAPI
	var out strings.Builder
	a := &app{stdin: strings.NewReader(""), stdout: &out, stderr: &out, interactive: true, now: func() time.Time { return fixedNow },
		runTUI: func(_ context.Context, api tuiAPI, _ io.Writer) error { got = api; return nil }}
	if code := a.run(context.Background(), []string{"--url", f.srv.URL, "--token-file", tokenFile(t)}); code != 0 || got == nil {
		t.Errorf("tui: %d %s", code, out.String())
	}
}
