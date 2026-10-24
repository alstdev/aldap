package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/alstdev/aldap/internal/events"
)

// tuiAPI is what the TUI needs from the API (implemented by *client).
type tuiAPI interface {
	Status(ctx context.Context) (statusView, error)
	Upstreams(ctx context.Context) (map[string][]serverView, error)
	Profiles(ctx context.Context) ([]profileView, error)
	Locks(ctx context.Context) ([]lockView, error)
	Indicators(ctx context.Context) ([]indicatorView, error)
	ConfigGet(ctx context.Context) (string, error)
	ConfigPut(ctx context.Context, body string, dry bool) (applyResult, error)
	Lock(ctx context.Context, target, key string, d time.Duration, reason string) (lockView, error)
	Unlock(ctx context.Context, target, key string) error
	Lockdown(ctx context.Context, on bool) (bool, error)
	Reload(ctx context.Context) error
	Sync(ctx context.Context, profile string) error
	Learn(ctx context.Context, profile string, d time.Duration) (learnResult, error)
	Stream(ctx context.Context, since uint64, types []string, fn func(events.Record) error, onState func(error)) error
}

const (
	// refreshEvery is the polling interval of the visible tab.
	refreshEvery = 3 * time.Second
	// callTimeout bounds one TUI action.
	callTimeout = 30 * time.Second
	// eventBacklog is how many buffered events the Events tab starts with.
	eventBacklog = 500
	// maxEvents bounds the events kept in memory (and held while paused).
	maxEvents = 2000
)

// Messages.
type (
	tickMsg    struct{}
	fetchedMsg struct {
		tab tab
		v   any
		err error
	}
	statusMsg struct {
		v   statusView
		err error
	}
	actionMsg struct {
		text    string
		err     error
		after   func(m *model)
		refresh bool
	}
	streamEventMsg struct{ rec events.Record }
	streamStateMsg struct {
		err   error
		final bool
	}
	editorDoneMsg struct{ err error }
)

// inputKind is what the input line collects.
type inputKind int

const (
	inputNone inputKind = iota
	inputLock
	inputLockIndicator
	inputLearn
	inputFilter
	inputSearch
)

// pending is an action waiting for y/n.
type pending struct {
	prompt string
	run    tea.Cmd
}

// evFilter selects events by type, profile, IP and account.
type evFilter struct {
	types   map[string]bool
	profile string
	ip      string
	account string
}

func (f evFilter) String() string {
	var parts []string
	if len(f.types) > 0 {
		parts = append(parts, "type="+strings.Join(sortedKeys(f.types), ","))
	}
	for _, kv := range [][2]string{{"profile", f.profile}, {"ip", f.ip}, {"account", f.account}} {
		if kv[1] != "" {
			parts = append(parts, kv[0]+"="+kv[1])
		}
	}
	return strings.Join(parts, " ")
}

func (f evFilter) match(r events.Record) bool {
	if len(f.types) > 0 && !f.types[r.Event] {
		return false
	}
	if f.profile != "" && !strings.EqualFold(f.profile, r.Profile) {
		return false
	}
	if f.ip != "" && f.ip != r.ClientIP {
		return false
	}
	return f.account == "" || strings.EqualFold(f.account, r.Account)
}

// parseFilter reads "type=a,b profile=x ip=y account=z".
func parseFilter(s string) (evFilter, error) {
	var f evFilter
	for _, tok := range strings.Fields(s) {
		k, v, ok := strings.Cut(tok, "=")
		if !ok || v == "" {
			return evFilter{}, fmt.Errorf("filter %q: use type=a,b profile=x ip=y account=z", tok)
		}
		switch strings.ToLower(k) {
		case "type", "types":
			f.types = map[string]bool{}
			for _, t := range splitList(v) {
				f.types[t] = true
			}
		case "profile":
			f.profile = v
		case "ip":
			f.ip = v
		case "account":
			f.account = v
		default:
			return evFilter{}, fmt.Errorf("filter key %q: use type, profile, ip or account", k)
		}
	}
	return f, nil
}

// model is the Bubble Tea model of the TUI.
type model struct {
	ctx context.Context
	api tuiAPI
	st  styles
	now func() time.Time
	// edit opens a file in the editor and reports editorDoneMsg.
	edit func(path string) tea.Cmd

	width, height int
	tab           tab
	help          bool
	quitting      bool

	status     *statusView
	upstreams  map[string][]serverView
	profiles   []profileView
	locks      []lockView
	indicators []indicatorView
	configText string
	configErr  string
	loaded     map[tab]bool

	cursor map[tab]int
	offset map[tab]int

	msg    string
	errMsg string

	confirm *pending
	input   textinput.Model
	inKind  inputKind

	stream     chan tea.Msg
	streamErr  string
	evts       []events.Record
	held       []events.Record
	paused     bool
	filter     evFilter
	search     string
	lastSeq    uint64
	draft      string
	draftDirty bool
	editPath   string
}

// tuiOptions configures a model.
type tuiOptions struct {
	color bool
	now   func() time.Time
	edit  func(path string) tea.Cmd
}

func newModel(ctx context.Context, api tuiAPI, o tuiOptions) *model {
	if o.now == nil {
		o.now = time.Now
	}
	if o.edit == nil {
		o.edit = editorCmd
	}
	ti := textinput.New()
	ti.CharLimit = 512
	// A steady cursor: no blink timer running behind the prompts.
	ti.Cursor.SetMode(cursor.CursorStatic)
	return &model{ctx: ctx, api: api, st: newStyles(o.color), now: o.now, edit: o.edit, input: ti,
		width: 80, height: 24, loaded: map[tab]bool{}, cursor: map[tab]int{}, offset: map[tab]int{},
		stream: make(chan tea.Msg, 256)}
}

// runTUI runs the TUI until q or Ctrl+C.
func runTUI(ctx context.Context, api tuiAPI, out io.Writer) error {
	_, noColor := os.LookupEnv("NO_COLOR")
	m := newModel(ctx, api, tuiOptions{color: !noColor && os.Getenv("TERM") != "dumb"})
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithContext(ctx), tea.WithOutput(out))
	_, err := p.Run()
	if errors.Is(err, tea.ErrProgramKilled) && ctx.Err() != nil {
		return nil //nolint:nilerr // Ctrl+C outside the TUI ends it normally
	}
	return err
}

// editorCmd opens path in $VISUAL / $EDITOR (vi, notepad on Windows).
func editorCmd(path string) tea.Cmd {
	ed := strings.TrimSpace(os.Getenv("VISUAL"))
	if ed == "" {
		ed = strings.TrimSpace(os.Getenv("EDITOR"))
	}
	if ed == "" {
		ed = "vi"
		if runtime.GOOS == "windows" {
			ed = "notepad"
		}
	}
	parts := strings.Fields(ed)
	c := exec.Command(parts[0], append(parts[1:], path)...) //nolint:gosec,noctx // the user's own editor, waited for by Bubble Tea
	return tea.ExecProcess(c, func(err error) tea.Msg { return editorDoneMsg{err} })
}

// Init starts the event stream and the first fetch.
func (m *model) Init() tea.Cmd {
	go m.runStream()
	return tea.Batch(m.fetch(tabStatus), m.waitStream(), tick())
}

func tick() tea.Cmd { return tea.Tick(refreshEvery, func(time.Time) tea.Msg { return tickMsg{} }) }

// runStream feeds the Events tab from /v1/events/stream.
func (m *model) runStream() {
	send := func(msg tea.Msg) bool {
		select {
		case m.stream <- msg:
			return true
		case <-m.ctx.Done():
			return false
		}
	}
	var since uint64
	ctx, cancel := context.WithTimeout(m.ctx, callTimeout)
	st, err := m.api.Status(ctx)
	cancel()
	if err == nil && st.EventsSeq > eventBacklog {
		since = st.EventsSeq - eventBacklog
	}
	err = m.api.Stream(m.ctx, since, nil, func(r events.Record) error {
		if !send(streamEventMsg{r}) {
			return m.ctx.Err()
		}
		return nil
	}, func(err error) {
		select {
		case m.stream <- streamStateMsg{err: err}:
		default:
		}
	})
	if err != nil && m.ctx.Err() == nil {
		send(streamStateMsg{err: err, final: true})
	}
}

func (m *model) waitStream() tea.Cmd {
	ch, ctx := m.stream, m.ctx
	return func() tea.Msg {
		select {
		case msg := <-ch:
			return msg
		case <-ctx.Done():
			return nil
		}
	}
}

// call runs f with a timeout for a command.
func (m *model) call(f func(ctx context.Context) error) error {
	ctx, cancel := context.WithTimeout(m.ctx, callTimeout)
	defer cancel()
	return f(ctx)
}

// fetch loads the data of a tab.
func (m *model) fetch(t tab) tea.Cmd {
	api := m.api
	if t == tabStatus {
		return func() tea.Msg {
			var st statusView
			err := m.call(func(ctx context.Context) error {
				var err error
				st, err = api.Status(ctx)
				return err
			})
			return statusMsg{st, err}
		}
	}
	return func() tea.Msg {
		var v any
		err := m.call(func(ctx context.Context) error {
			var err error
			switch t {
			case tabUpstreams:
				v, err = api.Upstreams(ctx)
			case tabProfiles:
				v, err = api.Profiles(ctx)
			case tabLocks:
				v, err = api.Locks(ctx)
			case tabIndicators:
				v, err = api.Indicators(ctx)
			case tabConfig:
				v, err = api.ConfigGet(ctx)
			case tabStatus, tabEvents, numTabs:
			}
			return err
		})
		return fetchedMsg{t, v, err}
	}
}

// refreshCmd reloads the status line and the visible tab.
func (m *model) refreshCmd(withConfig bool) tea.Cmd {
	cmds := []tea.Cmd{m.fetch(tabStatus)}
	switch m.tab {
	case tabStatus, tabEvents, numTabs:
	case tabConfig:
		if withConfig {
			cmds = append(cmds, m.fetch(tabConfig))
		}
	default:
		cmds = append(cmds, m.fetch(m.tab))
	}
	return tea.Batch(cmds...)
}

// action runs f and reports its result line.
func (m *model) action(f func(ctx context.Context) (string, error)) tea.Cmd {
	return func() tea.Msg {
		var text string
		err := m.call(func(ctx context.Context) error {
			var err error
			text, err = f(ctx)
			return err
		})
		return actionMsg{text: text, err: err, refresh: true}
	}
}

// ask shows a y/n prompt for run.
func (m *model) ask(prompt string, run tea.Cmd) {
	m.confirm = &pending{prompt: prompt, run: run}
	m.msg, m.errMsg = "", ""
}

func (m *model) startInput(kind inputKind, prompt, value string) tea.Cmd {
	m.inKind = kind
	m.input.Prompt = prompt
	m.input.SetValue(value)
	m.input.CursorEnd()
	m.msg, m.errMsg = "", ""
	return m.input.Focus()
}

func (m *model) setErr(err error) {
	m.msg = ""
	m.errMsg = firstLine(err.Error())
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i] + " …"
	}
	return s
}

// Update handles one message.
func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case tickMsg:
		return m, tea.Batch(m.refreshCmd(false), tick())
	case statusMsg:
		if msg.err != nil {
			m.setErr(msg.err)
		} else {
			v := msg.v
			m.status = &v
		}
		return m, nil
	case fetchedMsg:
		m.applyFetched(msg)
		return m, nil
	case actionMsg:
		if msg.err != nil {
			m.setErr(msg.err)
		} else {
			m.msg, m.errMsg = msg.text, ""
			if msg.after != nil {
				msg.after(m)
			}
		}
		if msg.refresh {
			return m, m.refreshCmd(true)
		}
		return m, nil
	case streamEventMsg:
		m.addEvent(msg.rec)
		return m, m.waitStream()
	case streamStateMsg:
		if msg.err != nil {
			m.streamErr = firstLine(msg.err.Error())
		}
		if msg.final {
			return m, nil
		}
		return m, m.waitStream()
	case editorDoneMsg:
		m.editorDone(msg.err)
		return m, nil
	case tea.KeyMsg:
		return m, m.key(msg)
	}
	if m.inKind != inputNone {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *model) applyFetched(msg fetchedMsg) {
	if msg.err != nil {
		if msg.tab == tabConfig {
			m.configErr = msg.err.Error()
		}
		m.setErr(msg.err)
		return
	}
	m.loaded[msg.tab] = true
	switch v := msg.v.(type) {
	case map[string][]serverView:
		m.upstreams = v
	case []profileView:
		m.profiles = v
	case []lockView:
		m.locks = v
	case []indicatorView:
		m.indicators = v
	case string:
		m.configText = v
	}
	if msg.tab != tabConfig {
		m.clampCursor(msg.tab)
	}
}

// addEvent keeps a streamed event; a reconnect never repeats one.
func (m *model) addEvent(r events.Record) {
	if r.Seq <= m.lastSeq {
		return
	}
	m.lastSeq = r.Seq
	m.streamErr = ""
	if m.paused {
		m.held = appendBounded(m.held, r)
		return
	}
	m.evts = appendBounded(m.evts, r)
}

func appendBounded(list []events.Record, r events.Record) []events.Record {
	list = append(list, r)
	if len(list) > maxEvents {
		list = append(list[:0:0], list[len(list)-maxEvents:]...)
	}
	return list
}

// key handles a key press: confirmation first, then input, help, globals
// and the keys of the visible tab.
func (m *model) key(k tea.KeyMsg) tea.Cmd {
	if k.Type == tea.KeyCtrlC {
		m.quitting = true
		return tea.Quit
	}
	switch {
	case m.confirm != nil:
		return m.confirmKey(k)
	case m.inKind != inputNone:
		return m.inputKey(k)
	case m.help:
		if key.Matches(k, keyHelp, keyQuit, keyCancel) {
			m.help = false
		}
		return nil
	}
	if cmd, ok := m.globalKey(k); ok {
		return cmd
	}
	if m.moveKey(k) {
		return nil
	}
	return m.tabKey(k)
}

// confirmKey answers a y/n prompt; other keys keep it.
func (m *model) confirmKey(k tea.KeyMsg) tea.Cmd {
	switch {
	case key.Matches(k, keyYes):
		run := m.confirm.run
		m.confirm = nil
		m.msg = "working…"
		return run
	case key.Matches(k, keyNo):
		m.confirm = nil
		m.msg = "canceled"
	}
	return nil
}

// inputKey feeds the input line; enter submits, esc cancels.
func (m *model) inputKey(k tea.KeyMsg) tea.Cmd {
	switch {
	case key.Matches(k, keySubmit):
		kind, val := m.inKind, strings.TrimSpace(m.input.Value())
		m.inKind = inputNone
		m.input.Blur()
		return m.submit(kind, val)
	case key.Matches(k, keyCancel):
		m.inKind = inputNone
		m.input.Blur()
		m.msg = "canceled"
		return nil
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(k)
	return cmd
}

// globalKey handles quit, help, tabs, refresh and reload.
func (m *model) globalKey(k tea.KeyMsg) (tea.Cmd, bool) {
	switch {
	case key.Matches(k, keyQuit):
		m.quitting = true
		return tea.Quit, true
	case key.Matches(k, keyHelp):
		m.help = true
		return nil, true
	case key.Matches(k, keyNext):
		return m.switchTab((m.tab + 1) % numTabs), true
	case key.Matches(k, keyPrev):
		return m.switchTab((m.tab + numTabs - 1) % numTabs), true
	case key.Matches(k, keyJump):
		return m.switchTab(tab(k.Runes[0] - '1')), true
	case key.Matches(k, keyRefresh):
		m.msg = "refreshing…"
		return m.refreshCmd(true), true
	case key.Matches(k, keyReload):
		m.ask("Reload the configuration?", m.action(func(ctx context.Context) (string, error) {
			return "configuration reloaded", m.api.Reload(ctx)
		}))
		return nil, true
	}
	return nil, false
}

// moveKey handles the selection and scroll keys.
func (m *model) moveKey(k tea.KeyMsg) bool {
	switch {
	case key.Matches(k, keyUp):
		m.move(-1)
	case key.Matches(k, keyDown):
		m.move(1)
	case key.Matches(k, keyPgUp):
		m.move(-m.pageSize())
	case key.Matches(k, keyPgDown):
		m.move(m.pageSize())
	case key.Matches(k, keyTop):
		m.move(-1 << 30)
	case key.Matches(k, keyBottom):
		m.move(1 << 30)
	default:
		return false
	}
	return true
}

func (m *model) switchTab(t tab) tea.Cmd {
	if t < 0 || t >= numTabs {
		return nil
	}
	m.tab = t
	switch t {
	case tabStatus, tabEvents, numTabs:
		return nil
	case tabConfig:
		if m.loaded[tabConfig] {
			return nil
		}
	default:
	}
	return m.fetch(t)
}

// tabKey handles the keys of the visible tab.
func (m *model) tabKey(k tea.KeyMsg) tea.Cmd {
	switch m.tab {
	case tabStatus:
		if key.Matches(k, keyLockdown) {
			on := m.status == nil || !m.status.Lockdown
			m.ask("Switch lockdown "+yesNo(on, "on", "off")+"?", m.action(func(ctx context.Context) (string, error) {
				got, err := m.api.Lockdown(ctx, on)
				return "lockdown " + yesNo(got, "on", "off"), err
			}))
		}
	case tabProfiles:
		return m.profilesKey(k)
	case tabLocks:
		return m.locksKey(k)
	case tabEvents:
		return m.eventsKey(k)
	case tabIndicators:
		if key.Matches(k, keyLockInd) {
			if len(m.indicators) == 0 {
				m.errMsg = "no indicator selected"
				return nil
			}
			return m.startInput(inputLockIndicator, "lock "+m.indicators[m.cursor[tabIndicators]].Key+" for: ", "1h")
		}
	case tabConfig:
		return m.configKey(k)
	case tabUpstreams, numTabs:
	}
	return nil
}

func (m *model) profilesKey(k tea.KeyMsg) tea.Cmd {
	if !key.Matches(k, keySync, keyLearn) {
		return nil
	}
	p, ok := m.selectedProfile()
	switch {
	case !ok:
		m.errMsg = "no profile selected"
	case key.Matches(k, keySync):
		m.ask("Force a replica sync of profile "+p+"?", m.action(func(ctx context.Context) (string, error) {
			return "sync of " + p + " started", m.api.Sync(ctx, p)
		}))
	default:
		return m.startInput(inputLearn, "learn "+p+" for: ", "24h")
	}
	return nil
}

func (m *model) locksKey(k tea.KeyMsg) tea.Cmd {
	switch {
	case key.Matches(k, keyUnlock):
		if len(m.locks) == 0 {
			m.errMsg = "no lock selected"
			return nil
		}
		l := m.locks[m.cursor[tabLocks]]
		m.ask(fmt.Sprintf("Unlock %s %s?", l.Target, l.Key), m.action(func(ctx context.Context) (string, error) {
			return fmt.Sprintf("unlocked %s %s", l.Target, l.Key), m.api.Unlock(ctx, l.Target, l.Key)
		}))
	case key.Matches(k, keyLock):
		return m.startInput(inputLock, "lock <ip|account> [duration] [reason]: ", "")
	}
	return nil
}

func (m *model) eventsKey(k tea.KeyMsg) tea.Cmd {
	switch {
	case key.Matches(k, keyPause):
		m.paused = !m.paused
		if !m.paused {
			for _, r := range m.held {
				m.evts = appendBounded(m.evts, r)
			}
			m.held = nil
		}
	case key.Matches(k, keyFilter):
		return m.startInput(inputFilter, "filter: ", m.filter.String())
	case key.Matches(k, keySearch):
		return m.startInput(inputSearch, "search: ", m.search)
	case key.Matches(k, keyClear):
		m.filter, m.search = evFilter{}, ""
		m.offset[tabEvents] = 0
		m.msg = "filter and search cleared"
	}
	return nil
}

func (m *model) selectedProfile() (string, bool) {
	if len(m.profiles) == 0 {
		return "", false
	}
	return m.profiles[m.cursor[tabProfiles]].Name, true
}

// submit acts on a finished input line.
func (m *model) submit(kind inputKind, val string) tea.Cmd {
	switch kind {
	case inputLock:
		target, k, d, reason, err := parseLockInput(val)
		if err != nil {
			m.setErr(err)
			return nil
		}
		m.askLock(target, k, d, reason)
	case inputLockIndicator:
		d, err := parsePositive(val)
		if err != nil {
			m.setErr(err)
			return nil
		}
		in := m.indicators[m.cursor[tabIndicators]]
		m.askLock(in.Target, in.Key, d, "aldapctl: indicator")
	case inputLearn:
		d, err := parsePositive(val)
		if err != nil {
			m.setErr(err)
			return nil
		}
		p, ok := m.selectedProfile()
		if !ok {
			return nil
		}
		m.ask(fmt.Sprintf("Restart baseline learning for %s (process-wide)?", d), m.action(func(ctx context.Context) (string, error) {
			res, err := m.api.Learn(ctx, p, d)
			return "learning until " + fmtTime(res.Until), err
		}))
	case inputFilter:
		f, err := parseFilter(val)
		if err != nil {
			m.setErr(err)
			return nil
		}
		m.filter = f
		m.offset[tabEvents] = 0
	case inputSearch:
		m.search = val
		m.offset[tabEvents] = 0
	case inputNone:
	}
	return nil
}

func (m *model) askLock(target, k string, d time.Duration, reason string) {
	m.ask(fmt.Sprintf("Lock %s %s for %s?", target, k, d), m.action(func(ctx context.Context) (string, error) {
		l, err := m.api.Lock(ctx, target, k, d, reason)
		return fmt.Sprintf("locked %s %s until %s", l.Target, l.Key, fmtTime(l.Until)), err
	}))
}

func parsePositive(v string) (time.Duration, error) {
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("duration %q: want a positive duration such as 30m or 2h", v)
	}
	return d, nil
}

// parseLockInput reads "<ip|account> [duration] [reason…]" (default 1h);
// a leading "ip" or "account" word forces the target.
func parseLockInput(v string) (target, k string, d time.Duration, reason string, err error) {
	f := strings.Fields(v)
	forced := ""
	if len(f) > 1 && (f[0] == "ip" || f[0] == "account") {
		forced, f = f[0], f[1:]
	}
	if len(f) == 0 {
		return "", "", 0, "", errors.New("lock: give an IP address or an account")
	}
	k, d = f[0], time.Hour
	if len(f) > 1 {
		if d, err = parsePositive(f[1]); err != nil {
			return "", "", 0, "", err
		}
		reason = strings.Join(f[2:], " ")
	}
	target = targetOf(k, forced == "account")
	if forced == "ip" {
		if _, perr := netip.ParseAddr(k); perr != nil {
			return "", "", 0, "", fmt.Errorf("lock: %q is not an IP address", k)
		}
		target = "ip"
	}
	return target, k, d, reason, nil
}

// configKey handles e, v, a and x on the Config tab.
func (m *model) configKey(k tea.KeyMsg) tea.Cmd {
	switch {
	case key.Matches(k, keyEdit):
		text := m.configText
		if m.draftDirty {
			text = m.draft
		}
		if text == "" {
			m.errMsg = "the configuration is not loaded yet (r refreshes)"
			return nil
		}
		f, err := os.CreateTemp("", "aldap-config-*.toml")
		if err != nil {
			m.setErr(err)
			return nil
		}
		_, werr := f.WriteString(text)
		if err := errors.Join(werr, f.Close()); err != nil {
			_ = os.Remove(f.Name()) //nolint:errcheck // cleanup
			m.setErr(err)
			return nil
		}
		m.editPath = f.Name()
		return m.edit(f.Name())
	case key.Matches(k, keyValidate):
		if !m.draftDirty {
			m.errMsg = "no draft: e opens the configuration in $EDITOR"
			return nil
		}
		body := m.draft
		return func() tea.Msg {
			err := m.call(func(ctx context.Context) error {
				_, err := m.api.ConfigPut(ctx, body, true)
				return err
			})
			return actionMsg{text: "the draft is valid", err: err, after: func(m *model) { m.configErr = "" }}
		}
	case key.Matches(k, keyApply):
		if !m.draftDirty {
			m.errMsg = "no draft: e opens the configuration in $EDITOR"
			return nil
		}
		body := m.draft
		m.ask("Apply the draft and reload?", func() tea.Msg {
			var res applyResult
			err := m.call(func(ctx context.Context) error {
				var err error
				res, err = m.api.ConfigPut(ctx, body, false)
				return err
			})
			text := "applied and reloaded"
			if res.Backup != "" {
				text += "; backup " + res.Backup
			}
			return actionMsg{text: text, err: err, refresh: err == nil, after: func(m *model) {
				m.draft, m.draftDirty, m.configErr = "", false, ""
			}}
		})
	case key.Matches(k, keyDiscard):
		if m.draftDirty {
			m.draft, m.draftDirty, m.configErr = "", false, ""
			m.msg = "draft discarded"
		}
	}
	return nil
}

// editorDone reads the edited file back and removes it.
func (m *model) editorDone(err error) {
	path := m.editPath
	m.editPath = ""
	if path == "" {
		return
	}
	b, rerr := os.ReadFile(path)
	_ = os.Remove(path) //nolint:errcheck // temporary file
	if err == nil {
		err = rerr
	}
	if err != nil {
		m.setErr(fmt.Errorf("editor: %w", err))
		return
	}
	text := string(b)
	if text == m.configText {
		m.draft, m.draftDirty = "", false
		m.msg = "no changes"
		return
	}
	m.draft, m.draftDirty, m.configErr = text, true, ""
	m.msg = "draft saved: v validates, a applies, x discards"
}

// rowsOf counts the selectable rows of a tab.
func (m *model) rowsOf(t tab) int {
	switch t {
	case tabUpstreams:
		n := 0
		for _, l := range m.upstreams {
			n += len(l)
		}
		return n
	case tabProfiles:
		return len(m.profiles)
	case tabLocks:
		return len(m.locks)
	case tabIndicators:
		return len(m.indicators)
	case tabStatus, tabEvents, tabConfig, numTabs:
	}
	return 0
}

func (m *model) clampCursor(t tab) {
	n := m.rowsOf(t)
	c := m.cursor[t]
	if c >= n {
		c = n - 1
	}
	m.cursor[t] = max(c, 0)
}

func (m *model) pageSize() int { return max(m.bodyHeight()-2, 1) }

// move moves the selection or scrolls the visible tab.
func (m *model) move(delta int) {
	switch m.tab {
	case tabEvents:
		// The offset counts lines from the newest event (0 = follow).
		n := len(m.filteredEvents())
		m.offset[tabEvents] = clamp(m.offset[tabEvents]-delta, max(n-1, 0))
	case tabConfig, tabStatus:
		n := len(m.scrollLines())
		m.offset[m.tab] = clamp(m.offset[m.tab]+delta, max(n-1, 0))
	default:
		m.cursor[m.tab] = clamp(m.cursor[m.tab]+delta, max(m.rowsOf(m.tab)-1, 0))
	}
}

// clamp limits v to 0..hi.
func clamp(v, hi int) int { return min(max(v, 0), hi) }

func (m *model) filteredEvents() []events.Record {
	if len(m.filter.types) == 0 && m.filter.profile == "" && m.filter.ip == "" && m.filter.account == "" && m.search == "" {
		return m.evts
	}
	needle := strings.ToLower(m.search)
	var out []events.Record
	for _, r := range m.evts {
		if !m.filter.match(r) {
			continue
		}
		if needle != "" && !strings.Contains(strings.ToLower(string(r.JSON())), needle) {
			continue
		}
		out = append(out, r)
	}
	return out
}
