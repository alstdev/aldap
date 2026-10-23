package main

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/lipgloss"
)

// styles of the TUI. Meaning never depends on color alone: the active tab
// is [bracketed], the selected row starts with ">", errors with "!".
// Colors are the 16 ANSI ones, adaptive to light and dark backgrounds.
type styles struct {
	tabActive lipgloss.Style
	header    lipgloss.Style
	sel       lipgloss.Style
	err       lipgloss.Style
	ok        lipgloss.Style
	warn      lipgloss.Style
	dim       lipgloss.Style
}

func newStyles(color bool) styles {
	s := styles{
		tabActive: lipgloss.NewStyle().Bold(true).Reverse(true),
		header:    lipgloss.NewStyle().Bold(true),
		sel:       lipgloss.NewStyle().Reverse(true),
		err:       lipgloss.NewStyle().Bold(true),
		ok:        lipgloss.NewStyle(),
		warn:      lipgloss.NewStyle().Bold(true),
		dim:       lipgloss.NewStyle().Faint(true),
	}
	if color {
		s.err = s.err.Foreground(lipgloss.AdaptiveColor{Light: "1", Dark: "9"})
		s.ok = s.ok.Foreground(lipgloss.AdaptiveColor{Light: "2", Dark: "10"})
		s.warn = s.warn.Foreground(lipgloss.AdaptiveColor{Light: "3", Dark: "11"})
		s.header = s.header.Foreground(lipgloss.AdaptiveColor{Light: "4", Dark: "12"})
	}
	return s
}

// fit cuts a plain line to w display cells.
func fit(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= w {
		return s
	}
	var b strings.Builder
	n := 0
	for _, r := range s {
		rw := lipgloss.Width(string(r))
		if n+rw > w-1 {
			break
		}
		b.WriteRune(r)
		n += rw
	}
	b.WriteString("…")
	return b.String()
}

// bodyHeight is the space between the tab bar and the status line.
func (m *model) bodyHeight() int { return max(m.height-2, 1) }

// View renders the whole screen: tab bar, body, status line.
func (m *model) View() string {
	if m.quitting {
		return ""
	}
	w, h := max(m.width, 20), m.bodyHeight()
	var body []string
	if m.help {
		body = m.helpView(w, h)
	} else {
		body = m.tabView(w, h)
	}
	if len(body) > h {
		body = body[:h]
	}
	for len(body) < h {
		body = append(body, "")
	}
	lines := append([]string{m.tabBar(w)}, body...)
	lines = append(lines, m.statusLine(w))
	return strings.Join(lines, "\n")
}

func (m *model) tabBar(w int) string {
	var b strings.Builder
	for t := range numTabs {
		if t == m.tab {
			b.WriteString(m.st.tabActive.Render("[" + t.String() + "]"))
		} else {
			b.WriteString(" " + t.String() + " ")
		}
	}
	plain := lipgloss.Width(b.String())
	right := ""
	if m.status != nil && m.status.Lockdown {
		right = m.st.warn.Render(" LOCKDOWN")
	}
	if plain+lipgloss.Width(right) <= w {
		return b.String() + right
	}
	return lipgloss.NewStyle().MaxWidth(w).Render(b.String())
}

func (m *model) statusLine(w int) string {
	style := lipgloss.NewStyle().MaxWidth(w)
	switch {
	case m.confirm != nil:
		return style.Render(m.st.warn.Render(fit(m.confirm.prompt+" [y/n]", w)))
	case m.inKind != inputNone:
		m.input.Width = max(w-lipgloss.Width(m.input.Prompt)-2, 4)
		return style.Render(m.input.View())
	case m.errMsg != "":
		return m.st.err.Render(fit("! "+m.errMsg, w))
	case m.msg != "":
		return m.st.ok.Render(fit(m.msg, w))
	}
	hint := "? help  q quit  tab next  r refresh"
	if m.status != nil {
		hint = fmt.Sprintf("%s  |  aldap %s  locks %d  attacks %d", hint, dash(m.status.Version), m.status.LocksActive, m.status.AttacksActive)
	}
	return m.st.dim.Render(fit(hint, w))
}

// helpView lists every key in two columns.
func (m *model) helpView(w, h int) []string {
	left, right := helpLayout()
	col := func(secs []helpSection, blank bool) []string {
		var out []string
		for i, s := range secs {
			if blank && i > 0 {
				out = append(out, "")
			}
			out = append(out, s.title)
			for _, k := range s.keys {
				hl := k.Help()
				out = append(out, fmt.Sprintf("  %-8s %s", hl.Key, hl.Desc))
			}
		}
		return out
	}
	l, r := col(left, true), col(right, false)
	half := w / 2
	out := []string{m.st.header.Render(fit("Keys (? or esc closes the help)", w))}
	for i := 0; i < max(len(l), len(r)); i++ {
		var a, b string
		if i < len(l) {
			a = l[i]
		}
		if i < len(r) {
			b = r[i]
		}
		a = fit(a, half-1)
		line := a + strings.Repeat(" ", max(half-lipgloss.Width(a), 1)) + fit(b, w-half)
		out = append(out, line)
	}
	if len(out) > h {
		out = out[:h]
	}
	return out
}

// helpKeys lists every binding the help screen shows (tests).
func helpKeys() []key.Binding {
	left, right := helpLayout()
	var out []key.Binding
	for _, s := range append(left, right...) {
		out = append(out, s.keys...)
	}
	return out
}

func (m *model) tabView(w, h int) []string {
	switch m.tab {
	case tabStatus, tabConfig:
		return m.scrollView(w, h)
	case tabUpstreams:
		return m.listView(w, h, m.upstreamRows())
	case tabProfiles:
		return m.listView(w, h, m.profileRows())
	case tabLocks:
		return m.listView(w, h, m.lockRows())
	case tabIndicators:
		return m.listView(w, h, m.indicatorRows())
	case tabEvents:
		return m.eventsView(w, h)
	case numTabs:
	}
	return nil
}

// columns aligns a header and rows like the CLI tables.
func columns(header string, rows []string) (string, []string) {
	var b bytes.Buffer
	tw := table(&b)
	fmt.Fprintln(tw, header)
	for _, r := range rows {
		fmt.Fprintln(tw, r)
	}
	_ = tw.Flush() //nolint:errcheck // in-memory buffer
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	return lines[0], lines[1:]
}

// listRows is a table with one selectable row per item.
type listRows struct {
	title  string
	header string
	rows   []string
	// alert marks rows drawn in the error style (down servers).
	alert []bool
	// detail is shown in full under the list for the selected row.
	detail []string
	empty  string
	tab    tab
}

func (m *model) listView(w, h int, lr listRows) []string {
	out := []string{m.st.header.Render(fit(lr.title, w))}
	if !m.loaded[lr.tab] {
		return append(out, "", fit("  loading…", w))
	}
	if len(lr.rows) == 0 {
		return append(out, "", fit("  "+lr.empty, w))
	}
	header, rows := columns(lr.header, lr.rows)
	out = append(out, m.st.header.Render(fit("  "+header, w)))
	cur := m.cursor[lr.tab]
	var detail []string
	if cur < len(lr.detail) && lr.detail[cur] != "" {
		detail = wrap(lr.detail[cur], w, 3)
	}
	avail := max(h-len(out)-len(detail)-1, 1)
	start := 0
	if cur >= avail {
		start = cur - avail + 1
	}
	for i := start; i < len(rows) && i < start+avail; i++ {
		line := fit("  "+rows[i], w)
		switch {
		case i == cur:
			line = m.st.sel.Render(fit("> "+rows[i], w))
		case i < len(lr.alert) && lr.alert[i]:
			line = m.st.err.Render(line)
		}
		out = append(out, line)
	}
	if len(detail) > 0 && len(out)+1+len(detail) <= h {
		out = append(out, "")
		out = append(out, detail...)
	}
	return out
}

// wrap breaks s into at most n lines of w cells (the last one cut).
func wrap(s string, w, n int) []string {
	var out []string
	line := ""
	for _, word := range strings.Fields(s) {
		switch {
		case line == "":
			line = word
		case lipgloss.Width(line)+1+lipgloss.Width(word) <= w:
			line += " " + word
		default:
			out = append(out, fit(line, w))
			line = word
		}
	}
	if line != "" {
		out = append(out, fit(line, w))
	}
	if len(out) > n {
		out = out[:n]
		out[n-1] = fit(out[n-1]+" …", w)
	}
	return out
}

func (m *model) upstreamRows() listRows {
	lr := listRows{title: "Upstream servers", header: "UPSTREAM\tSERVER\tSTATE\tFAIL\tP50\tP95\tACTIVE\tLAST ERROR", empty: "no upstreams", tab: tabUpstreams}
	for _, name := range sortedKeys(m.upstreams) {
		for _, u := range m.upstreams[name] {
			lr.rows = append(lr.rows, fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%s\t%d\t%s", name, u.URL, u.State, u.ConsecutiveFail,
				fmtDur(time.Duration(u.P50)), fmtDur(time.Duration(u.P95)), u.ActiveConns, dash(u.LastError)))
			lr.alert = append(lr.alert, u.State == "down")
			lr.detail = append(lr.detail, fmt.Sprintf("%s: %s, last check %s, last change %s, last error: %s", u.URL, u.State, fmtTime(u.LastCheck), fmtTime(u.LastChange), dash(u.LastError)))
		}
	}
	return lr
}

func (m *model) profileRows() listRows {
	lr := listRows{title: "Profiles   s sync  b baseline learn", header: "NAME\tMODE\tTRANSPORT\tLISTEN\tUPSTREAM\tCACHE\tVIRTUAL BASE", empty: "no profiles", tab: tabProfiles}
	for _, p := range m.profiles {
		lr.rows = append(lr.rows, fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%s", p.Name, p.Mode, p.Transport, strings.Join(p.Listen, ","), dash(p.Upstream), p.Cache, p.VirtualBase))
	}
	return lr
}

func (m *model) lockRows() listRows {
	lr := listRows{title: "Active locks   u unlock  l lock", header: "TARGET\tKEY\tREMAINING\tFAILS\tSOURCE\tPROFILE\tREASON", empty: "no active locks (l locks an IP or account)", tab: tabLocks}
	for _, l := range m.locks {
		lr.rows = append(lr.rows, fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%s\t%s", l.Target, l.Key, fmtDur(l.Until.Sub(m.now())), l.Failures, l.Source, dash(l.Profile), dash(l.Reason)))
		lr.detail = append(lr.detail, fmt.Sprintf("%s %s locked until %s by %s; reason: %s", l.Target, l.Key, fmtTime(l.Until), l.Source, dash(l.Reason)))
	}
	return lr
}

func (m *model) indicatorRows() listRows {
	lr := listRows{title: "Indicators   l lock selected", header: "TARGET\tKEY\tSCORE\tLOCKED\tREASONS\tLAST SEEN", empty: "no indicators", tab: tabIndicators}
	for _, in := range m.indicators {
		lr.rows = append(lr.rows, fmt.Sprintf("%s\t%s\t%.1f\t%s\t%s\t%s", in.Target, in.Key, in.Score, yesNo(in.Locked, "yes", "no"), strings.Join(in.Reasons, ","), in.LastSeen.UTC().Format("01-02 15:04:05")))
		var hits []string
		for _, k := range sortedKeys(in.Hits) {
			hits = append(hits, fmt.Sprintf("%s=%d", k, in.Hits[k]))
		}
		lr.detail = append(lr.detail, fmt.Sprintf("%s %s first seen %s, last seen %s, hits %s", in.Target, in.Key, fmtTime(in.FirstSeen), fmtTime(in.LastSeen), dash(strings.Join(hits, " "))))
	}
	return lr
}

// scrollLines are the lines of the Status and Config tabs.
func (m *model) scrollLines() []string {
	if m.tab == tabStatus {
		if m.status == nil {
			return []string{"loading…"}
		}
		var b bytes.Buffer
		writeStatus(&b, *m.status)
		lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
		return append(lines, "", "d switches lockdown, R reloads the configuration (both ask y/n).")
	}
	text := m.configText
	if m.draftDirty {
		text = m.draft
	}
	if !m.loaded[tabConfig] && !m.draftDirty {
		return []string{"loading…"}
	}
	return strings.Split(strings.TrimRight(text, "\n"), "\n")
}

func (m *model) scrollView(w, h int) []string {
	var out []string
	if m.tab == tabConfig {
		title := "Running configuration (secrets ***)   e edit  v validate  a apply  x discard"
		if m.draftDirty {
			title = "DRAFT, not applied   v validate  a apply  x discard  e edit again"
		}
		out = append(out, m.st.header.Render(fit(title, w)))
		if m.configErr != "" {
			for _, l := range strings.Split(strings.TrimSpace(m.configErr), "\n") {
				out = append(out, m.st.err.Render(fit("! "+l, w)))
				if len(out) >= h/2 {
					break
				}
			}
		}
	}
	lines := m.scrollLines()
	off := clamp(m.offset[m.tab], max(len(lines)-1, 0))
	for i := off; i < len(lines) && len(out) < h; i++ {
		line := fit(lines[i], w)
		if m.tab == tabStatus && strings.HasPrefix(lines[i], "lockdown ON") {
			line = m.st.warn.Render(line)
		}
		out = append(out, line)
	}
	return out
}

func (m *model) eventsView(w, h int) []string {
	state := "live"
	switch {
	case m.paused:
		state = fmt.Sprintf("PAUSED (+%d new)", len(m.held))
	case m.streamErr != "":
		state = "disconnected: " + m.streamErr
	}
	list := m.filteredEvents()
	title := fmt.Sprintf("Events %d/%d  %s", len(list), len(m.evts), state)
	if f := m.filter.String(); f != "" {
		title += "  filter " + f
	}
	if m.search != "" {
		title += "  search " + m.search
	}
	out := []string{m.st.header.Render(fit(title, w))}
	if len(list) == 0 {
		return append(out, "", fit("  no events (f filter, / search, c clear)", w))
	}
	avail := max(h-1, 1)
	end := len(list) - clamp(m.offset[tabEvents], len(list)-1)
	start := max(end-avail, 0)
	for _, r := range list[start:end] {
		line := fit(eventLine(r, "15:04:05"), w)
		if r.Level == "high" || r.Level == "critical" {
			line = m.st.err.Render(line)
		}
		out = append(out, line)
	}
	return out
}
