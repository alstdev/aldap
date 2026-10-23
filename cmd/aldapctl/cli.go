package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/events"
)

// session is one command with its options and the lazily built client.
type session struct {
	app *app
	o   *opts
	set []string
	c   *client
	// base is the context of the invocation (canceled by Ctrl+C).
	base context.Context
}

func (s *session) client() (*client, error) {
	if s.c != nil {
		return s.c, nil
	}
	co := s.o.conn
	if co.url == "" && co.socket == "" {
		co.socket = config.DefaultIPCSocket()
	}
	co.warn = func(msg string) { fmt.Fprintf(s.app.stderr, "aldapctl: warning: %s\n", msg) }
	c, err := newClient(co)
	if err != nil {
		if errors.Is(err, errNoToken) || errors.Is(err, errSocketAndURL) {
			return nil, usageError{err.Error()}
		}
		return nil, err
	}
	s.c = c
	return c, nil
}

// ctx is the invocation context; each API call has its own timeout.
func (s *session) ctx() context.Context { return s.base }

// confirm asks y/n on a terminal; without one the command needs --yes.
func (s *session) confirm(action string) error {
	if s.o.yes {
		return nil
	}
	if !s.app.interactive {
		return abortedError{action + ": not confirmed; pass --yes to run without a prompt"}
	}
	fmt.Fprintf(s.app.stderr, "%s? [y/N] ", upperFirst(action))
	line, err := s.app.in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read confirmation: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return nil
	}
	return abortedError{action + ": aborted"}
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func (s *session) out() io.Writer { return s.app.stdout }

func (s *session) printJSON(v any) error {
	enc := json.NewEncoder(s.out())
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func table(w io.Writer) *tabwriter.Writer { return tabwriter.NewWriter(w, 0, 0, 2, ' ', 0) }

// fmtTime renders an API time in UTC; the zero time is "-".
func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

// fmtDur renders a duration rounded to seconds (or ms below a second).
func fmtDur(d time.Duration) string {
	switch {
	case d <= 0:
		return "0s"
	case d < time.Second:
		return d.Round(time.Millisecond).String()
	}
	return d.Round(time.Second).String()
}

func fmtMS(ms float64) string { return fmt.Sprintf("%.1fms", ms) }

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func yesNo(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}

// targetOf decides ip or account for a lock key.
func targetOf(key string, account bool) string {
	if account {
		return "account"
	}
	if _, err := netip.ParseAddr(key); err == nil {
		return "ip"
	}
	return "account"
}

func cmdStatus(s *session, _ []string) error {
	c, err := s.client()
	if err != nil {
		return err
	}
	st, err := c.Status(s.ctx())
	if err != nil {
		return err
	}
	if s.o.json {
		return s.printJSON(st)
	}
	writeStatus(s.out(), st)
	return nil
}

func writeStatus(w io.Writer, st statusView) {
	fmt.Fprintf(w, "aldap %s (%s)  uptime %s\n", dash(st.Version), dash(st.GoVersion), fmtDur(time.Duration(st.UptimeS)*time.Second))
	fmt.Fprintf(w, "lockdown %s  learning %s  locks %d  attacks %d  events seq %d\n",
		yesNo(st.Lockdown, "ON", "off"), yesNo(st.Learning, "yes", "no"), st.LocksActive, st.AttacksActive, st.EventsSeq)
	profiles := slices.Clone(st.Profiles)
	sort.Strings(profiles)
	fmt.Fprintf(w, "profiles: %s\n", dash(strings.Join(profiles, ", ")))
	if len(st.Upstreams) == 0 {
		return
	}
	fmt.Fprintln(w)
	tw := table(w)
	fmt.Fprintln(tw, "UPSTREAM\tSERVER\tSTATE\tFAILS\tP50\tP95\tLAST ERROR")
	for _, name := range sortedKeys(st.Upstreams) {
		for _, u := range st.Upstreams[name] {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\t%s\n", name, u.URL, u.State, u.ConsecutiveFailures, fmtMS(u.LatencyP50MS), fmtMS(u.LatencyP95MS), dash(u.LastError))
		}
	}
	_ = tw.Flush() //nolint:errcheck // stdout
}

func sortedKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func cmdUpstreams(s *session, _ []string) error {
	c, err := s.client()
	if err != nil {
		return err
	}
	ups, err := c.Upstreams(s.ctx())
	if err != nil {
		return err
	}
	if s.o.json {
		return s.printJSON(ups)
	}
	tw := table(s.out())
	fmt.Fprintln(tw, "UPSTREAM\tSERVER\tSTATE\tOK\tFAIL\tP50\tP95\tIDLE\tACTIVE\tLAST CHECK\tLAST ERROR")
	for _, name := range sortedKeys(ups) {
		for _, u := range ups[name] {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%s\t%s\t%d\t%d\t%s\t%s\n", name, u.URL, u.State, u.ConsecutiveOK, u.ConsecutiveFail,
				fmtDur(time.Duration(u.P50)), fmtDur(time.Duration(u.P95)), u.IdleConns, u.ActiveConns, fmtTime(u.LastCheck), dash(u.LastError))
		}
	}
	return tw.Flush()
}

func cmdProfiles(s *session, _ []string) error {
	c, err := s.client()
	if err != nil {
		return err
	}
	ps, err := c.Profiles(s.ctx())
	if err != nil {
		return err
	}
	if s.o.json {
		return s.printJSON(ps)
	}
	tw := table(s.out())
	fmt.Fprintln(tw, "NAME\tMODE\tTRANSPORT\tLISTEN\tUPSTREAM\tCACHE\tVIRTUAL BASE")
	for _, p := range ps {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", p.Name, p.Mode, p.Transport, strings.Join(p.Listen, ","), dash(p.Upstream), p.Cache, p.VirtualBase)
	}
	return tw.Flush()
}

func cmdLocks(s *session, _ []string) error {
	c, err := s.client()
	if err != nil {
		return err
	}
	locks, err := c.Locks(s.ctx())
	if err != nil {
		return err
	}
	if s.o.json {
		return s.printJSON(locks)
	}
	if len(locks) == 0 {
		fmt.Fprintln(s.out(), "no active locks")
		return nil
	}
	tw := table(s.out())
	fmt.Fprintln(tw, "TARGET\tKEY\tUNTIL\tREMAINING\tFAILURES\tSOURCE\tPROFILE\tREASON")
	for _, l := range locks {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n", l.Target, l.Key, fmtTime(l.Until), fmtDur(l.Until.Sub(s.app.now())), l.Failures, l.Source, dash(l.Profile), dash(l.Reason))
	}
	return tw.Flush()
}

func cmdUnlock(s *session, args []string) error {
	key := args[0]
	target := targetOf(key, s.o.account)
	c, err := s.client()
	if err != nil {
		return err
	}
	if err := s.confirm(fmt.Sprintf("unlock %s %s", target, key)); err != nil {
		return err
	}
	if err := c.Unlock(s.ctx(), target, key); err != nil {
		return err
	}
	fmt.Fprintf(s.out(), "unlocked %s %s\n", target, key)
	return nil
}

func cmdLock(s *session, args []string) error {
	key := args[0]
	target := targetOf(key, s.o.account)
	if !slices.Contains(s.set, "for") {
		return usagef("lock: --for DURATION is required, e.g. --for 1h")
	}
	if s.o.forDur <= 0 {
		return usagef("lock: --for must be positive")
	}
	c, err := s.client()
	if err != nil {
		return err
	}
	if err := s.confirm(fmt.Sprintf("lock %s %s for %s", target, key, s.o.forDur)); err != nil {
		return err
	}
	l, err := c.Lock(s.ctx(), target, key, s.o.forDur, s.o.reason)
	if err != nil {
		return err
	}
	fmt.Fprintf(s.out(), "locked %s %s until %s\n", l.Target, l.Key, fmtTime(l.Until))
	return nil
}

func cmdLockdown(s *session, args []string) error {
	var on bool
	switch args[0] {
	case "on":
		on = true
	case "off":
	default:
		return usagef("lockdown: want on or off")
	}
	c, err := s.client()
	if err != nil {
		return err
	}
	if err := s.confirm("switch lockdown " + args[0]); err != nil {
		return err
	}
	state, err := c.Lockdown(s.ctx(), on)
	if err != nil {
		return err
	}
	fmt.Fprintf(s.out(), "lockdown %s\n", yesNo(state, "on", "off"))
	return nil
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// eventLine renders one event on one line.
func eventLine(r events.Record, layout string) string {
	var b strings.Builder
	ts := r.TS
	if t, err := time.Parse(time.RFC3339Nano, r.TS); err == nil {
		ts = t.UTC().Format(layout)
	}
	fmt.Fprintf(&b, "%s #%d %s %s", ts, r.Seq, r.Event, r.Level)
	add := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, " %s=%s", k, v)
		}
	}
	add("profile", r.Profile)
	add("ip", r.ClientIP)
	add("account", r.Account)
	add("account_hash", r.AccountHash)
	add("reason", r.Reason)
	add("upstream", r.Upstream)
	for _, k := range sortedKeys(r.Data) {
		v := r.Data[k]
		var s string
		switch x := v.(type) {
		case string:
			s = x
		default:
			bs, err := json.Marshal(x)
			if err != nil {
				continue
			}
			s = string(bs)
		}
		if strings.ContainsAny(s, " \t\n") {
			s = fmt.Sprintf("%q", s)
		}
		add(k, s)
	}
	return b.String()
}

func cmdEvents(s *session, _ []string) error {
	c, err := s.client()
	if err != nil {
		return err
	}
	types := splitList(s.o.types)
	if s.o.limit < 0 || s.o.limit > 10000 {
		return usagef("events: --limit must be 1–10000")
	}
	last := s.o.since
	if s.o.json {
		raw, err := c.EventsRaw(s.ctx(), s.o.since, s.o.limit, types)
		if err != nil {
			return err
		}
		for _, r := range raw {
			var seq struct {
				Seq uint64 `json:"seq"`
			}
			_ = json.Unmarshal(r, &seq) //nolint:errcheck // seq only advances the follow cursor
			last = max(last, seq.Seq)
			fmt.Fprintln(s.out(), string(r))
		}
	} else {
		recs, err := c.Events(s.ctx(), s.o.since, s.o.limit, types)
		if err != nil {
			return err
		}
		for _, r := range recs {
			last = max(last, r.Seq)
			fmt.Fprintln(s.out(), eventLine(r, time.RFC3339))
		}
	}
	if !s.o.follow {
		return nil
	}
	return c.Stream(s.ctx(), last, types, func(r events.Record) error {
		if s.o.json {
			_, err := fmt.Fprintln(s.out(), string(r.JSON()))
			return err
		}
		_, err := fmt.Fprintln(s.out(), eventLine(r, time.RFC3339))
		return err
	}, func(err error) {
		fmt.Fprintf(s.app.stderr, "aldapctl: event stream: %v; reconnecting\n", err)
	})
}

func cmdIndicators(s *session, _ []string) error {
	c, err := s.client()
	if err != nil {
		return err
	}
	format := s.o.format
	if s.o.json {
		if format != "" && format != "json" {
			return usagef("indicators: --json and --format %s conflict", format)
		}
		format = "json"
	}
	switch format {
	case "", "table":
	case "json", "stix-lite", "plain":
		b, err := c.IndicatorsRaw(s.ctx(), format, s.o.minScore)
		if err != nil {
			return err
		}
		_, err = s.out().Write(b)
		return err
	default:
		return usagef("indicators: --format must be table, json, stix-lite or plain")
	}
	b, err := c.IndicatorsRaw(s.ctx(), "json", s.o.minScore)
	if err != nil {
		return err
	}
	var list []indicatorView
	if err := json.Unmarshal(b, &list); err != nil {
		return fmt.Errorf("decode indicators: %w", err)
	}
	if len(list) == 0 {
		fmt.Fprintln(s.out(), "no indicators")
		return nil
	}
	tw := table(s.out())
	fmt.Fprintln(tw, "TARGET\tKEY\tSCORE\tLOCKED\tREASONS\tFIRST SEEN\tLAST SEEN")
	for _, in := range list {
		fmt.Fprintf(tw, "%s\t%s\t%.1f\t%s\t%s\t%s\t%s\n", in.Target, in.Key, in.Score, yesNo(in.Locked, "yes", "no"), strings.Join(in.Reasons, ","), fmtTime(in.FirstSeen), fmtTime(in.LastSeen))
	}
	return tw.Flush()
}

func cmdReload(s *session, _ []string) error {
	c, err := s.client()
	if err != nil {
		return err
	}
	if err := s.confirm("reload the configuration"); err != nil {
		return err
	}
	if err := c.Reload(s.ctx()); err != nil {
		return err
	}
	fmt.Fprintln(s.out(), "reloaded")
	return nil
}

// writeOut writes data to --out (0600, no overwrite without --force).
func (s *session) writeOut(data []byte) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if s.o.force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(s.o.out, flags, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s exists; pass --force to overwrite", s.o.out)
	}
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	if err := errors.Join(werr, f.Close()); err != nil {
		return fmt.Errorf("write %s: %w", s.o.out, err)
	}
	return nil
}

func cmdConfigGet(s *session, _ []string) error {
	c, err := s.client()
	if err != nil {
		return err
	}
	text, err := c.ConfigGet(s.ctx())
	if err != nil {
		return err
	}
	if s.o.out != "" {
		if err := s.writeOut([]byte(text)); err != nil {
			return err
		}
		fmt.Fprintf(s.app.stderr, "wrote %s (secrets masked as ***: replace them or use *_file / *_env before config set)\n", s.o.out)
		return nil
	}
	_, err = io.WriteString(s.out(), text)
	return err
}

// readConfigFile reads a configuration to upload (bounded like the API).
func readConfigFile(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if fi.Size() > 4<<20 {
		return "", fmt.Errorf("%s: larger than 4 MiB", path)
	}
	b, err := os.ReadFile(path)
	return string(b), err
}

func cmdConfigSet(s *session, args []string) error {
	body, err := readConfigFile(args[0])
	if err != nil {
		return err
	}
	c, err := s.client()
	if err != nil {
		return err
	}
	if err := s.confirm(fmt.Sprintf("apply %s and reload", args[0])); err != nil {
		return err
	}
	res, err := c.ConfigPut(s.ctx(), body, false)
	if err != nil {
		return err
	}
	if res.Backup != "" {
		fmt.Fprintf(s.out(), "applied and reloaded; previous file saved as %s\n", res.Backup)
	} else {
		fmt.Fprintln(s.out(), "applied and reloaded")
	}
	return nil
}

func cmdConfigValidate(s *session, args []string) error {
	body, err := readConfigFile(args[0])
	if err != nil {
		return err
	}
	c, err := s.client()
	if err != nil {
		return err
	}
	if _, err := c.ConfigPut(s.ctx(), body, true); err != nil {
		return err
	}
	fmt.Fprintln(s.out(), "configuration is valid")
	return nil
}

func resultName(code int) string {
	if name, ok := ldap.LDAPResultCodeMap[uint16(code)]; ok && code >= 0 && code <= 0xffff { //nolint:gosec // bounds checked
		return name
	}
	return "unknown"
}

func cmdTest(s *session, args []string) error {
	if s.o.filter == "" {
		return usagef("test: --filter is required")
	}
	switch s.o.scope {
	case "", "base", "one", "sub":
	default:
		return usagef("test: --scope must be base, one or sub")
	}
	if s.o.size < 0 {
		return usagef("test: --size-limit must not be negative")
	}
	c, err := s.client()
	if err != nil {
		return err
	}
	res, err := c.Test(s.ctx(), args[0], testRequest{Base: s.o.base, Scope: s.o.scope, Filter: s.o.filter, Attrs: splitList(s.o.attrs), SizeLimit: s.o.size})
	if err != nil {
		return err
	}
	if s.o.json {
		return s.printJSON(res)
	}
	w := s.out()
	fmt.Fprintf(w, "result: %s (%d)  entries: %d  upstream queries: %d  %s\n", resultName(res.ResultCode), res.ResultCode, len(res.Entries), res.UpstreamQueries, fmtMS(res.DurationMS))
	fmt.Fprintf(w, "effective filter: %s\n", dash(res.EffectiveFilter))
	if res.PostFilter != "" {
		fmt.Fprintf(w, "post filter: %s\n", res.PostFilter)
	}
	if len(res.DeniedTerms) > 0 {
		fmt.Fprintf(w, "denied terms: %s\n", strings.Join(res.DeniedTerms, ", "))
	}
	if len(res.DeniedAttrs) > 0 {
		fmt.Fprintf(w, "denied attributes: %s\n", strings.Join(res.DeniedAttrs, ", "))
	}
	if res.Honeytoken != "" {
		fmt.Fprintf(w, "honeytoken: %s\n", res.Honeytoken)
	}
	for _, e := range res.Entries {
		fmt.Fprintf(w, "\ndn: %s\n", e.DN)
		for _, k := range sortedKeys(e.Attrs) {
			for _, v := range e.Attrs[k] {
				fmt.Fprintf(w, "%s: %s\n", k, v)
			}
		}
	}
	return nil
}

func cmdSync(s *session, args []string) error {
	c, err := s.client()
	if err != nil {
		return err
	}
	if err := s.confirm("sync the replica of profile " + args[0]); err != nil {
		return err
	}
	if err := c.Sync(s.ctx(), args[0]); err != nil {
		return err
	}
	fmt.Fprintf(s.out(), "sync of %s started (outcome: replica_synced or replica_sync_failed event)\n", args[0])
	return nil
}

func cmdLearn(s *session, args []string) error {
	d := s.o.forDur
	if !slices.Contains(s.set, "for") {
		d = 24 * time.Hour
	}
	if d <= 0 {
		return usagef("baseline learn: --for must be positive")
	}
	c, err := s.client()
	if err != nil {
		return err
	}
	if err := s.confirm(fmt.Sprintf("restart baseline learning for %s (process-wide)", d)); err != nil {
		return err
	}
	res, err := c.Learn(s.ctx(), args[0], d)
	if err != nil {
		return err
	}
	fmt.Fprintf(s.out(), "learning until %s (scope %s)\n", fmtTime(res.Until), dash(res.Scope))
	return nil
}

func cmdRecordStart(s *session, args []string) error { return record(s, args[0], true) }
func cmdRecordStop(s *session, args []string) error  { return record(s, args[0], false) }

func record(s *session, profile string, on bool) error {
	c, err := s.client()
	if err != nil {
		return err
	}
	verb := yesNo(on, "start", "stop")
	if err := s.confirm(verb + " recording of profile " + profile); err != nil {
		return err
	}
	if err := c.Record(s.ctx(), profile, on); err != nil {
		return err
	}
	fmt.Fprintf(s.out(), "recording of %s: %s\n", profile, yesNo(on, "on", "off"))
	return nil
}

func cmdTUI(s *session, _ []string) error {
	if !s.app.interactive {
		return usagef("the TUI needs a terminal; run a command instead (aldapctl help)")
	}
	c, err := s.client()
	if err != nil {
		return err
	}
	return s.app.runTUI(s.ctx(), c, s.out())
}

func cmdVersion(s *session, _ []string) error {
	fmt.Fprintln(s.out(), versionLine())
	return nil
}
