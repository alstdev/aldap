// Command aldapctl is the ALDAP control client (CLI and TUI).
// It talks to a running aldap instance over its API only: the IPC socket
// (named pipe on Windows) without a token, or TCP with --url and a token
// file. It never reads the daemon configuration or state files.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/alstdev/aldap/internal/config"
)

// Build metadata, injected with -ldflags "-X main.version=... -X main.commit=... -X main.date=...".
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Exit codes.
const (
	exitOK      = 0
	exitError   = 1
	exitUsage   = 2
	exitAborted = 3
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	a := &app{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, interactive: isTerminal(os.Stdin) && isTerminal(os.Stdout),
		now: time.Now, runTUI: runTUI}
	code := a.run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}

// isTerminal reports a character device (a console on Windows too).
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// app is one invocation: its streams and the hooks tests replace.
type app struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	// interactive allows y/n prompts and the TUI.
	interactive bool
	now         func() time.Time
	runTUI      func(ctx context.Context, api tuiAPI, out io.Writer) error

	in *bufio.Reader
}

// usageError is a command line mistake (exit 2).
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func usagef(format string, args ...any) error { return usageError{fmt.Sprintf(format, args...)} }

// abortedError is a state-changing command that was not confirmed (exit 3).
type abortedError struct{ msg string }

func (e abortedError) Error() string { return e.msg }

// opts holds every flag; a command accepts the subset its spec names.
type opts struct {
	conn connOpts

	yes      bool
	json     bool
	help     bool
	forDur   time.Duration
	reason   string
	account  bool
	follow   bool
	types    string
	since    uint64
	limit    int
	format   string
	minScore float64
	base     string
	filter   string
	attrs    string
	scope    string
	size     int
	profile  string
	out      string
	force    bool
	nEvents  int
}

// flagDoc describes one flag for the help text.
type flagDoc struct {
	name, arg, help string
}

var connFlagDocs = []flagDoc{
	{"socket", "PATH", "IPC socket, a named pipe on Windows (default " + config.DefaultIPCSocket() + "); no token"},
	{"url", "URL", "API over TCP: https://host:8636 (plain http on loopback only)"},
	{"token-file", "FILE", "bearer token for --url; tokens are never taken on the command line"},
	{"ca-file", "FILE", "CA certificates (PEM) for the API certificate (default: system roots)"},
	{"client-cert", "FILE", "client certificate (PEM) for API mTLS, with --client-key"},
	{"client-key", "FILE", "client key (PEM) for API mTLS"},
	{"timeout", "DURATION", "timeout of one API call (default 30s)"},
}

var optFlagDocs = map[string]flagDoc{
	"yes":        {"yes", "", "confirm without a prompt (scripts); -y for short"},
	"json":       {"json", "", "print the API answer as JSON"},
	"for":        {"for", "DURATION", "duration, e.g. 30m, 1h, 24h"},
	"reason":     {"reason", "TEXT", "reason stored with the lock"},
	"account":    {"account", "", "treat the key as an account even if it looks like an IP address"},
	"follow":     {"follow", "", "keep streaming new events (Ctrl+C stops); -f for short"},
	"types":      {"types", "LIST", "event types, comma separated (default: all)"},
	"since":      {"since", "SEQ", "events after this sequence number"},
	"limit":      {"limit", "N", "at most N events (1–10000)"},
	"format":     {"format", "FMT", "table (default), json, stix-lite or plain"},
	"min-score":  {"min-score", "N", "only indicators with at least this score"},
	"base":       {"base", "DN", "search base (default: the profile's virtual base)"},
	"filter":     {"filter", "FILTER", "LDAP filter (required), e.g. (uid=jdoe)"},
	"attrs":      {"attrs", "LIST", "attributes, comma separated"},
	"scope":      {"scope", "SCOPE", "base, one or sub (default sub)"},
	"size-limit": {"size-limit", "N", "size limit of the test search"},
	"profile":    {"profile", "NAME", "profile to replay against (required)"},
	"out":        {"out", "FILE", "output file"},
	"force":      {"force", "", "overwrite an existing output file"},
	"events":     {"events", "N", "number of recent events in the bundle (default 10000)"},
}

// command is one CLI command (SPEC §8).
type command struct {
	name     string
	args     string
	summary  string
	mutating bool
	flags    []string
	min, max int
	run      func(s *session, args []string) error
}

// commands lists the CLI; the help text and the dispatcher read it.
var commands = []command{
	{name: "status", summary: "version, uptime, lockdown, profiles and upstream states", flags: []string{"json"}, run: cmdStatus},
	{name: "upstreams", summary: "upstream servers in detail", flags: []string{"json"}, run: cmdUpstreams},
	{name: "profiles", summary: "profiles without secrets", flags: []string{"json"}, run: cmdProfiles},
	{name: "locks", summary: "active IP and account locks", flags: []string{"json"}, run: cmdLocks},
	{name: "unlock", args: "<ip|account>", summary: "remove a lock", mutating: true, flags: []string{"account"}, min: 1, max: 1, run: cmdUnlock},
	{name: "lock", args: "<ip|account>", summary: "lock an IP address or an account", mutating: true, flags: []string{"for", "reason", "account"}, min: 1, max: 1, run: cmdLock},
	{name: "lockdown", args: "on|off", summary: "switch the global lockdown", mutating: true, min: 1, max: 1, run: cmdLockdown},
	{name: "events", summary: "buffered events; --follow streams new ones", flags: []string{"follow", "types", "since", "limit", "json"}, run: cmdEvents},
	{name: "indicators", summary: "suspicious IPs and accounts with scores", flags: []string{"format", "min-score", "json"}, run: cmdIndicators},
	{name: "reload", summary: "reload the configuration file", mutating: true, run: cmdReload},
	{name: "config get", summary: "print the running configuration (secrets masked)", flags: []string{"out", "force"}, run: cmdConfigGet},
	{name: "config set", args: "<file>", summary: "validate, back up, write and reload a configuration file", mutating: true, min: 1, max: 1, run: cmdConfigSet},
	{name: "config validate", args: "<file>", summary: "validate a configuration file on the daemon without applying it", min: 1, max: 1, run: cmdConfigValidate},
	{name: "test", args: "<profile>", summary: "what a client would see for a search, with diagnostics", flags: []string{"base", "filter", "attrs", "scope", "size-limit", "json"}, min: 1, max: 1, run: cmdTest},
	{name: "sync", args: "<profile>", summary: "force a replica sync", mutating: true, min: 1, max: 1, run: cmdSync},
	{name: "baseline learn", args: "<profile>", summary: "restart IDS baseline learning", mutating: true, flags: []string{"for"}, min: 1, max: 1, run: cmdLearn},
	{name: "record start", args: "<profile>", summary: "start recording requests of a profile", mutating: true, min: 1, max: 1, run: cmdRecordStart},
	{name: "record stop", args: "<profile>", summary: "stop recording requests of a profile", mutating: true, min: 1, max: 1, run: cmdRecordStop},
	{name: "replay", args: "<file>", summary: "replay recorded searches against a profile and compare", flags: []string{"profile", "json"}, min: 1, max: 1, run: cmdReplay},
	{name: "bundle", summary: "support bundle: config without secrets, events, versions, health, metrics", flags: []string{"out", "force", "events"}, run: cmdBundle},
	{name: "tui", summary: "interactive terminal UI (also: aldapctl without a command)", run: cmdTUI},
	{name: "version", summary: "print build information", run: cmdVersion},
	{name: "help", args: "[command]", summary: "print this help or the help of a command", max: 2, run: nil},
}

// lookup finds a command by its first one or two words.
func lookup(words []string) (*command, int) {
	if len(words) >= 2 {
		for i := range commands {
			if commands[i].name == words[0]+" "+words[1] {
				return &commands[i], 2
			}
		}
	}
	if len(words) >= 1 {
		for i := range commands {
			if commands[i].name == words[0] {
				return &commands[i], 1
			}
		}
	}
	return nil, 0
}

// group names a two-word command family ("config", "baseline", "record").
func group(word string) []string {
	var subs []string
	for _, c := range commands {
		if g, sub, ok := strings.Cut(c.name, " "); ok && g == word {
			subs = append(subs, sub)
		}
	}
	return subs
}

// newFlagSet registers every flag; parse checks which ones a command accepts.
func newFlagSet(o *opts) *flag.FlagSet {
	fs := flag.NewFlagSet("aldapctl", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.conn.socket, "socket", "", "")
	fs.StringVar(&o.conn.url, "url", "", "")
	fs.StringVar(&o.conn.tokenFile, "token-file", "", "")
	fs.StringVar(&o.conn.caFile, "ca-file", "", "")
	fs.StringVar(&o.conn.clientCert, "client-cert", "", "")
	fs.StringVar(&o.conn.clientKey, "client-key", "", "")
	fs.DurationVar(&o.conn.timeout, "timeout", 30*time.Second, "")
	fs.BoolVar(&o.yes, "yes", false, "")
	fs.BoolVar(&o.yes, "y", false, "")
	fs.BoolVar(&o.json, "json", false, "")
	fs.BoolVar(&o.help, "help", false, "")
	fs.BoolVar(&o.help, "h", false, "")
	fs.DurationVar(&o.forDur, "for", 0, "")
	fs.StringVar(&o.reason, "reason", "", "")
	fs.BoolVar(&o.account, "account", false, "")
	fs.BoolVar(&o.follow, "follow", false, "")
	fs.BoolVar(&o.follow, "f", false, "")
	fs.StringVar(&o.types, "types", "", "")
	fs.Uint64Var(&o.since, "since", 0, "")
	fs.IntVar(&o.limit, "limit", 0, "")
	fs.StringVar(&o.format, "format", "", "")
	fs.Float64Var(&o.minScore, "min-score", 0, "")
	fs.StringVar(&o.base, "base", "", "")
	fs.StringVar(&o.filter, "filter", "", "")
	fs.StringVar(&o.attrs, "attrs", "", "")
	fs.StringVar(&o.scope, "scope", "", "")
	fs.IntVar(&o.size, "size-limit", 0, "")
	fs.StringVar(&o.profile, "profile", "", "")
	fs.StringVar(&o.out, "out", "", "")
	fs.BoolVar(&o.force, "force", false, "")
	fs.IntVar(&o.nEvents, "events", 10000, "")
	return fs
}

// parseArgs parses flags anywhere on the line (until "--") and returns the
// positional words and the names of the flags given.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, []string, error) {
	var tail []string
	if i := slices.Index(args, "--"); i >= 0 {
		args, tail = args[:i], args[i+1:]
	}
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, nil, usageError{err.Error()}
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
	var set []string
	fs.Visit(func(f *flag.Flag) { set = append(set, canonical(f.Name)) })
	return append(pos, tail...), set, nil
}

// canonical maps short aliases to the documented flag name.
func canonical(name string) string {
	switch name {
	case "y":
		return "yes"
	case "f":
		return "follow"
	case "h":
		return "help"
	}
	return name
}

func isConnFlag(name string) bool {
	for _, d := range connFlagDocs {
		if d.name == name {
			return true
		}
	}
	return false
}

// run parses the command line, executes it and returns the exit code.
func (a *app) run(ctx context.Context, args []string) int {
	if a.now == nil {
		a.now = time.Now
	}
	a.in = bufio.NewReader(a.stdin)
	o := &opts{}
	fs := newFlagSet(o)
	words, set, err := parseArgs(fs, args)
	if err != nil {
		return a.fail(err)
	}
	if len(words) == 0 {
		if o.help {
			fmt.Fprint(a.stdout, usageText())
			return exitOK
		}
		words = []string{"tui"}
	}
	if words[0] == "help" {
		return a.help(words[1:])
	}
	cmd, n := lookup(words)
	if cmd == nil {
		if subs := group(words[0]); subs != nil {
			return a.fail(usagef("%s: want one of: %s", words[0], strings.Join(subs, ", ")))
		}
		return a.fail(usagef("unknown command %q (aldapctl help lists the commands)", words[0]))
	}
	if o.help {
		fmt.Fprint(a.stdout, commandHelp(cmd))
		return exitOK
	}
	for _, name := range set {
		if isConnFlag(name) || name == "help" || (name == "yes" && cmd.mutating) || slices.Contains(cmd.flags, name) {
			continue
		}
		return a.fail(usagef("%s: flag --%s does not apply (aldapctl help %s)", cmd.name, name, cmd.name))
	}
	rest := words[n:]
	if len(rest) < cmd.min || len(rest) > cmd.max {
		return a.fail(usagef("usage: aldapctl %s", synopsis(cmd)))
	}
	s := &session{app: a, o: o, set: set, base: ctx}
	return a.fail(cmd.run(s, rest), ctx)
}

// fail prints err and maps it to an exit code (nil = success). The
// optional context marks an interrupted command as aborted.
func (a *app) fail(err error, ctx ...context.Context) int {
	if err == nil {
		return exitOK
	}
	var ue usageError
	var ab abortedError
	switch {
	case errors.As(err, &ue):
		fmt.Fprintf(a.stderr, "aldapctl: %s\n", ue.msg)
		return exitUsage
	case errors.As(err, &ab):
		fmt.Fprintf(a.stderr, "aldapctl: %s\n", ab.msg)
		return exitAborted
	}
	if len(ctx) > 0 && ctx[0] != nil && ctx[0].Err() != nil && errors.Is(err, context.Canceled) {
		fmt.Fprintln(a.stderr, "aldapctl: interrupted")
		return exitAborted
	}
	fmt.Fprintf(a.stderr, "aldapctl: %v\n", err)
	return exitError
}

func (a *app) help(words []string) int {
	if len(words) == 0 {
		fmt.Fprint(a.stdout, usageText())
		return exitOK
	}
	cmd, n := lookup(words)
	if cmd == nil || n != len(words) {
		if len(words) == 1 && group(words[0]) != nil {
			for _, sub := range group(words[0]) {
				c, _ := lookup([]string{words[0], sub})
				fmt.Fprint(a.stdout, commandHelp(c))
				fmt.Fprintln(a.stdout)
			}
			return exitOK
		}
		return a.fail(usagef("help: unknown command %q", strings.Join(words, " ")))
	}
	fmt.Fprint(a.stdout, commandHelp(cmd))
	return exitOK
}

func synopsis(c *command) string {
	parts := []string{c.name}
	if c.args != "" {
		parts = append(parts, c.args)
	}
	for _, f := range c.flags {
		d := optFlagDocs[f]
		if d.arg != "" {
			parts = append(parts, "[--"+d.name+" "+d.arg+"]")
		} else {
			parts = append(parts, "[--"+d.name+"]")
		}
	}
	if c.mutating {
		parts = append(parts, "[--yes]")
	}
	return strings.Join(parts, " ")
}

func writeFlags(b *strings.Builder, docs []flagDoc) {
	for _, d := range docs {
		left := "--" + d.name
		if d.arg != "" {
			left += " " + d.arg
		}
		fmt.Fprintf(b, "  %-22s %s\n", left, d.help)
	}
}

func usageText() string {
	var b strings.Builder
	b.WriteString(`aldapctl - control client of a running aldap (API over the IPC socket or TCP)

Usage:
  aldapctl [connection flags]                  interactive TUI (needs a terminal)
  aldapctl [connection flags] <command> [args] [flags]

Commands:
`)
	for i := range commands {
		c := &commands[i]
		left := c.name
		if c.args != "" {
			left += " " + c.args
		}
		mark := ""
		if c.mutating {
			mark = " *"
		}
		fmt.Fprintf(&b, "  %-30s %s%s\n", left, c.summary, mark)
	}
	b.WriteString("\nConnection flags (default: the local IPC socket, no token):\n")
	writeFlags(&b, connFlagDocs)
	b.WriteString("\nCommand flags:\n")
	names := make([]string, 0, len(optFlagDocs))
	for k := range optFlagDocs {
		names = append(names, k)
	}
	sort.Strings(names)
	docs := make([]flagDoc, 0, len(names))
	for _, n := range names {
		docs = append(docs, optFlagDocs[n])
	}
	writeFlags(&b, docs)
	b.WriteString(`  --help, -h             help of a command (aldapctl <command> --help)

* changes the daemon state: on a terminal aldapctl asks y/n first, otherwise
  (scripts, pipes) the command runs only with --yes.

Exit codes: 0 success, 1 error (API or connection), 2 usage error,
3 not confirmed or interrupted.
`)
	return b.String()
}

func commandHelp(c *command) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Usage: aldapctl %s\n\n%s.\n", synopsis(c), strings.ToUpper(c.summary[:1])+c.summary[1:])
	if c.mutating {
		b.WriteString("Changes the daemon state: asks y/n on a terminal, needs --yes otherwise.\n")
	}
	if len(c.flags) > 0 || c.mutating {
		b.WriteString("\nFlags:\n")
		var docs []flagDoc
		for _, f := range c.flags {
			docs = append(docs, optFlagDocs[f])
		}
		if c.mutating {
			docs = append(docs, optFlagDocs["yes"])
		}
		writeFlags(&b, docs)
	}
	b.WriteString("\nConnection flags: --socket, --url, --token-file, --ca-file, --client-cert, --client-key, --timeout (aldapctl help).\n")
	return b.String()
}

// versionLine formats the build metadata on a single line.
func versionLine() string {
	return fmt.Sprintf("aldapctl %s (commit %s, built %s, %s %s/%s)",
		version, commit, date, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
