package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"sort"
	"time"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/secret"
	"github.com/alstdev/aldap/internal/upstream"
)

// envOnlySource is printed instead of a path when no configuration file was
// read and everything came from ALDAP_* environment variables.
const envOnlySource = "(environment only)"

// checkResult is the JSON shape of `aldap check --json`. Config is "" when the
// configuration came from the environment only.
type checkResult struct {
	OK       bool           `json:"ok"`
	Config   string         `json:"config"`
	Errors   []config.Issue `json:"errors"`
	Warnings []config.Issue `json:"warnings"`
	// Online lists every probe of --online (also the successful ones).
	Online []onlineCheck `json:"online,omitempty"`
	// ClientTest is the result of --as-client.
	ClientTest *clientTest `json:"client_test,omitempty"`
}

// onlineCheck is one upstream probe of `aldap check --online`.
type onlineCheck struct {
	Upstream string `json:"upstream"`
	Server   string `json:"server,omitempty"`
	Check    string `json:"check"`
	OK       bool   `json:"ok"`
	Warn     bool   `json:"warn,omitempty"`
	Msg      string `json:"msg"`
}

// onlineTimeout bounds the whole --online run.
const onlineTimeout = 2 * time.Minute

// checkFlags are the parsed flags of `aldap check`.
type checkFlags struct {
	cfgPath                         string
	asJSON, quick, online, asClient bool
	ct                              clientTestRequest
}

// parseCheckFlags parses and cross-validates the flags; a non-nil error
// was already reported on stderr (usage error, exit 2).
func parseCheckFlags(args []string, stderr io.Writer) (*checkFlags, error) {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	f := &checkFlags{}
	fs.StringVar(&f.cfgPath, "config", "", "configuration file (default $"+config.EnvConfigPath+" or "+config.DefaultConfigPath+")")
	fs.BoolVar(&f.asJSON, "json", false, "print the report as JSON")
	fs.BoolVar(&f.quick, "quick", false, "offline checks only (the default)")
	fs.BoolVar(&f.online, "online", false, "also connect to every upstream: bind, root DSE, profile bases, service account audit")
	fs.BoolVar(&f.asClient, "as-client", false, "run one search through the virtual directory of --profile and print what a client sees (connects to its upstream)")
	fs.StringVar(&f.ct.Profile, "profile", "", "profile name for --as-client")
	fs.StringVar(&f.ct.Base, "base", "", "search base for --as-client (default ou=users,<virtual_base>)")
	fs.StringVar(&f.ct.Scope, "scope", "sub", "search scope for --as-client: base, one or sub")
	fs.StringVar(&f.ct.Filter, "filter", "(objectClass=*)", "search filter for --as-client")
	fs.StringVar(&f.ct.Attrs, "attrs", "", "comma-separated attributes for --as-client (default all allowed)")
	fs.IntVar(&f.ct.Size, "size", 20, "size limit for --as-client (0 = profile limit)")
	fs.Usage = func() {
		fmt.Fprint(stderr, "Usage: aldap check [--config FILE] [--json] [--quick] [--online]\n"+
			"       aldap check --as-client --profile NAME [--base DN] [--scope base|one|sub] [--filter F] [--attrs a,b] [--size N]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	var err error
	switch {
	case fs.NArg() > 0:
		err = fmt.Errorf("unexpected argument %q", fs.Arg(0))
	case f.quick && (f.online || f.asClient):
		err = errors.New("--quick is mutually exclusive with --online and --as-client")
	case f.asClient != (f.ct.Profile != ""):
		err = errors.New("--as-client and --profile go together")
	default:
		_, err = parseScope(f.ct.Scope)
	}
	if err != nil {
		fmt.Fprintf(stderr, "aldap check: %v\n", err)
		return nil, err
	}
	return f, nil
}

// runCheck validates the configuration offline and, with --online, probes
// every upstream (SPEC §3.5); --as-client runs one search through a
// profile. Exit codes: 0 valid, 1 errors found, 2 usage error.
func runCheck(args []string, stdout, stderr io.Writer) int {
	f, err := parseCheckFlags(args, stderr)
	if err != nil {
		return 2
	}
	cfgPath, asJSON, online, asClient, ct := &f.cfgPath, &f.asJSON, &f.online, &f.asClient, f.ct

	path, required := config.ResolvePath(*cfgPath, os.LookupEnv)
	res := checkResult{Config: path, Errors: []config.Issue{}, Warnings: []config.Issue{}}
	cfg, err := config.LoadFile(path, required)
	if err != nil {
		res.Errors = append(res.Errors, config.Issue{Path: "config", Msg: err.Error()})
	} else {
		if !required && !fileExists(path) {
			res.Config = ""
		}
		rep := config.Validator{StrictFiles: *online || *asClient}.Validate(cfg)
		res.Errors, res.Warnings = rep.Errors, rep.Warnings
	}
	if *online && len(res.Errors) == 0 {
		ctx, cancel := context.WithTimeout(context.Background(), onlineTimeout)
		defer cancel()
		checkOnline(ctx, cfg, &res)
	}
	if *asClient && len(res.Errors) == 0 {
		ctx, cancel := context.WithTimeout(context.Background(), onlineTimeout)
		defer cancel()
		out, err := runAsClient(ctx, cfg, ct, secret.Default)
		res.ClientTest = out
		if err != nil {
			res.Errors = append(res.Errors, config.Issue{Path: "profile." + ct.Profile, Msg: err.Error()})
		}
	}
	res.OK = len(res.Errors) == 0
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			fmt.Fprintf(stderr, "aldap check: %v\n", err)
			return 2
		}
	} else {
		printReport(stdout, res)
	}
	if res.OK {
		return 0
	}
	return 1
}

// checkOnline probes every upstream with the bases of the proxy profiles
// that use it and folds the findings into the report.
func checkOnline(ctx context.Context, cfg *config.Config, res *checkResult) {
	names := make([]string, 0, len(cfg.Upstreams))
	for name := range cfg.Upstreams {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ucfg := cfg.Upstreams[name]
		path := "upstream." + name
		pw, _, err := secret.Default.Resolve(ucfg.BindPasswordSource())
		if err != nil {
			res.Errors = append(res.Errors, config.Issue{Path: path + ".bind_password", Msg: err.Error()})
			continue
		}
		u, err := upstream.New(name, ucfg, pw.Reveal(), upstream.Options{Logger: slog.New(slog.DiscardHandler)})
		if err != nil {
			res.Errors = append(res.Errors, config.Issue{Path: path, Msg: err.Error()})
			continue
		}
		findings := u.Check(ctx, profileBases(cfg, name))
		u.Close()
		for _, f := range findings {
			res.Online = append(res.Online, onlineCheck{Upstream: name, Server: f.Server, Check: f.Check, OK: f.OK, Warn: f.Warn, Msg: f.Msg})
			switch {
			case f.Warn:
				res.Warnings = append(res.Warnings, config.Issue{Path: path, Msg: f.String()})
			case !f.OK:
				res.Errors = append(res.Errors, config.Issue{Path: path, Msg: f.String()})
			}
		}
	}
}

// profileBases returns the distinct bases of the proxy profiles using the
// upstream, in first-seen order.
func profileBases(cfg *config.Config, upstreamName string) []string {
	names := make([]string, 0, len(cfg.Profiles))
	for name := range cfg.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	seen := map[string]bool{}
	var bases []string
	for _, name := range names {
		p := cfg.Profiles[name]
		if p.Upstream != upstreamName || p.Mode != "proxy" {
			continue
		}
		for _, b := range p.Bases {
			if !seen[b] {
				seen[b] = true
				bases = append(bases, b)
			}
		}
	}
	return bases
}

func printReport(w io.Writer, res checkResult) {
	if res.ClientTest != nil {
		fmt.Fprint(w, res.ClientTest.Text)
	}
	for _, c := range res.Online {
		if c.OK && !c.Warn {
			where := c.Upstream
			if c.Server != "" {
				where += " " + c.Server
			}
			fmt.Fprintf(w, "OK    %s %s: %s\n", where, c.Check, c.Msg)
		}
	}
	for _, e := range res.Errors {
		fmt.Fprintf(w, "ERROR %s\n", e)
	}
	for _, wn := range res.Warnings {
		fmt.Fprintf(w, "WARN  %s\n", wn)
	}
	status := "OK"
	if !res.OK {
		status = "FAILED"
	}
	source := res.Config
	if source == "" {
		source = envOnlySource
	}
	fmt.Fprintf(w, "%s: %s, %d errors, %d warnings\n", status, source, len(res.Errors), len(res.Warnings))
}

// fileExists reports whether path names an existing file; any error other
// than "not exist" is treated as existing so that LoadFile's error wins.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, fs.ErrNotExist)
}
