package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/alstdev/aldap/internal/config"
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
}

// runCheck validates the configuration offline (SPEC §3.5). Exit codes:
// 0 valid, 1 errors found, 2 usage error.
func runCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "configuration file (default $"+config.EnvConfigPath+" or "+config.DefaultConfigPath+")")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	quick := fs.Bool("quick", false, "offline checks only (the default until online checks exist)")
	online := fs.Bool("online", false, "also connect to every upstream (not implemented yet)")
	fs.Usage = func() {
		fmt.Fprint(stderr, "Usage: aldap check [--config FILE] [--json] [--quick] [--online]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "aldap check: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	_ = quick
	if *online {
		fmt.Fprintln(stderr, "aldap check: --online is not implemented yet")
		return 2
	}

	path, required := config.ResolvePath(*cfgPath, os.LookupEnv)
	res := checkResult{Config: path, Errors: []config.Issue{}, Warnings: []config.Issue{}}
	cfg, err := config.LoadFile(path, required)
	if err != nil {
		res.Errors = append(res.Errors, config.Issue{Path: "config", Msg: err.Error()})
	} else {
		if !required && !fileExists(path) {
			res.Config = ""
		}
		rep := config.Validator{}.Validate(cfg)
		res.Errors, res.Warnings = rep.Errors, rep.Warnings
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

func printReport(w io.Writer, res checkResult) {
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
