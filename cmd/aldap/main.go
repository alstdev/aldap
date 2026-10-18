// Command aldap is the ALDAP daemon: an LDAP proxy with a virtual directory,
// brute-force protection and IDS telemetry.
package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
)

// Build metadata, injected with -ldflags "-X main.version=... -X main.commit=... -X main.date=...".
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const usageText = `Usage: aldap <command> [options]

Commands:
  run       start the proxy (see: aldap run -h)
  check     validate the configuration (see: aldap check -h)
  gen-ca    create the built-in certificate authority
  gen-cert  issue a server certificate from the built-in CA
  version   print build information
  help      print this help
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches the command line and returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	switch args[0] {
	case "run":
		return runRun(args[1:], stdout, stderr)
	case "check":
		return runCheck(args[1:], stdout, stderr)
	case "gen-ca":
		return runGenCA(args[1:], stdout, stderr)
	case "gen-cert":
		return runGenCert(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, versionLine())
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usageText)
		return 0
	default:
		fmt.Fprintf(stderr, "aldap: unknown command %q\n\n", args[0])
		fmt.Fprint(stderr, usageText)
		return 2
	}
}

// versionLine formats the build metadata on a single line.
func versionLine() string {
	return fmt.Sprintf("aldap %s (commit %s, built %s, %s %s/%s)",
		version, commit, date, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
