package main

import (
	"bytes"
	"context"
	"os"
	"runtime"
	"strings"
	"testing"
)

// Audit 14 / A.6 (4): `aldap check` on malformed TOML. The TOML decoder's
// error is wrapped verbatim (config/load.go: fmt.Errorf("%s: %w", path, err))
// and printed. Some lexer errors echo the offending token.
func TestAudit14_A6_CheckParseErrorsNoSecret(t *testing.T) {
	// Letters only: the TOML lexer treats an unquoted word as a would-be
	// boolean and echoes the whole word in its error.
	const bare = "SecretMarkerLeakCheck"
	const pw = "S3CR3T-check-" + bare
	cases := map[string]string{
		"unterminated": "bind_password = \"" + pw + "\n",
		"bare_word":    "bind_password = " + bare + "\n",
		"bad_escape":   "bind_password = \"" + pw + "\\q\"\n",
		"wrong_type":   "bind_password = [\"" + pw + "\"]\n",
		"duplicate":    "bind_password = \"" + pw + "\"\nbind_password = \"" + pw + "\"\n",
		"control_char": "bind_password = \"" + pw + "\x01\"\n",
		"int_dest":     "[upstream.u.pool]\nsize = \"" + pw + "\"\n",
	}
	for name, frag := range cases {
		t.Run(name, func(t *testing.T) {
			p := writeTemp(t, "[upstream.u]\nservers = [\"ldaps://dc\"]\nbind_dn = \"cn=a\"\n"+frag)
			for _, args := range [][]string{{"check", "--config", p}, {"check", "--json", "--config", p}} {
				var stdout, stderr bytes.Buffer
				run(args, &stdout, &stderr)
				out := stdout.String() + stderr.String()
				if strings.Contains(out, bare) {
					t.Errorf("FINDING: %v echoes the secret value:\n%s", args, out)
				}
			}
		})
	}
}

// Audit 14 / A.6 (3): PUT /v1/config writes the new file and the backup
// with the mode of the existing file. A 0644 aldap.toml (no inline secrets
// so far) receives a body with an inline secret and stays world-readable.
func TestAudit14_A6_ApplyConfigKeepsWorldReadableMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	const pw = "S3CR3T-inline-client-pw-5e2c"
	ctl, _, path := testController(t, func() error { return nil })
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	orig, _ := os.ReadFile(path)
	body := strings.Replace(string(orig), `password_env = "ALDAP_TEST_CLIENT_PW"`, `password = "`+pw+`"`, 1)
	if body == string(orig) {
		t.Fatal("fixture changed: client_bind.password_env not found")
	}
	res, err := ctl.ApplyConfig(context.Background(), []byte(body))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	for _, f := range []string{path, res.Backup} {
		fi, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(f)
		if fi.Mode().Perm()&^0o640 != 0 {
			t.Errorf("FINDING: %s written with mode %04o (inline secret present: %v)", f, fi.Mode().Perm(), strings.Contains(string(b), pw))
		}
	}
}
