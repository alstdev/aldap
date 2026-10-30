package main

// Audit 14, area A.7: the daemon side of the management API (controller):
// GET /v1/config masking and what PUT /v1/config (dry_run included) lets an
// admin token holder read on the host through include and *_file keys.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/secret"
)

const a7ArgonHash = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNo"

// a7LoadBody loads body as if it were the file at path (includes resolve
// against its directory, nothing is written).
func a7LoadBody(t *testing.T, path, body string) *config.Config {
	t.Helper()
	l := config.Loader{ReadFile: func(p string) ([]byte, error) {
		if p == path {
			return []byte(body), nil
		}
		return os.ReadFile(p)
	}}
	cfg, err := l.Load(path, true)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return cfg
}

// TestAudit14_A7_Finding_ConfigGetPasswordHash: client_bind.password_hash
// is a plain string in config.ClientBind, so ConfigTOML (GET /v1/config and
// aldapctl bundle) renders the argon2id hash of the application's service
// password in clear, while every other credential form renders "***".
func TestAudit14_A7_Finding_ConfigGetPasswordHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aldap.toml")
	cfg := a7LoadBody(t, path, `
[upstream.ad]
servers = ["ldaps://dc1:636"]
bind_dn = "cn=svc"
bind_password = "S3CR3T-bind-password-value"
[profile.app]
listen = ["127.0.0.1:1636"]
upstream = "ad"
virtual_base = "ou=app,dc=aldap"
bases = ["DC=x"]
[profile.app.client_bind]
dn = "cn=app,ou=app,dc=aldap"
password_hash = "`+a7ArgonHash+`"
[[events.webhook]]
url = "https://siem/hook"
hmac_secret = "S3CR3T-hmac"
[events.webhook.headers]
Authorization = "Bearer S3CR3T-header"
[[api.token]]
name = "t"
token = "S3CR3T-token-0123456789abcdef0123456789"
scopes = ["admin"]
`)
	c := newController(path, true, daemonOptions{Secrets: secret.Default}, &daemon{cfg: cfg})
	b, err := c.ConfigTOML()
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	if strings.Contains(out, "S3CR3T") {
		t.Errorf("an inline secret is rendered:\n%s", out)
	}
	if !strings.Contains(out, `bind_password = "***"`) || !strings.Contains(out, `Authorization = "***"`) {
		t.Errorf("masking of inline secrets/headers missing:\n%s", out)
	}
	if strings.Contains(out, "$argon2id$") {
		t.Errorf("FINDING: GET /v1/config renders client_bind.password_hash in clear (offline-crackable argon2id hash of the application's service password):\n%s", out)
	}
}

// TestAudit14_A7_Info_DryRunIncludeAndFileOracle documents what an admin
// token can learn about the host through PUT /v1/config?dry_run=true:
// include globs are resolved relative to the configuration directory and
// may escape it with ".." or an absolute path (no guard); *_file and
// tls.cert paths are opened by the strict validator, so the error text
// tells apart missing, unreadable and well-formed files. File contents
// never appear in the answer (the TOML parser reports positions only).
func TestAudit14_A7_Info_DryRunIncludeAndFileOracle(t *testing.T) {
	root := t.TempDir()
	cfgDir := filepath.Join(root, "etc")
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	secretFile := filepath.Join(outside, "shadow")
	if err := os.WriteFile(secretFile, []byte("root:$6$SUPERSECRETVALUE:19000:0:99999:7:::\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tomlFile := filepath.Join(outside, "other.toml")
	if err := os.WriteFile(tomlFile, []byte("[upstream.leak]\nservers = [\"ldaps://LEAKEDHOST:636\"]\nbind_dn = \"cn=LEAKEDDN\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfgDir, "aldap.toml")
	c := newController(path, true, daemonOptions{Secrets: secret.Default}, &daemon{cfg: config.Default()})
	ctx := context.Background()

	// 1. include escaping the configuration directory: accepted, parsed, no content in the error.
	for _, inc := range []string{`"../outside/shadow"`, `"` + secretFile + `"`, `"../outside/*"`} {
		err := c.ValidateConfig(ctx, []byte("[server]\ninclude = ["+inc+"]\n"))
		msg := "<nil>"
		if err != nil {
			msg = err.Error()
		}
		t.Logf("include %s -> %s", inc, strings.ReplaceAll(msg, "\n", " | "))
		if strings.Contains(msg, "SUPERSECRETVALUE") {
			t.Errorf("include leaks file content: %s", msg)
		}
	}
	// 2. A TOML file outside the configuration directory becomes configuration
	//    and its non-secret values are rendered by GET /v1/config after apply.
	cfg := a7LoadBody(t, path, "[server]\ninclude = [\"../outside/other.toml\"]\n")
	c2 := newController(path, true, daemonOptions{Secrets: secret.Default}, &daemon{cfg: cfg})
	b, err := c2.ConfigTOML()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "LEAKEDHOST") || !strings.Contains(string(b), "LEAKEDDN") {
		t.Errorf("included TOML not rendered (unexpected): %s", b)
	}
	t.Logf("INFO: an included TOML file outside the config dir is rendered by GET /v1/config (string values in clear)")

	// 3. *_file existence oracle through the strict validator.
	oracle := func(label, body string) string {
		err := c.ValidateConfig(ctx, []byte(body))
		msg := "<nil>"
		if err != nil {
			msg = err.Error()
		}
		if strings.Contains(msg, "SUPERSECRETVALUE") {
			t.Errorf("%s leaks file content: %s", label, msg)
		}
		var hits []string
		for _, line := range strings.Split(msg, "\n") {
			if strings.Contains(line, "_file") || strings.Contains(line, "tls.cert") || strings.Contains(line, "tls.key") {
				hits = append(hits, strings.TrimSpace(line))
			}
		}
		t.Logf("%s -> %s", label, strings.Join(hits, " | "))
		return strings.Join(hits, " | ")
	}
	up := "[upstream.ad]\nservers = [\"ldaps://dc1:636\"]\nbind_dn = \"cn=svc\"\nbind_password_file = %q\n"
	missing := oracle("bind_password_file missing", strings.ReplaceAll(up, "%q", `"`+filepath.Join(outside, "nope")+`"`))
	present := oracle("bind_password_file present", strings.ReplaceAll(up, "%q", `"`+secretFile+`"`))
	dir := oracle("bind_password_file is a dir", strings.ReplaceAll(up, "%q", `"`+outside+`"`))
	if missing == present || missing == dir {
		t.Logf("no oracle: %q / %q / %q", missing, present, dir)
	} else {
		t.Logf("INFO: dry_run distinguishes missing / readable / directory for any path the daemon can stat (admin only)")
	}
	tl := "[tls]\nmode = \"external\"\ncert = %q\nkey = %q\n"
	oracle("tls.cert non-PEM file", strings.ReplaceAll(tl, "%q", `"`+secretFile+`"`))
	oracle("tls.cert missing", strings.ReplaceAll(tl, "%q", `"`+filepath.Join(outside, "nope.pem")+`"`))
}
