//go:build integration

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/alstdev/aldap/internal/testdir"
)

func TestRunCheck_Online(t *testing.T) {
	dc := testdir.StartFixture(t)
	dead := testdir.Start(t, testdir.WithDirectory(dc.Dir))
	dead.Kill()
	otherURL := fmt.Sprintf("ldap://127.0.0.1:%d", freePort(t))
	appPort, honeyPort := freePort(t), freePort(t)
	toml := func(servers, bases string) string {
		return fmt.Sprintf(`
[upstream.ad]
servers = [%s]
bind_dn = "CN=svc-aldap,CN=Users,DC=test,DC=aldap"
bind_password_env = "ALDAP_TEST_PW"
base_dn = "DC=test,DC=aldap"
[upstream.ad.timeouts]
connect = "1s"
[upstream.other]
servers = ["%s"]
[upstream.other.timeouts]
connect = "300ms"
[profile.app]
listen = ["127.0.0.1:%d"]
upstream = "ad"
virtual_base = "ou=app,dc=aldap"
bases = [%s]
[profile.app.attrs]
allow = ["cn"]
[profile.honey]
listen = ["127.0.0.1:%d"]
mode = "honeypot"
virtual_base = "ou=honey,dc=aldap"
`, servers, otherURL, appPort, bases, honeyPort)
	}
	t.Setenv("ALDAP_TEST_PW", "svc-aldap-pass")
	t.Setenv("ALDAP_CONFIG", "")
	good := writeTemp(t, toml(fmt.Sprintf("%q", dc.URL()), `"OU=Office,DC=test,DC=aldap", "OU=Branch,DC=test,DC=aldap"`))
	var stdout, stderr bytes.Buffer
	code := run([]string{"check", "--config", good, "--online", "--json"}, &stdout, &stderr)
	var res checkResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("json: %v\n%s", err, stdout.String())
	}
	if code != 1 || res.OK {
		t.Fatalf("exit %d ok=%v (upstream.other must fail)\n%s", code, res.OK, stdout.String())
	}
	var adOK, otherFail int
	for _, c := range res.Online {
		switch {
		case c.Upstream == "ad" && c.OK && !c.Warn:
			adOK++
		case c.Upstream == "other" && !c.OK:
			otherFail++
		}
	}
	// ad: connect, bind, rootdse, base ×2, audit.
	if adOK != 6 || otherFail != 1 || len(res.Errors) != 1 || !strings.HasPrefix(res.Errors[0].Path, "upstream.other") {
		t.Fatalf("adOK=%d otherFail=%d errors=%v", adOK, otherFail, res.Errors)
	}
	if dc.Calls().Binds == 0 || dc.Calls().Searches < 4 {
		t.Fatalf("probes did not reach the server: %+v", dc.Calls())
	}

	// Text output lists passed probes; a missing base and a dead primary are errors.
	mixed := writeTemp(t, strings.Replace(toml(fmt.Sprintf("%q, %q", dead.URL(), dc.URL()), `"OU=Office,DC=test,DC=aldap", "OU=Nope,DC=test,DC=aldap"`),
		`[upstream.other]
servers = ["`+otherURL+`"]
[upstream.other.timeouts]
connect = "300ms"
`, "", 1))
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"check", "--config", mixed, "--online"}, &stdout, &stderr)
	out := stdout.String()
	if code != 1 || !strings.Contains(out, "OK    ad "+dc.URL()+" bind: service bind ok") ||
		!strings.Contains(out, "ERROR upstream.ad: "+dead.URL()+" connect:") ||
		!strings.Contains(out, "ERROR upstream.ad: "+dc.URL()+" base: OU=Nope,DC=test,DC=aldap") ||
		!strings.Contains(out, "FAILED: "+mixed+", 2 errors") {
		t.Fatalf("exit %d\n%s", code, out)
	}

	// Privileged service account → warning, exit 0.
	t.Setenv("ALDAP_TEST_PW", "svc-admin-pass")
	admin := writeTemp(t, strings.Replace(strings.Replace(toml(fmt.Sprintf("%q", dc.URL()), `"OU=Office,DC=test,DC=aldap"`),
		"CN=svc-aldap,", "CN=svc-admin,", 1), `[upstream.other]
servers = ["`+otherURL+`"]
[upstream.other.timeouts]
connect = "300ms"
`, "", 1))
	stdout.Reset()
	code = run([]string{"check", "--config", admin, "--online"}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "WARN  upstream.ad: audit: service account is a member of CN=Administrators,CN=Builtin,DC=test,DC=aldap; CN=Domain Admins") {
		t.Fatalf("exit %d\n%s", code, stdout.String())
	}
	if strings.Contains(stdout.String(), "svc-admin-pass") {
		t.Fatal("password leaked into output")
	}
}
