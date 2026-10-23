//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/ratelimit"
	"github.com/alstdev/aldap/internal/testdir"
)

const (
	vUsers = "ou=users,ou=v,dc=aldap"
	vGroup = "cn=virola-users,ou=groups,ou=v,dc=aldap"
)

// stage5Config adds the Stage 5 profiles to the daemon configuration: "v"
// (ldaps, groups, computed, mask, honeytokens), "honey" (honeypot) and
// "mock" (mock file). It returns the extra TOML and the three ports.
func stage5Config(t *testing.T) (extra string, vPort, honeyPort, mockPort int) {
	t.Helper()
	vPort, honeyPort, mockPort = freePort(t), freePort(t), freePort(t)
	mockFile := filepath.Join(t.TempDir(), "mock.toml")
	if err := os.WriteFile(mockFile, []byte("base_dn = \"ou=people,dc=mock\"\n[[users]]\ncn = \"Mock One\"\nsAMAccountName = \"mock.one\"\nuserPrincipalName = \"mock.one@mock.local\"\nmail = \"mock.one@mock.local\"\nuserPassword = \"S3CR3T-mock-one\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	extra = fmt.Sprintf(`
[profile.v]
listen = ["127.0.0.1:%d"]
transport = "ldaps"
upstream = "ad"
virtual_base = "ou=v,dc=aldap"
bases = ["OU=Office,DC=test,DC=aldap", "OU=Branch,DC=test,DC=aldap"]
rdn_attr = "sAMAccountName"
nested_groups = true
honeytokens = ["h.petrenko@test.aldap"]
[profile.v.client_bind]
dn = %q
password_env = "ALDAP_TEST_CLIENT_PW"
[profile.v.user_bind]
default_domain = "test.aldap"
require_membership = true
[profile.v.attrs]
allow = ["userPrincipalName", "sAMAccountName", "displayName", "givenName", "sn", "mail", "telephoneNumber", "objectClass", "objectGUID"]
[profile.v.attrs.map]
uid = "sAMAccountName"
cn = "displayName"
[profile.v.attrs.computed]
mail = "{{ or .mail (printf \"%%s@corp.local\" .sAMAccountName) }}"
[profile.v.attrs.mask]
telephoneNumber = "***{last4}"
[profile.v.objectclass.map]
user = "inetOrgPerson"
[profile.v.groups.virola-users]
description = "All Virola users"
objectclass = "groupOfNames"
[profile.v.groups.staff]
objectclass = "group"
[profile.v.groups.staff.members]
ad_groups = ["CN=Staff,CN=Users,DC=test,DC=aldap"]

[profile.honey]
listen = ["127.0.0.1:%d"]
transport = "ldap"
mode = "honeypot"
upstream = "ad"
virtual_base = "dc=corp,dc=local"
honeytokens = ["backup-admin@corp.local"]

[profile.mock]
listen = ["127.0.0.1:%d"]
transport = "ldap"
mode = "mock"
virtual_base = "ou=mock,dc=aldap"
rdn_attr = "sAMAccountName"
[profile.mock.mock]
file = %q
[profile.mock.user_bind]
default_domain = "mock.local"
[profile.mock.attrs]
allow = ["sAMAccountName", "mail", "cn"]
[profile.mock.groups.everyone]
`, vPort, tClientDN, honeyPort, mockPort, mockFile)
	return extra, vPort, honeyPort, mockPort
}

// TestDaemon_Virola is the mandatory Stage 5 end-to-end scenario over the
// real listener: two bases, computers excluded, a group with everyone,
// user bind by UPN, memberOf on the user (TESTING.md 1, 6, 7, 12, 14).
func TestDaemon_Virola(t *testing.T) {
	extra, vPort, _, _ := stage5Config(t)
	r := startDaemon(t, extra)
	dial := func() *ldap.Conn {
		t.Helper()
		c, err := ldap.DialURL(fmt.Sprintf("ldaps://127.0.0.1:%d", vPort), ldap.DialWithTLSConfig(r.tlsConfig(t)))
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		c.SetTimeout(10 * time.Second)
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	c := dial()
	if err := c.Bind(tClientDN, clientPassword); err != nil {
		t.Fatalf("client bind: %v", err)
	}
	// 1. Whole tree: containers, 19 users, 2 groups, 1 honeytoken, no computer.
	res := search(t, c, "ou=v,dc=aldap", "(objectClass=*)", "objectClass")
	var users, groups, computers int
	for _, e := range res.Entries {
		switch {
		case strings.HasSuffix(e.DN, ","+vUsers):
			users++
		case strings.HasSuffix(e.DN, ",ou=groups,ou=v,dc=aldap"):
			groups++
		}
		for _, oc := range e.GetAttributeValues("objectClass") {
			if strings.EqualFold(oc, "computer") || strings.EqualFold(oc, "user") {
				computers++
			}
		}
	}
	if len(res.Entries) != 3+20+2 || users != 20 || groups != 2 || computers != 0 {
		t.Errorf("tree: %d entries, %d users, %d groups, %d computer/user classes", len(res.Entries), users, groups, computers)
	}
	// 7. The group lists everyone from both bases; memberOf and (memberOf=) agree; nested Staff.
	g := search(t, c, vGroup, "(objectClass=groupOfNames)", "member", "description")
	if len(g.Entries) != 1 || len(g.Entries[0].GetAttributeValues("member")) != 20 || g.Entries[0].GetAttributeValue("description") != "All Virola users" {
		t.Fatalf("group = %+v", g.Entries)
	}
	members := g.Entries[0].GetAttributeValues("member")
	byMember := search(t, c, vUsers, "(memberOf="+vGroup+")", "uid")
	if len(byMember.Entries) != 20 {
		t.Errorf("(memberOf=) = %d", len(byMember.Entries))
	}
	for _, e := range byMember.Entries {
		if !containsFold(members, e.DN) {
			t.Errorf("%s not in member list", e.DN)
		}
	}
	staff := search(t, c, "cn=staff,ou=groups,ou=v,dc=aldap", "(objectClass=*)", "member", "sAMAccountName")
	if len(staff.Entries) != 1 || !containsFold(staff.Entries[0].GetAttributeValues("member"), "cn=alice.adams,"+vUsers) || staff.Entries[0].GetAttributeValue("sAMAccountName") != "staff" {
		t.Errorf("nested staff = %+v", staff.Entries)
	}
	// 12/14. User bind by UPN (require_membership), then memberOf, computed, mask, object class.
	u := dial()
	if err := u.Bind("alice.adams@test.aldap", "alice.adams-pass"); err != nil {
		t.Fatalf("user bind: %v", err)
	}
	me := search(t, u, vUsers, "(uid=alice.adams)", "memberOf", "mail", "objectClass", "telephoneNumber")
	if len(me.Entries) != 1 {
		for _, e := range me.Entries {
			t.Logf("entry %s %+v", e.DN, e.Attributes)
		}
		t.Fatalf("self = %d entries", len(me.Entries))
	}
	e := me.Entries[0]
	if mo := e.GetAttributeValues("memberOf"); len(mo) != 2 || !containsFold(mo, vGroup) || !containsFold(mo, "cn=staff,ou=groups,ou=v,dc=aldap") {
		t.Errorf("memberOf = %v", mo)
	}
	if e.GetAttributeValue("mail") != "alice.adams@test.aldap" || !containsFold(e.GetAttributeValues("objectClass"), "inetOrgPerson") || containsFold(e.GetAttributeValues("objectClass"), "user") {
		t.Errorf("alice = %+v", e.Attributes)
	}
	if err := dial().Bind("carol.clark@test.aldap", "carol.clark-pass"); err == nil || !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Errorf("disabled user bind: %v", err)
	}
	// 6. Computed mail through post-filtering, masked telephone.
	byMail := search(t, c, vUsers, "(mail=alice.adams@test.aldap)", "uid")
	if len(byMail.Entries) != 1 || byMail.Entries[0].GetAttributeValue("uid") != "alice.adams" {
		t.Errorf("computed mail filter = %+v", byMail.Entries)
	}
	// Honeytoken: listed, targeted search is a hit, the IP is then locked for binds.
	trap := search(t, c, vUsers, "(uid=h.petrenko)", "uid", "memberOf")
	if len(trap.Entries) != 1 || !containsFold(trap.Entries[0].GetAttributeValues("memberOf"), vGroup) {
		t.Errorf("trap = %+v", trap.Entries)
	}
	waitFor(t, func() bool {
		return strings.Contains(r.logs.String(), `"event":"honeytoken"`) || strings.Contains(r.logs.String(), "honeytoken hit")
	})
	if err := dial().Bind("alice.adams@test.aldap", "alice.adams-pass"); err == nil || !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Errorf("bind from locked ip: %v", err)
	}
	if !strings.Contains(r.logs.String(), "ip_locked") {
		t.Errorf("bind_blocked missing:\n%s", r.logs.String())
	}
	// Paged search over users with memberOf still works on the bound session.
	// The trap hit locked this source for every operation (Stage 6); the
	// rest of the scenario needs the client connection back.
	r.d.state.limiter.Unlock(ratelimit.TargetIP, "127.0.0.1", ratelimit.SourceAPI)
	paged, err := c.SearchWithPaging(ldap.NewSearchRequest(vUsers, ldap.ScopeWholeSubtree, 0, 0, 0, false, "(objectClass=*)", []string{"uid", "memberOf"}, nil), 7)
	if err != nil || len(paged.Entries) != 20 {
		t.Errorf("paged: %v %d", err, len(paged.Entries))
	}
}

func containsFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

// TestDaemon_HoneypotMock drives the honeypot and mock profiles end to end.
func TestDaemon_HoneypotMock(t *testing.T) {
	extra, _, honeyPort, mockPort := stage5Config(t)
	r := startDaemon(t, extra)
	// Mock first: the honeypot lock below applies to every profile of the process.
	m, err := ldap.DialURL(fmt.Sprintf("ldap://127.0.0.1:%d", mockPort))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Bind("mock.one@mock.local", "S3CR3T-mock-one"); err != nil {
		t.Fatalf("mock bind: %v", err)
	}
	res := search(t, m, "ou=mock,dc=aldap", "(objectClass=*)", "sAMAccountName", "memberOf", "member")
	var found bool
	for _, e := range res.Entries {
		if e.DN == "cn=mock.one,ou=users,ou=mock,dc=aldap" && e.GetAttributeValue("memberOf") == "cn=everyone,ou=groups,ou=mock,dc=aldap" {
			found = true
		}
	}
	if !found || len(res.Entries) != 5 {
		t.Errorf("mock tree = %+v", res.Entries)
	}
	if err := m.Bind("mock.one", "wrong"); err == nil || !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Errorf("mock wrong password: %v", err)
	}
	if strings.Contains(r.logs.String(), "S3CR3T-mock-one") {
		t.Error("mock password leaked into logs")
	}
	// Honeypot: the root DSE answers, any bind fails and locks the source, the next bind is blocked.
	h, err := ldap.DialURL(fmt.Sprintf("ldap://127.0.0.1:%d", honeyPort))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if res, err := h.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, 0, 0, 0, false, "(objectClass=*)", []string{"namingContexts"}, nil)); err == nil && len(res.Entries) == 1 && res.Entries[0].GetAttributeValue("namingContexts") != "dc=corp,dc=local" {
		t.Errorf("honeypot root DSE = %+v", res.Entries)
	}
	if err := h.Bind("administrator@corp.local", "Passw0rd"); err == nil || !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Errorf("honeypot bind: %v", err)
	}
	waitFor(t, func() bool { return strings.Contains(r.logs.String(), "honeytoken hit") })
	if err := h.Bind("other@corp.local", "x"); err == nil || !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Errorf("honeypot second bind: %v", err)
	}
	if !strings.Contains(r.logs.String(), "ip_locked") || !strings.Contains(r.logs.String(), `"source":"honeytoken"`) && !strings.Contains(r.logs.String(), "source=honeytoken") {
		t.Errorf("lock not logged:\n%s", r.logs.String())
	}
	if r.dc.Calls().Binds != 0 && r.dc.Calls().Searches > 2 {
		t.Errorf("honeypot reached the upstream: %+v", r.dc.Calls())
	}
}

// TestDaemon_Ldap3 runs testdata/ldap3_test.py (TESTING.md 48): simple
// bind by UPN over ldaps, paged search and memberOf. It uses the local
// python3 with ldap3, else python:3-slim in Docker, else skips.
func TestDaemon_Ldap3(t *testing.T) {
	script, err := filepath.Abs(filepath.Join("..", "..", "testdata", "ldap3_test.py"))
	if err != nil {
		t.Fatal(err)
	}
	extra, vPort, _, _ := stage5Config(t)
	r := startDaemon(t, extra)
	caFile := filepath.Join(r.caDir, "ca.crt")
	args := []string{fmt.Sprintf("ldaps://127.0.0.1:%d", vPort), caFile, "alice.adams@test.aldap", "alice.adams-pass", vUsers, vGroup, "5", "aldap.test"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var cmd *exec.Cmd
	switch {
	case pythonHasLdap3():
		cmd = exec.CommandContext(ctx, "python3", append([]string{script}, args...)...)
	case dockerAvailable():
		// The container shares the host network to reach the loopback listener.
		dir := t.TempDir()
		for _, f := range []string{script, caFile} {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, filepath.Base(f)), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		args[1] = "/t/ca.crt"
		cmd = exec.CommandContext(ctx, "docker", append([]string{"run", "--rm", "--network", "host", "-v", dir + ":/t:ro", "python:3-slim",
			"sh", "-c", "pip install -q ldap3 >/dev/null 2>&1 && python /t/ldap3_test.py \"$@\"", "sh"}, args...)...)
	default:
		t.Skip("neither python3 with ldap3 nor Docker is available")
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	var out struct {
		OK             bool     `json:"ok"`
		Error          string   `json:"error"`
		Entries        int      `json:"entries"`
		Pages          int      `json:"pages"`
		MemberOf       []string `json:"member_of"`
		NamingContexts []string `json:"naming_contexts"`
		Controls       []string `json:"supported_controls"`
	}
	line := strings.TrimSpace(stdout.String())
	if i := strings.LastIndexByte(line, '\n'); i >= 0 {
		line = line[i+1:]
	}
	if err := json.Unmarshal([]byte(line), &out); err != nil {
		t.Fatalf("ldap3 output: %v\nstdout: %s\nstderr: %s\nrun: %v", err, stdout.String(), stderr.String(), runErr)
	}
	if runErr != nil || !out.OK || out.Entries != 20 || out.Pages < 4 || !containsFold(out.MemberOf, vGroup) || !containsFold(out.NamingContexts, "ou=v,dc=aldap") || !containsFold(out.Controls, "1.2.840.113556.1.4.319") {
		t.Errorf("ldap3: %v %+v\nstderr: %s", runErr, out, stderr.String())
	}
}

func pythonHasLdap3() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "python3", "-c", "import ldap3").Run() == nil
}

func dockerAvailable() bool {
	if os.Getenv("ALDAP_TEST_NO_DOCKER") != "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "docker", "info").Run() == nil
}

// TestRunCheck_AsClient exercises `aldap check --as-client` over the
// testdir upstream, a mock file and a honeypot profile.
func TestRunCheck_AsClient(t *testing.T) {
	dc := testdir.StartFixture(t)
	mockFile := filepath.Join(t.TempDir(), "m.csv")
	if err := os.WriteFile(mockFile, []byte("cn,sAMAccountName,mail\nMock One,mock.one,m1@mock.local\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	appPort, mockPort, honeyPort := freePort(t), freePort(t), freePort(t)
	cfg := writeTemp(t, fmt.Sprintf(`
[upstream.ad]
servers = [%q]
bind_dn = "CN=svc-aldap,CN=Users,DC=test,DC=aldap"
bind_password_env = "ALDAP_TEST_PW"
base_dn = "DC=test,DC=aldap"
[profile.app]
listen = ["127.0.0.1:%d"]
upstream = "ad"
virtual_base = "ou=app,dc=aldap"
bases = ["OU=Office,DC=test,DC=aldap", "OU=Branch,DC=test,DC=aldap"]
rdn_attr = "sAMAccountName"
honeytokens = ["h.petrenko@test.aldap"]
[profile.app.client_bind]
dn = "cn=app,dc=aldap"
password_env = "ALDAP_TEST_PW"
[profile.app.attrs]
allow = ["sAMAccountName", "mail"]
[profile.app.attrs.map]
uid = "sAMAccountName"
[profile.app.attrs.computed]
tag = "{{ .department }}"
[profile.app.groups.all]
[profile.mock]
listen = ["127.0.0.1:%d"]
mode = "mock"
virtual_base = "ou=mock,dc=aldap"
bases = ["ou=people,dc=mock"]
[profile.mock.mock]
file = %q
[profile.mock.attrs]
allow = ["cn", "mail"]
[profile.honey]
listen = ["127.0.0.1:%d"]
mode = "honeypot"
virtual_base = "ou=honey,dc=aldap"
honeytokens = ["x@y"]
`, dc.URL(), appPort, mockPort, mockFile, honeyPort))
	t.Setenv("ALDAP_TEST_PW", "svc-aldap-pass")
	t.Setenv("ALDAP_CONFIG", "")
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := run(append([]string{"check", "--config", cfg}, args...), &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	// Text output with the pipeline diagnostics.
	code, out, errOut := run("--as-client", "--profile", "app", "--filter", "(&(uid=alice*)(tag=IT)(telephoneNumber=1))", "--attrs", "uid,tag,memberOf")
	if code != 0 || strings.Contains(out, "dn: ") || !strings.Contains(out, "# denied_terms: [telephoneNumber]") || !strings.Contains(out, "OK:") {
		t.Errorf("denied term: %d\n%s%s", code, out, errOut)
	}
	code, out, _ = run("--as-client", "--profile", "app", "--filter", "(&(uid=alice*)(tag=IT))", "--attrs", "uid,tag,memberOf", "--scope", "sub", "--size", "3")
	if code != 0 || !strings.Contains(out, "dn: cn=alice.adams,ou=users,ou=app,dc=aldap") || !strings.Contains(out, "memberOf: cn=all,ou=groups,ou=app,dc=aldap") ||
		!strings.Contains(out, "# post_filter: (tag=IT)") || !strings.Contains(out, "# upstream_filter: (&(sAMAccountName=alice*)") {
		t.Errorf("as-client text: %d\n%s", code, out)
	}
	// JSON output, default base and filter, size limit exceeded is still a success.
	code, out, _ = run("--as-client", "--profile", "app", "--json", "--size", "2")
	var res checkResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if code != 0 || res.ClientTest == nil || res.ClientTest.ResultCode != 4 || len(res.ClientTest.Entries) != 2 || res.ClientTest.Base != "ou=users,ou=app,dc=aldap" || res.ClientTest.UpstreamQueries != 2 {
		t.Errorf("as-client json: %d %+v", code, res.ClientTest)
	}
	// Honeytoken target is reported.
	code, out, _ = run("--as-client", "--profile", "app", "--filter", "(uid=h.petrenko)")
	if code != 0 || !strings.Contains(out, "# honeytoken: h.petrenko@test.aldap") {
		t.Errorf("honeytoken: %d\n%s", code, out)
	}
	// Mock and honeypot profiles need no upstream.
	code, out, errOut = run("--as-client", "--profile", "mock", "--base", "ou=users,ou=mock,dc=aldap")
	if code != 0 || !strings.Contains(out, "dn: cn=Mock One,ou=users,ou=mock,dc=aldap") || !strings.Contains(out, "mail: m1@mock.local") {
		t.Errorf("mock: %d\n%s%s", code, out, errOut)
	}
	code, out, _ = run("--as-client", "--profile", "honey", "--base", "ou=honey,dc=aldap")
	if code != 0 || !strings.Contains(out, "dn: cn=X User,ou=users,ou=honey,dc=aldap") || !strings.Contains(out, "# honeytoken:") {
		t.Errorf("honeypot: %d\n%s", code, out)
	}
	// Failures: unknown profile, base outside the tree, unreachable upstream.
	if code, _, errOut = run("--as-client", "--profile", "nope"); code != 1 || !strings.Contains(errOut+out, "not defined") {
		code, out, errOut = run("--as-client", "--profile", "nope")
		if code != 1 || !strings.Contains(out, "not defined") {
			t.Errorf("unknown profile: %d %s %s", code, out, errOut)
		}
	}
	if code, out, _ = run("--as-client", "--profile", "app", "--base", "dc=other"); code != 1 || !strings.Contains(out, "result code 32") {
		t.Errorf("outside base: %d\n%s", code, out)
	}
	dc.Kill()
	if code, out, _ = run("--as-client", "--profile", "app"); code != 1 || !strings.Contains(out, "ERROR profile.app") {
		t.Errorf("dead upstream: %d\n%s", code, out)
	}
	// Usage errors.
	for _, args := range [][]string{{"--profile", "app"}, {"--as-client"}, {"--as-client", "--profile", "app", "--quick"}, {"--as-client", "--profile", "app", "--scope", "deep"}} {
		if code, _, _ := run(args...); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}
