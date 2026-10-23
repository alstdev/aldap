package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/profile"
	"github.com/alstdev/aldap/internal/secret"
	"github.com/alstdev/aldap/internal/testdir"
)

const (
	tSvcDN    = "CN=svc-aldap,CN=Users,DC=test,DC=aldap"
	tSvcPW    = "svc-aldap-pass"
	tClientDN = "cn=virola,ou=services,dc=aldap"
	tUsersDN  = "ou=users,ou=virola,dc=aldap"
)

var fastArgon = profile.Argon2Params{Time: 1, Memory: 1024, Threads: 1, KeyLen: 16, SaltLen: 8}

// safeBuffer is a goroutine-safe bytes.Buffer for log capture.
type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// freePort reserves a loopback port and releases it for the daemon.
// daemonConfig renders a configuration with an ldaps profile "virola" and
// a ldap+starttls (required) profile "plain" over one plain testdir upstream.
func daemonConfig(t *testing.T, dc *testdir.Server, caDir string, extra string) (path string, ldapsPort, plainPort int) {
	t.Helper()
	return daemonConfigVirola(t, dc, caDir, extra, "")
}

// daemonConfigVirola also inserts virolaExtra into the [profile.virola] table.
func daemonConfigVirola(t *testing.T, dc *testdir.Server, caDir string, extra, virolaExtra string) (path string, ldapsPort, plainPort int) {
	t.Helper()
	ldapsPort, plainPort = freePort(t), freePort(t)
	t.Setenv("ALDAP_TEST_SVC_PW", tSvcPW)
	t.Setenv("ALDAP_TEST_CLIENT_PW", clientPassword)
	body := fmt.Sprintf(`
[server]
log_level = "debug"
log_format = "json"
shutdown_timeout = "2s"

[tls]
ca_dir = %q
auto_init = true
san = ["aldap.test"]

[upstream.ad]
servers = [%q]
bind_dn = %q
bind_password_env = "ALDAP_TEST_SVC_PW"
base_dn = "DC=test,DC=aldap"
audit_service_account = false
[upstream.ad.timeouts]
connect = "2s"
bind = "2s"
search = "5s"

[profile.virola]
listen = ["127.0.0.1:%d"]
transport = "ldaps"
upstream = "ad"
virtual_base = "ou=virola,dc=aldap"
bases = ["OU=Office,DC=test,DC=aldap", "OU=Branch,DC=test,DC=aldap"]
rdn_attr = "sAMAccountName"
%s
[profile.virola.client_bind]
dn = %q
password_env = "ALDAP_TEST_CLIENT_PW"
[profile.virola.user_bind]
default_domain = "test.aldap"
[profile.virola.attrs]
allow = ["userPrincipalName", "sAMAccountName", "displayName", "mail", "objectClass", "objectGUID"]
[profile.virola.attrs.map]
uid = "sAMAccountName"
cn = "displayName"
[profile.virola.limits]
max_conns_per_ip = 16

[profile.plain]
listen = ["127.0.0.1:%d"]
transport = "ldap+starttls"
starttls_required = true
upstream = "ad"
virtual_base = "ou=plain,dc=aldap"
bases = ["OU=Office,DC=test,DC=aldap"]
rdn_attr = "sAMAccountName"
[profile.plain.user_bind]
default_domain = "test.aldap"
[profile.plain.attrs]
allow = ["sAMAccountName", "mail", "objectClass"]
%s
`, caDir, dc.URL(), tSvcDN, ldapsPort, virolaExtra, tClientDN, plainPort, extra)
	path = filepath.Join(t.TempDir(), "aldap.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, ldapsPort, plainPort
}

const clientPassword = "S3CR3T-client-7f3a"

type running struct {
	d         *daemon
	dc        *testdir.Server
	logs      *safeBuffer
	ldapsAddr string
	plainAddr string
	caDir     string
}

func startDaemon(t *testing.T, extra string) *running {
	t.Helper()
	return startDaemonVirola(t, extra, "")
}

// startDaemonVirola starts a daemon with extra keys in [profile.virola].
func startDaemonVirola(t *testing.T, extra, virolaExtra string) *running {
	t.Helper()
	dc := testdir.StartFixture(t)
	caDir := filepath.Join(t.TempDir(), "ca")
	path, lp, pp := daemonConfigVirola(t, dc, caDir, extra, virolaExtra)
	logs := &safeBuffer{}
	d, err := loadDaemon(path, true, daemonOptions{LogOut: logs, EventsOut: logs, Secrets: secret.Default, Argon2: fastArgon, Hostname: "aldap-test"})
	if err != nil {
		t.Fatalf("loadDaemon: %v", err)
	}
	if err := d.start(context.Background()); err != nil {
		t.Fatalf("start: %v\n%s", err, logs.String())
	}
	t.Cleanup(d.stop)
	return &running{d: d, dc: dc, logs: logs, ldapsAddr: fmt.Sprintf("127.0.0.1:%d", lp), plainAddr: fmt.Sprintf("127.0.0.1:%d", pp), caDir: caDir}
}

func (r *running) tlsConfig(t *testing.T) *tls.Config {
	t.Helper()
	pem, err := os.ReadFile(filepath.Join(r.caDir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	return &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}
}

func (r *running) ldaps(t *testing.T) *ldap.Conn {
	t.Helper()
	c, err := ldap.DialURL("ldaps://"+r.ldapsAddr, ldap.DialWithTLSConfig(r.tlsConfig(t)))
	if err != nil {
		t.Fatalf("dial ldaps: %v", err)
	}
	c.SetTimeout(5 * time.Second)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func (r *running) plain(t *testing.T) *ldap.Conn {
	t.Helper()
	c, err := ldap.DialURL("ldap://" + r.plainAddr)
	if err != nil {
		t.Fatalf("dial ldap: %v", err)
	}
	c.SetTimeout(5 * time.Second)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func search(t *testing.T, c *ldap.Conn, base, filter string, attrs ...string) *ldap.SearchResult {
	t.Helper()
	res, err := c.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, filter, attrs, nil))
	if err != nil {
		t.Fatalf("search %s %s: %v", base, filter, err)
	}
	return res
}

// TestDaemon_TLSTermination is the mandatory Stage 4 scenario: ldaps client
// → ALDAP → plain ldap upstream, with the clear-text upstream reported.
func TestDaemon_TLSTermination(t *testing.T) {
	r := startDaemon(t, "")
	c := r.ldaps(t)
	if err := c.Bind(tClientDN, clientPassword); err != nil {
		t.Fatalf("client bind: %v", err)
	}
	res := search(t, c, tUsersDN, "(uid=alice*)", "uid", "mail", "cn")
	if len(res.Entries) != 1 || res.Entries[0].DN != "cn=alice.adams,"+tUsersDN || res.Entries[0].GetAttributeValue("mail") != "alice.adams@test.aldap" ||
		res.Entries[0].GetAttributeValue("cn") != "Alice Adams" {
		t.Errorf("entries = %+v", res.Entries)
	}
	logs := r.logs.String()
	if !strings.Contains(logs, `"event":"insecure_config"`) || !strings.Contains(logs, `"what":"plaintext_upstream"`) ||
		!strings.Contains(logs, "plain ldap:// to upstream without StartTLS") || !strings.Contains(logs, `"level":"WARN"`) {
		t.Errorf("plaintext upstream not reported:\n%s", logs)
	}
	if !strings.Contains(logs, `"event":"startup"`) || !strings.Contains(logs, `"event":"search"`) || !strings.Contains(logs, `"bind_kind":"client"`) {
		t.Errorf("events missing:\n%s", logs)
	}
	// User binds in every form over the terminated TLS.
	for _, name := range []string{"alice.adams@test.aldap", `TEST\alice.adams`, "alice.adams", "cn=alice.adams," + tUsersDN} {
		if err := c.Bind(name, "alice.adams-pass"); err != nil {
			t.Errorf("user bind %q: %v", name, err)
		}
	}
	if err := c.Bind("alice.adams@test.aldap", "wrong"); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Errorf("wrong password: %v", err)
	}
	// KP: attribute outside the allowlist is absent, a filter on it finds nothing without an error.
	res = search(t, c, tUsersDN, "(objectClass=user)", "telephoneNumber", "mail")
	if len(res.Entries) == 0 || res.Entries[0].GetAttributeValue("telephoneNumber") != "" || res.Entries[0].GetAttributeValue("mail") == "" {
		t.Errorf("telephoneNumber leaked or mail missing: %+v", res.Entries)
	}
	if res = search(t, c, tUsersDN, "(telephoneNumber=*)"); len(res.Entries) != 0 {
		t.Errorf("filter on denied attribute returned %d entries", len(res.Entries))
	}
	// Root DSE and paging through the real stack.
	root := search(t, c, "", "(objectClass=*)", "namingContexts", "supportedControl")
	if _, err := c.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, 0, 0, 0, false, "(objectClass=*)", nil, nil)); err != nil {
		t.Fatal(err)
	}
	_ = root
	paged, err := c.SearchWithPaging(ldap.NewSearchRequest(tUsersDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, "(objectClass=user)", []string{"uid"}, nil), 5)
	if err != nil || len(paged.Entries) != 19 {
		t.Errorf("paged: %d entries, %v", len(paged.Entries), err)
	}
	// Writes and compare are refused and reported.
	if ok, err := c.Compare("cn=alice.adams,"+tUsersDN, "mail", "alice.adams@test.aldap"); err != nil || ok {
		t.Errorf("compare = %v %v", ok, err)
	}
	add := ldap.NewAddRequest("cn=x,"+tUsersDN, nil)
	add.Attribute("cn", []string{"x"})
	if err := c.Add(add); !ldap.IsErrorWithCode(err, ldap.LDAPResultUnwillingToPerform) {
		t.Errorf("add: %v", err)
	}
	if !strings.Contains(r.logs.String(), `"op":"compare"`) || !strings.Contains(r.logs.String(), `"op":"add"`) {
		t.Error("op_denied events missing")
	}
	// Second profile: StartTLS required.
	p := r.plain(t)
	if err := p.Bind("alice.adams", "alice.adams-pass"); !ldap.IsErrorWithCode(err, ldap.LDAPResultConfidentialityRequired) {
		t.Errorf("plain bind without StartTLS: %v", err)
	}
	if err := p.StartTLS(r.tlsConfig(t)); err != nil {
		t.Fatalf("StartTLS: %v", err)
	}
	if err := p.Bind("alice.adams", "alice.adams-pass"); err != nil {
		t.Errorf("bind after StartTLS: %v", err)
	}
	if res := search(t, p, "ou=users,ou=plain,dc=aldap", "(sAMAccountName=bob.brown)"); len(res.Entries) != 1 || res.Entries[0].DN != "cn=bob.brown,ou=users,ou=plain,dc=aldap" {
		t.Errorf("plain profile search = %+v", res.Entries)
	}
	if got := r.d.addrs("virola"); len(got) != 1 || got[0] != r.ldapsAddr {
		t.Errorf("addrs = %v", got)
	}
	if r.d.addrs("none") != nil {
		t.Error("unknown profile addrs")
	}
	// Certificate persisted in ca_dir with the expected names.
	if _, err := os.Stat(filepath.Join(r.caDir, "server.key")); err != nil {
		t.Errorf("server.key: %v", err)
	}
	r.d.stop()
	if !strings.Contains(r.logs.String(), `"event":"shutdown"`) {
		t.Error("shutdown event missing")
	}
}

// TestDaemon_Ldapsearch runs the OpenLDAP client (KP of Stage 4). Skipped
// when ldapsearch is not installed; CI installs ldap-utils.
func TestDaemon_Ldapsearch(t *testing.T) {
	bin, err := exec.LookPath("ldapsearch")
	if err != nil {
		t.Skip("ldapsearch not installed")
	}
	r := startDaemon(t, "")
	caFile := filepath.Join(r.caDir, "ca.crt")
	run := func(args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Env = append(os.Environ(), "LDAPTLS_CACERT="+caFile, "LDAPTLS_REQCERT=demand")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	// ldaps:// with the client bind.
	out, err := run("-x", "-H", "ldaps://"+r.ldapsAddr, "-D", tClientDN, "-w", clientPassword, "-b", tUsersDN, "(uid=alice*)", "uid", "mail")
	if err != nil || !strings.Contains(out, "dn: cn=alice.adams,"+tUsersDN) || !strings.Contains(out, "mail: alice.adams@test.aldap") || !strings.Contains(out, "numEntries: 1") {
		t.Errorf("ldaps search: %v\n%s", err, out)
	}
	// -ZZ StartTLS on the plain profile with a user bind.
	out, err = run("-x", "-ZZ", "-H", "ldap://"+r.plainAddr, "-D", "alice.adams@test.aldap", "-w", "alice.adams-pass", "-b", "ou=users,ou=plain,dc=aldap", "(sAMAccountName=bob.brown)")
	if err != nil || !strings.Contains(out, "dn: cn=bob.brown,ou=users,ou=plain,dc=aldap") {
		t.Errorf("-ZZ search: %v\n%s", err, out)
	}
	// Paged results.
	out, err = run("-x", "-H", "ldaps://"+r.ldapsAddr, "-D", tClientDN, "-w", clientPassword, "-E", "pr=5/noprompt", "-b", tUsersDN, "(objectClass=user)", "uid")
	if err != nil || strings.Count(out, "\ndn: ") != 19 || !strings.Contains(out, "numEntries: 19") {
		t.Errorf("paged search: %v (dn count %d)\n%s", err, strings.Count(out, "\ndn: "), out)
	}
	// Denied attribute: present in the request, absent in the answer, no error.
	out, err = run("-x", "-H", "ldaps://"+r.ldapsAddr, "-D", tClientDN, "-w", clientPassword, "-b", tUsersDN, "(uid=bob.brown)", "telephoneNumber", "uid")
	if err != nil || strings.Contains(out, "telephoneNumber:") || !strings.Contains(out, "uid: bob.brown") {
		t.Errorf("denied attribute: %v\n%s", err, out)
	}
	out, err = run("-x", "-H", "ldaps://"+r.ldapsAddr, "-D", tClientDN, "-w", clientPassword, "-b", tUsersDN, "(telephoneNumber=*)")
	if err != nil || !strings.Contains(out, "numEntries") && !strings.Contains(out, "result: 0 Success") || strings.Contains(out, "\ndn: ") {
		t.Errorf("denied term: %v\n%s", err, out)
	}
	// Root DSE with the client bind; the anonymous bind ldapsearch performs
	// without -D is refused (anonymous_bind = false).
	out, err = run("-x", "-H", "ldaps://"+r.ldapsAddr, "-D", tClientDN, "-w", clientPassword, "-b", "", "-s", "base", "(objectClass=*)", "namingContexts", "supportedControl")
	if err != nil || !strings.Contains(out, "namingContexts: ou=virola,dc=aldap") || !strings.Contains(out, "supportedControl: 1.2.840.113556.1.4.319") {
		t.Errorf("root DSE: %v\n%s", err, out)
	}
	if out, err = run("-x", "-H", "ldaps://"+r.ldapsAddr, "-b", "", "-s", "base", "(objectClass=*)"); err == nil || !strings.Contains(out, "Invalid credentials") {
		t.Errorf("anonymous bind accepted: %v\n%s", err, out)
	}
	// Wrong password.
	if out, err = run("-x", "-H", "ldaps://"+r.ldapsAddr, "-D", "alice.adams@test.aldap", "-w", "nope", "-b", tUsersDN, "(uid=*)"); err == nil || !strings.Contains(out, "Invalid credentials") {
		t.Errorf("wrong password: %v\n%s", err, out)
	}
}

func TestDaemon_BuildErrors(t *testing.T) {
	dc := testdir.StartFixture(t)
	caDir := filepath.Join(t.TempDir(), "ca")
	opts := daemonOptions{LogOut: &safeBuffer{}, EventsOut: io.Discard, Secrets: secret.Default, Argon2: fastArgon}
	// Invalid configuration.
	path, _, _ := daemonConfig(t, dc, caDir, fmt.Sprintf("[profile.bad]\nlisten = [\"127.0.0.1:%d\"]\nupstream = \"ad\"\nvirtual_base = \"dc=bad\"\nbases = [\"DC=test,DC=aldap\"]\n[profile.bad.attrs]\nallow = [\"*\"]\n", freePort(t)))
	if _, err := loadDaemon(path, true, opts); err == nil || !strings.Contains(err.Error(), "configuration invalid") {
		t.Errorf("invalid config: %v", err)
	}
	if _, err := loadDaemon(filepath.Join(t.TempDir(), "missing.toml"), true, opts); err == nil {
		t.Error("missing file")
	}
	// Missing secret.
	os.Unsetenv("ALDAP_TEST_CLIENT_PW")
	path, _, _ = daemonConfig(t, dc, caDir, "")
	t.Setenv("ALDAP_TEST_CLIENT_PW", "")
	os.Unsetenv("ALDAP_TEST_CLIENT_PW")
	if _, err := loadDaemon(path, true, opts); err == nil || !strings.Contains(err.Error(), "client_bind.password") {
		t.Errorf("missing client secret: %v", err)
	}
	t.Setenv("ALDAP_TEST_CLIENT_PW", clientPassword)
	// honeypot profile is served (with a warning); a mock profile needs a readable file.
	logs := &safeBuffer{}
	path, _, _ = daemonConfig(t, dc, caDir, fmt.Sprintf("[profile.honey]\nlisten = [\"127.0.0.1:%d\"]\ntransport = \"ldap\"\nupstream = \"ad\"\nmode = \"honeypot\"\nvirtual_base = \"dc=honey\"\n", freePort(t)))
	d, err := loadDaemon(path, true, daemonOptions{LogOut: logs, EventsOut: logs, Secrets: secret.Default, Argon2: fastArgon, NoPersistCerts: true})
	if err != nil {
		t.Fatalf("honeypot config: %v", err)
	}
	if len(d.profiles) != 3 || !strings.Contains(logs.String(), "honeypot profile") {
		t.Errorf("honeypot handling: %d profiles\n%s", len(d.profiles), logs.String())
	}
	d.stop()
	path, _, _ = daemonConfig(t, dc, caDir, fmt.Sprintf("[profile.mock]\nlisten = [\"127.0.0.1:%d\"]\ntransport = \"ldap\"\nmode = \"mock\"\nvirtual_base = \"dc=mock\"\n[profile.mock.mock]\nfile = \"/nonexistent/mock.toml\"\n[profile.mock.attrs]\nallow = [\"cn\"]\n", freePort(t)))
	if _, err := loadDaemon(path, true, daemonOptions{LogOut: logs, EventsOut: logs, Secrets: secret.Default, Argon2: fastArgon, NoPersistCerts: true}); err == nil || !strings.Contains(err.Error(), "mock.file") {
		t.Errorf("mock file missing: %v", err)
	}
	// Port already in use → start fails and cleans up.
	path, lp, _ := daemonConfig(t, dc, caDir, "")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", fmt.Sprintf("127.0.0.1:%d", lp))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	d, err = loadDaemon(path, true, daemonOptions{LogOut: logs, EventsOut: logs, Secrets: secret.Default, Argon2: fastArgon, NoPersistCerts: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.start(context.Background()); err == nil || !strings.Contains(err.Error(), "listen") {
		t.Errorf("start on busy port: %v", err)
	}
	if err := d.start(context.Background()); err == nil {
		t.Error("second start after failure should still fail or be refused")
	}
	d.stop()
	// External TLS without files.
	path, _, _ = daemonConfig(t, dc, caDir, "[profile.virola.tls]\nmode = \"external\"\ncert = \"/nonexistent/a.crt\"\nkey = \"/nonexistent/a.key\"\n")
	if _, err := loadDaemon(path, true, opts); err == nil {
		t.Error("external tls without files")
	}
	// Bad TLS override is caught.
	path, _, _ = daemonConfig(t, dc, caDir, "[profile.virola.tls]\nmin_version = \"1.3\"\nkey_type = \"rsa-2048\"\n")
	d, err = loadDaemon(path, true, daemonOptions{LogOut: logs, EventsOut: logs, Secrets: secret.Default, Argon2: fastArgon, NoPersistCerts: true})
	if err != nil {
		t.Fatalf("tls override: %v", err)
	}
	for _, sp := range d.profiles {
		if sp.name == "virola" && sp.tls.Config().MinVersion != tls.VersionTLS13 {
			t.Error("min_version override ignored")
		}
	}
	d.stop()
}

func TestEffectiveTLS_Overrides(t *testing.T) {
	g := config.Default().TLS
	s := func(v string) *string { return &v }
	b := false
	san := []string{"x"}
	dur := config.Duration(time.Hour)
	o := config.TLSOverride{Mode: s("external"), CADir: s("/c"), AutoInit: &b, Cert: s("c"), Key: s("k"), SAN: &san,
		KeyType: s("rsa-2048"), MinVersion: s("1.3"), ClientAuth: s("require"), ClientCA: s("ca"), AutoRenewBefore: &dur, ExpiryAlertBefore: &dur}
	e := effectiveTLS(g, o)
	if e.Mode != "external" || e.CADir != "/c" || e.AutoInit || e.Cert != "c" || e.Key != "k" || e.SAN[0] != "x" ||
		e.KeyType != "rsa-2048" || e.MinVersion != "1.3" || e.ClientAuth != "require" || e.ClientCA != "ca" || e.AutoRenewBefore != dur || e.ExpiryAlertBefore != dur {
		t.Errorf("effective = %+v", e)
	}
	if e := effectiveTLS(g, config.TLSOverride{}); e.Mode != g.Mode || e.CADir != g.CADir || e.KeyType != g.KeyType {
		t.Error("empty override must keep the global table")
	}
	sans := certSANs([]string{":636", "10.0.0.5:636", "bad", "[::]:389", "ldap.corp:1"}, []string{"extra.corp"}, "host1")
	if strings.Join(sans.DNS, ",") != "host1,localhost,ldap.corp,extra.corp" || len(sans.IPs) != 3 {
		t.Errorf("sans = %+v", sans)
	}
	for lvl, want := range map[string]slog.Level{"debug": slog.LevelDebug, "info": slog.LevelInfo, "warn": slog.LevelWarn, "error": slog.LevelError} {
		var buf bytes.Buffer
		log := newLogger(config.Server{LogLevel: lvl, LogFormat: "json"}, &buf)
		log.Log(context.Background(), want-1, "hidden")
		log.Log(context.Background(), want, "shown")
		if strings.Contains(buf.String(), "hidden") || !strings.Contains(buf.String(), `"msg":"shown"`) {
			t.Errorf("%s: %s", lvl, buf.String())
		}
	}
	var buf bytes.Buffer
	newLogger(config.Server{LogLevel: "info", LogFormat: "text"}, &buf).Info("hello")
	if !strings.Contains(buf.String(), "msg=hello") {
		t.Errorf("text format: %s", buf.String())
	}
}

func TestServe_Signals(t *testing.T) {
	dc := testdir.StartFixture(t)
	caDir := filepath.Join(t.TempDir(), "ca")
	path, _, _ := daemonConfig(t, dc, caDir, "")
	logs := &safeBuffer{}
	stdout := &safeBuffer{}
	sigs := make(chan os.Signal, 1)
	done := make(chan int, 1)
	opts := daemonOptions{LogOut: logs, EventsOut: logs, Secrets: secret.Default, Argon2: fastArgon, NoPersistCerts: true}
	go func() { done <- serve(context.Background(), path, true, opts, sigs, stdout) }()
	waitFor(t, func() bool { return strings.Contains(stdout.String(), "listening") })
	// Reload with the same configuration.
	sigs <- syscall.SIGHUP
	waitFor(t, func() bool { return strings.Contains(logs.String(), "configuration reloaded") })
	if !strings.Contains(logs.String(), `"event":"config_reload"`) || !strings.Contains(logs.String(), `"ok":true`) {
		t.Errorf("config_reload event missing:\n%s", logs.String())
	}
	// Reload with a broken configuration keeps the old one.
	if err := os.WriteFile(path, []byte("[server]\nlog_level = \"loud\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sigs <- syscall.SIGHUP
	waitFor(t, func() bool { return strings.Contains(logs.String(), "reload failed") })
	if !strings.Contains(logs.String(), `"ok":false`) {
		t.Error("config_reload{ok=false} missing")
	}
	sigs <- syscall.SIGTERM
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop")
	}
	// Start failures.
	if code := serve(context.Background(), filepath.Join(t.TempDir(), "none.toml"), true, opts, sigs, stdout); code != 1 {
		t.Errorf("missing config exit %d", code)
	}
	// Context cancellation stops the daemon.
	path2, _, _ := daemonConfig(t, dc, caDir, "")
	ctx, cancel := context.WithCancel(context.Background())
	go func() { done <- serve(ctx, path2, true, opts, make(chan os.Signal), stdout) }()
	waitFor(t, func() bool { return strings.Count(stdout.String(), "listening") >= 2 })
	cancel()
	if code := <-done; code != 0 {
		t.Errorf("exit after cancel %d", code)
	}
}

func TestRunRun_Usage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"run", "--bogus"}, &stdout, &stderr); code != 2 {
		t.Errorf("bad flag exit %d", code)
	}
	if code := run([]string{"run", "extra"}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "unexpected argument") {
		t.Errorf("extra arg exit %d: %s", code, stderr.String())
	}
	if code := run([]string{"run", "--config", filepath.Join(t.TempDir(), "none.toml")}, &stdout, &stderr); code != 1 {
		t.Errorf("missing config exit %d", code)
	}
}

func TestGenCA_GenCert(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"gen-ca", "--dir", dir, "--key-type", "ecdsa-p256"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "CA created") {
		t.Fatalf("gen-ca exit %d: %s %s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"gen-ca", "--dir", dir}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "already exists") {
		t.Errorf("second gen-ca exit %d: %s", code, stderr.String())
	}
	if code := run([]string{"gen-ca", "--dir", dir, "--key-type", "dsa"}, &stdout, &stderr); code != 2 {
		t.Errorf("bad key type exit %d", code)
	}
	if code := run([]string{"gen-ca", "extra"}, &stdout, &stderr); code != 2 {
		t.Errorf("extra arg exit %d", code)
	}
	if code := run([]string{"gen-ca", "--nope"}, &stdout, &stderr); code != 2 {
		t.Errorf("bad flag exit %d", code)
	}
	out := filepath.Join(t.TempDir(), "out")
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"gen-cert", "--dir", dir, "--out", out, "--san", "ldap.test,10.0.0.5"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "server certificate written") {
		t.Fatalf("gen-cert exit %d: %s %s", code, stdout.String(), stderr.String())
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(out, "server.crt"), filepath.Join(out, "server.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	if leaf.DNSNames[0] != "ldap.test" || len(leaf.IPAddresses) != 1 {
		t.Errorf("names = %v %v", leaf.DNSNames, leaf.IPAddresses)
	}
	for _, args := range [][]string{
		{"gen-cert", "--dir", dir},                                      // no names
		{"gen-cert", "--dir", filepath.Join(dir, "none"), "--san", "a"}, // no CA
		{"gen-cert", "--dir", dir, "--san", "a", "--key-type", "dsa"},
		{"gen-cert", "extra"},
		{"gen-cert", "--nope"},
	} {
		if code := run(args, &stdout, &stderr); code == 0 {
			t.Errorf("%v should fail", args)
		}
	}
	// Defaults from a configuration file.
	cfgDir := filepath.Join(t.TempDir(), "ca2")
	cfg := filepath.Join(t.TempDir(), "a.toml")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf("[tls]\nca_dir = %q\nsan = [\"from.config\"]\n", cfgDir)), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"gen-ca", "--config", cfg}, &stdout, &stderr); code != 0 {
		t.Fatalf("gen-ca from config: %s", stderr.String())
	}
	stdout.Reset()
	if code := run([]string{"gen-cert", "--config", cfg}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "from.config") {
		t.Errorf("gen-cert from config exit %d: %s %s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(cfgDir, "server.key")); err != nil {
		t.Errorf("server.key in ca_dir: %v", err)
	}
	// tls defaults when the configuration is unreadable.
	if got := tlsFromConfig(filepath.Join(t.TempDir(), "none.toml")).CADir; got == "" {
		t.Error("default ca_dir")
	}
}

// TestNoSecretsInOutput_Daemon drives the whole stack with marker passwords
// and checks that neither logs, events nor stdout contain them (TESTING.md 41).
func TestNoSecretsInOutput_Daemon(t *testing.T) {
	r := startDaemon(t, "")
	markers := []string{clientPassword, tSvcPW, "S3CR3T-user-11111111", "S3CR3T-user-22222222", "S3CR3T-filter-33333333"}
	c := r.ldaps(t)
	_ = c.Bind(tClientDN, clientPassword)
	_ = c.Bind(tClientDN, markers[2])
	_ = c.Bind("alice.adams@test.aldap", markers[3])
	_ = c.Bind("cn=alice.adams,"+tUsersDN, markers[2])
	_ = c.Bind("nobody", markers[3])
	_, _ = c.Search(ldap.NewSearchRequest(tUsersDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, "(userPassword="+markers[4]+")", nil, nil))
	_, _ = c.Search(ldap.NewSearchRequest(tUsersDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, "(|(uid=a)(unicodePwd="+markers[4]+"*))", nil, nil))
	_, _ = c.Compare("cn=alice.adams,"+tUsersDN, "userPassword", markers[4])
	_ = c.Close()
	r.d.stop()
	out := r.logs.String()
	for _, m := range markers {
		if strings.Contains(out, m) {
			t.Errorf("marker %q found in output:\n%s", m, out)
		}
	}
	if !strings.Contains(out, `userpassword=***`) {
		t.Errorf("redacted filter missing:\n%s", out)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timeout")
}
