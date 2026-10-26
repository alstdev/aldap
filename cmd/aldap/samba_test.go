//go:build integration_samba

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/events/schematest"
	"github.com/alstdev/aldap/internal/listener"
	"github.com/alstdev/aldap/internal/secret"
)

// The Samba AD test bench (deploy/samba-dc, docs/samba.md). `make
// integration-samba` starts it and sets these variables; without
// ALDAP_TEST_SAMBA_URL every test is skipped.
const (
	sbVBase    = "ou=virola,dc=aldap"
	sbUsers    = "ou=users," + sbVBase
	sbGroups   = "ou=groups," + sbVBase
	sbClientDN = "cn=virola,ou=services,dc=aldap"
	sbAdminTok = "S3CR3T-samba-admin-0123456789abcdef0123"
	sbHMAC     = "S3CR3T-samba-hmac-5d1e"
	sbHoney    = "h.petrenko@test.aldap"
	sbStaffDN  = "CN=Staff,CN=Users,DC=test,DC=aldap"
)

type sambaBench struct {
	servers []string // ldaps URLs, dc1 first
	bindDN  string
	svcPW   string
	userPW  string
	adminPW string
	caFile  string
	compose string // compose file for the failover test
}

func readSecretFile(t *testing.T, env string) string {
	t.Helper()
	path := os.Getenv(env)
	if path == "" {
		t.Fatalf("%s is not set", env)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v", env, err)
	}
	return strings.TrimSpace(string(b))
}

func sambaFromEnv(t *testing.T) *sambaBench {
	t.Helper()
	urls := os.Getenv("ALDAP_TEST_SAMBA_URL")
	if urls == "" {
		t.Skip("ALDAP_TEST_SAMBA_URL not set (make integration-samba)")
	}
	return &sambaBench{
		servers: strings.Split(urls, ","),
		bindDN:  os.Getenv("ALDAP_TEST_SAMBA_BIND_DN"),
		svcPW:   readSecretFile(t, "ALDAP_TEST_SAMBA_BIND_PASSWORD_FILE"),
		userPW:  readSecretFile(t, "ALDAP_TEST_SAMBA_USER_PASSWORD_FILE"),
		adminPW: readSecretFile(t, "ALDAP_TEST_SAMBA_ADMIN_PASSWORD_FILE"),
		caFile:  os.Getenv("ALDAP_TEST_SAMBA_CA"),
		compose: os.Getenv("ALDAP_TEST_SAMBA_COMPOSE"),
	}
}

// sambaRun is `aldap run` (serve) against the bench with the API enabled.
type sambaRun struct {
	sb      *sambaBench
	path    string
	ldaps   string // profile virola
	proxied string // profile proxied (PROXY protocol from 127.0.0.2)
	api     string
	caDir   string
	logs    *safeBuffer
	stdout  *safeBuffer
	hooks   *sambaHooks
}

// sambaHooks collects the webhook deliveries.
type sambaHooks struct {
	mu     sync.Mutex
	bodies [][]byte
	sigs   []string
}

func (h *sambaHooks) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	h.bodies = append(h.bodies, b)
	h.sigs = append(h.sigs, r.Header.Get(events.SignatureHeader))
	h.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

const sambaConfig = `
[server]
log_level = "debug"
log_format = "json"
shutdown_timeout = "2s"
ipc_socket = %[1]q

[tls]
ca_dir = %[2]q
auto_init = true
san = ["aldap.test"]

[api]
enabled = true
listen = "127.0.0.1:%[3]d"
rate_limit_rps = 0
[[api.token]]
name = "ops"
token_env = "ALDAP_TEST_SAMBA_API"
scopes = ["admin"]

[upstream.ad]
servers = [%[4]s]
tls_ca_file = %[5]q
bind_dn = %[6]q
bind_password_env = "ALDAP_TEST_SAMBA_SVC_PW"
base_dn = "DC=test,DC=aldap"
health_interval = "500ms"
[upstream.ad.failover]
fail_threshold = 2
recover_threshold = 1
prefer_primary = true
[upstream.ad.timeouts]
connect = "2s"
bind = "5s"
search = "10s"

[ratelimit]
constant_time_bind_fail = false
negative_cache_ttl = "1m"
[ratelimit.ip]
max_failures = 1000
bind_rps = 1000
bind_burst = 1000
search_rps = 1000
search_burst = 1000
[ratelimit.account]
max_failures = 3
lock_duration = "4s"
[ratelimit.delay]
base = "1ms"
max = "2ms"

[[events.webhook]]
name = "siem"
url = %[7]q
batch_interval = "200ms"
hmac_secret_env = "ALDAP_TEST_SAMBA_HMAC"
[events.webhook.retry]
backoff = "100ms"

[profile.virola]
listen = ["127.0.0.1:%[8]d"]
transport = "ldaps"
upstream = "ad"
virtual_base = "ou=virola,dc=aldap"
bases = ["OU=Office,DC=test,DC=aldap", "OU=Branch,DC=test,DC=aldap"]
filter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
rdn_attr = "sAMAccountName"
nested_groups = true
honeytokens = [%[10]q]
[profile.virola.client_bind]
dn = %[11]q
password_env = "ALDAP_TEST_CLIENT_PW"
[profile.virola.user_bind]
default_domain = "test.aldap"
require_membership = true
[profile.virola.attrs]
allow = ["userPrincipalName", "sAMAccountName", "displayName", "mail", "department", "memberOf", "objectClass", "objectGUID"]
[profile.virola.attrs.map]
uid = "sAMAccountName"
cn = "displayName"
[profile.virola.attrs.computed]
mail = "{{ or .mail (printf \"%%s@test.aldap\" .sAMAccountName) }}"
[profile.virola.groups.virola-users]
description = "All Virola users"
objectclass = "groupOfNames"
[profile.virola.groups.virola-users.members]
ad_groups = [%[12]q]
[profile.virola.cache]
mode = "none"
[profile.virola.limits]
max_conns_per_ip = 64

[profile.proxied]
listen = ["127.0.0.1:%[9]d"]
transport = "ldaps"
upstream = "ad"
virtual_base = "ou=proxied,dc=aldap"
bases = ["OU=Office,DC=test,DC=aldap"]
rdn_attr = "sAMAccountName"
proxy_protocol = { enabled = true, trusted_cidrs = ["127.0.0.2/32"] }
[profile.proxied.user_bind]
default_domain = "test.aldap"
[profile.proxied.attrs]
allow = ["sAMAccountName", "mail", "objectClass"]
`

func startSamba(t *testing.T, sb *sambaBench) *sambaRun {
	t.Helper()
	t.Setenv("ALDAP_TEST_SAMBA_SVC_PW", sb.svcPW)
	t.Setenv("ALDAP_TEST_CLIENT_PW", clientPassword)
	t.Setenv("ALDAP_TEST_SAMBA_API", sbAdminTok)
	t.Setenv("ALDAP_TEST_SAMBA_HMAC", sbHMAC)
	hooks := &sambaHooks{}
	hs := httptest.NewServer(hooks)
	t.Cleanup(hs.Close)
	apiPort, lp, pp := freePort(t), freePort(t), freePort(t)
	servers := make([]string, len(sb.servers))
	for i, s := range sb.servers {
		servers[i] = strconv.Quote(s)
	}
	caDir := filepath.Join(t.TempDir(), "ca")
	body := fmt.Sprintf(sambaConfig, ipcPath(t), caDir, apiPort, strings.Join(servers, ", "), sb.caFile, sb.bindDN,
		hs.URL, lp, pp, sbHoney, sbClientDN, sbStaffDN)
	path := filepath.Join(t.TempDir(), "aldap.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &sambaRun{sb: sb, path: path, ldaps: fmt.Sprintf("127.0.0.1:%d", lp), proxied: fmt.Sprintf("127.0.0.1:%d", pp),
		api: fmt.Sprintf("http://127.0.0.1:%d", apiPort), caDir: caDir, logs: &safeBuffer{}, stdout: &safeBuffer{}, hooks: hooks}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	opts := daemonOptions{LogOut: r.logs, EventsOut: r.logs, Secrets: secret.Default, Argon2: fastArgon, NoPersistCerts: true, Hostname: "aldap-samba"}
	go func() { done <- serve(ctx, path, true, opts, make(chan os.Signal), r.stdout) }()
	waitFor(t, func() bool { return strings.Contains(r.stdout.String(), "listening") || len(done) > 0 })
	if len(done) > 0 {
		t.Fatalf("serve exited early:\n%s", r.logs.String())
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("serve did not stop")
		}
		// TESTING.md 41 against the bench: no password reaches the output.
		out := r.logs.String() + r.stdout.String()
		for _, pw := range []string{sb.svcPW, sb.userPW, sb.adminPW, clientPassword, sbHMAC, sbAdminTok} {
			if strings.Contains(out, pw) {
				t.Errorf("a secret (%d bytes) appears in the daemon output", len(pw))
			}
		}
		if t.Failed() {
			t.Logf("daemon output:\n%s", out)
		}
	})
	return r
}

func (r *sambaRun) tlsConfig(t *testing.T) *tls.Config {
	t.Helper()
	pem, err := os.ReadFile(filepath.Join(r.caDir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	return &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}
}

// dial opens an ldaps connection to addr from the local address (empty =
// default) without binding.
func (r *sambaRun) dial(t *testing.T, addr, local string) *ldap.Conn {
	t.Helper()
	d := &net.Dialer{Timeout: 5 * time.Second}
	if local != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(local)}
	}
	c, err := ldap.DialURL("ldaps://"+addr, ldap.DialWithDialer(d), ldap.DialWithTLSConfig(r.tlsConfig(t)))
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	c.SetTimeout(15 * time.Second)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// client is a connection to profile virola bound as Virola's service account.
func (r *sambaRun) client(t *testing.T) *ldap.Conn {
	t.Helper()
	c := r.dial(t, r.ldaps, "")
	if err := c.Bind(sbClientDN, clientPassword); err != nil {
		t.Fatalf("client bind: %v", err)
	}
	return c
}

func (r *sambaRun) events() []events.Record {
	var out []events.Record
	for _, line := range strings.Split(r.logs.String(), "\n") {
		if !strings.HasPrefix(line, `{"schema":"aldap.event.v1"`) {
			continue
		}
		var rec events.Record
		if err := json.Unmarshal([]byte(line), &rec); err == nil {
			out = append(out, rec)
		}
	}
	return out
}

func (r *sambaRun) find(kind string, match func(events.Record) bool) []events.Record {
	var out []events.Record
	for _, e := range r.events() {
		if e.Event == kind && (match == nil || match(e)) {
			out = append(out, e)
		}
	}
	return out
}

func (r *sambaRun) wait(t *testing.T, what, kind string, match func(events.Record) bool) events.Record {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if got := r.find(kind, match); len(got) > 0 {
			return got[0]
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no %s event (%s)", kind, what)
	return events.Record{}
}

// dc connects to one bench DC directly, bound as Administrator.
func (sb *sambaBench) dc(t *testing.T, url string) *ldap.Conn {
	t.Helper()
	pem, err := os.ReadFile(sb.caFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	c, err := ldap.DialURL(url, ldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatalf("dial %s: %v", url, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := c.Bind("Administrator@test.aldap", sb.adminPW); err != nil {
		t.Fatalf("admin bind %s: %v", url, err)
	}
	return c
}

// badPwd returns badPwdCount and lockoutTime of an account on the primary DC.
func (sb *sambaBench) badPwd(t *testing.T, sam string) (count, lockout string) {
	t.Helper()
	c := sb.dc(t, sb.servers[0])
	res, err := c.Search(ldap.NewSearchRequest("DC=test,DC=aldap", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(sAMAccountName="+ldap.EscapeFilter(sam)+")", []string{"badPwdCount", "lockoutTime"}, nil))
	if err != nil || len(res.Entries) != 1 {
		t.Fatalf("read %s on the DC: %v", sam, err)
	}
	return res.Entries[0].GetAttributeValue("badPwdCount"), res.Entries[0].GetAttributeValue("lockoutTime")
}

func atoiOr0(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func uids(res *ldap.SearchResult) []string {
	var out []string
	for _, e := range res.Entries {
		if v := e.GetAttributeValue("uid"); v != "" {
			out = append(out, v)
		}
	}
	slices.Sort(out)
	return out
}

func sambaSearch(t *testing.T, c *ldap.Conn, base, filter string, attrs ...string) *ldap.SearchResult {
	t.Helper()
	res, err := c.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, filter, attrs, nil))
	if err != nil {
		t.Fatalf("search %s %s: %v", base, filter, err)
	}
	return res
}

// The enabled users of OU=Office and OU=Branch (deploy/samba-dc/provision.ldif):
// computers, the disabled heidi.hill/olga.orlova and CN=Users are not exported.
var sbExported = []string{
	"alice.adams", "bob.brown", "carol.clark", "dave.davis", "eve.evans", "frank.fox", "grace.green", "ivan.ivanov", "judy.jones",
	"kim.king", "leo.lee", "mia.moore", "ned.nash", "pete.price", "quinn.quill", "rosa.reed",
}

// TestSamba_VirolaDirectory is the docs/virola.md scenario against Samba AD
// (SPEC §13.2): two bases merged, computers and disabled accounts excluded,
// the virtual group from nested AD groups with member/memberOf, paging.
func TestSamba_VirolaDirectory(t *testing.T) {
	sb := sambaFromEnv(t)
	r := startSamba(t, sb)
	c := r.client(t)

	all := sambaSearch(t, c, sbVBase, "(objectClass=*)", "uid", "objectClass", "member")
	dns := map[string]bool{}
	for _, e := range all.Entries {
		dns[strings.ToLower(e.DN)] = true
	}
	for _, dn := range []string{sbVBase, sbUsers, sbGroups, "cn=virola-users," + sbGroups} {
		if !dns[dn] {
			t.Errorf("%s missing from the virtual base", dn)
		}
	}
	want := append(slices.Clone(sbExported), "h.petrenko")
	slices.Sort(want)
	if got := uids(all); !slices.Equal(got, want) {
		t.Errorf("users = %v\nwant %v", got, want)
	}
	for _, f := range []string{"(sAMAccountName=PC-OFFICE-01$)", "(objectClass=computer)", "(uid=heidi.hill)", "(uid=outside.user)",
		"(userAccountControl:1.2.840.113556.1.4.803:=2)"} {
		if n := len(sambaSearch(t, c, sbVBase, f).Entries); n != 0 {
			t.Errorf("%s: %d entries", f, n)
		}
	}

	one := sambaSearch(t, c, sbUsers, "(uid=alice.adams)")
	if len(one.Entries) != 1 || one.Entries[0].DN != "cn=alice.adams,"+sbUsers {
		t.Fatalf("alice: %+v", one.Entries)
	}
	a := one.Entries[0]
	if a.GetAttributeValue("userPrincipalName") != "alice.adams@test.aldap" || a.GetAttributeValue("cn") != "Alice Adams" ||
		a.GetAttributeValue("department") != "Sales" || len(a.GetRawAttributeValue("objectGUID")) != 16 {
		t.Errorf("alice attributes: %v", a.Attributes)
	}
	for _, at := range a.Attributes {
		if slices.Contains([]string{"telephoneNumber", "description", "userAccountControl", "distinguishedName", "badPwdCount"}, at.Name) {
			t.Errorf("attribute %s outside the allowlist returned", at.Name)
		}
	}
	// frank.fox has no mail in AD: computed.
	if m := sambaSearch(t, c, sbUsers, "(uid=frank.fox)", "mail").Entries; len(m) != 1 || m[0].GetAttributeValue("mail") != "frank.fox@test.aldap" {
		t.Errorf("computed mail: %+v", m)
	}

	// virola-users = members of Staff, nested Managers and Directors, within
	// the profile (not heidi.hill, not outside.user), plus the honeytoken
	// (honeytoken_in_groups defaults to true).
	wantMembers := []string{"alice.adams", "bob.brown", "carol.clark", "dave.davis", "eve.evans", "h.petrenko", "kim.king", "leo.lee", "mia.moore"}
	g := sambaSearch(t, c, "cn=virola-users,"+sbGroups, "(objectClass=*)", "member")
	if len(g.Entries) != 1 {
		t.Fatalf("group: %d entries", len(g.Entries))
	}
	members := make([]string, 0, len(wantMembers))
	for _, m := range g.Entries[0].GetAttributeValues("member") {
		members = append(members, strings.TrimPrefix(strings.SplitN(m, ",", 2)[0], "cn="))
	}
	slices.Sort(members)
	if !slices.Equal(members, wantMembers) {
		t.Errorf("member = %v\nwant %v", members, wantMembers)
	}
	if got := uids(sambaSearch(t, c, sbUsers, "(memberOf=cn=virola-users,"+sbGroups+")", "uid")); !slices.Equal(got, wantMembers) {
		t.Errorf("(memberOf=virola-users) = %v", got)
	}
	// eve.evans is in Directors ⊂ Managers ⊂ Staff.
	if e := sambaSearch(t, c, sbUsers, "(uid=eve.evans)", "memberOf").Entries; len(e) != 1 || e[0].GetAttributeValue("memberOf") != "cn=virola-users,"+sbGroups {
		t.Errorf("eve memberOf: %+v", e)
	}

	// Paged results through to the client: 17 users in pages of 5.
	pages := 0
	ctrl := ldap.NewControlPaging(5)
	var paged []string
	for {
		res, err := c.Search(ldap.NewSearchRequest(sbUsers, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(uid=*)", []string{"uid"}, []ldap.Control{ctrl}))
		if err != nil {
			t.Fatalf("page %d: %v", pages, err)
		}
		pages++
		paged = append(paged, uids(res)...)
		pc, _ := ldap.FindControl(res.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
		if pc == nil || len(pc.Cookie) == 0 {
			break
		}
		ctrl.SetCookie(pc.Cookie)
	}
	slices.Sort(paged)
	if pages != 4 || !slices.Equal(paged, want) {
		t.Errorf("paging: %d pages, %v", pages, paged)
	}
	ev := r.wait(t, "search served by dc1", events.Search, func(e events.Record) bool { return e.UpstreamServer != "" })
	if ev.UpstreamServer != sb.servers[0] {
		t.Errorf("search served by %q, want the primary %q", ev.UpstreamServer, sb.servers[0])
	}
}

// TestSamba_UserBind: every bind form against Samba, the real AD reason in
// the event and invalidCredentials to the client; require_membership.
func TestSamba_UserBind(t *testing.T) {
	sb := sambaFromEnv(t)
	r := startSamba(t, sb)
	for _, name := range []string{"kim.king@test.aldap", "kim.king", `TEST\kim.king`, "cn=kim.king," + sbUsers} {
		c := r.dial(t, r.ldaps, "")
		if err := c.Bind(name, sb.userPW); err != nil {
			t.Errorf("bind %s: %v", name, err)
		}
	}
	ok := r.wait(t, "bind_ok", events.BindOK, nil)
	if ok.Account != "kim.king@test.aldap" || ok.UpstreamServer != sb.servers[0] {
		t.Errorf("bind_ok %+v", ok)
	}
	c := r.dial(t, r.ldaps, "")
	if err := c.Bind("leo.lee@test.aldap", "Aa1-wrong-password"); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	r.wait(t, "invalid password", events.BindFail, func(e events.Record) bool {
		return e.Account == "leo.lee@test.aldap" && e.Reason == "invalid_password"
	})
	// The disabled account with its right password: the client sees only
	// invalidCredentials, the event says why (AD data 533).
	if err := c.Bind("heidi.hill@test.aldap", sb.userPW); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Fatalf("disabled: %v", err)
	}
	// outside.user exists in CN=Users with the same password but is not in a profile base.
	if err := c.Bind("outside.user@test.aldap", sb.userPW); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Fatalf("outside the profile: %v", err)
	}
	if got := r.find(events.BindOK, func(e events.Record) bool {
		return e.Account == "heidi.hill@test.aldap" || e.Account == "outside.user@test.aldap"
	}); len(got) != 0 {
		t.Errorf("bind_ok for an excluded account: %+v", got)
	}
	r.wait(t, "outside.user refused", events.BindFail, func(e events.Record) bool { return e.Account == "outside.user@test.aldap" })
	r.wait(t, "heidi.hill refused", events.BindFail, func(e events.Record) bool {
		return e.Account == "heidi.hill@test.aldap" && e.Reason == "disabled"
	})
}

// TestSamba_AccountLock: ALDAP locks bob.brown after 3 failures, before
// Samba's own lockout (threshold 5) is reached: badPwdCount stays 3, the
// right password is refused without reaching the DC until lock_duration
// ends; a repeated (account, password) pair hits the negative cache.
func TestSamba_AccountLock(t *testing.T) {
	sb := sambaFromEnv(t)
	r := startSamba(t, sb)
	if n, _ := sb.badPwd(t, "bob.brown"); n != "0" && n != "" {
		t.Fatalf("bob.brown starts with badPwdCount %s (bench reused?)", n)
	}
	c := r.dial(t, r.ldaps, "")
	for i := range 3 {
		if err := c.Bind("bob.brown@test.aldap", fmt.Sprintf("Aa1-wrong-%d", i)); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			t.Fatalf("failure %d: %v", i, err)
		}
	}
	r.wait(t, "account lock", events.Lock, func(e events.Record) bool { return e.Data["target"] == "account" && e.Data["key"] == "bob.brown" })
	for i := range 6 {
		pw := fmt.Sprintf("Aa1-more-%d", i)
		if i%2 == 0 {
			pw = sb.userPW
		}
		if err := c.Bind("bob.brown@test.aldap", pw); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			t.Fatalf("locked attempt %d: %v", i, err)
		}
	}
	r.wait(t, "bind_blocked", events.BindBlocked, func(e events.Record) bool { return e.Reason == "account_locked" })
	count, lockout := sb.badPwd(t, "bob.brown")
	if count != "3" || (lockout != "" && lockout != "0") {
		t.Errorf("Samba: badPwdCount=%s lockoutTime=%s, want 3 and no AD lockout", count, lockout)
	}
	// Other accounts keep working.
	if err := r.dial(t, r.ldaps, "").Bind("carol.clark@test.aldap", sb.userPW); err != nil {
		t.Errorf("carol.clark: %v", err)
	}
	// Negative cache: the same wrong pair twice reaches Samba once.
	before, _ := sb.badPwd(t, "grace.green")
	for range 2 {
		if err := c.Bind("grace.green@test.aldap", "Aa1-same-wrong"); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			t.Fatalf("negative cache: %v", err)
		}
	}
	r.wait(t, "negative cache", events.BindBlocked, func(e events.Record) bool { return e.Reason == "negative_cache" })
	if n, _ := sb.badPwd(t, "grace.green"); n != fmt.Sprint(atoiOr0(before)+1) {
		t.Errorf("grace.green badPwdCount %s → %s, want one more", before, n)
	}
	// After lock_duration the right password works; Samba resets the counter.
	r.wait(t, "unlock", events.Unlock, func(e events.Record) bool { return e.Data["key"] == "bob.brown" })
	if err := r.dial(t, r.ldaps, "").Bind("bob.brown@test.aldap", sb.userPW); err != nil {
		t.Fatalf("after the lock: %v", err)
	}
	if n, _ := sb.badPwd(t, "bob.brown"); n != "0" {
		t.Errorf("badPwdCount after success = %s", n)
	}
}

// TestSamba_ReconAndHoneytoken: a security descriptor dump is reported as
// recon; touching the honeytoken locks the source IP.
func TestSamba_ReconAndHoneytoken(t *testing.T) {
	sb := sambaFromEnv(t)
	r := startSamba(t, sb)
	c := r.client(t)
	sambaSearch(t, c, sbVBase, "(objectClass=*)", "nTSecurityDescriptor")
	r.wait(t, "sd_dump", events.Recon, func(e events.Record) bool { return e.Data["signature"] == "sd_dump" })

	h := r.dial(t, r.ldaps, "127.0.0.3")
	if err := h.Bind(sbHoney, "Aa1-anything"); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Fatalf("honeytoken bind: %v", err)
	}
	ht := r.wait(t, "honeytoken bind", events.Honeytoken, func(e events.Record) bool { return e.Data["op"] == "bind" && e.ClientIP == "127.0.0.3" })
	if ht.Level != "high" {
		t.Errorf("honeytoken level %s", ht.Level)
	}
	r.wait(t, "honeytoken lock", events.Lock, func(e events.Record) bool { return e.Data["source"] == "honeytoken" && e.Data["key"] == "127.0.0.3" })
	if err := r.dial(t, r.ldaps, "127.0.0.3").Bind("alice.adams@test.aldap", sb.userPW); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Errorf("locked IP with a right password: %v", err)
	}
	// The honeytoken entry is listed like a user, its search is reported too.
	sambaSearch(t, c, sbUsers, "(mail="+sbHoney+")")
	r.wait(t, "honeytoken search", events.Honeytoken, func(e events.Record) bool { return e.Data["op"] == "search" })
}

func sambaProxyV2(src string, port uint16) []byte {
	h := append([]byte("\r\n\r\n\x00\r\nQUIT\n"), 0x21, 0x11, 0, 12)
	h = append(h, netip.MustParseAddr(src).AsSlice()...)
	h = append(h, 127, 0, 0, 1)
	h = binary.BigEndian.AppendUint16(h, port)
	return binary.BigEndian.AppendUint16(h, 636)
}

// viaProxy sends header from local to the proxied profile, then speaks LDAP over TLS.
func (r *sambaRun) viaProxy(t *testing.T, local string, header []byte) (*ldap.Conn, error) {
	t.Helper()
	d := &net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(local)}}
	raw, err := d.DialContext(context.Background(), "tcp", r.proxied)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Write(header); err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(raw, r.tlsConfig(t))
	hctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	c := ldap.NewConn(tc, true)
	c.Start()
	c.SetTimeout(15 * time.Second)
	t.Cleanup(func() { _ = c.Close() })
	return c, nil
}

// TestSamba_ProxyProtocol: v1 and v2 headers from the trusted proxy carry
// the client address into the events of Samba binds; a header from an
// untrusted address is cut and reported.
func TestSamba_ProxyProtocol(t *testing.T) {
	sb := sambaFromEnv(t)
	r := startSamba(t, sb)
	v1, err := r.viaProxy(t, "127.0.0.2", []byte("PROXY TCP4 198.51.100.7 127.0.0.1 40007 636\r\n"))
	if err != nil {
		t.Fatalf("v1 via the trusted proxy: %v", err)
	}
	if err := v1.Bind("judy.jones@test.aldap", sb.userPW); err != nil {
		t.Fatalf("bind via v1: %v", err)
	}
	ok := r.wait(t, "bind_ok via v1", events.BindOK, func(e events.Record) bool { return e.Profile == "proxied" })
	if ok.ClientIP != "198.51.100.7" || ok.ClientPort != 40007 {
		t.Errorf("v1 bind_ok client %s:%d", ok.ClientIP, ok.ClientPort)
	}
	v2, err := r.viaProxy(t, "127.0.0.2", sambaProxyV2("203.0.113.9", 40009))
	if err != nil {
		t.Fatalf("v2 via the trusted proxy: %v", err)
	}
	if err := v2.Bind("ivan.ivanov@test.aldap", "Aa1-wrong"); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Fatalf("bind via v2: %v", err)
	}
	fail := r.wait(t, "bind_fail via v2", events.BindFail, func(e events.Record) bool { return e.Profile == "proxied" })
	if fail.ClientIP != "203.0.113.9" || fail.ClientPort != 40009 || fail.Reason != "invalid_password" {
		t.Errorf("v2 bind_fail %+v", fail)
	}
	if _, err := r.viaProxy(t, "127.0.0.1", sambaProxyV2("192.0.2.66", 1)); err == nil {
		t.Error("a header from an untrusted address was accepted")
	}
	r.wait(t, "untrusted header", events.InsecureConfig, func(e events.Record) bool { return e.Data["what"] == listener.WhatProxyUntrusted })
}

func (sb *sambaBench) composeCmd(t *testing.T, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", append([]string{"compose", "-f", sb.compose}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker compose %v: %v\n%s", args, err, out)
	}
}

// TestSamba_Failover: dc1 stopped → upstream_down, searches and binds go to
// dc2; dc1 started → upstream_up and back to the primary (prefer_primary).
func TestSamba_Failover(t *testing.T) {
	sb := sambaFromEnv(t)
	if sb.compose == "" || len(sb.servers) < 2 {
		t.Skip("ALDAP_TEST_SAMBA_COMPOSE and two servers are needed")
	}
	r := startSamba(t, sb)
	c := r.client(t)
	served := func() string {
		before := len(r.find(events.Search, nil))
		sambaSearch(t, c, sbUsers, "(uid=alice.adams)")
		var got []events.Record
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if got = r.find(events.Search, nil); len(got) > before {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if len(got) <= before {
			t.Fatal("no search event")
		}
		return got[len(got)-1].UpstreamServer
	}
	if s := served(); s != sb.servers[0] {
		t.Fatalf("before: served by %q", s)
	}
	restarted := false
	t.Cleanup(func() {
		if !restarted {
			sb.composeCmd(t, "start", "dc1")
		}
	})
	sb.composeCmd(t, "stop", "-t", "2", "dc1")
	r.wait(t, "dc1 down", events.UpstreamDown, func(e events.Record) bool { return e.UpstreamServer == sb.servers[0] })
	if s := served(); s != sb.servers[1] {
		t.Errorf("dc1 stopped: served by %q", s)
	}
	if err := r.dial(t, r.ldaps, "").Bind("rosa.reed@test.aldap", sb.userPW); err != nil {
		t.Errorf("user bind via dc2: %v", err)
	}
	sb.composeCmd(t, "start", "dc1")
	restarted = true
	sb.composeCmd(t, "up", "-d", "--wait", "--no-build", "dc1")
	r.wait(t, "dc1 up", events.UpstreamUp, func(e events.Record) bool { return e.UpstreamServer == sb.servers[0] })
	if s := served(); s != sb.servers[0] {
		t.Errorf("dc1 back: served by %q", s)
	}
}

// TestSamba_WebhookAndSSE: the bind events of a Samba-backed profile reach
// the webhook with a valid HMAC and the SSE stream resumes after
// Last-Event-ID; every event matches docs/events.schema.json.
func TestSamba_WebhookAndSSE(t *testing.T) {
	sb := sambaFromEnv(t)
	r := startSamba(t, sb)
	stream := func(last string) (*http.Response, *bufio.Scanner) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, r.api+"/v1/events/stream?types=bind_ok", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+sbAdminTok)
		if last != "" {
			req.Header.Set("Last-Event-ID", last)
		}
		resp, err := (&http.Client{}).Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("stream: %v %v", err, resp)
		}
		return resp, bufio.NewScanner(resp.Body)
	}
	nextID := func(sc *bufio.Scanner) string {
		ch := make(chan string, 1)
		go func() {
			for sc.Scan() {
				if v, ok := strings.CutPrefix(sc.Text(), "id: "); ok {
					ch <- v
					return
				}
			}
			close(ch)
		}()
		select {
		case id := <-ch:
			return id
		case <-time.After(20 * time.Second):
			t.Fatal("SSE stalled")
		}
		return ""
	}
	bind := func(user string) {
		if err := r.dial(t, r.ldaps, "").Bind(user, sb.userPW); err != nil {
			t.Fatalf("bind %s: %v", user, err)
		}
	}
	resp, sc := stream("")
	bind("pete.price@test.aldap")
	first := nextID(sc)
	_ = resp.Body.Close()
	bind("quinn.quill@test.aldap") // while disconnected
	resp, sc = stream(first)
	defer resp.Body.Close()
	second := nextID(sc)
	oks := r.find(events.BindOK, nil)
	if len(oks) != 2 || first != strconv.FormatUint(oks[0].Seq, 10) || second != strconv.FormatUint(oks[1].Seq, 10) {
		t.Fatalf("SSE ids %s, %s; bind_ok %+v", first, second, oks)
	}
	schematest.Check(t, r.events()...)

	// Webhook: both bind_ok events delivered, every batch signed.
	deadline := time.Now().Add(20 * time.Second)
	for {
		r.hooks.mu.Lock()
		joined := bytes.Join(r.hooks.bodies, nil)
		r.hooks.mu.Unlock()
		if bytes.Contains(joined, []byte("quinn.quill@test.aldap")) || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	r.hooks.mu.Lock()
	defer r.hooks.mu.Unlock()
	var accounts []string
	for i, b := range r.hooks.bodies {
		m := hmac.New(sha256.New, []byte(sbHMAC))
		m.Write(b)
		if want := "sha256=" + hex.EncodeToString(m.Sum(nil)); r.hooks.sigs[i] != want {
			t.Errorf("batch %d: signature %q, want %q", i, r.hooks.sigs[i], want)
		}
		var recs []events.Record
		if err := json.Unmarshal(b, &recs); err != nil {
			t.Fatalf("batch %d: %v", i, err)
		}
		schematest.Check(t, recs...)
		for _, e := range recs {
			if e.Event == events.BindOK {
				accounts = append(accounts, e.Account)
			}
		}
	}
	if !slices.Contains(accounts, "pete.price@test.aldap") || !slices.Contains(accounts, "quinn.quill@test.aldap") {
		t.Errorf("webhook bind_ok accounts %v", accounts)
	}
}

// TestSamba_CheckOnline is SPEC §13.3: `aldap check --online` on the bench.
func TestSamba_CheckOnline(t *testing.T) {
	sb := sambaFromEnv(t)
	r := startSamba(t, sb)
	var out, errb bytes.Buffer
	if code := runCheck([]string{"--config", r.path, "--online"}, &out, &errb); code != 0 {
		t.Fatalf("check --online = %d\n%s\n%s", code, out.String(), errb.String())
	}
	for _, s := range sb.servers {
		if !strings.Contains(out.String(), s) {
			t.Errorf("check output does not name %s:\n%s", s, out.String())
		}
	}
}
