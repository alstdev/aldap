package config

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alstdev/aldap/internal/secret"
)

var update = flag.Bool("update", false, "rewrite docs/config.md from the model")

const minimalTOML = `
[upstream.ad-main]
servers = ["ldaps://dc1.example.org:636"]
bind_dn = "CN=svc,DC=example,DC=org"
bind_password_env = "ALDAP_TEST_PW"

[profile.app]
listen = [":636"]
upstream = "ad-main"
virtual_base = "ou=app,dc=aldap"
bases = ["OU=People,DC=example,DC=org"]
[profile.app.attrs]
allow = ["sAMAccountName", "mail"]
`

// loadFS loads cfg from an in-memory file set and environment.
func loadFS(t *testing.T, files map[string]string, env []string, path string) (*Config, error) {
	t.Helper()
	l := Loader{
		ReadFile: func(p string) ([]byte, error) {
			if s, ok := files[p]; ok {
				return []byte(s), nil
			}
			return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
		},
		Glob: func(pattern string) ([]string, error) {
			var out []string
			for p := range files {
				if ok, err := filepath.Match(pattern, p); err == nil && ok {
					out = append(out, p)
				}
			}
			return out, nil
		},
		Environ: func() []string { return env },
	}
	return l.Load(path, path != "")
}

func loadString(t *testing.T, body string, env ...string) (*Config, error) {
	t.Helper()
	return loadFS(t, map[string]string{"/etc/aldap/aldap.toml": body}, env, "/etc/aldap/aldap.toml")
}

func mustLoad(t *testing.T, body string, env ...string) *Config {
	t.Helper()
	cfg, err := loadString(t, body, env...)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return cfg
}

func validate(cfg *Config) *Report {
	return Validator{Secrets: secret.Resolver{LookupEnv: func(string) (string, bool) { return "x", true }}}.Validate(cfg)
}

func hasIssue(list []Issue, path, msg string) bool {
	for _, i := range list {
		if i.Path == path && strings.Contains(i.Msg, msg) {
			return true
		}
	}
	return false
}

func TestLoad_Example(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("../../aldap.toml.example")
	if err != nil {
		t.Fatal(err)
	}
	cfg := mustLoad(t, string(data))
	rep := validate(cfg)
	if !rep.OK() {
		t.Fatalf("example has errors:\n%v", rep)
	}
	u := cfg.Upstreams["ad-main"]
	if u == nil || len(u.Servers) != 2 || u.Kind != "ad" || !u.Failover.PreferPrimary || u.Pool.Size != 4 || u.BindPasswordFile != "/run/secrets/ad_pass" {
		t.Errorf("upstream ad-main decoded wrongly: %+v", u)
	}
	p := cfg.Profiles["virola"]
	if p == nil || p.Mode != "proxy" || p.RDNAttr != "sAMAccountName" || !p.UserBind.RequireMembership || p.Cache.Mode != "ttl" || p.Limits.MaxRequestBytes != 1<<20 {
		t.Errorf("profile virola decoded wrongly: %+v", p)
	}
	if g, ok := p.Groups["virola-users"]; !ok || g.ObjectClass != "groupOfNames" || len(g.Members.ADGroups) != 1 {
		t.Errorf("group virola-users decoded wrongly: %+v", g)
	}
	if hp := cfg.Profiles["honeypot"]; hp == nil || hp.Mode != "honeypot" || hp.Transport != "ldap+starttls" || hp.Filter != DefaultADFilter {
		t.Errorf("profile honeypot decoded wrongly: %+v", hp)
	}
	if len(cfg.Events.Webhooks) != 1 || cfg.Events.Webhooks[0].Retry.MaxBackoff != Duration(60*time.Second) || cfg.Events.Webhooks[0].Headers["X-Source"] != "aldap" {
		t.Errorf("events.webhook decoded wrongly: %+v", cfg.Events.Webhooks)
	}
	if len(cfg.Notify.Channels) != 4 || cfg.Notify.Channels[0].Type != "telegram" || cfg.Notify.Channels[1].RoomID != 42 || cfg.Notify.Channels[2].SMTPPort != 587 {
		t.Errorf("notify.channel decoded wrongly: %+v", cfg.Notify.Channels)
	}
	if !cfg.API.Enabled || len(cfg.API.Tokens) != 2 || !cfg.API.TLS.Builtin {
		t.Errorf("api decoded wrongly: %+v", cfg.API)
	}
	if !hasIssue(rep.Warnings, "notify.channel[3].headers", "") && !hasIssue(rep.Warnings, "upstream.ad-main.bind_password_file", "verified again") {
		t.Errorf("expected file probe warnings, got %v", rep.Warnings)
	}
}

func TestLoad_DefaultsAndTypes(t *testing.T) {
	t.Parallel()
	cfg := mustLoad(t, `
[server]
shutdown_timeout = "45s"
[upstream.u1]
servers = ["ldap://dc.example.org"]
starttls = true
[upstream.u1.failover]
prefer_primary = false
[profile.p1]
listen = [":1636"]
upstream = "u1"
virtual_base = "dc=x"
bases = ["dc=example,dc=org"]
[profile.p1.attrs]
allow = ["cn"]
[profile.p1.limits]
max_request_bytes = "2MiB"
[profile.p1.cache]
sync_jitter = "25%"
[profile.p1.ratelimit.account]
max_failures = 2
[profile.p1.user_bind]
allow = false
[[events.webhook]]
name = "w"
url = "https://siem.example.org/x"
`)
	if cfg.Server.ShutdownTimeout != Duration(45*time.Second) || cfg.Server.MaxConnections != 1024 || cfg.Server.LogLevel != "info" {
		t.Errorf("server defaults: %+v", cfg.Server)
	}
	u := cfg.Upstreams["u1"]
	if u.Failover.PreferPrimary || u.Failover.FailThreshold != 3 || u.PageSize != 500 || !u.AuditServiceAccount || u.Timeouts.Search != Duration(30*time.Second) {
		t.Errorf("upstream defaults: %+v", u)
	}
	p := cfg.Profiles["p1"]
	if p.Transport != "ldaps" || p.Mode != "proxy" || p.RDNAttr != "cn" || p.UserBind.Allow || p.NestedDepth != 10 || p.Filter != DefaultADFilter {
		t.Errorf("profile defaults: %+v", p)
	}
	if p.Limits.MaxRequestBytes != 2<<20 || p.Limits.MaxResultSize != 5000 || p.Cache.SyncJitter != 0.25 {
		t.Errorf("profile typed values: %+v %+v", p.Limits, p.Cache)
	}
	if p.Ratelimit.Account.MaxFailures == nil || *p.Ratelimit.Account.MaxFailures != 2 || p.Ratelimit.Account.Window != nil {
		t.Errorf("ratelimit patch: %+v", p.Ratelimit.Account)
	}
	w := cfg.Events.Webhooks[0]
	if w.BatchSize != 100 || w.Retry.Max != 5 || w.OnOverflow != "drop_oldest" || w.QueueSize != 10000 {
		t.Errorf("webhook defaults: %+v", w)
	}
	if !cfg.Intrusion.Spray.Enabled || cfg.Intrusion.Fingerprint.Enabled || cfg.Ratelimit.Account.MaxFailures != 3 {
		t.Errorf("ids/ratelimit defaults: %+v %+v", cfg.Intrusion, cfg.Ratelimit)
	}
}

func TestLoad_Errors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		body    string
		wantErr error
		wantMsg string
	}{
		{"unknown_top_key", "[server]\nlog_levl = \"info\"\n", ErrUnknownKey, "server.log_levl"},
		{"unknown_upstream_key", "[upstream.u]\nservers = [\"ldaps://a\"]\nkid = \"ad\"\n", ErrUnknownKey, "upstream.u.kid"},
		{"unknown_profile_nested", "[profile.p]\nlisten=[\":1\"]\n[profile.p.attrs]\nallw = [\"cn\"]\n", ErrUnknownKey, "profile.p.attrs.allw"},
		{"bad_duration", "[server]\nshutdown_timeout = \"soon\"\n", nil, "invalid duration"},
		{"bad_size", "[profile.p]\n[profile.p.limits]\nmax_request_bytes = \"big\"\n", nil, "invalid byte size"},
		{"bad_toml", "[server\n", nil, "aldap.toml"},
		{"wrong_type", "[server]\nmax_connections = \"many\"\n", nil, "max_connections"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := loadString(t, tt.body)
			if err == nil {
				t.Fatal("expected error")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("err = %v, want substring %q", err, tt.wantMsg)
			}
		})
	}
}

func TestLoad_Include(t *testing.T) {
	t.Parallel()
	files := map[string]string{
		"/etc/aldap/aldap.toml": `
[server]
include = ["profiles/*.toml", "/etc/aldap/upstreams.toml"]
[profile.main]
listen = [":636"]
upstream = "ad"
virtual_base = "dc=main"
bases = ["dc=example,dc=org"]
[profile.main.attrs]
allow = ["cn"]
`,
		"/etc/aldap/profiles/extra.toml": `
[profile.extra]
listen = [":1636"]
upstream = "ad"
virtual_base = "dc=extra"
bases = ["dc=example,dc=org"]
[profile.extra.attrs]
allow = ["cn"]
`,
		"/etc/aldap/upstreams.toml": `
[upstream.ad]
servers = ["ldaps://dc.example.org"]
`,
	}
	cfg, err := loadFS(t, files, nil, "/etc/aldap/aldap.toml")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Profiles) != 2 || len(cfg.Upstreams) != 1 {
		t.Errorf("profiles=%d upstreams=%d", len(cfg.Profiles), len(cfg.Upstreams))
	}
	if rep := validate(cfg); !rep.OK() {
		t.Errorf("unexpected errors: %v", rep)
	}

	files["/etc/aldap/profiles/dup.toml"] = "[profile.main]\nlisten = [\":2\"]\n"
	_, err = loadFS(t, files, nil, "/etc/aldap/aldap.toml")
	if !errors.Is(err, ErrDuplicateName) || !strings.Contains(err.Error(), "profile.main") {
		t.Errorf("duplicate: err = %v", err)
	}
	delete(files, "/etc/aldap/profiles/dup.toml")

	files["/etc/aldap/profiles/bad.toml"] = "[server]\ninclude = [\"/x/*.toml\"]\n"
	cfg, err = loadFS(t, files, nil, "/etc/aldap/aldap.toml")
	if err != nil || len(cfg.Server.Include) != 1 {
		t.Errorf("nested include must not be followed: err=%v include=%v", err, cfg.Server.Include)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	t.Parallel()
	if _, err := loadFS(t, nil, nil, "/etc/aldap/aldap.toml"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("required missing file: err = %v", err)
	}
	cfg, err := Loader{
		ReadFile: func(string) ([]byte, error) { return nil, fs.ErrNotExist },
		Environ:  func() []string { return nil },
	}.Load(DefaultConfigPath, false)
	if err != nil || cfg == nil {
		t.Errorf("optional missing file: err = %v", err)
	}
}

func TestResolvePath(t *testing.T) {
	t.Parallel()
	env := func(k string) (string, bool) {
		if k == EnvConfigPath {
			return "/env/aldap.toml", true
		}
		return "", false
	}
	if p, req := ResolvePath("/flag.toml", env); p != "/flag.toml" || !req {
		t.Errorf("flag: %s %v", p, req)
	}
	if p, req := ResolvePath("", env); p != "/env/aldap.toml" || !req {
		t.Errorf("env: %s %v", p, req)
	}
	if p, req := ResolvePath("", func(string) (string, bool) { return "", false }); p != DefaultConfigPath || req {
		t.Errorf("default: %s %v", p, req)
	}
}

func TestEnv_MinimalWithoutFile(t *testing.T) {
	t.Parallel()
	env := []string{
		"ALDAP_UPSTREAM_AD_MAIN_SERVERS=ldaps://dc1.example.org:636, ldaps://dc2.example.org:636",
		"ALDAP_UPSTREAM_AD_MAIN_BIND_DN=CN=svc,DC=example,DC=org",
		"ALDAP_UPSTREAM_AD_MAIN_BIND_PASSWORD_FILE=/run/secrets/ad_pass",
		"ALDAP_PROFILE_VIROLA_LISTEN=:636",
		"ALDAP_PROFILE_VIROLA_UPSTREAM=ad-main",
		"ALDAP_PROFILE_VIROLA_VIRTUAL_BASE=ou=virola,dc=aldap",
		"ALDAP_PROFILE_VIROLA_BASES=OU=People,DC=example,DC=org",
		"ALDAP_PROFILE_VIROLA_ATTRS_ALLOW=sAMAccountName,mail",
		"ALDAP_API_ENABLED=true",
		"ALDAP_CONFIG=/ignored",
		"ALDAP_TEST_SAMBA_URL=ignored",
		"OTHER=1",
	}
	cfg, err := loadFS(t, nil, env, "")
	if err != nil {
		t.Fatal(err)
	}
	u := cfg.Upstreams["ad-main"]
	if u == nil || len(u.Servers) != 2 || u.Servers[1] != "ldaps://dc2.example.org:636" || u.BindPasswordFile != "/run/secrets/ad_pass" || u.PageSize != 500 {
		t.Fatalf("upstream from env: %+v", u)
	}
	p := cfg.Profiles["virola"]
	if p == nil || p.Listen[0] != ":636" || p.Upstream != "ad-main" || len(p.Attrs.Allow) != 2 || p.Filter != DefaultADFilter {
		t.Fatalf("profile from env: %+v", p)
	}
	if !cfg.API.Enabled {
		t.Error("api.enabled not set")
	}
	rep := Validator{Secrets: secret.Resolver{Stat: nil}}.Validate(cfg)
	if !rep.OK() {
		t.Errorf("minimal env config must validate: %v", rep)
	}
}

func TestEnv_Overrides(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		env   []string
		check func(*Config) error
		err   error
		msg   string
	}{
		{name: "scalar_types", env: []string{
			"ALDAP_SERVER_LOG_LEVEL=debug", "ALDAP_SERVER_MAX_CONNECTIONS=7", "ALDAP_SERVER_SHUTDOWN_TIMEOUT=1m",
			"ALDAP_RATELIMIT_ENABLED=false", "ALDAP_RATELIMIT_IP_WINDOW=2m", "ALDAP_TLS_SAN=a.example.org,b.example.org",
			"ALDAP_IDS_SPRAY_MIN_ACCOUNTS=9",
		}, check: func(c *Config) error {
			if c.Server.LogLevel != "debug" || c.Server.MaxConnections != 7 || c.Server.ShutdownTimeout != Duration(time.Minute) ||
				c.Ratelimit.Enabled || c.Ratelimit.IP.Window != Duration(2*time.Minute) || len(c.TLS.SAN) != 2 || c.Intrusion.Spray.MinAccounts != 9 {
				return fmt.Errorf("values not applied: %+v", c.Server)
			}
			return nil
		}},
		{name: "existing_table_hyphen", env: []string{"ALDAP_UPSTREAM_AD_MAIN_PAGE_SIZE=50", "ALDAP_UPSTREAM_AD_MAIN_FAILOVER_PREFER_PRIMARY=false"},
			check: func(c *Config) error {
				if len(c.Upstreams) != 1 || c.Upstreams["ad-main"].PageSize != 50 || c.Upstreams["ad-main"].Failover.PreferPrimary {
					return fmt.Errorf("upstream not updated: %+v", c.Upstreams)
				}
				return nil
			}},
		{name: "secret_env_wins_over_file", env: []string{"ALDAP_UPSTREAM_AD_MAIN_BIND_PASSWORD=inline-pw"},
			check: func(c *Config) error {
				u := c.Upstreams["ad-main"]
				if u.BindPassword.Reveal() != "inline-pw" || u.BindPasswordEnv != "" || u.BindPasswordFile != "" {
					return fmt.Errorf("secret siblings not cleared: file=%q env=%q", u.BindPasswordFile, u.BindPasswordEnv)
				}
				return nil
			}},
		{name: "secret_file_form", env: []string{"ALDAP_PROFILE_APP_CLIENT_BIND_PASSWORD_FILE=/run/secrets/x", "ALDAP_PROFILE_APP_CLIENT_BIND_DN=cn=app"},
			check: func(c *Config) error {
				cb := c.Profiles["app"].ClientBind
				if cb.PasswordFile != "/run/secrets/x" || cb.DN != "cn=app" {
					return fmt.Errorf("client_bind: %+v", cb)
				}
				return nil
			}},
		{name: "patch_pointer", env: []string{"ALDAP_PROFILE_APP_RATELIMIT_ACCOUNT_MAX_FAILURES=2"},
			check: func(c *Config) error {
				v := c.Profiles["app"].Ratelimit.Account.MaxFailures
				if v == nil || *v != 2 {
					return fmt.Errorf("patch: %v", v)
				}
				return nil
			}},
		{name: "new_table", env: []string{"ALDAP_PROFILE_NEW_ONE_LISTEN=:1636"},
			check: func(c *Config) error {
				p := c.Profiles["new-one"]
				if p == nil || p.Listen[0] != ":1636" || p.Transport != "ldaps" {
					return fmt.Errorf("new profile: %+v", p)
				}
				return nil
			}},
		{name: "unknown", env: []string{"ALDAP_SERVER_LOG_LEVL=debug"}, err: ErrUnknownKey, msg: "ALDAP_SERVER_LOG_LEVL"},
		{name: "unknown_wild", env: []string{"ALDAP_UPSTREAM_X_NOPE=1"}, err: ErrUnknownKey},
		{name: "unknown_no_name", env: []string{"ALDAP_UPSTREAM_SERVERS=ldaps://a"}, err: ErrUnknownKey},
		{name: "bad_bool", env: []string{"ALDAP_API_ENABLED=maybe"}, msg: "invalid boolean"},
		{name: "bad_int", env: []string{"ALDAP_SERVER_MAX_CONNECTIONS=lots"}, msg: "invalid integer"},
		{name: "bad_duration", env: []string{"ALDAP_SERVER_SHUTDOWN_TIMEOUT=never"}, msg: "invalid duration"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := loadString(t, minimalTOML, tt.env...)
			if tt.err != nil || tt.msg != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if tt.err != nil && !errors.Is(err, tt.err) {
					t.Errorf("err = %v, want %v", err, tt.err)
				}
				if !strings.Contains(err.Error(), tt.msg) {
					t.Errorf("err = %v, want substring %q", err, tt.msg)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := tt.check(cfg); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestEnv_Leaves(t *testing.T) {
	t.Parallel()
	leaves := envLeaves()
	want := map[string]bool{
		"ALDAP_SERVER_LOG_LEVEL":                   true,
		"ALDAP_UPSTREAM_*_BIND_PASSWORD_FILE":      true,
		"ALDAP_UPSTREAM_*_FAILOVER_FAIL_THRESHOLD": true,
		"ALDAP_PROFILE_*_ATTRS_ALLOW":              true,
		"ALDAP_PROFILE_*_TLS_MODE":                 true,
		"ALDAP_API_METRICS_PUBLIC":                 true,
		"ALDAP_EVENTS_STDOUT_ENABLED":              true,
	}
	for _, l := range leaves {
		delete(want, l.env)
		if strings.Contains(l.env, "ATTRS_MAP") || strings.Contains(l.env, "_GROUPS_") || strings.Contains(l.env, "WEBHOOK") || strings.Contains(l.env, "CHANNEL") || strings.Contains(l.env, "TOKEN_") && strings.HasPrefix(l.env, "ALDAP_API_TOKEN") {
			t.Errorf("free-form table leaked into env keys: %s", l.env)
		}
	}
	if len(want) != 0 {
		t.Errorf("missing env keys: %v", want)
	}
}

func TestValidate_Rules(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
		path string
		msg  string
		warn bool
	}{
		{"server_log_level", "[server]\nlog_level = \"loud\"\n", "server.log_level", "not one of", false},
		{"server_timeout", "[server]\nshutdown_timeout = \"0s\"\n", "server.shutdown_timeout", "positive", false},
		{"tls_external_no_cert", "[tls]\nmode = \"external\"\n", "tls.cert", "required", false},
		{"tls_client_ca", "[tls]\nclient_auth = \"require\"\n", "tls.client_ca", "required", false},
		{"upstream_no_servers", "[upstream.u]\nkind = \"ad\"\n", "upstream.u.servers", "at least one", false},
		{"upstream_bad_url", "[upstream.u]\nservers = [\"http://x\"]\n", "upstream.u.servers[0]", "ldap://", false},
		{"upstream_plain_warn", "[upstream.u]\nservers = [\"ldap://x\"]\n", "upstream.u.starttls", "clear text", true},
		{"upstream_starttls_required", "[upstream.u]\nservers = [\"ldap://x\"]\nstarttls_required = true\n", "upstream.u.starttls_required", "starttls = true", false},
		{"upstream_insecure_warn", "[upstream.u]\nservers = [\"ldaps://x\"]\ntls_insecure_skip_verify = true\n", "upstream.u.tls_insecure_skip_verify", "disabled", true},
		{"upstream_pw_without_dn", "[upstream.u]\nservers = [\"ldaps://x\"]\nbind_password_env = \"P\"\n", "upstream.u.bind_dn", "required", false},
		{"upstream_dn_without_pw", "[upstream.u]\nservers = [\"ldaps://x\"]\nbind_dn = \"cn=a\"\n", "upstream.u.bind_password", "required", false},
		{"upstream_two_sources", "[upstream.u]\nservers = [\"ldaps://x\"]\nbind_dn = \"cn=a\"\nbind_password = \"a\"\nbind_password_env = \"P\"\n", "upstream.u.bind_password", "exactly one", false},
		{"upstream_inline_warn", "[upstream.u]\nservers = [\"ldaps://x\"]\nbind_dn = \"cn=a\"\nbind_password = \"a\"\n", "upstream.u.bind_password", "inline", true},
		{"upstream_bad_dn", "[upstream.u]\nservers = [\"ldaps://x\"]\nbase_dn = \"nodn\"\n", "upstream.u.base_dn", "attr=value", false},
		{"upstream_kind", "[upstream.u]\nservers = [\"ldaps://x\"]\nkind = \"ldap\"\n", "upstream.u.kind", "not one of", false},
		{"upstream_name_warn", "[upstream.AD_Main]\nservers = [\"ldaps://x\"]\n", "upstream.AD_Main", "environment", true},
		{"ratelimit_account_warn", "[ratelimit.account]\nmax_failures = 5\n", "ratelimit.account.max_failures", "lockout", true},
		{"ratelimit_lock_response", "[ratelimit]\nlock_response = \"nope\"\n", "ratelimit.lock_response", "not one of", false},
		{"ratelimit_cidr", "[ratelimit]\nallow_cidrs = [\"10.0.0.0/8\", \"bad\"]\n", "ratelimit.allow_cidrs[1]", "CIDR", false},
		{"ratelimit_delay", "[ratelimit.delay]\nbase = \"5s\"\nmax = \"1s\"\n", "ratelimit.delay.max", "delay.base", false},
		{"ids_window", "[ids.spray]\nwindow = \"0s\"\n", "ids.spray.window", "positive", false},
		{"profile_no_listen", "[profile.p]\nupstream = \"u\"\n", "profile.p.listen", "at least one", false},
		{"profile_bad_listen", "[profile.p]\nlisten = [\"636\"]\n", "profile.p.listen[0]", "host:port", false},
		{"profile_bad_port", "[profile.p]\nlisten = [\":99999\"]\n", "profile.p.listen[0]", "port", false},
		{"profile_transport", "[profile.p]\nlisten = [\":1\"]\ntransport = \"tls\"\n", "profile.p.transport", "not one of", false},
		{"profile_plain_warn", "[profile.p]\nlisten = [\":1\"]\ntransport = \"ldap\"\n", "profile.p.transport", "clear text", true},
		{"profile_starttls_required_ldaps", "[profile.p]\nlisten = [\":1\"]\nstarttls_required = true\n", "profile.p.starttls_required", "starttls", false},
		{"profile_unknown_upstream", "[profile.p]\nlisten = [\":1\"]\nupstream = \"ghost\"\n", "profile.p.upstream", "not defined", false},
		{"profile_no_upstream", "[profile.p]\nlisten = [\":1\"]\n", "profile.p.upstream", "required", false},
		{"profile_no_bases", "[profile.p]\nlisten = [\":1\"]\n", "profile.p.bases", "at least one", false},
		{"profile_no_virtual_base", "[profile.p]\nlisten = [\":1\"]\n", "profile.p.virtual_base", "required", false},
		{"profile_attrs_star", "[profile.p]\nlisten = [\":1\"]\n[profile.p.attrs]\nallow = [\"cn\", \"*\"]\n", "profile.p.attrs.allow[1]", "'*' is not allowed", false},
		{"profile_bad_filter", "[profile.p]\nlisten = [\":1\"]\nfilter = \"(objectClass=user\"\n", "profile.p.filter", "parentheses", false},
		{"profile_bad_exclude", "[profile.p]\nlisten = [\":1\"]\nexclude_filter = \"cn=x\"\n", "profile.p.exclude_filter", "parentheses", false},
		{"profile_bad_computed", "[profile.p]\nlisten = [\":1\"]\n[profile.p.attrs.computed]\nmail = \"{{ .x \"\n", "profile.p.attrs.computed.mail", "template", false},
		{"profile_client_bind_dn", "[profile.p]\nlisten = [\":1\"]\n[profile.p.client_bind]\npassword_env = \"X\"\n", "profile.p.client_bind.dn", "required", false},
		{"profile_client_bind_pw", "[profile.p]\nlisten = [\":1\"]\n[profile.p.client_bind]\ndn = \"cn=app\"\n", "profile.p.client_bind.password", "required", false},
		{"profile_mock_file", "[profile.p]\nlisten = [\":1\"]\nmode = \"mock\"\n", "profile.p.mock.file", "required", false},
		{"profile_mode", "[profile.p]\nlisten = [\":1\"]\nmode = \"fake\"\n", "profile.p.mode", "not one of", false},
		{"profile_cache_mode", "[profile.p]\nlisten = [\":1\"]\n[profile.p.cache]\nmode = \"lru\"\n", "profile.p.cache.mode", "not one of", false},
		{"profile_cache_replica", "[profile.p]\nlisten = [\":1\"]\n[profile.p.cache]\nmode = \"replica\"\nsync_interval = \"0s\"\n", "profile.p.cache.sync_interval", "positive", false},
		{"profile_group_class", "[profile.p]\nlisten = [\":1\"]\n[profile.p.groups.g]\nobjectclass = \"team\"\n", "profile.p.groups.g.objectclass", "not one of", false},
		{"profile_group_posix", "[profile.p]\nlisten = [\":1\"]\n[profile.p.groups.g]\nobjectclass = \"posixGroup\"\n", "profile.p.groups.g.gid_number", "required", false},
		{"profile_group_ad_dn", "[profile.p]\nlisten = [\":1\"]\n[profile.p.groups.g.members]\nad_groups = [\"Staff\"]\n", "profile.p.groups.g.members.ad_groups[0]", "attr=value", false},
		{"profile_limits", "[profile.p]\nlisten = [\":1\"]\n[profile.p.limits]\nmax_result_size = 0\n", "profile.p.limits.max_result_size", "at least 1", false},
		{"profile_record", "[profile.p]\nlisten = [\":1\"]\n[profile.p.record]\nenabled = true\n", "profile.p.record.file", "required", false},
		{"profile_patch_warn", "[profile.p]\nlisten = [\":1\"]\n[profile.p.ratelimit.account]\nmax_failures = 6\n", "profile.p.ratelimit.account.max_failures", "lockout", true},
		{"profile_anonymous_warn", "[profile.p]\nlisten = [\":1\"]\nanonymous_bind = true\n", "profile.p.anonymous_bind", "enabled", true},
		{"profile_tls_override", "[profile.p]\nlisten = [\":1\"]\n[profile.p.tls]\nmode = \"external\"\n", "profile.p.tls.cert", "required", false},
		{"cross_virtual_base", "[profile.a]\nlisten = [\":1\"]\nvirtual_base = \"dc=x\"\n[profile.b]\nlisten = [\":2\"]\nvirtual_base = \"DC=X\"\n", "profile.b.virtual_base", "already used", false},
		{"cross_port_wildcard", "[profile.a]\nlisten = [\":636\"]\n[profile.b]\nlisten = [\"10.0.0.5:636\"]\n", "profile.b.listen[0]", "conflicts", false},
		{"cross_port_same", "[profile.a]\nlisten = [\"10.0.0.5:636\"]\n[profile.b]\nlisten = [\"10.0.0.5:636\"]\n", "profile.b.listen[0]", "conflicts", false},
		{"events_salt", "[events]\nhash_accounts = true\n", "events.salt_file", "required", false},
		{"events_include_exclude", "[events]\ninclude = [\"a\"]\nexclude = [\"b\"]\n", "events.include", "mutually exclusive", false},
		{"events_file_path", "[events.file]\nenabled = true\n", "events.file.path", "required", false},
		{"events_syslog", "[events.syslog]\nenabled = true\nnetwork = \"sctp\"\n", "events.syslog.network", "not one of", false},
		{"events_webhook_url", "[[events.webhook]]\nname = \"w\"\nurl = \"ftp://x\"\n", "events.webhook[0].url", "http(s)", false},
		{"events_webhook_dup", "[[events.webhook]]\nname = \"w\"\nurl = \"https://x\"\n[[events.webhook]]\nname = \"w\"\nurl = \"https://y\"\n", "events.webhook[1].name", "already used", false},
		{"events_webhook_http_warn", "[[events.webhook]]\nname = \"w\"\nurl = \"http://siem.example.org/\"\n", "events.webhook[0].url", "plain http", true},
		{"events_webhook_overflow", "[[events.webhook]]\nname = \"w\"\nurl = \"https://x\"\non_overflow = \"panic\"\n", "events.webhook[0].on_overflow", "not one of", false},
		{"notify_type", "[[notify.channel]]\nname = \"c\"\ntype = \"sms\"\n", "notify.channel[0].type", "not one of", false},
		{"notify_telegram", "[[notify.channel]]\nname = \"c\"\ntype = \"telegram\"\n", "notify.channel[0].bot_token", "required", false},
		{"notify_telegram_chat", "[[notify.channel]]\nname = \"c\"\ntype = \"telegram\"\nbot_token_env = \"T\"\n", "notify.channel[0].chat_id", "required", false},
		{"notify_virola_room", "[[notify.channel]]\nname = \"c\"\ntype = \"virola\"\nbase_url = \"https://v\"\ntoken_env = \"T\"\n", "notify.channel[0].room_id", "exactly one", false},
		{"notify_virola_both", "[[notify.channel]]\nname = \"c\"\ntype = \"virola\"\nbase_url = \"https://v\"\ntoken_env = \"T\"\nroom_id = 1\nuser_id = 2\n", "notify.channel[0].room_id", "exactly one", false},
		{"notify_email", "[[notify.channel]]\nname = \"c\"\ntype = \"email\"\n", "notify.channel[0].smtp_host", "required", false},
		{"notify_email_to", "[[notify.channel]]\nname = \"c\"\ntype = \"email\"\nsmtp_host = \"m\"\nfrom = \"a@b\"\n", "notify.channel[0].to", "recipient", false},
		{"notify_email_tls_warn", "[[notify.channel]]\nname = \"c\"\ntype = \"email\"\nsmtp_host = \"m\"\nfrom = \"a@b\"\nto = [\"c@d\"]\ntls = \"none\"\n", "notify.channel[0].tls", "without TLS", true},
		{"notify_webhook_method", "[[notify.channel]]\nname = \"c\"\ntype = \"webhook\"\nurl = \"https://x\"\nmethod = \"GET\"\n", "notify.channel[0].method", "not one of", false},
		{"notify_webhook_tpl", "[[notify.channel]]\nname = \"c\"\ntype = \"webhook\"\nurl = \"https://x\"\nbody_template = \"{{\"\n", "notify.channel[0].body_template", "template", false},
		{"notify_dup", "[[notify.channel]]\nname = \"c\"\ntype = \"webhook\"\nurl = \"https://x\"\n[[notify.channel]]\nname = \"c\"\ntype = \"webhook\"\nurl = \"https://x\"\n", "notify.channel[1].name", "already used", false},
		{"api_tls_required", "[api]\nenabled = true\nlisten = \"0.0.0.0:8636\"\n", "api.tls", "mandatory", false},
		{"api_loopback_ok_token_short", "[api]\nenabled = true\n[[api.token]]\nname = \"t\"\ntoken = \"short\"\nscopes = [\"admin\"]\n", "api.token[0].token", "32 bytes", false},
		{"api_token_scope", "[api]\nenabled = true\n[[api.token]]\nname = \"t\"\ntoken_env = \"T\"\nscopes = [\"root\"]\n", "api.token[0].scopes[0]", "not one of", false},
		{"api_token_no_scope", "[api]\nenabled = true\n[[api.token]]\nname = \"t\"\ntoken_env = \"T\"\n", "api.token[0].scopes", "at least one", false},
		{"api_token_dup", "[api]\n[[api.token]]\nname = \"t\"\ntoken_env = \"T\"\nscopes = [\"admin\"]\n[[api.token]]\nname = \"t\"\ntoken_env = \"T\"\nscopes = [\"admin\"]\n", "api.token[1].name", "already used", false},
		{"api_cors", "[api]\ncors = true\n", "api.cors", "cannot", false},
		{"api_client_ca", "[api]\nclient_auth = \"require\"\n", "api.client_ca", "required", false},
		{"api_cert_pair", "[api.tls]\ncert = \"/c\"\n", "api.tls.cert", "together", false},
		{"api_metrics_public_warn", "[api]\nenabled = true\n[api.metrics]\npublic = true\n", "api.metrics.public", "without a token", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := mustLoad(t, tt.body)
			rep := validate(cfg)
			list := rep.Errors
			if tt.warn {
				list = rep.Warnings
			}
			if !hasIssue(list, tt.path, tt.msg) {
				t.Errorf("want %s containing %q at %s; got errors=%v warnings=%v", map[bool]string{true: "warning", false: "error"}[tt.warn], tt.msg, tt.path, rep.Errors, rep.Warnings)
			}
		})
	}
}

func TestValidate_SecretFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	loose := filepath.Join(dir, "loose")
	if err := os.WriteFile(good, []byte("pw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(loose, []byte("pw\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("[upstream.a]\nservers = [\"ldaps://x\"]\nbind_dn = \"cn=a\"\nbind_password_file = %q\n"+
		"[upstream.b]\nservers = [\"ldaps://x\"]\nbind_dn = \"cn=b\"\nbind_password_file = %q\n"+
		"[upstream.c]\nservers = [\"ldaps://x\"]\nbind_dn = \"cn=c\"\nbind_password_file = %q\n",
		good, loose, filepath.Join(dir, "missing"))
	cfg := mustLoad(t, body)
	rep := Validator{}.Validate(cfg)
	if !rep.OK() {
		t.Errorf("offline check must not fail on a missing file: %v", rep)
	}
	if !hasIssue(rep.Warnings, "upstream.b.bind_password_file", "permissive") {
		t.Errorf("want permission warning, got %v", rep.Warnings)
	}
	if !hasIssue(rep.Warnings, "upstream.c.bind_password_file", "verified again") {
		t.Errorf("want missing-file warning, got %v", rep.Warnings)
	}
	strict := Validator{StrictFiles: true}.Validate(cfg)
	if !hasIssue(strict.Errors, "upstream.c.bind_password_file", "") || hasIssue(strict.Errors, "upstream.a.bind_password_file", "") {
		t.Errorf("strict: %v", strict.Errors)
	}
}

func TestValidate_SectionMethods(t *testing.T) {
	t.Parallel()
	cfg := Default()
	for name, err := range map[string]error{
		"server": cfg.Server.Validate(), "tls": cfg.TLS.Validate(), "ratelimit": cfg.Ratelimit.Validate(),
		"ids": cfg.Intrusion.Validate(), "events": cfg.Events.Validate(), "notify": cfg.Notify.Validate(), "api": cfg.API.Validate(),
		"config": cfg.Validate(),
	} {
		if err != nil {
			t.Errorf("%s: defaults must validate: %v", name, err)
		}
	}
	if err := DefaultUpstream().Validate(); err == nil || !strings.Contains(err.Error(), "upstream.servers") {
		t.Errorf("empty upstream must fail on servers: %v", err)
	}
	if err := DefaultProfile().Validate(); err == nil || !strings.Contains(err.Error(), "profile.listen") {
		t.Errorf("empty profile must fail on listen: %v", err)
	}
	bad := Default()
	bad.Server.LogLevel = "x"
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "server.log_level") {
		t.Errorf("Validate() = %v", err)
	}
}

func TestTypes_Parse(t *testing.T) {
	t.Parallel()
	var d Duration
	if err := d.UnmarshalText([]byte(" 90s ")); err != nil || d.D() != 90*time.Second || d.String() != "1m30s" {
		t.Errorf("duration: %v %v", d, err)
	}
	if err := d.UnmarshalText([]byte("1 day")); err == nil {
		t.Error("duration: want error")
	}
	for in, want := range map[string]ByteSize{"1MiB": 1 << 20, "512KiB": 512 << 10, "2MB": 2_000_000, "1G": 1 << 30, "3B": 3, "4096": 4096} {
		var s ByteSize
		if err := s.UnmarshalText([]byte(in)); err != nil || s != want {
			t.Errorf("size %q = %d (%v), want %d", in, s, err, want)
		}
	}
	for _, in := range []string{"-1", "x", "1TiB2"} {
		var s ByteSize
		if err := s.UnmarshalText([]byte(in)); err == nil {
			t.Errorf("size %q: want error", in)
		}
	}
	if ByteSize(1<<20).String() != "1MiB" || ByteSize(1500).String() != "1500" {
		t.Errorf("size strings: %s %s", ByteSize(1<<20), ByteSize(1500))
	}
	for in, want := range map[string]Percent{"20%": 0.2, "0.5": 0.5, "100 %": 1} {
		var p Percent
		if err := p.UnmarshalText([]byte(in)); err != nil || p != want {
			t.Errorf("percent %q = %v (%v), want %v", in, p, err, want)
		}
	}
	var p Percent
	if err := p.UnmarshalText([]byte("-5%")); err == nil {
		t.Error("percent: want error")
	}
	if Percent(0.25).String() != "25%" {
		t.Errorf("percent string: %s", Percent(0.25))
	}
	for _, m := range []interface{ MarshalText() ([]byte, error) }{Duration(time.Second), ByteSize(1), Percent(1)} {
		if b, err := m.MarshalText(); err != nil || len(b) == 0 {
			t.Errorf("MarshalText: %s %v", b, err)
		}
	}
}

func TestNoSecretsInOutput_Config(t *testing.T) {
	t.Parallel()
	const pw = "Sup3r-S3cret-Value-That-Must-Not-Leak-Anywhere"
	cfg := mustLoad(t, strings.ReplaceAll(minimalTOML, "bind_password_env = \"ALDAP_TEST_PW\"", "bind_password = \""+pw+"\"")+
		"[[api.token]]\nname = \"t\"\ntoken = \""+pw+"\"\nscopes = [\"admin\"]\n")
	rep := validate(cfg)
	outputs := map[string]string{
		"plus_v":  fmt.Sprintf("%+v", cfg),
		"sharp_v": fmt.Sprintf("%#v", cfg.Upstreams["ad-main"]),
		"report":  fmt.Sprintf("%+v", rep),
	}
	if b, err := json.Marshal(cfg); err != nil {
		t.Fatal(err)
	} else {
		outputs["json_cfg"] = string(b)
	}
	if b, err := json.Marshal(rep); err != nil {
		t.Fatal(err)
	} else {
		outputs["json_report"] = string(b)
	}
	for name, out := range outputs {
		if strings.Contains(out, pw) {
			t.Errorf("%s leaks the secret", name)
		}
	}
	if cfg.Upstreams["ad-main"].BindPassword.Reveal() != pw {
		t.Error("Reveal() must still return the value")
	}
}

func TestConfigDocsInSync(t *testing.T) {
	t.Parallel()
	const path = "../../docs/config.md"
	want := RenderDocs()
	if *update {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to generate)", err)
	}
	if string(got) != want {
		t.Fatalf("docs/config.md is stale: run `go test ./internal/config -run TestConfigDocsInSync -update`")
	}
	keys := Keys()
	seen := map[string]bool{}
	for _, k := range keys {
		if k.Doc == "" {
			t.Errorf("%s has no doc tag", k.Path)
		}
		if seen[k.Path] {
			t.Errorf("%s listed twice", k.Path)
		}
		seen[k.Path] = true
	}
	for _, must := range []string{"server.log_level", "upstream.<name>.bind_password_file", "profile.<name>.attrs.allow", "events.webhook[].url", "api.token[].scopes", "profile.<name>.groups.<name>.members.ad_groups"} {
		if !seen[must] {
			t.Errorf("missing documented key %s", must)
		}
	}
	for _, k := range keys {
		if k.Type == "secret" && k.Default != "" {
			t.Errorf("%s: secret must have no rendered default", k.Path)
		}
	}
}
