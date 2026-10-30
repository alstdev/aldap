package config

// Audit 14, area A.10 (configuration and validation). These tests document
// the behaviour of Load/Validate against SPEC §3.4/§3.5/§9; a failing test
// is a finding (see the audit report), not a regression to "fix" by editing
// the test.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alstdev/aldap/internal/secret"
)

// --- 1. unknown keys ---------------------------------------------------------

func TestAudit14_A10_UnknownKeys(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, body, key string
	}{
		{"top_level", "anonymos_bind = true\n", "anonymos_bind"},
		{"server_wrong_table", "[server]\nmax_failures = 3\n", "server.max_failures"},
		{"tls_typo", "[tls]\ntls_insecure_skip_verfy = true\n", "tls.tls_insecure_skip_verfy"},
		{"upstream_typo", "[upstream.u]\nservers=[\"ldaps://a\"]\ntls_insecure_skip_verfy = true\n", "upstream.u.tls_insecure_skip_verfy"},
		{"upstream_starttls_typo", "[upstream.u]\nservers=[\"ldaps://a\"]\nstarttls_requried = true\n", "upstream.u.starttls_requried"},
		{"upstream_failover", "[upstream.u]\nservers=[\"ldaps://a\"]\n[upstream.u.failover]\nmax_failures = 3\n", "upstream.u.failover.max_failures"},
		{"upstream_pool", "[upstream.u]\nservers=[\"ldaps://a\"]\n[upstream.u.pool]\nsizes = 3\n", "upstream.u.pool.sizes"},
		{"upstream_timeouts", "[upstream.u]\nservers=[\"ldaps://a\"]\n[upstream.u.timeouts]\nconnectt = \"1s\"\n", "upstream.u.timeouts.connectt"},
		{"ratelimit_allowed", "[ratelimit]\nallowed_cidrs = [\"10.0.0.0/8\"]\n", "ratelimit.allowed_cidrs"},
		{"ratelimit_ip", "[ratelimit.ip]\nmax_failure = 1\n", "ratelimit.ip.max_failure"},
		{"ratelimit_account", "[ratelimit.account]\nlock_durations = \"1m\"\n", "ratelimit.account.lock_durations"},
		{"ratelimit_delay", "[ratelimit.delay]\nbases = \"1s\"\n", "ratelimit.delay.bases"},
		{"ratelimit_tarpit", "[ratelimit.tarpit]\ndelays = \"1s\"\n", "ratelimit.tarpit.delays"},
		{"ratelimit_lockdown", "[ratelimit.lockdown]\nallowed_cidrs = []\n", "ratelimit.lockdown.allowed_cidrs"},
		{"ratelimit_max_failures_wrong_level", "[ratelimit]\nmax_failures = 1\n", "ratelimit.max_failures"},
		{"ids_top", "[ids]\nenabled = false\n", "ids.enabled"},
		{"ids_spray", "[ids.spray]\nwindows = \"1m\"\n", "ids.spray.windows"},
		{"ids_unknown_detector", "[ids.sprey]\nenabled = false\n", "ids.sprey.enabled"},
		{"profile_anonymous", "[profile.p]\nlisten=[\":1\"]\nanonymos_bind = true\n", "profile.p.anonymos_bind"},
		{"profile_starttls", "[profile.p]\nlisten=[\":1\"]\nstarttls_requried = true\n", "profile.p.starttls_requried"},
		{"profile_tls", "[profile.p]\nlisten=[\":1\"]\n[profile.p.tls]\ninsecure = true\n", "profile.p.tls.insecure"},
		{"profile_attrs", "[profile.p]\nlisten=[\":1\"]\n[profile.p.attrs]\ndeny = [\"x\"]\n", "profile.p.attrs.deny"},
		{"profile_client_bind", "[profile.p]\nlisten=[\":1\"]\n[profile.p.client_bind]\npasswd = \"x\"\n", "profile.p.client_bind.passwd"},
		{"profile_user_bind", "[profile.p]\nlisten=[\":1\"]\n[profile.p.user_bind]\nallowed = false\n", "profile.p.user_bind.allowed"},
		{"profile_group", "[profile.p]\nlisten=[\":1\"]\n[profile.p.groups.g]\nmember = []\n", "profile.p.groups.g.member"},
		{"profile_group_members", "[profile.p]\nlisten=[\":1\"]\n[profile.p.groups.g.members]\nad_group = []\n", "profile.p.groups.g.members.ad_group"},
		{"profile_group_nested_table", "[profile.p]\nlisten=[\":1\"]\n[profile.p.groups.g.extra]\nx = 1\n", "profile.p.groups.g.extra"},
		{"profile_limits", "[profile.p]\nlisten=[\":1\"]\n[profile.p.limits]\nmax_conns = 1\n", "profile.p.limits.max_conns"},
		{"profile_shadow", "[profile.p]\nlisten=[\":1\"]\n[profile.p.shadow]\nfilters = \"(a=b)\"\n", "profile.p.shadow.filters"},
		{"profile_record", "[profile.p]\nlisten=[\":1\"]\n[profile.p.record]\nenable = true\n", "profile.p.record.enable"},
		{"profile_cache", "[profile.p]\nlisten=[\":1\"]\n[profile.p.cache]\nmodes = \"ttl\"\n", "profile.p.cache.modes"},
		{"profile_proxy_protocol", "[profile.p]\nlisten=[\":1\"]\n[profile.p.proxy_protocol]\ntrusted = []\n", "profile.p.proxy_protocol.trusted"},
		{"profile_mock", "[profile.p]\nlisten=[\":1\"]\n[profile.p.mock]\npath = \"x\"\n", "profile.p.mock.path"},
		{"profile_ratelimit_patch", "[profile.p]\nlisten=[\":1\"]\n[profile.p.ratelimit]\nallowed_cidrs = []\n", "profile.p.ratelimit.allowed_cidrs"},
		{"profile_ratelimit_patch_ip", "[profile.p]\nlisten=[\":1\"]\n[profile.p.ratelimit.ip]\nmax_failure = 1\n", "profile.p.ratelimit.ip.max_failure"},
		{"profile_ratelimit_patch_lockdown", "[profile.p]\nlisten=[\":1\"]\n[profile.p.ratelimit.lockdown]\nautomatic = true\n", "profile.p.ratelimit.lockdown.automatic"},
		{"events", "[events]\nbuffer = 1\n", "events.buffer"},
		{"events_stdout", "[events.stdout]\nenable = true\n", "events.stdout.enable"},
		{"events_file", "[events.file]\npaths = \"x\"\n", "events.file.paths"},
		{"events_syslog", "[events.syslog]\naddr = \"x\"\n", "events.syslog.addr"},
		{"events_webhook", "[[events.webhook]]\nname=\"w\"\nurls = \"https://x\"\n", "events.webhook.urls"},
		{"events_webhook_headers_nested", "[[events.webhook]]\nname=\"w\"\nurl=\"https://x\"\n[events.webhook.headers.X]\ny = 1\n", "headers"},
		{"notify_channel", "[[notify.channel]]\nname=\"c\"\ntype=\"email\"\nbot_tokn = \"x\"\n", "notify.channel.bot_tokn"},
		{"notify_top", "[notify]\ncooldowns = \"1m\"\n", "notify.cooldowns"},
		{"api", "[api]\nlistens = \"x\"\n", "api.listens"},
		{"api_token", "[[api.token]]\nname=\"t\"\nscope = [\"admin\"]\n", "api.token.scope"},
		{"api_metrics", "[api.metrics]\nenable = true\n", "api.metrics.enable"},
		{"api_tls", "[api.tls]\ncerts = \"x\"\n", "api.tls.certs"},
		{"attrs_map_nested_table", "[profile.p]\nlisten=[\":1\"]\n[profile.p.attrs.map.uid]\nx = \"y\"\n", "attrs.map"},
		{"attrs_computed_nested_table", "[profile.p]\nlisten=[\":1\"]\n[profile.p.attrs.computed.mail]\nx = \"y\"\n", "attrs.computed"},
		{"attrs_mask_nested_table", "[profile.p]\nlisten=[\":1\"]\n[profile.p.attrs.mask.mail]\nx = \"y\"\n", "attrs.mask"},
		{"honeytoken_template_nested", "[profile.p]\nlisten=[\":1\"]\n[profile.p.honeytoken_template.mail]\nx = \"y\"\n", "honeytoken_template"},
		{"duplicate_key", "[server]\nlog_level = \"info\"\nlog_level = \"debug\"\n", "log_level"},
		{"duplicate_table", "[ratelimit]\nenabled = true\n[ratelimit]\nenabled = false\n", "ratelimit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := loadString(t, tt.body)
			if err == nil {
				t.Fatalf("accepted silently:\n%s", tt.body)
			}
			if !strings.Contains(err.Error(), tt.key) {
				t.Errorf("error does not name the key %q: %v", tt.key, err)
			}
		})
	}
}

// Keys in an included file must be as strict as in the main file.
func TestAudit14_A10_UnknownKeys_IncludedFile(t *testing.T) {
	t.Parallel()
	files := map[string]string{
		"/etc/aldap/aldap.toml":           "[server]\ninclude = [\"conf.d/*.toml\"]\n",
		"/etc/aldap/conf.d/upstream.toml": "[upstream.u]\nservers = [\"ldaps://a\"]\ntls_insecure_skip_verfy = true\n",
	}
	_, err := loadFS(t, files, nil, "/etc/aldap/aldap.toml")
	if !errors.Is(err, ErrUnknownKey) || !strings.Contains(err.Error(), "conf.d/upstream.toml") {
		t.Fatalf("included file typo must be ErrUnknownKey naming the file, got %v", err)
	}
}

// Unknown ALDAP_* variables, including typos of security keys, are errors.
func TestAudit14_A10_UnknownKeys_Env(t *testing.T) {
	t.Parallel()
	for _, env := range []string{
		"ALDAP_UPSTREAM_AD_MAIN_TLS_INSECURE_SKIP_VERFY=true",
		"ALDAP_RATELIMIT_ENABLE=false",
		"ALDAP_PROFILE_APP_ANONYMOS_BIND=true",
		"ALDAP_API_TOKEN_0_TOKEN=x",
		"ALDAP_IDS_SPRAY_ENABLE=false",
		"ALDAP_ENABLED=false",
	} {
		_, err := loadString(t, minimalTOML, env)
		if !errors.Is(err, ErrUnknownKey) {
			t.Errorf("%s: want ErrUnknownKey, got %v", env, err)
		}
	}
}

// --- 2. dangerous combinations: implemented rules ---------------------------

func TestAudit14_A10_ImplementedRules(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, body, path, msg string
		warn                  bool
	}{
		{"profile_transport_ldap_warn", "[profile.p]\nlisten=[\":1\"]\ntransport=\"ldap\"\n", "profile.p.transport", "clear text", true},
		{"profile_ldap_starttls_optional_warn", "[profile.p]\nlisten=[\":1\"]\ntransport=\"ldap+starttls\"\n", "profile.p.starttls_required", "plain binds", true},
		{"upstream_ldap_no_starttls_warn", "[upstream.u]\nservers=[\"ldap://a\"]\n", "upstream.u.starttls", "clear text", true},
		{"upstream_insecure_warn", "[upstream.u]\nservers=[\"ldaps://a\"]\ntls_insecure_skip_verify=true\n", "upstream.u.tls_insecure_skip_verify", "disabled", true},
		{"virola_insecure_warn", "[[notify.channel]]\nname=\"c\"\ntype=\"virola\"\nbase_url=\"https://v\"\ntoken_env=\"T\"\nroom_id=1\ntls_insecure_skip_verify=true\n", "notify.channel[0].tls_insecure_skip_verify", "disabled", true},
		{"inline_secret_warn", "[upstream.u]\nservers=[\"ldaps://a\"]\nbind_dn=\"cn=a\"\nbind_password=\"x\"\n", "upstream.u.bind_password", "inline", true},
		{"inline_api_token_warn", "[[api.token]]\nname=\"t\"\ntoken=\"0123456789abcdef0123456789abcdef\"\nscopes=[\"admin\"]\n", "api.token[0].token", "inline", true},
		{"account_max_failures_5_warn", "[ratelimit.account]\nmax_failures = 5\n", "ratelimit.account.max_failures", "lockout", true},
		{"account_max_failures_0_err", "[ratelimit.account]\nmax_failures = 0\n", "ratelimit.account.max_failures", "at least 1", false},
		{"account_max_failures_neg_err", "[ratelimit.account]\nmax_failures = -1\n", "ratelimit.account.max_failures", "at least 1", false},
		{"ip_max_failures_0_err", "[ratelimit.ip]\nmax_failures = 0\n", "ratelimit.ip.max_failures", "at least 1", false},
		{"ip_window_0_err", "[ratelimit.ip]\nwindow = \"0s\"\n", "ratelimit.ip.window", "positive", false},
		{"ip_lock_neg_err", "[ratelimit.ip]\nlock_duration = \"-1m\"\n", "ratelimit.ip.lock_duration", "positive", false},
		{"bind_rps_0_err", "[ratelimit.ip]\nbind_rps = 0\n", "ratelimit.ip.bind_rps", "at least 1", false},
		{"negative_cache_0_err", "[ratelimit]\nnegative_cache_ttl = \"0s\"\n", "ratelimit.negative_cache_ttl", "positive", false},
		{"delay_base_0_err", "[ratelimit.delay]\nbase = \"0s\"\n", "ratelimit.delay.base", "positive", false},
		{"tarpit_enabled_zero_delay_err", "[ratelimit.tarpit]\nenabled = true\ndelay = \"0s\"\n", "ratelimit.tarpit.delay", "positive", false},
		{"tarpit_enabled_zero_conns_err", "[ratelimit.tarpit]\nenabled = true\nmax_conns = 0\n", "ratelimit.tarpit.max_conns", "at least 1", false},
		{"bad_allow_cidr_err", "[ratelimit]\nallow_cidrs = [\"10.0.0.0/33\"]\n", "ratelimit.allow_cidrs[0]", "CIDR", false},
		{"proxy_protocol_no_trusted_err", "[profile.p]\nlisten=[\":1\"]\n[profile.p.proxy_protocol]\nenabled = true\n", "profile.p.proxy_protocol.trusted_cidrs", "required", false},
		{"proxy_protocol_trust_all_err", "[profile.p]\nlisten=[\":1\"]\n[profile.p.proxy_protocol]\nenabled = true\ntrusted_cidrs = [\"0.0.0.0/0\"]\n", "profile.p.proxy_protocol.trusted_cidrs[0]", "every address", false},
		{"api_nonloopback_no_tls_err", "[api]\nenabled = true\nlisten = \"10.0.0.5:8636\"\n", "api.tls", "mandatory", false},
		{"api_wildcard_no_tls_err", "[api]\nenabled = true\nlisten = \":8636\"\n", "api.tls", "mandatory", false},
		{"api_v6_wildcard_no_tls_err", "[api]\nenabled = true\nlisten = \"[::]:8636\"\n", "api.tls", "mandatory", false},
		{"attrs_star_err", "[profile.p]\nlisten=[\":1\"]\n[profile.p.attrs]\nallow = [\"*\"]\n", "profile.p.attrs.allow[0]", "not allowed", false},
		{"attrs_star_spaces_err", "[profile.p]\nlisten=[\":1\"]\n[profile.p.attrs]\nallow = [\" * \"]\n", "profile.p.attrs.allow[0]", "not allowed", false},
		{"attrs_plus_err", "[profile.p]\nlisten=[\":1\"]\n[profile.p.attrs]\nallow = [\"+\"]\n", "profile.p.attrs.allow[0]", "not allowed", false},
		{"attrs_empty_proxy_err", "[profile.p]\nlisten=[\":1\"]\n[profile.p.attrs]\nallow = []\n", "profile.p.attrs.allow", "at least one", false},
		{"secret_two_sources_err", "[upstream.u]\nservers=[\"ldaps://a\"]\nbind_dn=\"cn=a\"\nbind_password_file=\"/f\"\nbind_password_env=\"E\"\n", "upstream.u.bind_password", "exactly one", false},
		{"client_bind_two_sources_err", "[profile.p]\nlisten=[\":1\"]\n[profile.p.client_bind]\ndn=\"cn=a\"\npassword=\"x\"\npassword_file=\"/f\"\n", "profile.p.client_bind.password", "exactly one", false},
		{"client_bind_hash_and_password_err", "[profile.p]\nlisten=[\":1\"]\n[profile.p.client_bind]\ndn=\"cn=a\"\npassword_env=\"X\"\npassword_hash=\"$argon2id$x\"\n", "profile.p.client_bind.password_hash", "mutually exclusive", false},
		{"anonymous_bind_warn", "[profile.p]\nlisten=[\":1\"]\nanonymous_bind = true\n", "profile.p.anonymous_bind", "enabled", true},
		{"max_request_bytes_0_err", "[profile.p]\nlisten=[\":1\"]\n[profile.p.limits]\nmax_request_bytes = 0\n", "profile.p.limits.max_request_bytes", "positive", false},
		{"max_conns_per_ip_0_err", "[profile.p]\nlisten=[\":1\"]\n[profile.p.limits]\nmax_conns_per_ip = 0\n", "profile.p.limits.max_conns_per_ip", "at least 1", false},
		{"idle_timeout_0_err", "[profile.p]\nlisten=[\":1\"]\n[profile.p.limits]\nidle_timeout = \"0s\"\n", "profile.p.limits.idle_timeout", "positive", false},
		{"max_filter_depth_0_err", "[profile.p]\nlisten=[\":1\"]\n[profile.p.limits]\nmax_filter_depth = 0\n", "profile.p.limits.max_filter_depth", "at least 1", false},
		{"max_connections_0_err", "[server]\nmax_connections = 0\n", "server.max_connections", "at least 1", false},
		{"max_connections_neg_err", "[server]\nmax_connections = -5\n", "server.max_connections", "at least 1", false},
		{"page_size_0_err", "[upstream.u]\nservers=[\"ldaps://a\"]\npage_size = 0\n", "upstream.u.page_size", "at least 1", false},
		{"nested_depth_0_err", "[profile.p]\nlisten=[\":1\"]\nnested_depth = 0\n", "profile.p.nested_depth", "at least 1", false},
		{"buffer_size_0_err", "[events]\nbuffer_size = 0\n", "events.buffer_size", "at least 1", false},
		{"queue_size_neg_err", "[[events.webhook]]\nname=\"w\"\nurl=\"https://x\"\nqueue_size = -1\n", "events.webhook[0].queue_size", "at least 1", false},
		{"batch_size_neg_err", "[[events.webhook]]\nname=\"w\"\nurl=\"https://x\"\nbatch_size = -1\n", "events.webhook[0].batch_size", "at least 1", false},
		{"tls_min_1_0_err", "[tls]\nmin_version = \"1.0\"\n", "tls.min_version", "not one of", false},
		{"tls_min_1_1_err", "[tls]\nmin_version = \"1.1\"\n", "tls.min_version", "not one of", false},
		{"profile_tls_min_1_0_err", "[profile.p]\nlisten=[\":1\"]\n[profile.p.tls]\nmin_version = \"1.0\"\n", "profile.p.tls.min_version", "not one of", false},
		{"tls_require_no_ca_err", "[tls]\nclient_auth = \"require\"\n", "tls.client_ca", "required", false},
		{"tls_request_no_ca_err", "[tls]\nclient_auth = \"request\"\n", "tls.client_ca", "required", false},
		{"api_require_no_ca_err", "[api]\nclient_auth = \"require\"\n", "api.client_ca", "required", false},
		{"hash_accounts_no_salt_err", "[events]\nhash_accounts = true\n", "events.salt_file", "required", false},
		{"two_profiles_one_port_err", "[profile.a]\nlisten=[\":636\"]\n[profile.b]\nlisten=[\"0.0.0.0:636\"]\n", "profile.b.listen[0]", "conflicts", false},
		{"record_file_eq_events_file_err", "[events.file]\nenabled=true\npath=\"/var/log/aldap/x.jsonl\"\n[profile.p]\nlisten=[\":1\"]\n[profile.p.record]\nfile=\"/var/log/aldap/x.jsonl\"\n", "profile.p.record.file", "already written", false},
		{"metrics_public_warn", "[api]\nenabled=true\n[api.metrics]\npublic=true\n", "api.metrics.public", "without a token", true},
		{"cors_err", "[api]\ncors = true\n", "api.cors", "cannot", false},
		{"api_token_short_inline_err", "[[api.token]]\nname=\"t\"\ntoken=\"short\"\nscopes=[\"admin\"]\n", "api.token[0].token", "32 bytes", false},
		{"starttls_required_ldaps_err", "[profile.p]\nlisten=[\":1\"]\nstarttls_required=true\n", "profile.p.starttls_required", "requires transport", false},
		{"upstream_starttls_required_no_starttls_err", "[upstream.u]\nservers=[\"ldap://a\"]\nstarttls_required=true\n", "upstream.u.starttls_required", "starttls = true", false},
		{"ids_spray_min_1_err", "[ids.spray]\nmin_accounts = 1\n", "ids.spray.min_accounts", "at least 2", false},
		{"ids_window_neg_err", "[ids.stuffing]\nwindow = \"-1s\"\n", "ids.stuffing.window", "positive", false},
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
				t.Errorf("want %q at %s (warn=%v); errors=%v warnings=%v", tt.msg, tt.path, tt.warn, rep.Errors, rep.Warnings)
			}
		})
	}
}

// --- 2b. dangerous combinations the validator does not catch ----------------

// Each case is a configuration that passes `aldap check` although it
// silently weakens or breaks a control. A subtest that FAILS here means
// the validator stays silent on it (the finding); see the report.
func TestAudit14_A10_MissingRules(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, body, path string
	}{
		// allow lists that exempt everyone from rate limiting / locks.
		{"ratelimit_allow_all_v4", "[ratelimit]\nallow_cidrs = [\"0.0.0.0/0\"]\n", "ratelimit.allow_cidrs"},
		{"ratelimit_allow_all_v6", "[ratelimit]\nallow_cidrs = [\"::/0\"]\n", "ratelimit.allow_cidrs"},
		{"profile_ratelimit_allow_all", "[profile.p]\nlisten=[\":1\"]\n[profile.p.ratelimit]\nallow_cidrs = [\"0.0.0.0/0\"]\n", "profile.p.ratelimit.allow_cidrs"},
		{"lockdown_allow_all", "[ratelimit.lockdown]\nauto = true\nallow_cidrs = [\"0.0.0.0/0\"]\n", "ratelimit.lockdown.allow_cidrs"},
		{"api_token_allow_all", "[[api.token]]\nname=\"t\"\ntoken_env=\"T\"\nscopes=[\"admin\"]\nallow_cidrs=[\"0.0.0.0/0\"]\n", "api.token[0].allow_cidrs"},
		// lockdown.auto with nobody allowed: a high attack_start locks every client out.
		{"lockdown_auto_nobody_allowed", "[ratelimit.lockdown]\nauto = true\n", "ratelimit.lockdown"},
		// generic upstream, proxy profile, no mandatory filter: every entry under bases is exposed/bindable.
		{"generic_no_filter", "[upstream.u]\nservers=[\"ldaps://a\"]\nkind=\"generic\"\n[profile.p]\nlisten=[\":1\"]\nupstream=\"u\"\nvirtual_base=\"dc=v\"\nbases=[\"dc=example\"]\n[profile.p.attrs]\nallow=[\"cn\"]\n", "profile.p.filter"},
		// virtual_base equal to a real base: DN rewriting is ambiguous.
		{"virtual_base_eq_base", "[profile.p]\nlisten=[\":1\"]\nvirtual_base=\"dc=example,dc=org\"\nbases=[\"DC=example,DC=org\"]\n", "profile.p.virtual_base"},
		{"virtual_base_under_base", "[profile.p]\nlisten=[\":1\"]\nvirtual_base=\"ou=x,dc=example,dc=org\"\nbases=[\"dc=example,dc=org\"]\n", "profile.p.virtual_base"},
		// profile TLS override: client_auth = require without client_ca anywhere (start fails, check says OK).
		{"profile_tls_require_no_ca", "[profile.p]\nlisten=[\":1\"]\n[profile.p.tls]\nclient_auth = \"require\"\n", "profile.p.tls.client_ca"},
		// profile TLS override: mode external with a cert path that is never probed.
		{"profile_tls_external_unprobed", "[profile.p]\nlisten=[\":1\"]\n[profile.p.tls]\nmode = \"external\"\ncert = \"/nonexistent/c.pem\"\nkey = \"/nonexistent/k.pem\"\n", "profile.p.tls.cert"},
		// API: mTLS required on loopback without any TLS (start fails, check says OK).
		{"api_require_loopback_no_tls", "[api]\nenabled = true\nclient_auth = \"require\"\nclient_ca = \"/etc/aldap/clients.pem\"\n", "api.tls"},
		// metrics on a non-loopback address while the API itself is loopback: refused at start, accepted by check.
		{"metrics_nonloopback_no_tls", "[api]\nenabled = true\n[api.metrics]\nlisten = \"0.0.0.0:9100\"\n", "api.metrics.listen"},
		// metrics listener without the API enabled, non-loopback, no TLS (same).
		{"metrics_only_nonloopback_no_tls", "[api]\nenabled = false\n[api.metrics]\nlisten = \"0.0.0.0:9100\"\n", "api.metrics.listen"},
		// resource limits without an upper bound.
		{"max_request_bytes_1gib", "[profile.p]\nlisten=[\":1\"]\n[profile.p.limits]\nmax_request_bytes = \"1GiB\"\n", "profile.p.limits.max_request_bytes"},
		{"max_filter_depth_over_hard_cap", "[profile.p]\nlisten=[\":1\"]\n[profile.p.limits]\nmax_filter_depth = 1000000\n", "profile.p.limits.max_filter_depth"},
		{"nested_depth_huge", "[profile.p]\nlisten=[\":1\"]\nnested_depth = 1000000\n", "profile.p.nested_depth"},
		{"max_conns_per_ip_huge", "[profile.p]\nlisten=[\":1\"]\n[profile.p.limits]\nmax_conns_per_ip = 1000000000\n", "profile.p.limits.max_conns_per_ip"},
		// security controls switched off without a word.
		{"ratelimit_disabled", "[ratelimit]\nenabled = false\n", "ratelimit.enabled"},
		{"profile_ratelimit_disabled", "[profile.p]\nlisten=[\":1\"]\n[profile.p.ratelimit]\nenabled = false\n", "profile.p.ratelimit.enabled"},
		{"constant_time_off", "[ratelimit]\nconstant_time_bind_fail = false\n", "ratelimit.constant_time_bind_fail"},
		{"ids_spray_off", "[ids.spray]\nenabled = false\n", "ids.spray.enabled"},
		{"ids_honeytoken_off", "[ids.honeytoken]\nenabled = false\n", "ids.honeytoken.enabled"},
		{"audit_service_account_off", "[upstream.u]\nservers=[\"ldaps://a\"]\naudit_service_account = false\n", "upstream.u.audit_service_account"},
		// a channel that is not virola carries tls_insecure_skip_verify: accepted, ignored by internal/notify (only virola passes it to httpClient), never reported.
		{"webhook_channel_insecure", "[[notify.channel]]\nname=\"c\"\ntype=\"webhook\"\nurl=\"https://x\"\ntls_insecure_skip_verify = true\n", "notify.channel[0].tls_insecure_skip_verify"},
		{"telegram_channel_insecure", "[[notify.channel]]\nname=\"c\"\ntype=\"telegram\"\nbot_token_env=\"T\"\nchat_id=\"1\"\ntls_insecure_skip_verify = true\n", "notify.channel[0].tls_insecure_skip_verify"},
		// keys of another channel type accepted silently (misplaced secret).
		{"email_channel_with_telegram_keys", "[[notify.channel]]\nname=\"c\"\ntype=\"email\"\nsmtp_host=\"m\"\nfrom=\"a@b\"\nto=[\"c@d\"]\nbot_token_env=\"T\"\nchat_id=\"1\"\n", "notify.channel[0].bot_token"},
		// *_file keys pointing at the TLS private key / CA key: the content becomes a bind password sent to the (attacker's) upstream.
		{"bind_password_file_is_tls_key", "[tls]\nmode=\"external\"\ncert=\"/etc/aldap/server.crt\"\nkey=\"/etc/aldap/server.key\"\n[upstream.u]\nservers=[\"ldaps://a\"]\nbind_dn=\"cn=a\"\nbind_password_file=\"/etc/aldap/server.key\"\n", "upstream.u.bind_password_file"},
		{"bind_password_file_is_ca_key", "[tls]\nca_dir=\"/var/lib/aldap/ca\"\n[upstream.u]\nservers=[\"ldaps://a\"]\nbind_dn=\"cn=a\"\nbind_password_file=\"/var/lib/aldap/ca/ca.key\"\n", "upstream.u.bind_password_file"},
		{"client_bind_password_file_is_api_token_file", "[[api.token]]\nname=\"t\"\ntoken_file=\"/run/secrets/api_token\"\nscopes=[\"admin\"]\n[profile.p]\nlisten=[\":1\"]\n[profile.p.client_bind]\ndn=\"cn=app\"\npassword_file=\"/run/secrets/api_token\"\n", "profile.p.client_bind.password_file"},
		// output files pointing at inputs: events.file appends JSON to the CA key / config.
		{"events_file_is_ca_key", "[tls]\nca_dir=\"/var/lib/aldap/ca\"\n[events.file]\nenabled=true\npath=\"/var/lib/aldap/ca/ca.key\"\n", "events.file.path"},
		{"events_file_is_tls_key", "[tls]\nmode=\"external\"\ncert=\"/c.pem\"\nkey=\"/k.pem\"\n[events.file]\nenabled=true\npath=\"/k.pem\"\n", "events.file.path"},
		{"record_file_is_salt_file", "[events]\nhash_accounts=true\nsalt_file=\"/etc/aldap/salt\"\n[profile.p]\nlisten=[\":1\"]\n[profile.p.record]\nenabled=true\nfile=\"/etc/aldap/salt\"\n", "profile.p.record.file"},
		{"events_file_is_mock_file", "[events.file]\nenabled=true\npath=\"/etc/aldap/mock.toml\"\n[profile.p]\nlisten=[\":1\"]\nmode=\"mock\"\nvirtual_base=\"dc=v\"\n[profile.p.mock]\nfile=\"/etc/aldap/mock.toml\"\n", "events.file.path"},
	}
	// Every *_file exists and is readable, so the only issue that can show
	// up at the path is a rule about the combination itself.
	v := Validator{Secrets: secret.Resolver{
		ReadFile:  func(string) ([]byte, error) { return []byte("content\n"), nil },
		Stat:      func(string) (fs.FileInfo, error) { return nil, fs.ErrNotExist },
		LookupEnv: func(string) (string, bool) { return "x", true },
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := mustLoad(t, tt.body)
			rep := v.Validate(cfg)
			if !hasIssuePrefix(rep.Errors, tt.path) && !hasIssuePrefix(rep.Warnings, tt.path) {
				t.Errorf("validator is silent about %s; errors=%v warnings=%v", tt.path, rep.Errors, rep.Warnings)
			}
		})
	}
}

// --- 5. environment overlay ---------------------------------------------------

func TestAudit14_A10_EnvInsecureStillWarns(t *testing.T) {
	t.Parallel()
	cfg := mustLoad(t, minimalTOML, "ALDAP_UPSTREAM_AD_MAIN_TLS_INSECURE_SKIP_VERIFY=true")
	rep := validate(cfg)
	if !hasIssue(rep.Warnings, "upstream.ad-main.tls_insecure_skip_verify", "disabled") {
		t.Errorf("env-set tls_insecure_skip_verify not warned: %v", rep.Warnings)
	}
	cfg = mustLoad(t, minimalTOML, "ALDAP_PROFILE_APP_ANONYMOUS_BIND=true", "ALDAP_PROFILE_APP_TRANSPORT=ldap")
	rep = validate(cfg)
	if !hasIssue(rep.Warnings, "profile.app.anonymous_bind", "") || !hasIssue(rep.Warnings, "profile.app.transport", "clear text") {
		t.Errorf("env-set anonymous_bind/transport not warned: %v", rep.Warnings)
	}
}

func TestAudit14_A10_EnvAttrsStarRejected(t *testing.T) {
	t.Parallel()
	for _, v := range []string{"*", "cn,*", " * ", "+"} {
		cfg := mustLoad(t, minimalTOML, "ALDAP_PROFILE_APP_ATTRS_ALLOW="+v)
		if rep := validate(cfg); !hasIssue(rep.Errors, "profile.app.attrs.allow[0]", "not allowed") && !hasIssue(rep.Errors, "profile.app.attrs.allow[1]", "not allowed") {
			t.Errorf("ATTRS_ALLOW=%q accepted: %v", v, rep.Errors)
		}
	}
}

// Control characters in env values must not pass into security-relevant
// strings unnoticed.
func TestAudit14_A10_EnvControlChars(t *testing.T) {
	t.Parallel()
	tests := []struct{ env, path string }{
		{"ALDAP_SERVER_LOG_LEVEL=debug\n", "server.log_level"},
		{"ALDAP_PROFILE_APP_LISTEN=:636\x00", "profile.app.listen[0]"},
		{"ALDAP_RATELIMIT_ALLOW_CIDRS=10.0.0.0/8\x00", "ratelimit.allow_cidrs[0]"},
		{"ALDAP_UPSTREAM_AD_MAIN_SERVERS=ldaps://a\r\nX", "upstream.ad-main.servers[0]"},
	}
	for _, tt := range tests {
		cfg, err := loadString(t, minimalTOML, tt.env)
		if err != nil {
			continue // rejected at load: fine
		}
		if rep := validate(cfg); !hasIssue(rep.Errors, tt.path, "") {
			t.Errorf("%q accepted silently: %v", tt.env, rep.Errors)
		}
	}
}

// Two env forms of one secret (x and x_file) are "secret in two sources";
// SPEC §3.2 says the validator forbids more than one. The overlay instead
// keeps the one that sorts last and clears the other silently.
func TestAudit14_A10_EnvTwoSecretSources(t *testing.T) {
	t.Parallel()
	_, err := loadString(t, minimalTOML,
		"ALDAP_UPSTREAM_AD_MAIN_BIND_PASSWORD=inline-value",
		"ALDAP_UPSTREAM_AD_MAIN_BIND_PASSWORD_FILE=/run/secrets/other")
	if err == nil {
		t.Error("two env sources of one secret accepted without error")
	}
}

// A profile named with '_' and one named with '-' normalise to the same
// env spelling: the overlay applies to whichever map iteration finds first.
func TestAudit14_A10_EnvAmbiguousTableName(t *testing.T) {
	t.Parallel()
	body := "[profile.my-app]\nlisten=[\":1\"]\n[profile.my_app]\nlisten=[\":2\"]\n"
	_, err := loadString(t, body, "ALDAP_PROFILE_MY_APP_ANONYMOUS_BIND=true")
	if err == nil {
		t.Error("env variable matching two profile tables accepted without error")
	}
}

// --- 3. include ---------------------------------------------------------------

// Included files are meant for profiles and upstreams (SPEC §3.4 [server]
// include) but may redefine any global table: an include directory with
// looser permissions lets its writers switch global controls off.
func TestAudit14_A10_IncludeOverridesGlobalTables(t *testing.T) {
	t.Parallel()
	files := map[string]string{
		"/etc/aldap/aldap.toml": "[server]\ninclude = [\"conf.d/*.toml\"]\n[ratelimit]\nenabled = true\n[api]\nenabled = false\n",
		"/etc/aldap/conf.d/p.toml": "[ratelimit]\nenabled = false\nallow_cidrs = [\"0.0.0.0/0\"]\n[api]\nenabled = true\nlisten = \"127.0.0.1:8636\"\n" +
			"[[api.token]]\nname = \"evil\"\ntoken = \"0123456789abcdef0123456789abcdef\"\nscopes = [\"admin\"]\n[tls]\nmin_version = \"1.2\"\n[server]\nlog_level = \"error\"\n",
	}
	cfg, err := loadFS(t, files, nil, "/etc/aldap/aldap.toml")
	if err != nil {
		t.Logf("include refused: %v", err)
		return
	}
	if !cfg.Ratelimit.Enabled || cfg.API.Enabled || len(cfg.API.Tokens) != 0 || cfg.Server.LogLevel != "info" {
		t.Errorf("included file redefined global tables: ratelimit.enabled=%v api.enabled=%v tokens=%d log_level=%s",
			cfg.Ratelimit.Enabled, cfg.API.Enabled, len(cfg.API.Tokens), cfg.Server.LogLevel)
	}
}

// Behavioural evidence for the include mechanics on the real file system.
func TestAudit14_A10_IncludeBehavior(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	cfgDir := filepath.Join(dir, "etc")
	if err := os.MkdirAll(filepath.Join(cfgDir, "conf.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(p, body string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(outside, "up.toml"), "[upstream.outside-abs]\nservers=[\"ldaps://a\"]\n")
	write(filepath.Join(dir, "escaped.toml"), "[upstream.escaped-dotdot]\nservers=[\"ldaps://a\"]\n")
	write(filepath.Join(outside, "target.toml"), "[upstream.via-symlink]\nservers=[\"ldaps://a\"]\n")
	if err := os.Symlink(filepath.Join(outside, "target.toml"), filepath.Join(cfgDir, "conf.d", "link.toml")); err != nil {
		t.Skip("symlink:", err)
	}
	// An included file that carries a [server] table (a nested include) is
	// refused outright: included files define upstream/profile tables only.
	write(filepath.Join(cfgDir, "conf.d", "nested.toml"), "[server]\ninclude = [\""+filepath.Join(outside, "up.toml")+"\"]\n[upstream.nested-parent]\nservers=[\"ldaps://a\"]\n")
	main := filepath.Join(cfgDir, "aldap.toml")
	write(main, "[server]\ninclude = [\"../escaped.toml\", \""+filepath.Join(outside, "up.toml")+"\", \"conf.d/*.toml\"]\n")
	if _, err := LoadFile(main, true); !errors.Is(err, ErrIncludeScope) {
		t.Errorf("nested [server] include: err = %v, want ErrIncludeScope", err)
	}
	if err := os.Remove(filepath.Join(cfgDir, "conf.d", "nested.toml")); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(main, true)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// Documented behaviour (not a finding): ../, absolute paths and symlinks
	// are followed; the configuration directory is the operator's trust zone.
	for _, name := range []string{"outside-abs", "escaped-dotdot", "via-symlink"} {
		if _, ok := cfg.Upstreams[name]; !ok {
			t.Errorf("upstream %s not loaded; got %v", name, sortedKeys(cfg.Upstreams))
		}
	}
	// self include: the main file matched by its own glob is decoded twice
	write(main, "[server]\ninclude = [\"*.toml\"]\n[upstream.self]\nservers=[\"ldaps://a\"]\n")
	if _, err := LoadFile(main, true); !errors.Is(err, ErrIncludeScope) && !errors.Is(err, ErrDuplicateName) {
		t.Errorf("self include: err = %v", err)
	}
}

// --- 6. aldap check: leaks via error texts ------------------------------------

// A password written without quotes (operator typo) must not come back in
// the TOML parse error that `aldap check`, PUT /v1/config and the reload
// event print.
func TestAudit14_A10_ParseErrorNoSecret(t *testing.T) {
	t.Parallel()
	const pw = "Sup3rSecretBareWord99"
	for _, body := range []string{
		"[upstream.u]\nservers=[\"ldaps://a\"]\nbind_dn=\"cn=a\"\nbind_password = " + pw + "\n",
		"[upstream.u]\nservers=[\"ldaps://a\"]\nbind_dn=\"cn=a\"\nbind_password = \"" + pw + "\n",
		"[upstream.u]\nservers=[\"ldaps://a\"]\nbind_dn=\"cn=a\"\nbind_password = " + pw + "\"\n",
		"[upstream.u]\nservers=[\"ldaps://a\"]\nbind_dn=\"cn=a\"\nbind_password = \"" + pw + "\" extra\n",
		"[upstream.u]\nservers=[\"ldaps://a\"]\nbind_dn=\"cn=a\"\nbind_password = [\"" + pw + "\"]\n",
		"[upstream.u]\nservers=[\"ldaps://a\"]\nbind_dn=\"cn=a\"\nbind_password = { v = \"" + pw + "\" }\n",
		"[upstream.u]\nservers=[\"ldaps://a\"]\nbind_dn=\"cn=a\"\nbind_password = 12345678\n",
	} {
		_, err := loadString(t, body)
		if err == nil {
			t.Errorf("accepted:\n%s", body)
			continue
		}
		if strings.Contains(err.Error(), pw) {
			t.Errorf("parse error echoes the secret: %v\nconfig:\n%s", err, body)
		}
	}
}

// --- 7. defaults vs SPEC §3.4 ---------------------------------------------------

func TestAudit14_A10_DefaultsMatchSpec(t *testing.T) {
	t.Parallel()
	c, u, p, w, ch := Default(), DefaultUpstream(), DefaultProfile(), DefaultWebhook(), DefaultChannel()
	got := map[string]any{
		"server.log_level": c.Server.LogLevel, "server.log_format": c.Server.LogFormat, "server.max_connections": c.Server.MaxConnections,
		"server.shutdown_timeout": c.Server.ShutdownTimeout, "server.ipc_socket": c.Server.IPCSocket,
		"tls.mode": c.TLS.Mode, "tls.min_version": c.TLS.MinVersion, "tls.client_auth": c.TLS.ClientAuth,
		"tls.auto_renew_before": c.TLS.AutoRenewBefore, "tls.expiry_alert_before": c.TLS.ExpiryAlertBefore, "tls.key_type": c.TLS.KeyType,
		"ratelimit.enabled": c.Ratelimit.Enabled, "ratelimit.ip.max_failures": c.Ratelimit.IP.MaxFailures, "ratelimit.ip.window": c.Ratelimit.IP.Window,
		"ratelimit.ip.lock_duration": c.Ratelimit.IP.LockDuration, "ratelimit.ip.bind_rps": c.Ratelimit.IP.BindRPS, "ratelimit.ip.bind_burst": c.Ratelimit.IP.BindBurst,
		"ratelimit.ip.search_rps": c.Ratelimit.IP.SearchRPS, "ratelimit.ip.search_burst": c.Ratelimit.IP.SearchBurst,
		"ratelimit.account.max_failures": c.Ratelimit.Account.MaxFailures, "ratelimit.account.window": c.Ratelimit.Account.Window,
		"ratelimit.account.lock_duration": c.Ratelimit.Account.LockDuration, "ratelimit.negative_cache_ttl": c.Ratelimit.NegativeCacheTTL,
		"ratelimit.delay.base": c.Ratelimit.Delay.Base, "ratelimit.delay.max": c.Ratelimit.Delay.Max,
		"ratelimit.constant_time_bind_fail": c.Ratelimit.ConstantTimeBindFail, "ratelimit.lock_response": c.Ratelimit.LockResponse,
		"ratelimit.tarpit.enabled": c.Ratelimit.Tarpit.Enabled, "ratelimit.tarpit.delay": c.Ratelimit.Tarpit.Delay, "ratelimit.tarpit.max_conns": c.Ratelimit.Tarpit.MaxConns,
		"ratelimit.lockdown.auto": c.Ratelimit.Lockdown.Auto,
		"ids.summary_interval":    c.Intrusion.SummaryInterval, "ids.quiet_period": c.Intrusion.QuietPeriod,
		"ids.spray.enabled": c.Intrusion.Spray.Enabled, "ids.spray.window": c.Intrusion.Spray.Window, "ids.spray.min_accounts": c.Intrusion.Spray.MinAccounts, "ids.spray.same_password_hash": c.Intrusion.Spray.SamePasswordHash,
		"ids.stuffing.enabled": c.Intrusion.Stuffing.Enabled, "ids.stuffing.window": c.Intrusion.Stuffing.Window, "ids.stuffing.min_pairs": c.Intrusion.Stuffing.MinPairs,
		"ids.slow_brute.enabled": c.Intrusion.SlowBrute.Enabled, "ids.slow_brute.window": c.Intrusion.SlowBrute.Window, "ids.slow_brute.min_failures": c.Intrusion.SlowBrute.MinFailures, "ids.slow_brute.max_rate_per_min": c.Intrusion.SlowBrute.MaxRatePerMin,
		"ids.enumeration.enabled": c.Intrusion.Enumeration.Enabled, "ids.enumeration.min_accounts": c.Intrusion.Enumeration.MinAccounts,
		"ids.recon.enabled": c.Intrusion.Recon.Enabled, "ids.anomaly.enabled": c.Intrusion.Anomaly.Enabled, "ids.anomaly.learn_for": c.Intrusion.Anomaly.LearnFor,
		"ids.honeytoken.enabled": c.Intrusion.Honeytoken.Enabled, "ids.fingerprint.enabled": c.Intrusion.Fingerprint.Enabled,
		"events.schema": c.Events.Schema, "events.buffer_size": c.Events.BufferSize, "events.stdout.enabled": c.Events.Stdout.Enabled, "events.stdout.format": c.Events.Stdout.Format,
		"events.file.max_size_mb": c.Events.File.MaxSizeMB, "events.file.max_files": c.Events.File.MaxFiles, "events.file.compress": c.Events.File.Compress,
		"events.webhook.batch_size": w.BatchSize, "events.webhook.batch_interval": w.BatchInterval, "events.webhook.timeout": w.Timeout, "events.webhook.retry.max": w.Retry.Max,
		"events.webhook.retry.backoff": w.Retry.Backoff, "events.webhook.retry.max_backoff": w.Retry.MaxBackoff, "events.webhook.queue_size": w.QueueSize, "events.webhook.on_overflow": w.OnOverflow,
		"notify.cooldown": c.Notify.Cooldown, "notify.digest_interval": c.Notify.DigestInterval, "notify.channel.parse_mode": ch.ParseMode, "notify.channel.api_base": ch.APIBase, "notify.channel.method": ch.Method,
		"notify.channel.events": strings.Join(ch.Events, ","),
		"api.enabled":           c.API.Enabled, "api.listen": c.API.Listen, "api.client_auth": c.API.ClientAuth, "api.rate_limit_rps": c.API.RateLimitRPS, "api.metrics.enabled": c.API.Metrics.Enabled, "api.metrics.public": c.API.Metrics.Public, "api.cors": c.API.CORS,
		"upstream.kind": u.Kind, "upstream.tls_insecure_skip_verify": u.TLSInsecureSkipVerify, "upstream.starttls": u.StartTLS, "upstream.health_interval": u.HealthInterval, "upstream.health_check": u.HealthCheck,
		"upstream.failover.fail_threshold": u.Failover.FailThreshold, "upstream.failover.recover_threshold": u.Failover.RecoverThreshold, "upstream.failover.prefer_primary": u.Failover.PreferPrimary,
		"upstream.pool.size": u.Pool.Size, "upstream.pool.max_idle": u.Pool.MaxIdle, "upstream.timeouts.connect": u.Timeouts.Connect, "upstream.timeouts.bind": u.Timeouts.Bind, "upstream.timeouts.search": u.Timeouts.Search,
		"upstream.page_size": u.PageSize, "upstream.audit_service_account": u.AuditServiceAccount,
		"profile.transport": p.Transport, "profile.mode": p.Mode, "profile.rdn_attr": p.RDNAttr, "profile.anonymous_bind": p.AnonymousBind, "profile.user_bind.allow": p.UserBind.Allow, "profile.nested_depth": p.NestedDepth,
		"profile.limits.max_result_size": p.Limits.MaxResultSize, "profile.limits.max_filter_depth": p.Limits.MaxFilterDepth, "profile.limits.max_filter_len": p.Limits.MaxFilterLen,
		"profile.limits.max_request_bytes": int64(p.Limits.MaxRequestBytes), "profile.limits.max_conns_per_ip": p.Limits.MaxConnsPerIP, "profile.limits.idle_timeout": p.Limits.IdleTimeout,
		"profile.cache.mode": p.Cache.Mode, "profile.proxy_protocol.enabled": p.ProxyProtocol.Enabled, "profile.starttls_required": p.StartTLSRequired,
	}
	want := map[string]any{
		"server.log_level": "info", "server.log_format": "text", "server.max_connections": 1024, "server.shutdown_timeout": d(30 * time.Second), "server.ipc_socket": "/run/aldap/aldap.sock",
		"tls.mode": "builtin-ca", "tls.min_version": "1.2", "tls.client_auth": "none", "tls.auto_renew_before": d(720 * time.Hour), "tls.expiry_alert_before": d(336 * time.Hour), "tls.key_type": "ecdsa-p256",
		"ratelimit.enabled": true, "ratelimit.ip.max_failures": 20, "ratelimit.ip.window": d(5 * time.Minute), "ratelimit.ip.lock_duration": d(15 * time.Minute),
		"ratelimit.ip.bind_rps": 10, "ratelimit.ip.bind_burst": 20, "ratelimit.ip.search_rps": 50, "ratelimit.ip.search_burst": 100,
		"ratelimit.account.max_failures": 3, "ratelimit.account.window": d(10 * time.Minute), "ratelimit.account.lock_duration": d(15 * time.Minute), "ratelimit.negative_cache_ttl": d(60 * time.Second),
		"ratelimit.delay.base": d(250 * time.Millisecond), "ratelimit.delay.max": d(4 * time.Second), "ratelimit.constant_time_bind_fail": true, "ratelimit.lock_response": "invalidCredentials",
		"ratelimit.tarpit.enabled": false, "ratelimit.tarpit.delay": d(30 * time.Second), "ratelimit.tarpit.max_conns": 64, "ratelimit.lockdown.auto": false,
		"ids.summary_interval": d(5 * time.Minute), "ids.quiet_period": d(15 * time.Minute),
		"ids.spray.enabled": true, "ids.spray.window": d(10 * time.Minute), "ids.spray.min_accounts": 5, "ids.spray.same_password_hash": true,
		"ids.stuffing.enabled": true, "ids.stuffing.window": d(5 * time.Minute), "ids.stuffing.min_pairs": 20,
		"ids.slow_brute.enabled": true, "ids.slow_brute.window": d(6 * time.Hour), "ids.slow_brute.min_failures": 30, "ids.slow_brute.max_rate_per_min": 2,
		"ids.enumeration.enabled": true, "ids.enumeration.min_accounts": 10, "ids.recon.enabled": true, "ids.anomaly.enabled": true, "ids.anomaly.learn_for": d(24 * time.Hour),
		"ids.honeytoken.enabled": true, "ids.fingerprint.enabled": false,
		"events.schema": "aldap.event.v1", "events.buffer_size": 100000, "events.stdout.enabled": true, "events.stdout.format": "json",
		"events.file.max_size_mb": 100, "events.file.max_files": 10, "events.file.compress": true,
		"events.webhook.batch_size": 100, "events.webhook.batch_interval": d(2 * time.Second), "events.webhook.timeout": d(5 * time.Second), "events.webhook.retry.max": 5,
		"events.webhook.retry.backoff": d(time.Second), "events.webhook.retry.max_backoff": d(60 * time.Second), "events.webhook.queue_size": 10000, "events.webhook.on_overflow": "drop_oldest",
		"notify.cooldown": d(10 * time.Minute), "notify.digest_interval": d(15 * time.Minute), "notify.channel.parse_mode": "MarkdownV2", "notify.channel.api_base": "https://api.telegram.org", "notify.channel.method": "POST",
		"notify.channel.events": "attack_start,attack_summary,attack_end,lock_account,upstream_down,upstream_up,cert_expiring,honeytoken,lockdown",
		"api.enabled":           false, "api.listen": "127.0.0.1:8636", "api.client_auth": "none", "api.rate_limit_rps": 50, "api.metrics.enabled": true, "api.metrics.public": false, "api.cors": false,
		"upstream.kind": "ad", "upstream.tls_insecure_skip_verify": false, "upstream.starttls": false, "upstream.health_interval": d(10 * time.Second), "upstream.health_check": "rootdse",
		"upstream.failover.fail_threshold": 3, "upstream.failover.recover_threshold": 2, "upstream.failover.prefer_primary": true,
		"upstream.pool.size": 4, "upstream.pool.max_idle": d(5 * time.Minute), "upstream.timeouts.connect": d(5 * time.Second), "upstream.timeouts.bind": d(5 * time.Second), "upstream.timeouts.search": d(30 * time.Second),
		"upstream.page_size": 500, "upstream.audit_service_account": true,
		"profile.transport": "ldaps", "profile.mode": "proxy", "profile.rdn_attr": "cn", "profile.anonymous_bind": false, "profile.user_bind.allow": true, "profile.nested_depth": 10,
		"profile.limits.max_result_size": 5000, "profile.limits.max_filter_depth": 20, "profile.limits.max_filter_len": 4096, "profile.limits.max_request_bytes": int64(1 << 20),
		"profile.limits.max_conns_per_ip": 32, "profile.limits.idle_timeout": d(10 * time.Minute),
		"profile.cache.mode": "none", "profile.proxy_protocol.enabled": false, "profile.starttls_required": false,
	}
	for k, w := range want {
		g, ok := got[k]
		if !ok {
			t.Errorf("%s: not compared", k)
			continue
		}
		if fmt.Sprint(g) != fmt.Sprint(w) {
			t.Errorf("%s: code %v, SPEC %v", k, g, w)
		}
	}
	// the example file must not weaken a default silently
	if c.Profiles == nil || c.Upstreams == nil {
		t.Error("named tables must be non-nil maps")
	}
}

// hasIssuePrefix reports an issue at path or at an element of it (path[0]).
func hasIssuePrefix(list []Issue, path string) bool {
	for _, is := range list {
		if is.Path == path || strings.HasPrefix(is.Path, path+"[") {
			return true
		}
	}
	return false
}
