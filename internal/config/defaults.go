package config

import (
	"runtime"
	"time"
)

// DefaultADFilter is the profile filter applied for kind = ad when none is set:
// enabled person accounts only.
const DefaultADFilter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

// EventKinds lists the SPEC §6 event types; TestEventKindsInSync
// (internal/events) keeps it equal to the enum of docs/events.schema.json.
var EventKinds = []string{
	"bind_ok", "bind_fail", "bind_blocked", "lock", "unlock", "attack_start", "attack_summary", "attack_end",
	"recon", "anomaly", "honeytoken", "search", "op_denied", "session_summary", "rate_limited", "tarpit",
	"lockdown", "upstream_down", "upstream_up", "stale_served", "replica_sync_failed", "replica_synced",
	"cert_expiring", "cert_renewed", "config_reload", "insecure_config", "shadow_diff", "api_call",
	"startup", "shutdown",
}

// NotifyLockAliases are the [[notify.channel]].events names that select
// lock events by data.target (SPEC §3.4 lists lock_account by default).
var NotifyLockAliases = map[string]string{"lock_account": "account", "lock_ip": "ip"}

// NotifyTemplateFuncs names the functions available in notification
// templates (internal/notify); the validator parses templates with stubs
// of these names. TestTemplateFuncsInSync (internal/notify) keeps the
// list equal to the implementation.
var NotifyTemplateFuncs = []string{"get", "join", "json", "md", "html", "upper", "lower", "default"}

// ProfileTemplateFuncs names the functions available in profile templates
// (attrs.computed and honeytoken_template, internal/profile) besides the
// text/template built-ins (or, printf, …); the validator parses templates
// with stubs of these names. TestTemplateFuncsInSync (internal/profile)
// keeps the list equal to the implementation.
var ProfileTemplateFuncs = []string{"lower", "upper", "trim", "default", "first", "join", "regexReplace"}

// DefaultChannelEvents is the event list of a notification channel without an explicit one.
var DefaultChannelEvents = []string{
	"attack_start", "attack_summary", "attack_end", "lock_account",
	"upstream_down", "upstream_up", "cert_expiring", "honeytoken", "lockdown",
}

func d(v time.Duration) Duration { return Duration(v) }

// DefaultIPCSocket is the default [server].ipc_socket of the platform; aldapctl
// dials it without reading the configuration.
func DefaultIPCSocket() string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\aldap`
	}
	return "/run/aldap/aldap.sock"
}

// Default returns the built-in defaults for every section (SPEC §3.4).
// Named tables (upstream, profile) are empty; see DefaultUpstream and DefaultProfile.
func Default() *Config {
	return &Config{
		Server: Server{
			LogLevel:        "info",
			LogFormat:       "text",
			IPCSocket:       DefaultIPCSocket(),
			ShutdownTimeout: d(30 * time.Second),
			MaxConnections:  1024,
		},
		TLS: TLS{
			Mode:              "builtin-ca",
			CADir:             "/var/lib/aldap/ca",
			AutoInit:          true,
			AutoRenewBefore:   d(720 * time.Hour),
			ExpiryAlertBefore: d(336 * time.Hour),
			KeyType:           "ecdsa-p256",
			MinVersion:        "1.2",
			ClientAuth:        "none",
		},
		Ratelimit: Ratelimit{
			Enabled:              true,
			NegativeCacheTTL:     d(60 * time.Second),
			ConstantTimeBindFail: true,
			LockResponse:         "invalidCredentials",
			IP: IPLimits{
				MaxFailures: 20, Window: d(5 * time.Minute), LockDuration: d(15 * time.Minute),
				BindRPS: 10, BindBurst: 20, SearchRPS: 50, SearchBurst: 100,
			},
			Account:  AccountLimits{MaxFailures: 3, Window: d(10 * time.Minute), LockDuration: d(15 * time.Minute)},
			Delay:    DelayLimits{Base: d(250 * time.Millisecond), Max: d(4 * time.Second)},
			Tarpit:   Tarpit{Enabled: false, Delay: d(30 * time.Second), MaxConns: 64},
			Lockdown: Lockdown{Auto: false},
		},
		Intrusion: Intrusion{
			SummaryInterval: d(5 * time.Minute),
			QuietPeriod:     d(15 * time.Minute),
			Spray:           Spray{Enabled: true, Window: d(10 * time.Minute), MinAccounts: 5, SamePasswordHash: true},
			Stuffing:        Stuffing{Enabled: true, Window: d(5 * time.Minute), MinPairs: 20},
			SlowBrute:       SlowBrute{Enabled: true, Window: d(6 * time.Hour), MinFailures: 30, MaxRatePerMin: 2},
			Enumeration:     Enumeration{Enabled: true, MinAccounts: 10},
			Recon:           Detector{Enabled: true},
			Anomaly:         Anomaly{Enabled: true, LearnFor: d(24 * time.Hour)},
			Honeytoken:      Honeytoken{Enabled: true, LockDuration: d(24 * time.Hour)},
			Fingerprint:     Detector{Enabled: false},
			ClientIPMasked:  ClientIPMasked{Enabled: true, Window: d(10 * time.Minute), MinRequests: 50, MinSharePercent: 90, MinAccounts: 3, IgnoreCIDRs: []string{}},
		},
		Events: Events{
			Schema:     "aldap.event.v1",
			BufferSize: 100000,
			Stdout:     StdoutSink{Enabled: true, Format: "json"},
			File:       FileSink{Enabled: false, MaxSizeMB: 100, MaxFiles: 10, Compress: true},
			Syslog:     SyslogSink{Enabled: false, Network: "udp", Facility: "auth"},
		},
		Notify: Notify{
			Cooldown:       d(10 * time.Minute),
			DigestInterval: d(15 * time.Minute),
		},
		API: API{
			Enabled:      false,
			Listen:       "127.0.0.1:8636",
			ClientAuth:   "none",
			RateLimitRPS: 50,
			MaxStreams:   64,
			Metrics:      Metrics{Enabled: true, Public: false},
		},
		Upstreams: map[string]*Upstream{},
		Profiles:  map[string]*Profile{},
	}
}

// DefaultUpstream returns the defaults of one [upstream.<name>] table.
func DefaultUpstream() *Upstream {
	return &Upstream{
		Kind:                "ad",
		HealthInterval:      d(10 * time.Second),
		HealthCheck:         "rootdse",
		PageSize:            500,
		AuditServiceAccount: true,
		Failover:            Failover{FailThreshold: 3, RecoverThreshold: 2, PreferPrimary: true, Strategy: "primary"},
		Pool:                Pool{Size: 4, MaxIdle: d(5 * time.Minute)},
		Timeouts:            Timeouts{Connect: d(5 * time.Second), Bind: d(5 * time.Second), Search: d(30 * time.Second)},
	}
}

// DefaultProfile returns the defaults of one [profile.<name>] table.
// Transport defaults to ldaps and the filter to DefaultADFilter when the
// upstream kind is ad; both are applied in finalize when still empty.
func DefaultProfile() *Profile {
	return &Profile{
		Transport:          "ldaps",
		Mode:               "proxy",
		RDNAttr:            "cn",
		UserBind:           UserBind{Allow: true},
		NestedDepth:        10,
		HoneytokenInGroups: true,
		Cache:              Cache{Mode: "none", TTL: d(60 * time.Second), MaxEntries: 10000, StaleWhileDown: true, StaleMax: d(time.Hour), SyncInterval: d(5 * time.Minute), SyncJitter: 0.2},
		Limits: Limits{
			MaxResultSize: 5000, MaxFilterDepth: 20, MaxFilterLen: 4096, MaxRequestBytes: 1 << 20,
			MaxConnsPerIP: 32, IdleTimeout: d(10 * time.Minute), UpstreamParallel: 4,
		},
		Shadow:        Shadow{MaxParallel: 4, Timeout: d(10 * time.Second)},
		Record:        Record{MaxSizeMB: 100, MaxFiles: 5},
		ProxyProtocol: ProxyProtocol{TrustedCIDRs: []string{}},
	}
}

// DefaultGroup returns the defaults of one [profile.<name>.groups.<gname>] table.
func DefaultGroup() Group { return Group{ObjectClass: "groupOfNames"} }

// DefaultWebhook returns the defaults of one [[events.webhook]] table.
func DefaultWebhook() Webhook {
	return Webhook{
		BatchSize: 100, BatchInterval: d(2 * time.Second), Timeout: d(5 * time.Second),
		Retry:     Retry{Max: 5, Backoff: d(time.Second), MaxBackoff: d(60 * time.Second)},
		QueueSize: 10000, OnOverflow: "drop_oldest",
	}
}

// DefaultChannel returns the defaults of one [[notify.channel]] table.
func DefaultChannel() Channel {
	return Channel{
		Events:    append([]string(nil), DefaultChannelEvents...),
		MinLevel:  "low",
		ParseMode: "MarkdownV2",
		APIBase:   "https://api.telegram.org",
		SMTPPort:  587,
		TLSMode:   "starttls",
		Method:    "POST",
		Timeout:   d(5 * time.Second),
		Retry:     Retry{Max: 3, Backoff: d(time.Second), MaxBackoff: d(30 * time.Second)},
	}
}
