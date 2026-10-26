// Package config loads, overlays (env) and validates the TOML configuration (SPEC §3).
//
// Precedence, highest first: ALDAP_* environment variables, secret files,
// aldap.toml with its includes, built-in defaults. Unknown keys are errors.
package config

import (
	"strconv"
	"strings"

	"github.com/alstdev/aldap/internal/secret"
)

// Config is the whole ALDAP configuration after loading, overlaying and defaulting.
//
// Field tags: `toml` is the key name, `doc` the human description used for docs/config.md.
type Config struct {
	Server    Server    `toml:"server" doc:"Process-wide settings."`
	TLS       TLS       `toml:"tls" doc:"Global TLS defaults for listeners; a profile may override any key."`
	Ratelimit Ratelimit `toml:"ratelimit" doc:"Global rate limiting and locking; a profile may override any key."`
	Intrusion Intrusion `toml:"ids" doc:"Intrusion detection: detectors and their thresholds."`
	Events    Events    `toml:"events" doc:"Audit event stream and sinks."`
	Notify    Notify    `toml:"notify" doc:"Human notifications."`
	API       API       `toml:"api" doc:"Management HTTP API."`

	// Upstreams and Profiles are keyed by name ([upstream.<name>], [profile.<name>]).
	Upstreams map[string]*Upstream `toml:"-" env:"upstream" doc:"Upstream LDAP directories, one table per name."`
	Profiles  map[string]*Profile  `toml:"-" env:"profile" doc:"Client-facing profiles, one table per name."`
}

// Server holds process-wide settings ([server]).
type Server struct {
	LogLevel        string   `toml:"log_level" doc:"Log verbosity: debug, info, warn, error."`
	LogFormat       string   `toml:"log_format" doc:"Log output format: text or json."`
	IPCSocket       string   `toml:"ipc_socket" doc:"Local control channel for aldapctl without a token (unix socket 0600, named pipe on Windows)."`
	ShutdownTimeout Duration `toml:"shutdown_timeout" doc:"Graceful drain timeout on stop or reload."`
	MaxConnections  int      `toml:"max_connections" doc:"Global limit of concurrent client connections."`
	Include         []string `toml:"include" doc:"Glob patterns of additional TOML files (profiles, upstreams). Duplicate names are an error."`
}

// TLS holds listener TLS settings ([tls] and [profile.<name>.tls]).
type TLS struct {
	Mode              string   `toml:"mode" doc:"builtin-ca (certificates issued by the built-in CA) or external (cert and key given)."`
	CADir             string   `toml:"ca_dir" doc:"Directory of the built-in CA (ca.crt, ca.key 0600)."`
	AutoInit          bool     `toml:"auto_init" doc:"Create the built-in CA on first start when missing."`
	Cert              string   `toml:"cert" doc:"Server certificate path for mode = external."`
	Key               string   `toml:"key" doc:"Server private key path for mode = external (path is not a secret, content is)."`
	AutoRenewBefore   Duration `toml:"auto_renew_before" doc:"Reissue the built-in server certificate this long before expiry."`
	ExpiryAlertBefore Duration `toml:"expiry_alert_before" doc:"Emit cert_expiring this long before expiry."`
	SAN               []string `toml:"san" doc:"Additional DNS names or IPs for the server certificate."`
	KeyType           string   `toml:"key_type" doc:"Key type of certificates issued by the built-in CA: ecdsa-p256 or rsa-2048."`
	MinVersion        string   `toml:"min_version" doc:"Minimum TLS version: 1.2 or 1.3."`
	ClientAuth        string   `toml:"client_auth" doc:"Client certificates: none, request or require (mTLS)."`
	ClientCA          string   `toml:"client_ca" doc:"CA bundle used to verify client certificates."`
}

// Upstream describes one upstream directory ([upstream.<name>]).
type Upstream struct {
	Servers               []string      `toml:"servers" doc:"Server URLs in priority order: ldap://host:389 or ldaps://host:636."`
	Kind                  string        `toml:"kind" doc:"ad (Active Directory specifics enabled) or generic."`
	StartTLS              bool          `toml:"starttls" doc:"Upgrade ldap:// connections with StartTLS."`
	StartTLSRequired      bool          `toml:"starttls_required" doc:"Refuse to work when StartTLS cannot be negotiated."`
	TLSCAFile             string        `toml:"tls_ca_file" doc:"CA bundle used to verify the upstream certificate."`
	TLSInsecureSkipVerify bool          `toml:"tls_insecure_skip_verify" doc:"Disable certificate verification. Logged as a warning on every start and reported as insecure_config."`
	TLSServerName         string        `toml:"tls_server_name" doc:"SNI and expected certificate name when it differs from the host."`
	BindDN                string        `toml:"bind_dn" doc:"Service account DN used for searches (read-only)."`
	BindPassword          secret.Inline `toml:"bind_password" doc:"Service account password, inline (warned)."`
	BindPasswordFile      string        `toml:"bind_password_file" doc:"File holding the service account password."`
	BindPasswordEnv       string        `toml:"bind_password_env" doc:"Environment variable holding the service account password."`
	BaseDN                string        `toml:"base_dn" doc:"Directory root, used for RootDSE and to validate profile bases."`
	HealthInterval        Duration      `toml:"health_interval" doc:"Interval between health checks."`
	HealthCheck           string        `toml:"health_check" doc:"Health check kind: rootdse, bind or search."`
	PageSize              int           `toml:"page_size" doc:"Page size for the paged results control."`
	AuditServiceAccount   bool          `toml:"audit_service_account" doc:"On start, warn and emit insecure_config when the service account is in an administrative group."`
	Failover              Failover      `toml:"failover" doc:"Failover thresholds and strategy."`
	Pool                  Pool          `toml:"pool" doc:"Connection pool."`
	Timeouts              Timeouts      `toml:"timeouts" doc:"Operation timeouts."`
}

// BindPasswordSource returns the service account password source.
func (u *Upstream) BindPasswordSource() secret.Source {
	return secret.Source{Inline: u.BindPassword, File: u.BindPasswordFile, Env: u.BindPasswordEnv}
}

// Failover holds upstream failover settings ([upstream.<name>.failover]).
type Failover struct {
	FailThreshold    int    `toml:"fail_threshold" doc:"Consecutive failures that mark a server down."`
	RecoverThreshold int    `toml:"recover_threshold" doc:"Consecutive successes that mark a server up."`
	PreferPrimary    bool   `toml:"prefer_primary" doc:"Return to the first healthy server in the list."`
	Strategy         string `toml:"strategy" doc:"Server selection: primary or roundrobin."`
}

// Pool holds upstream connection pool settings ([upstream.<name>.pool]).
type Pool struct {
	Size    int      `toml:"size" doc:"Connections per server."`
	MaxIdle Duration `toml:"max_idle" doc:"Close idle connections after this long."`
}

// Timeouts holds upstream operation timeouts ([upstream.<name>.timeouts]).
type Timeouts struct {
	Connect Duration `toml:"connect" doc:"TCP and TLS connect timeout."`
	Bind    Duration `toml:"bind" doc:"Bind timeout."`
	Search  Duration `toml:"search" doc:"Search timeout."`
}

// Ratelimit holds limits and locking ([ratelimit]).
type Ratelimit struct {
	Enabled              bool          `toml:"enabled" doc:"Enable rate limiting and locks."`
	NegativeCacheTTL     Duration      `toml:"negative_cache_ttl" doc:"Remember a failed (account, password hash) pair this long and do not retry it upstream."`
	ConstantTimeBindFail bool          `toml:"constant_time_bind_fail" doc:"Pad every failed bind to the p95 latency of successful binds (anti-enumeration)."`
	LockResponse         string        `toml:"lock_response" doc:"LDAP result for locked clients: invalidCredentials or busy."`
	AllowCIDRs           []string      `toml:"allow_cidrs" doc:"Source networks exempt from limits."`
	AllowAccounts        []string      `toml:"allow_accounts" doc:"Accounts exempt from locking."`
	IP                   IPLimits      `toml:"ip" doc:"Per-source-IP limits."`
	Account              AccountLimits `toml:"account" doc:"Per-account limits."`
	Delay                DelayLimits   `toml:"delay" doc:"Progressive delay after failures."`
	Tarpit               Tarpit        `toml:"tarpit" doc:"Tarpit for sources in attack state."`
	Lockdown             Lockdown      `toml:"lockdown" doc:"Lockdown mode."`
}

// IPLimits holds per-IP limits ([ratelimit.ip]).
type IPLimits struct {
	MaxFailures  int      `toml:"max_failures" doc:"Failed binds from one IP within window that trigger a lock."`
	Window       Duration `toml:"window" doc:"Failure counting window."`
	LockDuration Duration `toml:"lock_duration" doc:"How long a locked IP stays locked."`
	BindRPS      int      `toml:"bind_rps" doc:"Sustained binds per second (token bucket)."`
	BindBurst    int      `toml:"bind_burst" doc:"Bind burst size."`
	SearchRPS    int      `toml:"search_rps" doc:"Sustained searches per second."`
	SearchBurst  int      `toml:"search_burst" doc:"Search burst size."`
}

// AccountLimits holds per-account limits ([ratelimit.account]).
type AccountLimits struct {
	MaxFailures  int      `toml:"max_failures" doc:"Failed binds per account within window that trigger a lock. Keep it below the directory lockout threshold."`
	Window       Duration `toml:"window" doc:"Failure counting window."`
	LockDuration Duration `toml:"lock_duration" doc:"How long a locked account stays locked."`
}

// DelayLimits holds progressive delay settings ([ratelimit.delay]).
type DelayLimits struct {
	Base Duration `toml:"base" doc:"Delay after the first failure; doubles on each next failure."`
	Max  Duration `toml:"max" doc:"Upper bound of the delay."`
}

// Tarpit holds tarpit settings ([ratelimit.tarpit]).
type Tarpit struct {
	Enabled  bool     `toml:"enabled" doc:"Hold connections from attacking sources and answer slowly."`
	Delay    Duration `toml:"delay" doc:"Response delay for tarpitted connections."`
	MaxConns int      `toml:"max_conns" doc:"Maximum tarpitted connections held at once."`
}

// Lockdown holds lockdown settings ([ratelimit.lockdown]).
type Lockdown struct {
	Auto          bool     `toml:"auto" doc:"Enter lockdown automatically on a high level attack_start."`
	AllowCIDRs    []string `toml:"allow_cidrs" doc:"Source networks still served during lockdown."`
	AllowAccounts []string `toml:"allow_accounts" doc:"Accounts still served during lockdown."`
}

// Intrusion holds detector settings ([ids]).
type Intrusion struct {
	SummaryInterval Duration       `toml:"summary_interval" doc:"Interval of attack_summary events during an attack."`
	QuietPeriod     Duration       `toml:"quiet_period" doc:"Silence after which attack_end is emitted."`
	Spray           Spray          `toml:"spray" doc:"Password spray detector."`
	Stuffing        Stuffing       `toml:"stuffing" doc:"Credential stuffing detector."`
	SlowBrute       SlowBrute      `toml:"slow_brute" doc:"Slow brute force detector."`
	Enumeration     Enumeration    `toml:"enumeration" doc:"Account enumeration detector."`
	Recon           Detector       `toml:"recon" doc:"Reconnaissance search signatures."`
	Anomaly         Anomaly        `toml:"anomaly" doc:"Baseline and anomaly detector."`
	Honeytoken      Honeytoken     `toml:"honeytoken" doc:"Honeytoken detector."`
	Fingerprint     Detector       `toml:"fingerprint" doc:"TLS and LDAP client fingerprint detector."`
	ClientIPMasked  ClientIPMasked `toml:"client_ip_masked" doc:"Detector of a proxy or container network that replaces client addresses with its own (insecure_config what=client_ip_masked)."`
}

// ClientIPMasked holds the detector of hidden client addresses
// ([ids.client_ip_masked]): most binds and searches arriving from one
// private address for several accounts means a NAT, proxy or container
// network (podman-compose, a custom Podman network) stands between the
// clients and ALDAP, and per-IP limits, allow_cidrs and the IDS see only
// that address.
type ClientIPMasked struct {
	Enabled         bool     `toml:"enabled" doc:"Enable the detector."`
	Window          Duration `toml:"window" doc:"Observation window."`
	MinRequests     int      `toml:"min_requests" doc:"Binds and searches within window needed before the share is judged."`
	MinSharePercent int      `toml:"min_share_percent" doc:"Share (percent) of the binds and searches from one private address that triggers the detector."`
	MinAccounts     int      `toml:"min_accounts" doc:"Distinct accounts seen from that address that trigger the detector."`
	IgnoreCIDRs     []string `toml:"ignore_cidrs" doc:"Sources never reported, e.g. an application server that binds on behalf of its users."`
}

// Detector is a detector with only an on/off switch.
type Detector struct {
	Enabled bool `toml:"enabled" doc:"Enable the detector."`
}

// Spray holds spray detector settings ([ids.spray]).
type Spray struct {
	Enabled          bool     `toml:"enabled" doc:"Enable the detector."`
	Window           Duration `toml:"window" doc:"Observation window."`
	MinAccounts      int      `toml:"min_accounts" doc:"Distinct accounts tried from one source that trigger the detector."`
	SamePasswordHash bool     `toml:"same_password_hash" doc:"Require the same password hash across accounts."`
}

// Stuffing holds stuffing detector settings ([ids.stuffing]).
type Stuffing struct {
	Enabled  bool     `toml:"enabled" doc:"Enable the detector."`
	Window   Duration `toml:"window" doc:"Observation window."`
	MinPairs int      `toml:"min_pairs" doc:"Distinct (account, password) pairs from one IP that trigger the detector."`
}

// SlowBrute holds slow brute force detector settings ([ids.slow_brute]).
type SlowBrute struct {
	Enabled       bool     `toml:"enabled" doc:"Enable the detector."`
	Window        Duration `toml:"window" doc:"Observation window."`
	MinFailures   int      `toml:"min_failures" doc:"Failures within window that trigger the detector."`
	MaxRatePerMin int      `toml:"max_rate_per_min" doc:"Upper rate (per minute) still counted as slow."`
}

// Enumeration holds enumeration detector settings ([ids.enumeration]).
type Enumeration struct {
	Enabled     bool `toml:"enabled" doc:"Enable the detector."`
	MinAccounts int  `toml:"min_accounts" doc:"Consecutive distinct accounts without a success that trigger the detector."`
}

// Anomaly holds anomaly detector settings ([ids.anomaly]).
type Anomaly struct {
	Enabled  bool     `toml:"enabled" doc:"Enable the detector."`
	LearnFor Duration `toml:"learn_for" doc:"Baseline learning period after start."`
}

// Honeytoken holds honeytoken detector settings ([ids.honeytoken]).
type Honeytoken struct {
	Enabled      bool     `toml:"enabled" doc:"Enable the detector."`
	LockDuration Duration `toml:"lock_duration" doc:"Lock duration applied to a source that touches a honeytoken."`
}

// Profile describes one client-facing profile ([profile.<name>]).
type Profile struct {
	Listen             []string          `toml:"listen" doc:"Listen addresses, e.g. \":636\" or \"10.0.0.5:636\", or \"systemd:<name>\" for the sockets systemd passes with that FileDescriptorName= (socket activation)."`
	ProxyProtocol      ProxyProtocol     `toml:"proxy_protocol" doc:"PROXY protocol v1/v2 header from a trusted proxy in front of the listeners (client address from the header)."`
	Transport          string            `toml:"transport" doc:"ldaps, ldap, starttls or ldap+starttls (plain allowed, StartTLS optional)."`
	StartTLSRequired   bool              `toml:"starttls_required" doc:"Reject binds without TLS with confidentialityRequired."`
	TLS                TLSOverride       `toml:"tls" doc:"Overrides of [tls] for this profile."`
	Upstream           string            `toml:"upstream" doc:"Name of the upstream to use."`
	Mode               string            `toml:"mode" doc:"proxy, honeypot (every request is a honeytoken hit) or mock (answers from mock.file, no upstream)."`
	Mock               Mock              `toml:"mock" doc:"Mock mode source."`
	VirtualBase        string            `toml:"virtual_base" doc:"DN the client sees; all DNs are rewritten under it and bases outside it get noSuchObject."`
	Bases              []string          `toml:"bases" doc:"Real upstream subtrees searched for users."`
	Filter             string            `toml:"filter" doc:"Mandatory filter AND-ed to every client filter. Default for kind = ad selects enabled person accounts."`
	ExcludeFilter      string            `toml:"exclude_filter" doc:"Optional filter NOT-ed to every client filter."`
	Attrs              Attrs             `toml:"attrs" doc:"Attribute policy."`
	ObjectClass        ObjectClass       `toml:"objectclass" doc:"Object class rewriting."`
	RDNAttr            string            `toml:"rdn_attr" doc:"Attribute used as RDN in virtual user DNs."`
	ClientBind         ClientBind        `toml:"client_bind" doc:"Local service login of the application; without it only user binds are possible."`
	UserBind           UserBind          `toml:"user_bind" doc:"User bind policy."`
	AnonymousBind      bool              `toml:"anonymous_bind" doc:"Allow anonymous bind."`
	Groups             map[string]Group  `toml:"groups" doc:"Virtual groups, one table per group name."`
	NestedGroups       bool              `toml:"nested_groups" doc:"Transitive memberOf."`
	NestedDepth        int               `toml:"nested_depth" doc:"Recursion limit for nested groups on generic upstreams."`
	Honeytokens        []string          `toml:"honeytokens" doc:"Trap accounts returned as ordinary users."`
	HoneytokenInGroups bool              `toml:"honeytoken_in_groups" doc:"List honeytokens as members of virtual groups."`
	HoneytokenTemplate map[string]string `toml:"honeytoken_template" doc:"Attribute templates for honeytoken entries."`
	Cache              Cache             `toml:"cache" doc:"Cache mode."`
	Limits             Limits            `toml:"limits" doc:"Request and connection limits."`
	Ratelimit          RatelimitPatch    `toml:"ratelimit" doc:"Overrides of [ratelimit] for this profile; unset keys inherit."`
	Shadow             Shadow            `toml:"shadow" doc:"Shadow rules evaluated in parallel; differences are reported as shadow_diff."`
	Record             Record            `toml:"record" doc:"Request recording for replay."`
}

// ListenSystemdPrefix marks a profile listen entry naming sockets
// inherited from systemd (LISTEN_FDNAMES) instead of an address.
const ListenSystemdPrefix = "systemd:"

// ProxyProtocol holds [profile.<name>.proxy_protocol].
type ProxyProtocol struct {
	Enabled      bool     `toml:"enabled" doc:"Accept a PROXY protocol v1 or v2 header from trusted_cidrs; the header's source address becomes the client address."`
	TrustedCIDRs []string `toml:"trusted_cidrs" doc:"Proxy addresses whose header is accepted (required when enabled). A connection from elsewhere that sends a header is closed and reported as insecure_config."`
}

// TLSOverride is a partial TLS section: unset keys inherit from [tls].
type TLSOverride struct {
	Mode              *string   `toml:"mode" doc:"See tls.mode."`
	CADir             *string   `toml:"ca_dir" doc:"See tls.ca_dir."`
	AutoInit          *bool     `toml:"auto_init" doc:"See tls.auto_init."`
	Cert              *string   `toml:"cert" doc:"See tls.cert."`
	Key               *string   `toml:"key" doc:"See tls.key."`
	AutoRenewBefore   *Duration `toml:"auto_renew_before" doc:"See tls.auto_renew_before."`
	ExpiryAlertBefore *Duration `toml:"expiry_alert_before" doc:"See tls.expiry_alert_before."`
	SAN               *[]string `toml:"san" doc:"See tls.san."`
	KeyType           *string   `toml:"key_type" doc:"See tls.key_type."`
	MinVersion        *string   `toml:"min_version" doc:"See tls.min_version."`
	ClientAuth        *string   `toml:"client_auth" doc:"See tls.client_auth."`
	ClientCA          *string   `toml:"client_ca" doc:"See tls.client_ca."`
}

// Mock holds mock mode settings ([profile.<name>.mock]).
type Mock struct {
	File string `toml:"file" doc:"TOML or CSV file with the entries served in mock mode."`
}

// Attrs holds the attribute policy ([profile.<name>.attrs]).
type Attrs struct {
	Allow    []string          `toml:"allow" doc:"Attributes returned to clients. \"*\" is rejected; operational attributes only when listed."`
	Map      map[string]string `toml:"map" doc:"client_name = \"upstream_name\" renames."`
	Computed map[string]string `toml:"computed" doc:"name = \"go-template\" computed attributes."`
	Mask     map[string]string `toml:"mask" doc:"name = \"pattern\" masking, e.g. \"***{last4}\"."`
}

// ObjectClass holds object class rewriting ([profile.<name>.objectclass]).
type ObjectClass struct {
	Map map[string]string `toml:"map" doc:"upstream_class = \"client_class\" renames."`
}

// ClientBind holds the application service login ([profile.<name>.client_bind]).
type ClientBind struct {
	DN           string        `toml:"dn" doc:"Local service DN of the application."`
	Password     secret.Inline `toml:"password" doc:"Service password, inline (warned)."`
	PasswordFile string        `toml:"password_file" doc:"File holding the service password."`
	PasswordEnv  string        `toml:"password_env" doc:"Environment variable holding the service password."`
	PasswordHash string        `toml:"password_hash" doc:"argon2id hash ($argon2id$...) of the service password; alternative to the password forms."`
}

// PasswordSource returns the client bind password source.
func (c *ClientBind) PasswordSource() secret.Source {
	return secret.Source{Inline: c.Password, File: c.PasswordFile, Env: c.PasswordEnv}
}

// UserBind holds the user bind policy ([profile.<name>.user_bind]).
type UserBind struct {
	Allow             bool   `toml:"allow" doc:"Forward user binds to the upstream."`
	DefaultDomain     string `toml:"default_domain" doc:"Domain appended to bare account names."`
	RequireMembership bool   `toml:"require_membership" doc:"Only users matching filter or in a virtual group may bind."`
}

// Group describes one virtual group ([profile.<name>.groups.<gname>]).
type Group struct {
	Description string       `toml:"description" doc:"Group description attribute."`
	ObjectClass string       `toml:"objectclass" doc:"groupOfNames, group or posixGroup."`
	GIDNumber   int          `toml:"gid_number" doc:"gidNumber for posixGroup."`
	Members     GroupMembers `toml:"members" doc:"Membership sources."`
}

// GroupMembers describes how a virtual group is populated ([profile.<name>.groups.<gname>.members]).
type GroupMembers struct {
	Bases    []string `toml:"bases" doc:"Subtrees searched; default profile.bases."`
	Filter   string   `toml:"filter" doc:"Filter; default profile.filter."`
	ADGroups []string `toml:"ad_groups" doc:"Upstream group DNs whose members are included."`
	Include  []string `toml:"include" doc:"Accounts always included."`
	Exclude  []string `toml:"exclude" doc:"Accounts always excluded."`
}

// Cache holds cache settings ([profile.<name>.cache]).
type Cache struct {
	Mode           string   `toml:"mode" doc:"none, ttl or replica."`
	TTL            Duration `toml:"ttl" doc:"Entry lifetime in ttl mode."`
	MaxEntries     int      `toml:"max_entries" doc:"Maximum cached entries."`
	StaleWhileDown bool     `toml:"stale_while_down" doc:"Serve stale entries while every upstream is down."`
	StaleMax       Duration `toml:"stale_max" doc:"Maximum age of stale entries served."`
	SyncInterval   Duration `toml:"sync_interval" doc:"Full sync interval in replica mode."`
	SyncJitter     Percent  `toml:"sync_jitter" doc:"Random jitter applied to sync_interval."`
}

// Limits holds request limits ([profile.<name>.limits]).
type Limits struct {
	MaxResultSize    int      `toml:"max_result_size" doc:"Maximum entries returned per search."`
	MaxFilterDepth   int      `toml:"max_filter_depth" doc:"Maximum filter nesting depth."`
	MaxFilterLen     int      `toml:"max_filter_len" doc:"Maximum filter length in bytes."`
	MaxRequestBytes  ByteSize `toml:"max_request_bytes" doc:"Maximum size of one LDAP request."`
	MaxConnsPerIP    int      `toml:"max_conns_per_ip" doc:"Concurrent connections per source IP."`
	IdleTimeout      Duration `toml:"idle_timeout" doc:"Close idle client connections after this long."`
	UpstreamParallel int      `toml:"upstream_parallel" doc:"Parallel upstream searches per client request."`
}

// RatelimitPatch is a partial [ratelimit]; nil pointers inherit the global value.
type RatelimitPatch struct {
	Enabled              *bool         `toml:"enabled" doc:"See ratelimit.enabled."`
	NegativeCacheTTL     *Duration     `toml:"negative_cache_ttl" doc:"See ratelimit.negative_cache_ttl."`
	ConstantTimeBindFail *bool         `toml:"constant_time_bind_fail" doc:"See ratelimit.constant_time_bind_fail."`
	LockResponse         *string       `toml:"lock_response" doc:"See ratelimit.lock_response."`
	AllowCIDRs           *[]string     `toml:"allow_cidrs" doc:"See ratelimit.allow_cidrs."`
	AllowAccounts        *[]string     `toml:"allow_accounts" doc:"See ratelimit.allow_accounts."`
	IP                   IPPatch       `toml:"ip" doc:"See ratelimit.ip."`
	Account              AccountPatch  `toml:"account" doc:"See ratelimit.account."`
	Delay                DelayPatch    `toml:"delay" doc:"See ratelimit.delay."`
	Tarpit               TarpitPatch   `toml:"tarpit" doc:"See ratelimit.tarpit."`
	Lockdown             LockdownPatch `toml:"lockdown" doc:"See ratelimit.lockdown."`
}

// IPPatch is a partial [ratelimit.ip].
type IPPatch struct {
	MaxFailures  *int      `toml:"max_failures" doc:"See ratelimit.ip.max_failures."`
	Window       *Duration `toml:"window" doc:"See ratelimit.ip.window."`
	LockDuration *Duration `toml:"lock_duration" doc:"See ratelimit.ip.lock_duration."`
	BindRPS      *int      `toml:"bind_rps" doc:"See ratelimit.ip.bind_rps."`
	BindBurst    *int      `toml:"bind_burst" doc:"See ratelimit.ip.bind_burst."`
	SearchRPS    *int      `toml:"search_rps" doc:"See ratelimit.ip.search_rps."`
	SearchBurst  *int      `toml:"search_burst" doc:"See ratelimit.ip.search_burst."`
}

// AccountPatch is a partial [ratelimit.account].
type AccountPatch struct {
	MaxFailures  *int      `toml:"max_failures" doc:"See ratelimit.account.max_failures."`
	Window       *Duration `toml:"window" doc:"See ratelimit.account.window."`
	LockDuration *Duration `toml:"lock_duration" doc:"See ratelimit.account.lock_duration."`
}

// DelayPatch is a partial [ratelimit.delay].
type DelayPatch struct {
	Base *Duration `toml:"base" doc:"See ratelimit.delay.base."`
	Max  *Duration `toml:"max" doc:"See ratelimit.delay.max."`
}

// TarpitPatch is a partial [ratelimit.tarpit].
type TarpitPatch struct {
	Enabled  *bool     `toml:"enabled" doc:"See ratelimit.tarpit.enabled."`
	Delay    *Duration `toml:"delay" doc:"See ratelimit.tarpit.delay."`
	MaxConns *int      `toml:"max_conns" doc:"See ratelimit.tarpit.max_conns."`
}

// LockdownPatch is a partial [ratelimit.lockdown].
type LockdownPatch struct {
	Auto          *bool     `toml:"auto" doc:"See ratelimit.lockdown.auto."`
	AllowCIDRs    *[]string `toml:"allow_cidrs" doc:"See ratelimit.lockdown.allow_cidrs."`
	AllowAccounts *[]string `toml:"allow_accounts" doc:"See ratelimit.lockdown.allow_accounts."`
}

// Shadow holds shadow rules ([profile.<name>.shadow]).
type Shadow struct {
	Filter      string   `toml:"filter" doc:"Shadow filter evaluated alongside the main one (replaces filter for the shadow search)."`
	Bases       []string `toml:"bases" doc:"Shadow bases evaluated alongside the main ones (replace bases for the shadow search)."`
	MaxParallel int      `toml:"max_parallel" doc:"Shadow searches running at once; a search arriving when all are busy is not shadowed."`
	Timeout     Duration `toml:"timeout" doc:"Upper bound of one shadow search; a shadow search that times out is not reported."`
}

// Enabled reports whether shadow rules are configured.
func (s Shadow) Enabled() bool { return s.Filter != "" || len(s.Bases) > 0 }

// Record holds request recording settings ([profile.<name>.record]).
type Record struct {
	Enabled   bool   `toml:"enabled" doc:"Record client searches from the start (never passwords, bind data or paging cookies) as JSON lines in the replay format; aldapctl record start/stop switches it at run time."`
	File      string `toml:"file" doc:"Output file (mode 0600); required to record."`
	MaxSizeMB int    `toml:"max_size_mb" doc:"Rotate the file when it would exceed this size."`
	MaxFiles  int    `toml:"max_files" doc:"Rotated files kept (file.1 … file.N); the oldest is removed."`
}

// Events holds the event stream settings ([events]).
type Events struct {
	Schema       string     `toml:"schema" doc:"Event schema identifier, informational (aldap.event.v1)."`
	BufferSize   int        `toml:"buffer_size" doc:"In-memory ring buffer size."`
	HashAccounts bool       `toml:"hash_accounts" doc:"Replace account with sha256(salt || account)."`
	SaltFile     string     `toml:"salt_file" doc:"File holding the hashing salt."`
	Include      []string   `toml:"include" doc:"Event types to keep; empty keeps all."`
	Exclude      []string   `toml:"exclude" doc:"Event types to drop."`
	Stdout       StdoutSink `toml:"stdout" doc:"Standard output sink."`
	File         FileSink   `toml:"file" doc:"File sink with rotation."`
	Syslog       SyslogSink `toml:"syslog" doc:"Syslog sink (RFC 5424)."`
	Webhooks     []Webhook  `toml:"webhook" doc:"Webhook sinks ([[events.webhook]])."`
}

// StdoutSink holds stdout sink settings ([events.stdout]).
type StdoutSink struct {
	Enabled bool   `toml:"enabled" doc:"Enable the sink."`
	Format  string `toml:"format" doc:"Output format: json."`
}

// FileSink holds file sink settings ([events.file]).
type FileSink struct {
	Enabled   bool   `toml:"enabled" doc:"Enable the sink."`
	Path      string `toml:"path" doc:"Output file."`
	MaxSizeMB int    `toml:"max_size_mb" doc:"Rotate after this size."`
	MaxFiles  int    `toml:"max_files" doc:"Rotated files to keep."`
	Compress  bool   `toml:"compress" doc:"Compress rotated files."`
}

// SyslogSink holds syslog sink settings ([events.syslog]).
type SyslogSink struct {
	Enabled  bool   `toml:"enabled" doc:"Enable the sink."`
	Network  string `toml:"network" doc:"udp, tcp or unix."`
	Address  string `toml:"address" doc:"Syslog server address."`
	Facility string `toml:"facility" doc:"Syslog facility."`
}

// Webhook holds one webhook sink ([[events.webhook]]).
type Webhook struct {
	Name           string        `toml:"name" doc:"Unique sink name."`
	URL            string        `toml:"url" doc:"Destination URL."`
	Events         []string      `toml:"events" doc:"Event types delivered; empty delivers all."`
	BatchSize      int           `toml:"batch_size" doc:"Events per request."`
	BatchInterval  Duration      `toml:"batch_interval" doc:"Maximum wait before a partial batch is sent."`
	Timeout        Duration      `toml:"timeout" doc:"Request timeout."`
	Retry          Retry         `toml:"retry" doc:"Retry policy."`
	HMACSecret     secret.Inline `toml:"hmac_secret" doc:"HMAC key for X-ALDAP-Signature, inline (warned)."`
	HMACSecretFile string        `toml:"hmac_secret_file" doc:"File holding the HMAC key."`
	HMACSecretEnv  string        `toml:"hmac_secret_env" doc:"Environment variable holding the HMAC key."`
	Headers        Headers       `toml:"headers" doc:"Extra request headers; values render \"***\". Credentials belong in headers_file."`
	HeadersFile    string        `toml:"headers_file" doc:"File with a TOML table of extra request headers (credentials such as Authorization); merged with headers, a name in both is an error."`
	TLSCAFile      string        `toml:"tls_ca_file" doc:"CA bundle used to verify the destination."`
	QueueSize      int           `toml:"queue_size" doc:"Pending events kept when the destination is slow."`
	OnOverflow     string        `toml:"on_overflow" doc:"drop_oldest or block when the queue is full."`
}

// HMACSecretSource returns the webhook HMAC key source.
func (w *Webhook) HMACSecretSource() secret.Source {
	return secret.Source{Inline: w.HMACSecret, File: w.HMACSecretFile, Env: w.HMACSecretEnv}
}

// Retry holds a retry policy.
type Retry struct {
	Max        int      `toml:"max" doc:"Maximum attempts."`
	Backoff    Duration `toml:"backoff" doc:"Initial backoff."`
	MaxBackoff Duration `toml:"max_backoff" doc:"Backoff upper bound."`
}

// Notify holds notification settings ([notify]).
type Notify struct {
	Cooldown       Duration  `toml:"cooldown" doc:"Minimum interval between notifications with the same (channel, event type, key)."`
	DigestInterval Duration  `toml:"digest_interval" doc:"During an attack send a digest at this interval instead of single messages."`
	Channels       []Channel `toml:"channel" doc:"Channels ([[notify.channel]])."`
}

// Channel holds one notification channel ([[notify.channel]]).
type Channel struct {
	Name        string   `toml:"name" doc:"Unique channel name."`
	Type        string   `toml:"type" doc:"telegram, virola, email or webhook."`
	Events      []string `toml:"events" doc:"Event types delivered; lock_account and lock_ip select lock events by target."`
	MinLevel    string   `toml:"min_level" doc:"Minimum event level delivered: low, medium or high."`
	TemplateDir string   `toml:"template_dir" doc:"Directory overriding the built-in message templates."`

	// telegram
	BotToken     secret.Inline `toml:"bot_token" doc:"telegram: bot token, inline (warned)."`
	BotTokenFile string        `toml:"bot_token_file" doc:"telegram: file holding the bot token."`
	BotTokenEnv  string        `toml:"bot_token_env" doc:"telegram: environment variable holding the bot token."`
	ChatID       string        `toml:"chat_id" doc:"telegram: chat id."`
	ParseMode    string        `toml:"parse_mode" doc:"telegram: MarkdownV2, HTML or none."`
	APIBase      string        `toml:"api_base" doc:"telegram: API base URL."`

	// virola
	BaseURL               string        `toml:"base_url" doc:"virola: server base URL."`
	Token                 secret.Inline `toml:"token" doc:"virola: Web API access token, inline (warned)."`
	TokenFile             string        `toml:"token_file" doc:"virola: file holding the access token."`
	TokenEnv              string        `toml:"token_env" doc:"virola: environment variable holding the access token."`
	RoomID                int64         `toml:"room_id" doc:"virola: destination room id."`
	UserID                int64         `toml:"user_id" doc:"virola: destination user id."`
	PathTemplate          string        `toml:"path_template" doc:"virola: request path under base_url; {room_id} or {user_id} is substituted. Empty: /api/v1/rooms/{room_id}/messages or /api/v1/users/{user_id}/messages (Virola Web API)."`
	TLSCAFile             string        `toml:"tls_ca_file" doc:"virola: CA bundle used to verify the server."`
	TLSInsecureSkipVerify bool          `toml:"tls_insecure_skip_verify" doc:"virola: disable certificate verification (warned)."`

	// email
	SMTPHost        string        `toml:"smtp_host" doc:"email: SMTP host."`
	SMTPPort        int           `toml:"smtp_port" doc:"email: SMTP port."`
	TLSMode         string        `toml:"tls" doc:"email: starttls, tls or none."`
	Username        string        `toml:"username" doc:"email: SMTP user."`
	Password        secret.Inline `toml:"password" doc:"email: SMTP password, inline (warned)."`
	PasswordFile    string        `toml:"password_file" doc:"email: file holding the SMTP password."`
	PasswordEnv     string        `toml:"password_env" doc:"email: environment variable holding the SMTP password."`
	From            string        `toml:"from" doc:"email: sender address."`
	To              []string      `toml:"to" doc:"email: recipients."`
	SubjectTemplate string        `toml:"subject_template" doc:"email: subject template."`

	// webhook
	URL            string        `toml:"url" doc:"webhook: destination URL."`
	Method         string        `toml:"method" doc:"webhook: HTTP method."`
	Headers        Headers       `toml:"headers" doc:"webhook: extra request headers; values render \"***\". Credentials belong in headers_file."`
	HeadersFile    string        `toml:"headers_file" doc:"webhook: file with a TOML table of extra request headers (credentials such as Authorization); merged with headers, a name in both is an error."`
	BodyTemplate   string        `toml:"body_template" doc:"webhook: Go text/template producing the request body."`
	HMACSecret     secret.Inline `toml:"hmac_secret" doc:"webhook: HMAC key, inline (warned)."`
	HMACSecretFile string        `toml:"hmac_secret_file" doc:"webhook: file holding the HMAC key."`
	HMACSecretEnv  string        `toml:"hmac_secret_env" doc:"webhook: environment variable holding the HMAC key."`
	Timeout        Duration      `toml:"timeout" doc:"Request timeout (every channel; SMTP: per command)."`
	Retry          Retry         `toml:"retry" doc:"Retry policy (every channel); max counts the attempts after the first."`
}

// BotTokenSource returns the telegram bot token source.
func (c *Channel) BotTokenSource() secret.Source {
	return secret.Source{Inline: c.BotToken, File: c.BotTokenFile, Env: c.BotTokenEnv}
}

// TokenSource returns the virola token source.
func (c *Channel) TokenSource() secret.Source {
	return secret.Source{Inline: c.Token, File: c.TokenFile, Env: c.TokenEnv}
}

// Virola message paths of the Virola Web API (virola.io/web-api/docs/messages).
const (
	VirolaRoomPath = "/api/v1/rooms/{room_id}/messages"
	VirolaUserPath = "/api/v1/users/{user_id}/messages"
)

// VirolaPath returns the virola request path with the destination id
// substituted: path_template, or the documented path for room_id/user_id.
func (c *Channel) VirolaPath() string {
	tpl := c.PathTemplate
	if tpl == "" {
		tpl = VirolaRoomPath
		if c.UserID != 0 {
			tpl = VirolaUserPath
		}
	}
	return strings.NewReplacer("{room_id}", strconv.FormatInt(c.RoomID, 10), "{user_id}", strconv.FormatInt(c.UserID, 10)).Replace(tpl)
}

// PasswordSource returns the SMTP password source.
func (c *Channel) PasswordSource() secret.Source {
	return secret.Source{Inline: c.Password, File: c.PasswordFile, Env: c.PasswordEnv}
}

// HMACSecretSource returns the webhook HMAC key source.
func (c *Channel) HMACSecretSource() secret.Source {
	return secret.Source{Inline: c.HMACSecret, File: c.HMACSecretFile, Env: c.HMACSecretEnv}
}

// API holds management API settings ([api]).
type API struct {
	Enabled      bool       `toml:"enabled" doc:"Enable the HTTP API (the IPC socket for aldapctl always works)."`
	Listen       string     `toml:"listen" doc:"Listen address."`
	TLS          APITLS     `toml:"tls" doc:"TLS; mandatory when listen is not loopback."`
	ClientAuth   string     `toml:"client_auth" doc:"mTLS: none or require."`
	ClientCA     string     `toml:"client_ca" doc:"CA bundle used to verify client certificates."`
	RateLimitRPS int        `toml:"rate_limit_rps" doc:"Requests per second per client."`
	Metrics      Metrics    `toml:"metrics" doc:"Prometheus metrics."`
	CORS         bool       `toml:"cors" doc:"CORS is disabled and cannot be enabled."`
	Tokens       []APIToken `toml:"token" doc:"Bearer tokens ([[api.token]])."`
}

// APITLS holds API TLS settings ([api.tls]).
type APITLS struct {
	Builtin bool   `toml:"builtin" doc:"Issue the API certificate from the built-in CA."`
	Cert    string `toml:"cert" doc:"Certificate path."`
	Key     string `toml:"key" doc:"Private key path."`
}

// Metrics holds metrics settings ([api.metrics]).
type Metrics struct {
	Enabled bool   `toml:"enabled" doc:"Expose /metrics."`
	Listen  string `toml:"listen" doc:"Separate listen address; default the API address."`
	Public  bool   `toml:"public" doc:"Serve /metrics without a token."`
}

// APIToken holds one bearer token ([[api.token]]).
type APIToken struct {
	Name       string        `toml:"name" doc:"Unique token name."`
	Token      secret.Inline `toml:"token" doc:"Token value (at least 32 bytes), inline (warned)."`
	TokenFile  string        `toml:"token_file" doc:"File holding the token."`
	TokenEnv   string        `toml:"token_env" doc:"Environment variable holding the token."`
	Scopes     []string      `toml:"scopes" doc:"Granted scopes: events:read, locks:read, locks:write, status:read, admin."`
	AllowCIDRs []string      `toml:"allow_cidrs" doc:"Source networks allowed to use the token."`
}

// TokenSource returns the token source.
func (t *APIToken) TokenSource() secret.Source {
	return secret.Source{Inline: t.Token, File: t.TokenFile, Env: t.TokenEnv}
}
