# Configuration keys

Generated from the `internal/config` model; `TestConfigDocsInSync` fails when this file is stale.
Regenerate with `go test ./internal/config -run TestConfigDocsInSync -update`.
See `aldap.toml.example` for a complete annotated example and SPEC.md §3 for semantics.

Precedence (highest first): `ALDAP_*` environment variables, secret files, `aldap.toml` with includes, built-in defaults.
Environment variable names are `ALDAP_` + the key path in upper case with `.` and `-` replaced by `_`; lists are comma separated. Tables with free-form keys (`attrs.map`, `groups`, `headers`) and arrays of tables cannot be set from the environment.

| Key | Type | Default | Description |
|---|---|---|---|
| `server` | table |  | Process-wide settings. |
| `server.log_level` | string | `"info"` | Log verbosity: debug, info, warn, error. |
| `server.log_format` | string | `"text"` | Log output format: text or json. |
| `server.ipc_socket` | string | `"/run/aldap/aldap.sock"` | Local control channel for aldapctl without a token (unix socket 0600, named pipe on Windows). |
| `server.shutdown_timeout` | duration | `30s` | Graceful drain timeout on stop or reload. |
| `server.max_connections` | int | `1024` | Global limit of concurrent client connections. |
| `server.include` | []string | `[]` | Glob patterns of additional TOML files (profiles, upstreams). Duplicate names are an error. |
| `tls` | table |  | Global TLS defaults for listeners; a profile may override any key. |
| `tls.mode` | string | `"builtin-ca"` | builtin-ca (certificates issued by the built-in CA) or external (cert and key given). |
| `tls.ca_dir` | string | `"/var/lib/aldap/ca"` | Directory of the built-in CA (ca.crt, ca.key 0600). |
| `tls.auto_init` | bool | `true` | Create the built-in CA on first start when missing. |
| `tls.cert` | string |  | Server certificate path for mode = external. |
| `tls.key` | string |  | Server private key path for mode = external (path is not a secret, content is). |
| `tls.auto_renew_before` | duration | `720h0m0s` | Reissue the built-in server certificate this long before expiry. |
| `tls.expiry_alert_before` | duration | `336h0m0s` | Emit cert_expiring this long before expiry. |
| `tls.san` | []string | `[]` | Additional DNS names or IPs for the server certificate. |
| `tls.key_type` | string | `"ecdsa-p256"` | Key type of certificates issued by the built-in CA: ecdsa-p256 or rsa-2048. |
| `tls.min_version` | string | `"1.2"` | Minimum TLS version: 1.2 or 1.3. |
| `tls.client_auth` | string | `"none"` | Client certificates: none, request or require (mTLS). |
| `tls.client_ca` | string |  | CA bundle used to verify client certificates. |
| `ratelimit` | table |  | Global rate limiting and locking; a profile may override any key. |
| `ratelimit.enabled` | bool | `true` | Enable rate limiting and locks. |
| `ratelimit.negative_cache_ttl` | duration | `1m0s` | Remember a failed (account, password hash) pair this long and do not retry it upstream. |
| `ratelimit.constant_time_bind_fail` | bool | `true` | Pad every failed bind to the p95 latency of successful binds (anti-enumeration). |
| `ratelimit.lock_response` | string | `"invalidCredentials"` | LDAP result for locked clients: invalidCredentials or busy. |
| `ratelimit.allow_cidrs` | []string | `[]` | Source networks exempt from limits. |
| `ratelimit.allow_accounts` | []string | `[]` | Accounts exempt from locking. |
| `ratelimit.ip` | table |  | Per-source-IP limits. |
| `ratelimit.ip.max_failures` | int | `20` | Failed binds from one IP within window that trigger a lock. |
| `ratelimit.ip.window` | duration | `5m0s` | Failure counting window. |
| `ratelimit.ip.lock_duration` | duration | `15m0s` | How long a locked IP stays locked. |
| `ratelimit.ip.bind_rps` | int | `10` | Sustained binds per second (token bucket). |
| `ratelimit.ip.bind_burst` | int | `20` | Bind burst size. |
| `ratelimit.ip.search_rps` | int | `50` | Sustained searches per second. |
| `ratelimit.ip.search_burst` | int | `100` | Search burst size. |
| `ratelimit.account` | table |  | Per-account limits. |
| `ratelimit.account.max_failures` | int | `3` | Failed binds per account within window that trigger a lock. Keep it below the directory lockout threshold. |
| `ratelimit.account.window` | duration | `10m0s` | Failure counting window. |
| `ratelimit.account.lock_duration` | duration | `15m0s` | How long a locked account stays locked. |
| `ratelimit.delay` | table |  | Progressive delay after failures. |
| `ratelimit.delay.base` | duration | `250ms` | Delay after the first failure; doubles on each next failure. |
| `ratelimit.delay.max` | duration | `4s` | Upper bound of the delay. |
| `ratelimit.tarpit` | table |  | Tarpit for sources in attack state. |
| `ratelimit.tarpit.enabled` | bool | `false` | Hold connections from attacking sources and answer slowly. |
| `ratelimit.tarpit.delay` | duration | `30s` | Response delay for tarpitted connections. |
| `ratelimit.tarpit.max_conns` | int | `64` | Maximum tarpitted connections held at once. |
| `ratelimit.lockdown` | table |  | Lockdown mode. |
| `ratelimit.lockdown.auto` | bool | `false` | Enter lockdown automatically on a high level attack_start. |
| `ratelimit.lockdown.allow_cidrs` | []string | `[]` | Source networks still served during lockdown. |
| `ratelimit.lockdown.allow_accounts` | []string | `[]` | Accounts still served during lockdown. |
| `ids` | table |  | Intrusion detection: detectors and their thresholds. |
| `ids.summary_interval` | duration | `5m0s` | Interval of attack_summary events during an attack. |
| `ids.quiet_period` | duration | `15m0s` | Silence after which attack_end is emitted. |
| `ids.spray` | table |  | Password spray detector. |
| `ids.spray.enabled` | bool | `true` | Enable the detector. |
| `ids.spray.window` | duration | `10m0s` | Observation window. |
| `ids.spray.min_accounts` | int | `5` | Distinct accounts tried from one source that trigger the detector. |
| `ids.spray.same_password_hash` | bool | `true` | Require the same password hash across accounts. |
| `ids.stuffing` | table |  | Credential stuffing detector. |
| `ids.stuffing.enabled` | bool | `true` | Enable the detector. |
| `ids.stuffing.window` | duration | `5m0s` | Observation window. |
| `ids.stuffing.min_pairs` | int | `20` | Distinct (account, password) pairs from one IP that trigger the detector. |
| `ids.slow_brute` | table |  | Slow brute force detector. |
| `ids.slow_brute.enabled` | bool | `true` | Enable the detector. |
| `ids.slow_brute.window` | duration | `6h0m0s` | Observation window. |
| `ids.slow_brute.min_failures` | int | `30` | Failures within window that trigger the detector. |
| `ids.slow_brute.max_rate_per_min` | int | `2` | Upper rate (per minute) still counted as slow. |
| `ids.enumeration` | table |  | Account enumeration detector. |
| `ids.enumeration.enabled` | bool | `true` | Enable the detector. |
| `ids.enumeration.min_accounts` | int | `10` | Consecutive distinct accounts without a success that trigger the detector. |
| `ids.recon` | table |  | Reconnaissance search signatures. |
| `ids.recon.enabled` | bool | `true` | Enable the detector. |
| `ids.anomaly` | table |  | Baseline and anomaly detector. |
| `ids.anomaly.enabled` | bool | `true` | Enable the detector. |
| `ids.anomaly.learn_for` | duration | `24h0m0s` | Baseline learning period after start. |
| `ids.honeytoken` | table |  | Honeytoken detector. |
| `ids.honeytoken.enabled` | bool | `true` | Enable the detector. |
| `ids.honeytoken.lock_duration` | duration | `24h0m0s` | Lock duration applied to a source that touches a honeytoken. |
| `ids.fingerprint` | table |  | TLS and LDAP client fingerprint detector. |
| `ids.fingerprint.enabled` | bool | `false` | Enable the detector. |
| `ids.client_ip_masked` | table |  | Detector of a proxy or container network that replaces client addresses with its own (insecure_config what=client_ip_masked). |
| `ids.client_ip_masked.enabled` | bool | `true` | Enable the detector. |
| `ids.client_ip_masked.window` | duration | `10m0s` | Observation window. |
| `ids.client_ip_masked.min_requests` | int | `50` | Binds and searches within window needed before the share is judged. |
| `ids.client_ip_masked.min_share_percent` | int | `90` | Share (percent) of the binds and searches from one private address that triggers the detector. |
| `ids.client_ip_masked.min_accounts` | int | `3` | Distinct accounts seen from that address that trigger the detector. |
| `ids.client_ip_masked.ignore_cidrs` | []string | `[]` | Sources never reported, e.g. an application server that binds on behalf of its users. |
| `events` | table |  | Audit event stream and sinks. |
| `events.schema` | string | `"aldap.event.v1"` | Event schema identifier, informational (aldap.event.v1). |
| `events.buffer_size` | int | `100000` | In-memory ring buffer size. |
| `events.hash_accounts` | bool | `false` | Replace account with sha256(salt \|\| account). |
| `events.salt_file` | string |  | File holding the hashing salt. |
| `events.include` | []string | `[]` | Event types to keep; empty keeps all. |
| `events.exclude` | []string | `[]` | Event types to drop. |
| `events.stdout` | table |  | Standard output sink. |
| `events.stdout.enabled` | bool | `true` | Enable the sink. |
| `events.stdout.format` | string | `"json"` | Output format: json. |
| `events.file` | table |  | File sink with rotation. |
| `events.file.enabled` | bool | `false` | Enable the sink. |
| `events.file.path` | string |  | Output file. |
| `events.file.max_size_mb` | int | `100` | Rotate after this size. |
| `events.file.max_files` | int | `10` | Rotated files to keep. |
| `events.file.compress` | bool | `true` | Compress rotated files. |
| `events.syslog` | table |  | Syslog sink (RFC 5424). |
| `events.syslog.enabled` | bool | `false` | Enable the sink. |
| `events.syslog.network` | string | `"udp"` | udp, tcp or unix. |
| `events.syslog.address` | string |  | Syslog server address. |
| `events.syslog.facility` | string | `"auth"` | Syslog facility. |
| `events.webhook[]` | array of tables |  | Webhook sinks ([[events.webhook]]). |
| `events.webhook[].name` | string |  | Unique sink name. |
| `events.webhook[].url` | string |  | Destination URL. |
| `events.webhook[].events` | []string | `[]` | Event types delivered; empty delivers all. |
| `events.webhook[].batch_size` | int | `100` | Events per request. |
| `events.webhook[].batch_interval` | duration | `2s` | Maximum wait before a partial batch is sent. |
| `events.webhook[].timeout` | duration | `5s` | Request timeout. |
| `events.webhook[].retry` | table |  | Retry policy. |
| `events.webhook[].retry.max` | int | `5` | Maximum attempts. |
| `events.webhook[].retry.backoff` | duration | `1s` | Initial backoff. |
| `events.webhook[].retry.max_backoff` | duration | `1m0s` | Backoff upper bound. |
| `events.webhook[].hmac_secret` | secret |  | HMAC key for X-ALDAP-Signature, inline (warned). |
| `events.webhook[].hmac_secret_file` | string |  | File holding the HMAC key. |
| `events.webhook[].hmac_secret_env` | string |  | Environment variable holding the HMAC key. |
| `events.webhook[].headers` | table of secret | `{}` | Extra request headers; values render "***". Credentials belong in headers_file. |
| `events.webhook[].headers_file` | string |  | File with a TOML table of extra request headers (credentials such as Authorization); merged with headers, a name in both is an error. |
| `events.webhook[].tls_ca_file` | string |  | CA bundle used to verify the destination. |
| `events.webhook[].queue_size` | int | `10000` | Pending events kept when the destination is slow. |
| `events.webhook[].on_overflow` | string | `"drop_oldest"` | drop_oldest or block when the queue is full. |
| `notify` | table |  | Human notifications. |
| `notify.cooldown` | duration | `10m0s` | Minimum interval between notifications with the same (channel, event type, key). |
| `notify.digest_interval` | duration | `15m0s` | During an attack send a digest at this interval instead of single messages. |
| `notify.channel[]` | array of tables |  | Channels ([[notify.channel]]). |
| `notify.channel[].name` | string |  | Unique channel name. |
| `notify.channel[].type` | string |  | telegram, virola, email or webhook. |
| `notify.channel[].events` | []string | `["attack_start", "attack_summary", "attack_end", "lock_account", "upstream_down", "upstream_up", "cert_expiring", "honeytoken", "lockdown"]` | Event types delivered; lock_account and lock_ip select lock events by target. |
| `notify.channel[].min_level` | string | `"low"` | Minimum event level delivered: low, medium or high. |
| `notify.channel[].template_dir` | string |  | Directory overriding the built-in message templates. |
| `notify.channel[].bot_token` | secret |  | telegram: bot token, inline (warned). |
| `notify.channel[].bot_token_file` | string |  | telegram: file holding the bot token. |
| `notify.channel[].bot_token_env` | string |  | telegram: environment variable holding the bot token. |
| `notify.channel[].chat_id` | string |  | telegram: chat id. |
| `notify.channel[].parse_mode` | string | `"MarkdownV2"` | telegram: MarkdownV2, HTML or none. |
| `notify.channel[].api_base` | string | `"https://api.telegram.org"` | telegram: API base URL. |
| `notify.channel[].base_url` | string |  | virola: server base URL. |
| `notify.channel[].token` | secret |  | virola: Web API access token, inline (warned). |
| `notify.channel[].token_file` | string |  | virola: file holding the access token. |
| `notify.channel[].token_env` | string |  | virola: environment variable holding the access token. |
| `notify.channel[].room_id` | int | `0` | virola: destination room id. |
| `notify.channel[].user_id` | int | `0` | virola: destination user id. |
| `notify.channel[].path_template` | string |  | virola: request path under base_url; {room_id} or {user_id} is substituted. Empty: /api/v1/rooms/{room_id}/messages or /api/v1/users/{user_id}/messages (Virola Web API). |
| `notify.channel[].tls_ca_file` | string |  | virola: CA bundle used to verify the server. |
| `notify.channel[].tls_insecure_skip_verify` | bool | `false` | virola: disable certificate verification (warned). |
| `notify.channel[].smtp_host` | string |  | email: SMTP host. |
| `notify.channel[].smtp_port` | int | `587` | email: SMTP port. |
| `notify.channel[].tls` | string | `"starttls"` | email: starttls, tls or none. |
| `notify.channel[].username` | string |  | email: SMTP user. |
| `notify.channel[].password` | secret |  | email: SMTP password, inline (warned). |
| `notify.channel[].password_file` | string |  | email: file holding the SMTP password. |
| `notify.channel[].password_env` | string |  | email: environment variable holding the SMTP password. |
| `notify.channel[].from` | string |  | email: sender address. |
| `notify.channel[].to` | []string | `[]` | email: recipients. |
| `notify.channel[].subject_template` | string |  | email: subject template. |
| `notify.channel[].url` | string |  | webhook: destination URL. |
| `notify.channel[].method` | string | `"POST"` | webhook: HTTP method. |
| `notify.channel[].headers` | table of secret | `{}` | webhook: extra request headers; values render "***". Credentials belong in headers_file. |
| `notify.channel[].headers_file` | string |  | webhook: file with a TOML table of extra request headers (credentials such as Authorization); merged with headers, a name in both is an error. |
| `notify.channel[].body_template` | string |  | webhook: Go text/template producing the request body. |
| `notify.channel[].hmac_secret` | secret |  | webhook: HMAC key, inline (warned). |
| `notify.channel[].hmac_secret_file` | string |  | webhook: file holding the HMAC key. |
| `notify.channel[].hmac_secret_env` | string |  | webhook: environment variable holding the HMAC key. |
| `notify.channel[].timeout` | duration | `5s` | Request timeout (every channel; SMTP: per command). |
| `notify.channel[].retry` | table |  | Retry policy (every channel); max counts the attempts after the first. |
| `notify.channel[].retry.max` | int | `3` | Maximum attempts. |
| `notify.channel[].retry.backoff` | duration | `1s` | Initial backoff. |
| `notify.channel[].retry.max_backoff` | duration | `30s` | Backoff upper bound. |
| `api` | table |  | Management HTTP API. |
| `api.enabled` | bool | `false` | Enable the HTTP API (the IPC socket for aldapctl always works). |
| `api.listen` | string | `"127.0.0.1:8636"` | Listen address. |
| `api.tls` | table |  | TLS; mandatory when listen is not loopback. |
| `api.tls.builtin` | bool | `false` | Issue the API certificate from the built-in CA. |
| `api.tls.cert` | string |  | Certificate path. |
| `api.tls.key` | string |  | Private key path. |
| `api.client_auth` | string | `"none"` | mTLS: none or require. |
| `api.client_ca` | string |  | CA bundle used to verify client certificates. |
| `api.rate_limit_rps` | int | `50` | Requests per second per client. |
| `api.metrics` | table |  | Prometheus metrics. |
| `api.metrics.enabled` | bool | `true` | Expose /metrics. |
| `api.metrics.listen` | string |  | Separate listen address; default the API address. |
| `api.metrics.public` | bool | `false` | Serve /metrics without a token. |
| `api.cors` | bool | `false` | CORS is disabled and cannot be enabled. |
| `api.token[]` | array of tables |  | Bearer tokens ([[api.token]]). |
| `api.token[].name` | string |  | Unique token name. |
| `api.token[].token` | secret |  | Token value (at least 32 bytes), inline (warned). |
| `api.token[].token_file` | string |  | File holding the token. |
| `api.token[].token_env` | string |  | Environment variable holding the token. |
| `api.token[].scopes` | []string | `[]` | Granted scopes: events:read, locks:read, locks:write, status:read, admin. |
| `api.token[].allow_cidrs` | []string | `[]` | Source networks allowed to use the token. |
| `upstream.<name>` | table |  | Upstream LDAP directories, one table per name. |
| `upstream.<name>.servers` | []string | `[]` | Server URLs in priority order: ldap://host:389 or ldaps://host:636. |
| `upstream.<name>.kind` | string | `"ad"` | ad (Active Directory specifics enabled) or generic. |
| `upstream.<name>.starttls` | bool | `false` | Upgrade ldap:// connections with StartTLS. |
| `upstream.<name>.starttls_required` | bool | `false` | Refuse to work when StartTLS cannot be negotiated. |
| `upstream.<name>.tls_ca_file` | string |  | CA bundle used to verify the upstream certificate. |
| `upstream.<name>.tls_insecure_skip_verify` | bool | `false` | Disable certificate verification. Logged as a warning on every start and reported as insecure_config. |
| `upstream.<name>.tls_server_name` | string |  | SNI and expected certificate name when it differs from the host. |
| `upstream.<name>.bind_dn` | string |  | Service account DN used for searches (read-only). |
| `upstream.<name>.bind_password` | secret |  | Service account password, inline (warned). |
| `upstream.<name>.bind_password_file` | string |  | File holding the service account password. |
| `upstream.<name>.bind_password_env` | string |  | Environment variable holding the service account password. |
| `upstream.<name>.base_dn` | string |  | Directory root, used for RootDSE and to validate profile bases. |
| `upstream.<name>.health_interval` | duration | `10s` | Interval between health checks. |
| `upstream.<name>.health_check` | string | `"rootdse"` | Health check kind: rootdse, bind or search. |
| `upstream.<name>.page_size` | int | `500` | Page size for the paged results control. |
| `upstream.<name>.audit_service_account` | bool | `true` | On start, warn and emit insecure_config when the service account is in an administrative group. |
| `upstream.<name>.failover` | table |  | Failover thresholds and strategy. |
| `upstream.<name>.failover.fail_threshold` | int | `3` | Consecutive failures that mark a server down. |
| `upstream.<name>.failover.recover_threshold` | int | `2` | Consecutive successes that mark a server up. |
| `upstream.<name>.failover.prefer_primary` | bool | `true` | Return to the first healthy server in the list. |
| `upstream.<name>.failover.strategy` | string | `"primary"` | Server selection: primary or roundrobin. |
| `upstream.<name>.pool` | table |  | Connection pool. |
| `upstream.<name>.pool.size` | int | `4` | Connections per server. |
| `upstream.<name>.pool.max_idle` | duration | `5m0s` | Close idle connections after this long. |
| `upstream.<name>.timeouts` | table |  | Operation timeouts. |
| `upstream.<name>.timeouts.connect` | duration | `5s` | TCP and TLS connect timeout. |
| `upstream.<name>.timeouts.bind` | duration | `5s` | Bind timeout. |
| `upstream.<name>.timeouts.search` | duration | `30s` | Search timeout. |
| `profile.<name>` | table |  | Client-facing profiles, one table per name. |
| `profile.<name>.listen` | []string | `[]` | Listen addresses, e.g. ":636" or "10.0.0.5:636", or "systemd:<name>" for the sockets systemd passes with that FileDescriptorName= (socket activation). |
| `profile.<name>.proxy_protocol` | table |  | PROXY protocol v1/v2 header from a trusted proxy in front of the listeners (client address from the header). |
| `profile.<name>.proxy_protocol.enabled` | bool | `false` | Accept a PROXY protocol v1 or v2 header from trusted_cidrs; the header's source address becomes the client address. |
| `profile.<name>.proxy_protocol.trusted_cidrs` | []string | `[]` | Proxy addresses whose header is accepted (required when enabled). A connection from elsewhere that sends a header is closed and reported as insecure_config. |
| `profile.<name>.transport` | string | `"ldaps"` | ldaps, ldap, starttls or ldap+starttls (plain allowed, StartTLS optional). |
| `profile.<name>.starttls_required` | bool | `false` | Reject binds without TLS with confidentialityRequired. |
| `profile.<name>.tls` | table |  | Overrides of [tls] for this profile. |
| `profile.<name>.tls.mode` | string | `inherit` | See tls.mode. |
| `profile.<name>.tls.ca_dir` | string | `inherit` | See tls.ca_dir. |
| `profile.<name>.tls.auto_init` | bool | `inherit` | See tls.auto_init. |
| `profile.<name>.tls.cert` | string | `inherit` | See tls.cert. |
| `profile.<name>.tls.key` | string | `inherit` | See tls.key. |
| `profile.<name>.tls.auto_renew_before` | duration | `inherit` | See tls.auto_renew_before. |
| `profile.<name>.tls.expiry_alert_before` | duration | `inherit` | See tls.expiry_alert_before. |
| `profile.<name>.tls.san` | []string | `inherit` | See tls.san. |
| `profile.<name>.tls.key_type` | string | `inherit` | See tls.key_type. |
| `profile.<name>.tls.min_version` | string | `inherit` | See tls.min_version. |
| `profile.<name>.tls.client_auth` | string | `inherit` | See tls.client_auth. |
| `profile.<name>.tls.client_ca` | string | `inherit` | See tls.client_ca. |
| `profile.<name>.upstream` | string |  | Name of the upstream to use. |
| `profile.<name>.mode` | string | `"proxy"` | proxy, honeypot (every request is a honeytoken hit) or mock (answers from mock.file, no upstream). |
| `profile.<name>.mock` | table |  | Mock mode source. |
| `profile.<name>.mock.file` | string |  | TOML or CSV file with the entries served in mock mode. |
| `profile.<name>.virtual_base` | string |  | DN the client sees; all DNs are rewritten under it and bases outside it get noSuchObject. |
| `profile.<name>.bases` | []string | `[]` | Real upstream subtrees searched for users. |
| `profile.<name>.filter` | string |  | Mandatory filter AND-ed to every client filter. Default for kind = ad selects enabled person accounts. |
| `profile.<name>.exclude_filter` | string |  | Optional filter NOT-ed to every client filter. |
| `profile.<name>.attrs` | table |  | Attribute policy. |
| `profile.<name>.attrs.allow` | []string | `[]` | Attributes returned to clients. "*" is rejected; operational attributes only when listed. |
| `profile.<name>.attrs.map` | table of string | `{}` | client_name = "upstream_name" renames. |
| `profile.<name>.attrs.computed` | table of string | `{}` | name = "go-template" computed attributes. |
| `profile.<name>.attrs.mask` | table of string | `{}` | name = "pattern" masking, e.g. "***{last4}". |
| `profile.<name>.objectclass` | table |  | Object class rewriting. |
| `profile.<name>.objectclass.map` | table of string | `{}` | upstream_class = "client_class" renames. |
| `profile.<name>.rdn_attr` | string | `"cn"` | Attribute used as RDN in virtual user DNs. |
| `profile.<name>.client_bind` | table |  | Local service login of the application; without it only user binds are possible. |
| `profile.<name>.client_bind.dn` | string |  | Local service DN of the application. |
| `profile.<name>.client_bind.password` | secret |  | Service password, inline (warned). |
| `profile.<name>.client_bind.password_file` | string |  | File holding the service password. |
| `profile.<name>.client_bind.password_env` | string |  | Environment variable holding the service password. |
| `profile.<name>.client_bind.password_hash` | string |  | argon2id hash ($argon2id$...) of the service password; alternative to the password forms. |
| `profile.<name>.user_bind` | table |  | User bind policy. |
| `profile.<name>.user_bind.allow` | bool | `true` | Forward user binds to the upstream. |
| `profile.<name>.user_bind.default_domain` | string |  | Domain appended to bare account names. |
| `profile.<name>.user_bind.require_membership` | bool | `false` | Only users matching filter or in a virtual group may bind. |
| `profile.<name>.anonymous_bind` | bool | `false` | Allow anonymous bind. |
| `profile.<name>.groups.<name>` | table |  | Virtual groups, one table per group name. |
| `profile.<name>.groups.<name>.description` | string |  | Group description attribute. |
| `profile.<name>.groups.<name>.objectclass` | string | `"groupOfNames"` | groupOfNames, group or posixGroup. |
| `profile.<name>.groups.<name>.gid_number` | int | `0` | gidNumber for posixGroup. |
| `profile.<name>.groups.<name>.members` | table |  | Membership sources. |
| `profile.<name>.groups.<name>.members.bases` | []string | `[]` | Subtrees searched; default profile.bases. |
| `profile.<name>.groups.<name>.members.filter` | string |  | Filter; default profile.filter. |
| `profile.<name>.groups.<name>.members.ad_groups` | []string | `[]` | Upstream group DNs whose members are included. |
| `profile.<name>.groups.<name>.members.include` | []string | `[]` | Accounts always included. |
| `profile.<name>.groups.<name>.members.exclude` | []string | `[]` | Accounts always excluded. |
| `profile.<name>.nested_groups` | bool | `false` | Transitive memberOf. |
| `profile.<name>.nested_depth` | int | `10` | Recursion limit for nested groups on generic upstreams. |
| `profile.<name>.honeytokens` | []string | `[]` | Trap accounts returned as ordinary users. |
| `profile.<name>.honeytoken_in_groups` | bool | `true` | List honeytokens as members of virtual groups. |
| `profile.<name>.honeytoken_template` | table of string | `{}` | Attribute templates for honeytoken entries. |
| `profile.<name>.cache` | table |  | Cache mode. |
| `profile.<name>.cache.mode` | string | `"none"` | none, ttl or replica. |
| `profile.<name>.cache.ttl` | duration | `1m0s` | Entry lifetime in ttl mode. |
| `profile.<name>.cache.max_entries` | int | `10000` | Maximum cached entries. |
| `profile.<name>.cache.stale_while_down` | bool | `true` | Serve stale entries while every upstream is down. |
| `profile.<name>.cache.stale_max` | duration | `1h0m0s` | Maximum age of stale entries served. |
| `profile.<name>.cache.sync_interval` | duration | `5m0s` | Full sync interval in replica mode. |
| `profile.<name>.cache.sync_jitter` | percent | `20%` | Random jitter applied to sync_interval. |
| `profile.<name>.limits` | table |  | Request and connection limits. |
| `profile.<name>.limits.max_result_size` | int | `5000` | Maximum entries returned per search. |
| `profile.<name>.limits.max_filter_depth` | int | `20` | Maximum filter nesting depth. |
| `profile.<name>.limits.max_filter_len` | int | `4096` | Maximum filter length in bytes. |
| `profile.<name>.limits.max_request_bytes` | size | `1MiB` | Maximum size of one LDAP request. |
| `profile.<name>.limits.max_conns_per_ip` | int | `32` | Concurrent connections per source IP. |
| `profile.<name>.limits.idle_timeout` | duration | `10m0s` | Close idle client connections after this long. |
| `profile.<name>.limits.upstream_parallel` | int | `4` | Parallel upstream searches per client request. |
| `profile.<name>.ratelimit` | table |  | Overrides of [ratelimit] for this profile; unset keys inherit. |
| `profile.<name>.ratelimit.enabled` | bool | `inherit` | See ratelimit.enabled. |
| `profile.<name>.ratelimit.negative_cache_ttl` | duration | `inherit` | See ratelimit.negative_cache_ttl. |
| `profile.<name>.ratelimit.constant_time_bind_fail` | bool | `inherit` | See ratelimit.constant_time_bind_fail. |
| `profile.<name>.ratelimit.lock_response` | string | `inherit` | See ratelimit.lock_response. |
| `profile.<name>.ratelimit.allow_cidrs` | []string | `inherit` | See ratelimit.allow_cidrs. |
| `profile.<name>.ratelimit.allow_accounts` | []string | `inherit` | See ratelimit.allow_accounts. |
| `profile.<name>.ratelimit.ip` | table |  | See ratelimit.ip. |
| `profile.<name>.ratelimit.ip.max_failures` | int | `inherit` | See ratelimit.ip.max_failures. |
| `profile.<name>.ratelimit.ip.window` | duration | `inherit` | See ratelimit.ip.window. |
| `profile.<name>.ratelimit.ip.lock_duration` | duration | `inherit` | See ratelimit.ip.lock_duration. |
| `profile.<name>.ratelimit.ip.bind_rps` | int | `inherit` | See ratelimit.ip.bind_rps. |
| `profile.<name>.ratelimit.ip.bind_burst` | int | `inherit` | See ratelimit.ip.bind_burst. |
| `profile.<name>.ratelimit.ip.search_rps` | int | `inherit` | See ratelimit.ip.search_rps. |
| `profile.<name>.ratelimit.ip.search_burst` | int | `inherit` | See ratelimit.ip.search_burst. |
| `profile.<name>.ratelimit.account` | table |  | See ratelimit.account. |
| `profile.<name>.ratelimit.account.max_failures` | int | `inherit` | See ratelimit.account.max_failures. |
| `profile.<name>.ratelimit.account.window` | duration | `inherit` | See ratelimit.account.window. |
| `profile.<name>.ratelimit.account.lock_duration` | duration | `inherit` | See ratelimit.account.lock_duration. |
| `profile.<name>.ratelimit.delay` | table |  | See ratelimit.delay. |
| `profile.<name>.ratelimit.delay.base` | duration | `inherit` | See ratelimit.delay.base. |
| `profile.<name>.ratelimit.delay.max` | duration | `inherit` | See ratelimit.delay.max. |
| `profile.<name>.ratelimit.tarpit` | table |  | See ratelimit.tarpit. |
| `profile.<name>.ratelimit.tarpit.enabled` | bool | `inherit` | See ratelimit.tarpit.enabled. |
| `profile.<name>.ratelimit.tarpit.delay` | duration | `inherit` | See ratelimit.tarpit.delay. |
| `profile.<name>.ratelimit.tarpit.max_conns` | int | `inherit` | See ratelimit.tarpit.max_conns. |
| `profile.<name>.ratelimit.lockdown` | table |  | See ratelimit.lockdown. |
| `profile.<name>.ratelimit.lockdown.auto` | bool | `inherit` | See ratelimit.lockdown.auto. |
| `profile.<name>.ratelimit.lockdown.allow_cidrs` | []string | `inherit` | See ratelimit.lockdown.allow_cidrs. |
| `profile.<name>.ratelimit.lockdown.allow_accounts` | []string | `inherit` | See ratelimit.lockdown.allow_accounts. |
| `profile.<name>.shadow` | table |  | Shadow rules evaluated in parallel; differences are reported as shadow_diff. |
| `profile.<name>.shadow.filter` | string |  | Shadow filter evaluated alongside the main one (replaces filter for the shadow search). |
| `profile.<name>.shadow.bases` | []string | `[]` | Shadow bases evaluated alongside the main ones (replace bases for the shadow search). |
| `profile.<name>.shadow.max_parallel` | int | `4` | Shadow searches running at once; a search arriving when all are busy is not shadowed. |
| `profile.<name>.shadow.timeout` | duration | `10s` | Upper bound of one shadow search; a shadow search that times out is not reported. |
| `profile.<name>.record` | table |  | Request recording for replay. |
| `profile.<name>.record.enabled` | bool | `false` | Record client searches from the start (never passwords, bind data or paging cookies) as JSON lines in the replay format; aldapctl record start/stop switches it at run time. |
| `profile.<name>.record.file` | string |  | Output file (mode 0600); required to record. |
| `profile.<name>.record.max_size_mb` | int | `100` | Rotate the file when it would exceed this size. |
| `profile.<name>.record.max_files` | int | `5` | Rotated files kept (file.1 … file.N); the oldest is removed. |
