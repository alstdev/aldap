# internal/ratelimit and internal/ids — rate limiting and intrusion detection (Stage 6)

Implements SPEC §3.4 `[ratelimit]` / `[ids]`, §9 and the lock/attack events
of §6. State is in memory only and survives `SIGHUP` (the `Limiter` and the
`Engine` are created once per process; profiles get a new `Policy` on
reload).

## Where the gates sit (`internal/vdir`)

`vdir.Guard` (implemented by `*ratelimit.Policy`) and `vdir.Observer`
(implemented by `*ids.Engine`) are consumer-side interfaces of the virtual
directory.

Bind (`Directory.Bind`):

1. `Guard.PreBind(ip, account, pwHash)` — before any upstream work. The
   account key is the normalized bare account (`user@domain`, `DOMAIN\user`
   and `user` count as one; client-bind DNs as themselves). A refusal is a
   `bind_blocked{reason}` event answered with `lock_response`
   (`invalidCredentials` or `busy`); the detectors still see the attempt.
2. The bind pipeline of Stage 5.
3. `Guard.PostBind(...)` records the outcome and returns the delay to apply
   (progressive delay, constant-time padding); `Observer.Bind` feeds the
   detectors.

Search (`Directory.Search`): `Guard.PreSearch(ip, boundAccount)` before any
work. A refusal is `unwillingToPerform` (or `busy` for rate limits) and a
`rate_limited{reason, op=search}` event — a locked IP cannot search on an
existing session either (closes the Stage 5 OPEN item). After the first
page `Observer.Search` receives the base kind, filter and attributes.

Honeytoken hits (`honeytokenHit`) call `Guard.LockIP(ip, now+lock_duration,
"honeytoken")`; the limiter records the lock and emits the `lock` event.

## ratelimit.Limiter / Policy

| mechanism | behaviour |
|---|---|
| IP failures | sliding window `ip.window`; `ip.max_failures` → lock for `ip.lock_duration`, `lock{target=ip, source=ratelimit, failures}` |
| account failures | `account.window` / `account.max_failures` (default 3, **below the directory lockout**) → `lock{target=account}`; `allow_accounts` never lock |
| lock expiry | lazily on the next check or by `Sweep` (daemon ticker, 1 s) → `unlock{source=expiry}`; a lock consumes the failure window, counting restarts after expiry |
| manual unlock | `Unlock(target, key, source)` (API/TUI in later stages) → `unlock{source=api|tui}`; clears the window and the delay |
| negative cache | `(account, sha256(salt‖password))` after a failure whose reason cannot change with a retry (`invalid_password`, `unknown_account`, `disabled`, `locked_in_ad`, `expired`, `must_change`, `not_member`) for `negative_cache_ttl`; the pair is answered `invalidCredentials` without upstream (`bind_blocked{negative_cache}`); `upstream_error` is never cached |
| token buckets | per IP: `ip.bind_rps`/`bind_burst`, `ip.search_rps`/`search_burst` → `busy` + `bind_blocked{rate_limited}` / `rate_limited` |
| progressive delay | per source IP: `delay.base × 2^(n−1)` up to `delay.max` after each failure, reset on success |
| constant-time failure | `constant_time_bind_fail`: a failed bind is padded to the p95 of the last 256 successful bind durations |
| `allow_cidrs` | sources without any limit, delay or lock |
| lockdown | `SetLockdown(on, source)` → `lockdown{state, source}`; while on, only `lockdown.allow_cidrs` and `lockdown.allow_accounts` are served, everything else is refused without upstream (`bind_blocked{lockdown}`, searches `unwillingToPerform`); `lockdown.auto` enters it on a high-level `attack_start`; it stays on until switched off |
| tarpit | sources marked by the detectors (`SetAttack`) wait `tarpit.delay` before every answer while `tarpit.enabled`; at most `tarpit.max_conns` are held, further requests are refused at once; `tarpit{ip, conns}` |

Passwords never enter the limiter: `HashPassword` returns
`hex(sha256(processSalt ‖ password))`, the only form that is stored (negative
cache) or shared (spray detection).

Every table is bounded (`MaxEntries`, default 100 000); the tarpit slot
counter and the lockdown flag are global.

## ids.Engine

Bind detectors run over the recent attempts of one source IP:

| detector | fires when | event |
|---|---|---|
| `spray` | within `spray.window` one password hash was tried against ≥ `min_accounts` accounts (`same_password_hash = false`: any passwords) | `attack_start{kind=spray}` |
| `stuffing` | within `stuffing.window` ≥ `min_pairs` distinct (account, password) pairs with at least `min_pairs/2` distinct passwords | `attack_start{kind=stuffing}` |
| `slow_brute` | within `slow_brute.window` ≥ `min_failures` failures at ≤ `max_rate_per_min` | `attack_start{kind=slow_brute}` |
| `enumeration` | ≥ `enumeration.min_accounts` distinct accounts without a success in between | `attack_start{kind=enumeration}` |

One attack per kind is active at a time; sources that fire later join it
(`ips[]`). `attack_summary` is emitted every `summary_interval`,
`attack_end` after `quiet_period` without detections (the histories of the
involved sources are reset so the same data does not restart it). Level is
`high` when the attack has ≥ 3 sources, ≥ 3× the threshold of failures or
accounts, or ≥ 60 failures per minute; `medium` otherwise. `OnAttack` /
`OnAttackEnd` callbacks mark the sources for the tarpit and drive
`lockdown.auto`.

Recon signatures (`ids.Signatures`), one `recon{signature, filter_norm,
base, attrs}` per match, the same signature from one source at most once a
minute:

| signature | match |
|---|---|
| `root_dump` | `(objectClass=*)` with `scope = sub` from the root DSE or `virtual_base` |
| `sd_dump` | `nTSecurityDescriptor` requested or filtered |
| `sid_history` | `sIDHistory` |
| `trusts` | `trustPartner`, `trustedDomain`, `trustDirection` |
| `msds_attrs` | any `msDS-*` attribute |
| `admin_count` | `adminCount` |
| `spn_sweep` | `servicePrincipalName` requested with a broad subtree filter or filtered on |
| `base_outside` | a base outside the virtual tree |

Baseline / anomaly: per profile the engine learns for `anomaly.learn_for`
after start (or `Learn(d)` — `aldapctl baseline learn`, Stage 10) the set of
source IPs (binds and searches), filter shapes (`ids.FilterShape`: values
replaced by `?`), bases, requested attribute sets, per-second search rates
and — with `fingerprint.enabled` — client fingerprints. Afterwards a value
outside the baseline is reported once as `anomaly{reason, observed,
baseline}` with reason `new_ip`, `new_filter`, `new_base`, `new_attrs`,
`rps_spike` (more than `max(2 × p95, 10)` searches in one second, at most
once a minute) or `fingerprint`.

Fingerprints come from `internal/listener`: the TLS ClientHello hash
(versions, cipher suites, curves, point formats, signature schemes, ALPN —
`listener.HelloFingerprint`) combined with the LDAP first packet (operation,
LDAP version for binds, number of controls, size bucket), e.g.
`tls:9f1c…|ldap:0/3/0/4`. The same string appears in `session_summary`.

Indicators (`Engine.Indicators(minScore)`, `/v1/indicators` in Stage 7):
every source IP and account carries a score, the sum of weighted hits with
an exponential decay (half-life 1 h): honeytoken 100, `attack_start` high
80 / medium 50, lock 30, recon 20, anomaly 10, refused operation 2, failed
bind 1. Locks, honeytoken hits and refused operations are scored from the
event stream (`Engine.Note`), the rest from the detectors.

## session_summary (`internal/listener`)

Every connection ends with `session_summary{binds_ok, binds_fail, searches,
results_total, denied, duration_ms, bytes_in, bytes_out, fingerprint}`.

## Metrics (`internal/metrics`)

`aldap_locks_active{target}` (refreshed by `Sweep`),
`aldap_attack_active{kind}`, `aldap_binds_total{profile,result=ok|fail|blocked}`,
`aldap_bind_duration_seconds`, `aldap_searches_total{profile,cache}`,
`aldap_search_results`, `aldap_profile_cost`,
`aldap_connections_active{profile}`,
`aldap_upstream_queries_total{upstream,server,op,result}`,
`aldap_upstream_latency_seconds`, `aldap_upstream_up`,
`aldap_cert_expiry_seconds{listener}`, `aldap_events_total`,
`aldap_events_dropped_total`, `aldap_build_info`. The registry is served by
`/metrics` from Stage 7.

## Management API (`internal/api`)

See [`api.md`](api.md). Security-relevant points: constant-time token check over SHA-256 hashes, no
token values kept in memory; `admin` implies all scopes; `allow_cidrs` per token; per-client rate limit;
TLS mandatory beyond loopback (validated in the configuration and on the bound address at start); IPC
socket `0600`, never reachable with wider permissions; `api_call` for every `locks:write`/`admin` call,
refused ones included; `GET /v1/config` masks inline secrets; `PUT /v1/config` never leaves a half-written
file (atomic rename) and keeps a backup of the previous one.
