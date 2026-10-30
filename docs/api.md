# Management API, IPC and metrics

Contract: [`openapi.yaml`](openapi.yaml) (normative; `TestOpenAPIRoutes` checks that the routes of
`internal/api` and the file match in both directions, scopes included). Implementation: `internal/api`,
wiring in `cmd/aldap/control.go`.

## Listeners

| Listener | When | Authentication |
|---|---|---|
| IPC `[server].ipc_socket` | always (unix socket; Windows named pipe, see below) | none, acts with scope `admin`; unix file mode `0600`, Windows ACL SYSTEM + Administrators |
| API `[api].listen` | `[api].enabled = true` | `Authorization: Bearer <token>` |
| Metrics `[api.metrics].listen` | `metrics.enabled` and a separate address | `status:read`, or none with `metrics.public = true` |

- **TLS beyond loopback is mandatory.** `aldap check` refuses a non-loopback `listen` without `tls.builtin`
  or `tls.cert/key`, and at start the daemon checks the *bound* address again (`api.CheckTransport`):
  `0.0.0.0`, `::` or a host name that resolves elsewhere without TLS → the daemon does not start.
- `tls.builtin = true` issues the API certificate from the built-in CA (`[tls].ca_dir`), kept in memory;
  `client_auth = "require"` + `client_ca` enables mTLS (needs TLS).
- The IPC socket is bound under a temporary name, set to `0600` and renamed into place, so it is never
  reachable with wider permissions. A stale socket of a crashed process is replaced; a live one or a
  regular file at the path is a start error.
- **Windows:** `ipc_socket` is a named pipe (`\\.\pipe\aldap` by default, `github.com/Microsoft/go-winio`).
  Its DACL grants access to SYSTEM and Administrators only (`D:P(A;;GA;;;SY)(A;;GA;;;BA)`), remote
  clients are rejected (`FILE_PIPE_REJECT_REMOTE_CLIENTS`), a pipe already served by another process is a
  start error, a path outside `\\.\pipe\` is a start error. Clients need an elevated shell. Manual
  checklist: `docs/windows.md` (not covered by CI, SPEC §10.5).

## Tokens and scopes

`[[api.token]]`: `name`, `token` / `token_file` / `token_env` (≥ 32 bytes), `scopes`, `allow_cidrs`.

- Scopes: `events:read`, `locks:read`, `locks:write`, `status:read`, `admin`; **`admin` implies every scope**.
- Comparison is constant-time: the presented token is hashed (SHA-256) and compared with every
  configured token hash with `crypto/subtle`, without an early exit. Token values are not kept in memory.
- Answers: no or unknown token → `401` + `WWW-Authenticate: Bearer`; source outside `allow_cidrs` →
  `403 forbidden_source`; missing scope → `403 insufficient_scope`.
- `rate_limit_rps` is a token bucket per client address (`429` + `Retry-After: 1`); `0` disables it.
  The IPC socket is not limited.
- Every call to a `locks:write` or `admin` endpoint, refused ones included, emits
  `api_call{method, path, token_name, client_ip, status}` (level `medium` for status ≥ 400). IPC calls
  carry `token_name = "ipc"`, `client_ip = "local"`.
- Tokens, scopes, CIDRs, the rate limit and the metrics settings follow a reload; `listen`, `tls`,
  `client_auth`, `metrics.listen` and `ipc_socket` take effect after a restart (a warning is logged).

## Endpoints

All answers are JSON except `GET /v1/config` (`application/toml`), `/metrics` (Prometheus text),
`/v1/indicators?format=plain` (`text/plain`) and the SSE stream. Errors: `{"error": "...", "code": "..."}`.

| Endpoint | Source of the data |
|---|---|
| `GET /v1/status`, `/v1/upstreams`, `/v1/profiles` | current daemon (profiles without secrets), `Limiter`, `ids.Engine`, `Bus.Seq` |
| `GET/POST /v1/locks`, `DELETE /v1/locks/{target}/{key}` | `ratelimit.Limiter` (`source = api`, optional `reason`) |
| `POST /v1/lockdown` | `Limiter.SetLockdown(…, "api")` |
| `GET /v1/indicators` | `ids.Engine.Indicators` + active locks |
| `GET /v1/events` | `Bus.Since(since)`, then `types` filter and `limit` (≤ 10000) |
| `GET /v1/events/stream` | `Bus.Subscribe` + `Bus.Since(Last-Event-ID)` |
| `GET/PUT /v1/config`, `POST /v1/reload` | the configuration file and the serve loop |
| `POST /v1/profiles/{name}/test` | `vdir.Directory.Test` (same pipeline as `aldap check --as-client`) |
| `POST /v1/profiles/{name}/sync` | asks the replica of the profile for a sync now: `202`; `404` unknown profile, `409 not_replica` without `cache.mode = replica`; the outcome is `replica_synced` / `replica_sync_failed` (`docs/cache.md`) |
| `POST /v1/profiles/{name}/record` | `{"state": "on"\|"off"}` starts or stops the recorder of the profile (`internal/record`, docs/record.md); `404` unknown profile, `409 no_record_file` without `record.file`, `500` when the file cannot be opened (symbolic link, not a regular file, no permission) |
| `POST /v1/baseline/{profile}/learn` | `ids.Engine.Learn` (the baseline window is process-wide) |
| `GET /metrics` | `metrics.Handler` |
| `GET /healthz`, `/readyz` | process alive; every `proxy` profile has an upstream server `up` |

### Locks

`POST /v1/locks {"target": "ip"|"account", "key": "...", "duration": "1h", "reason": "..."}` → `201` with the
lock. IP keys are stored canonically (`::ffff:192.0.2.7` → `192.0.2.7`), accounts under the key binds are counted under (`ratelimit.AccountKey`: lower-case, realm of a UPN and domain of `DOMAIN\user` removed — `Alice@corp.local`, `CORP\alice` and `alice` are one lock, for `POST` and `DELETE` alike); `duration`
defaults to `15m`, at most `8760h`. An existing lock that lasts longer is kept. `DELETE` → `204` or `404`.

### Events and SSE

`GET /v1/events?since=<seq>&limit=1000&types=a,b` returns the records with `seq > since` from the ring
buffer (`[events].buffer_size`).

`GET /v1/events/stream` sends every record as

```
id: <seq>
event: <type>
data: <aldap.event.v1 JSON>

```

and a `: ping` comment every 15 s. A client that reconnects with `Last-Event-ID: N` (or `?since=N`) gets
`N+1…` from the ring buffer first, then live records, without gaps or duplicates. When the client lags and
its queue overflows, the missing records are read back from the ring buffer by `seq`. Records older than
the buffer are lost; compare the first `id` with `N+1` to detect that.

### Indicators

`?format=json` (default) — `[{target, key, score, reasons, hits, first_seen, last_seen, locked}]`;
`?format=stix-lite` — a STIX 2.1 bundle of `indicator` objects only (deterministic ids per key, `pattern`
`[ipv4-addr:value = '…']` / `[ipv6-addr:…]` / `[user-account:account_login = '…']`,
`confidence = min(100, score)`, `x_aldap_*` extensions); `?format=plain` — tab-separated
`target key score reasons locked` lines after a `#` header. `min_score` filters.

### Configuration

- `GET /v1/config` — the effective configuration (file, includes, `ALDAP_*`, defaults) as TOML; every
  inline secret that is set is `"***"`, an unset one is `""` (so the rendering loads back). A body whose
  inline secret is still the placeholder `"***"` is refused (`400 invalid_config`, "masked placeholder"):
  give the secret or move it to `*_file` / `*_env` before `PUT`. Every value of a `headers` table
  (`[[events.webhook]]`, `[[notify.channel]]`) is `"***"` too, names stay; a `headers` value equal to
  `"***"` is refused the same way — keep credentials in `headers_file`, which is rendered as its path.
- `PUT /v1/config?dry_run=true` — step 1 below only: `{"ok": true, "dry_run": true}` or `400`; no backup,
  no write, no reload (`aldapctl config validate`, TUI `v`).
- `PUT /v1/config` (TOML body, ≤ 4 MiB):
  1. the body is loaded and validated in memory as if it were the file (includes and environment
     apply, strict file checks) → `400 invalid_config`, **the file is not touched**;
  2. the current file is copied to `aldap.toml.bak.<UTC ts>` (same mode, never overwritten — a suffix
     `.1`, `.2` … is added; backups are not pruned);
  3. the new file is written atomically (temporary file in the same directory, `fsync`, rename);
  4. reload; when it fails (e.g. a port in use) the previous file is restored atomically and the
     previous configuration keeps serving → `500`, the error names the cause.
  The answer is `{"ok": true, "backup": "<path>"}`. Requests are serialized. `409 no_config_file` when the
  configuration comes from the environment only; `409 config_read_only` when the file or its
  directory cannot be written (e.g. a container mount with `:ro`, `docs/podman.md`): view and
  `dry_run` validation still work, edits go through the host file and a reload.
- `POST /v1/reload` — same as `SIGHUP`; `400 invalid_config` keeps the running configuration.
