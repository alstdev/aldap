# internal/upstream — pool, health, failover (Stage 3)

Implements SPEC §5.2 and the `[upstream.<name>]` table (§3.4). One
`upstream.Upstream` serves one table; the daemon creates one per name.

## API

| Call | Purpose |
|---|---|
| `New(name, *config.Upstream, bindPassword, Options)` | Parses the server URLs, builds the TLS configuration (`tls_ca_file`, `tls_server_name`, `tls_insecure_skip_verify`) and one service pool plus one bind-only pool per server. |
| `Start(ctx)` | Launches a health loop per server and, with `audit_service_account`, the service-account audit. Non-blocking. |
| `Search(ctx, SearchRequest)` | Paged search (control `1.2.840.113556.1.4.319`, `page_size` per page) with failover; entries de-duplicated per page order; `SizeLimit` honoured and the paging cursor abandoned. |
| `RootDSE(ctx, attrs...)` | Root DSE of the first available server. |
| `UserBind(ctx, name, password)` | Simple bind on the bind-only pool; `*BindError` with the `bind_fail` reason on credential failures, `ErrUnavailable` on transport failures. |
| `AuditServiceAccount(ctx)` | Administrative groups the service account is a (transitive, `kind = ad`) member of. |
| `Check(ctx, bases)` | Probes for `aldap check --online`: connect, service bind, root DSE, every base, audit. |
| `Status()`, `Healthy()` | Per-server state, streaks, last error, p50/p95 latency, pool counters. |
| `Close()` | Stops loops and closes pooled connections. |

Options: `Logger` (`slog`), `Events` (`EventSink`), `Now`.

## Server state machine

Each server is `unknown`, `up` or `down` with consecutive success/failure
counters (SPEC §5.2):

- `unknown → up` on the first success (no event);
- `up → down` after `failover.fail_threshold` consecutive failures → `upstream_down` (`high`, `{server, reason, consecutive}`), idle pooled connections are dropped;
- `down → up` after `failover.recover_threshold` consecutive successes → `upstream_up` (`medium`, `{server, reason: recovered, consecutive}`).

A failure is a transport problem only: dial, TLS, StartTLS, service bind,
network errors, timeouts, `serverDown`/`unavailable`/`busy`, closed
connections. LDAP results such as `noSuchObject`, `invalidCredentials` or
`sizeLimitExceeded` mean the server answered and count as successes.

Health checks run every `health_interval` on a fresh connection
(`health_check = rootdse | bind | search`) and immediately after any
operation failure. Idle connections older than `pool.max_idle` are closed
by the health loop.

## Server selection

Down servers are never tried. `failover.strategy = primary` with
`prefer_primary = true` (default) walks the list in order; with
`prefer_primary = false` the server that answered last stays first until
it fails. `roundrobin` rotates the up servers. Servers still `unknown`
come after the up ones. A transport failure moves to the next candidate
(search, service operations and user binds alike); a credential failure of
a user bind is never retried elsewhere. With no candidate left the caller
gets `ErrUnavailable`.

## Filters sent upstream

`SerializeFilter` runs `ldapfilter.Simplify` first. RFC 4526 absolute
filters are never sent: absolute false (also when produced by a nested
`(|)`) yields `ErrAbsoluteFalse` and `Search` returns an empty result
without a query; absolute true (also nested) becomes `(objectClass=*)`.

## Bind diagnostics (SPEC §4.3)

`ClassifyBindError` maps `AcceptSecurityContext error, data NNN`:

| data | reason |
|---|---|
| 525 | `unknown_account` |
| 52e, unknown code, no code | `invalid_password` |
| 530, 531, 533 | `disabled` |
| 532, 701 | `expired` |
| 773 | `must_change` |
| 775 | `locked_in_ad` (event level `medium`) |

The client always receives `invalidCredentials`; the reason goes to the
`bind_fail` event only. `BindError.Error()` never contains the password or
the raw diagnostic.

## Transport

- `ldap://` plain, `ldap://` + `starttls = true`, `ldaps://`. Default ports 389/636.
- With `starttls = true` every StartTLS failure (refused or handshake) fails
  the connection; there is no clear-text fallback (see `docs/DECISIONS.md`).
- Referrals are never followed: search references are dropped and counted
  in `Result.Referrals`; a `referral` result code becomes `ErrReferral`.
- The bind-only pool never executes searches; a reused connection is
  re-authenticated by the next bind (RFC 4511 §4.2.1).

## Events

Before the event bus exists (Stage 6) the package emits `upstream.Event`
(`Kind`, `Level`, `Upstream`, `Server`, `Data`) to the consumer-side
`EventSink`. Kinds: `upstream_down`, `upstream_up`, `insecure_config`
(`what = tls_insecure_skip_verify | service_account_admin`).

## Tests

- Unit tests use fake connections (`fake_test.go`): pool, state machine,
  paging, failover, strategies, bind reasons, health kinds, audit, check.
- Integration tests (`-tags integration`) run against two `internal/testdir`
  servers sharing one directory: failover and return to primary, paged
  search in two pages, bind reason mapping, ldaps/StartTLS, audit and
  `aldap check --online`.

# internal/testdir — in-memory AD-like directory

Built on `gldap` (own mux, not `gldap/testdirectory`): `Start(tb, opts...)`
returns a server on `127.0.0.1`; `StartFixture` loads `testdata/ad.ldif`
(25 users: 3 disabled, 1 locked, 1 must-change; 6 computers; `Staff ⊃
Managers ⊃ Directors`, `Contractors`; admin groups; `svc-aldap` read-only
and `svc-admin` privileged service accounts; passwords
`<sAMAccountName>-pass`).

Features: RFC 4515 filters evaluated with `internal/ldapfilter` (case-insensitive
equality, DN equality for DN-syntax attributes, `objectCategory=person`
shorthand, substrings, ordering, bit rules 803/804, `LDAP_MATCHING_RULE_IN_CHAIN`
over `member`/`memberOf`), scopes, size limit, paged results (cookie =
offset, `WithMaxPageSize`), root DSE, simple bind by DN / UPN /
`DOMAIN\sam` / sAMAccountName with AD diagnostics (`525/52e/533/775/701/773`,
`WithADBindCodes(false)` for generic servers), unbound searches refused
(`WithAnonymousSearch` to allow), StartTLS (`WithoutStartTLS` to refuse),
ldaps (`WithTLS`, `CAFile(tb)`, `ClientTLS()`), read-only (add/modify/delete →
`insufficientAccessRights`), passwords never returned.

Hooks: `Calls()`/`ResetCalls()` (connections, binds, searches, root DSE
reads), `SetDelay(d)`, `Kill()`/`Restart()` (front listener and all client
connections closed, same port on restart), `WithDirectory(dir)` to share
one store between two servers, `Dir.Upsert` to mutate entries.
