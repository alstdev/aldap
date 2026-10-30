# internal/listener, profile, vdir, tlsutil — client side (Stage 4)

Implements SPEC §3.4 `[server]`/`[tls]`/`[profile.<name>]`, §4.2 (Search),
§4.3 (Bind), §9 (transport limits) and §12 (client compatibility). Virtual
groups, computed/masked attributes, honeytokens and the honeypot/mock
modes are in `docs/vdir.md` (Stage 5); rate limiting and IDS follow in
Stage 6.

## Packages

| Package | Responsibility |
|---|---|
| `internal/listener` | Accepts TCP connections, terminates TLS (`ldaps`) or upgrades with StartTLS, decodes LDAPMessages with `go-asn1-ber`, enforces the limits of §9, refuses every write/compare/unknown extended operation (`op_denied`), hands Bind and Search to a `Handler`. |
| `internal/profile` | Compiles one `[profile.<name>]` into immutable `Rules`: virtual tree DNs, upstream bases, mandatory/exclude filters, attribute allowlist and renames, `client_bind` (argon2id), bind-name normalization, base classification. |
| `internal/vdir` | The virtual directory (`listener.Handler`): root DSE, minimal `cn=Subschema`, container entries, user search pipeline over `internal/upstream`, paged results, user and client binds, `search`/`bind_ok`/`bind_fail` events. |
| `internal/tlsutil` | Built-in CA (`gen-ca`, auto-init), server certificate issue/persist/renew, external cert/key, `tls.Config` with min version and mTLS, `cert_expiring`/`cert_renewed`. |
| `internal/events` | `events.Event` record and `Sink` interface shared by every producer; `events.Logger` writes events through `slog` until the Stage 6 bus exists. |
| `cmd/aldap run` | Builds everything from the configuration, starts listeners, handles `SIGINT`/`SIGTERM` (graceful) and `SIGHUP` (reload). `gen-ca`, `gen-cert`. |

## Why not gldap as the server

`gldap` v0.1.14 listens by itself (`Run(addr)`, no `Serve(net.Listener)`),
reads packets without a size bound, sets one read deadline per connection,
does not expose the client address to handlers and has no route for
Compare. None of the SPEC §9 limits (`max_request_bytes`, 5 s first-packet
deadline, `idle_timeout`, per-IP and global connection limits) can be
enforced through it. `internal/listener` therefore decodes the protocol
itself with `go-asn1-ber` (SPEC §2.2) and `go-ldap`'s `DecompileFilter` and
control codecs; `gldap` stays the server of `internal/testdir`
(docs/DECISIONS.md).

## Connection life cycle

1. Accept → global limit (`server.max_connections`) → per-IP limit
   (`limits.max_conns_per_ip`, shared by all listeners of a profile). Over
   a limit: the connection is closed and `rate_limited{reason=conn_limit_ip|conn_limit_global}` emitted.
   With `proxy_protocol` (Stage 12b, `docs/proxy-protocol.md`) the PROXY
   header is read between the two, off the accept loop and within the
   first-packet deadline; the per-IP limit, every event and the guards then
   use the client address of the header.
2. `ldaps`: TLS handshake on the first read. Plain listeners: a non-BER first
   byte (for example a TLS ClientHello) closes the connection.
3. Read loop with a 5 s deadline for the first message and `limits.idle_timeout`
   afterwards. The BER header is parsed before any content is buffered; a
   message longer than `limits.max_request_bytes` closes the connection with a
   Notice of Disconnection (`protocolError`) and `rate_limited{reason=oversize}`.
   Before the decoder builds a packet tree, an allocation-free pre-scan
   (`scanBER`) refuses a message with nesting of 64 or more levels (SPEC §9),
   indefinite or truncated lengths, or more than 10 000 TLV elements (the
   decoder allocates ~370 bytes per element: a 1 MiB request of empty
   attribute names would cost ~190 MiB); the answer is a `protocolError`
   notice and the connection ends.
4. Requests are processed sequentially per connection (Bind semantics of
   RFC 4511 §4.2.1 for free; Abandon is a no-op, RFC 4511 §4.11).
5. Operations:
   - Bind: LDAPv3 simple only (`protocolError`/`authMethodNotSupported`
     otherwise); `confidentialityRequired` before StartTLS when TLS is
     required; the password buffer is zeroed after the handler returns.
   - Search: root DSE is readable in clear text even when TLS is required
     (clients discover StartTLS there); everything else gets
     `confidentialityRequired`.
   - StartTLS: offered on `starttls` and `ldap+starttls`; refused on `ldap`
     (`unwillingToPerform`) and when TLS is already up (`operationsError`).
     A failed handshake ends the connection, never a clear-text fallback.
   - Add/Modify/Delete/ModifyDN → `unwillingToPerform` + `op_denied{op}`;
     Compare → `compareFalse` + `op_denied{op=compare}`; other extended
     operations → `unwillingToPerform` + `op_denied{op=extended, oid}`.
   - Unbind closes; unknown protocol ops → Notice of Disconnection.
6. Shutdown: listeners close, every connection finishes its current request
   and then receives a Notice of Disconnection (`unavailable`); connections
   still busy at `server.shutdown_timeout` are cut (Stage 12, `docs/service.md`).

Transports: `ldap` (plain only), `ldaps`, `starttls` (StartTLS offered and
required for every operation but the root DSE), `ldap+starttls` (StartTLS
offered, required only with `starttls_required = true`).

## Search pipeline (SPEC §4.2)

1. Filter text (from the wire via `DecompileFilter`) is parsed with
   `limits.max_filter_depth`/`max_filter_len` → `adminLimitExceeded` when exceeded.
2. Base classification: root DSE, `cn=Subschema`, `<virtual_base>`,
   `ou=users`, `ou=groups`, `cn=<rdn>,ou=users` (one user), anything else →
   `noSuchObject` with an empty matchedDN.
3. Requested attributes: client names outside `attrs.allow` ∪ `attrs.map`
   are dropped silently (`attrs_denied` in the event); `*`/empty = every
   allowed attribute; `1.1` = none; `+` = nothing (no operational attributes
   are virtualized).
4. Filter rewrite: `attrs.map` (client→upstream), terms on attributes outside
   the allowlist become absolute false (`denied_terms`, no error, no
   upstream query when the whole filter is false); `objectClass` is always
   accepted in filters; AND `filter`, AND NOT `exclude_filter`; a single-user
   base adds `(rdn_attr=<value>)`.
5. One paged upstream search per `bases` entry (parallelism
   `limits.upstream_parallel`), asking only the upstream attributes needed
   plus `rdn_attr` and `objectGUID` (kind `ad`).
6. Merge: de-duplication by `objectGUID` (`ad`) or canonical DN (`generic`),
   stable order by virtual DN.
7. Transform: virtual DN `cn=<rdn_attr value>,ou=users,<virtual_base>`
   (collision → `cn=<value>+objectGUID=<hex>` and a WARN), attributes renamed
   to client names and reduced to the requested allowed ones.
8. Limits: `min(client sizeLimit, limits.max_result_size)` → `sizeLimitExceeded`.
9. Paged results (RFC 2696): the merged result is kept on the connection
   under a random 128-bit cookie (at most 8 cursors per connection, oldest
   evicted); later pages are served from memory; unknown cookie →
   `unwillingToPerform`; size 0 abandons.
10. Event `search{base, scope, filter_norm, attrs_requested, attrs_denied,
    denied_terms, results, upstream_queries, cache_hit=false, result_code}`;
    `userPassword`/`unicodePwd` values in `filter_norm` are replaced by `***`.

Static entries served by ALDAP: root DSE (`namingContexts`,
`subschemaSubentry`, `supportedLDAPVersion=3`, `supportedControl` = paged
results, `supportedExtension` = StartTLS when offered, `vendorName=ALDAP`,
`vendorVersion`), `cn=Subschema` (attribute types with well-known OIDs for
the allowed attributes, object classes of the virtual tree) and the three
containers. Virtual groups, computed/masked attributes, honeytokens and
the honeypot/mock modes are described in `docs/vdir.md` (Stage 5).

## Bind (SPEC §4.3)

| Name | Handling |
|---|---|
| empty, no password | anonymous: success only with `anonymous_bind = true`, else `invalidCredentials` + `bind_fail{anonymous}` |
| name without password | treated as anonymous (RFC 4513 §5.1.2) and refused |
| `client_bind.dn` | argon2id verification (constant time); `bind_ok{bind_kind=client}` |
| `user@realm` | sent as is |
| `DOMAIN\user` | `user@<default_domain>` when set, else as is |
| bare account | `account@<default_domain>` when set, else as is |
| `cn=<rdn>,ou=users,<virtual_base>` | resolved with the service account (`filter` AND `(rdn_attr=<rdn>)` over `bases`), exactly one match required, then bind with the real DN |
| any other DN | refused without an upstream call (`unknown_account`) |

Upstream outcomes: `*upstream.BindError` → `invalidCredentials` with the real
reason in `bind_fail` (`locked_in_ad` at level medium); `ErrUnavailable` →
`unavailable`. `user_bind.require_membership` runs the profile filter against
the authenticated user afterwards (`bind_fail{not_member}`). `user_bind.allow
= false` refuses every non-client bind with `unknown_account`. The password
reaches go-ldap as a string copy; the wire buffer is zeroed by the listener.

## TLS

`tls.mode = builtin-ca`: `ca_dir/ca.crt` + `ca.key` (0600) are loaded or,
with `auto_init`, created (`aldap gen-ca` does the same explicitly). The
server certificate (`server.crt`/`server.key` in `ca_dir`, kept in memory
when the directory is read-only) covers the listen hosts (host name,
`localhost` and loopback for wildcard addresses) plus `tls.san`; it is
reissued when a name is missing or `auto_renew_before` is reached
(`cert_renewed`), and `cert_expiring` fires once per certificate inside
`expiry_alert_before`. `tls.mode = external` loads `cert`/`key`.
`tls.key_type` selects ECDSA P-256 (default) or RSA-2048; `min_version` and
`client_auth`/`client_ca` map to `crypto/tls`.

## `aldap run`

`aldap run [--config FILE]` validates (strict: secret and certificate files
must exist), builds upstreams, profiles and listeners, binds every address
before serving (one failure aborts the start), starts health loops and
hourly certificate checks, emits `startup`. `SIGINT`/`SIGTERM`: graceful
stop within `shutdown_timeout`, `shutdown` event. `SIGHUP`: the new
configuration is loaded and validated; on failure the running one stays and
`config_reload{ok=false}` is emitted; on success the new configuration
takes the listeners over without closing unchanged addresses — requests in
flight finish under the old rules (Stage 12 hot reload, `docs/service.md`;
`config_reload{ok=true}`). Profiles with
`mode = honeypot` run without an upstream and `mode = mock` over
`mock.file` (`docs/vdir.md`).

## Tests

- `internal/listener`: unit tests over loopback with go-ldap as client
  (plain, ldaps, StartTLS flows, denied operations, protocol edge cases via
  raw BER, limits, timeouts, graceful shutdown, panic recovery);
  `FuzzParseMessage` (`make fuzz`, nightly).
- `internal/vdir`: pipeline tests against `internal/testdir` (static entries,
  users, allowlist, denied terms, merge/dedupe/exclude, RDN collisions,
  paging, limits, upstream errors, every bind form and failure reason).
- `cmd/aldap`: daemon tests — ldaps client → ALDAP → plain upstream with
  `insecure_config{plaintext_upstream}`, StartTLS-required profile,
  `ldapsearch -x`, `-ZZ`, `-E pr=5/noprompt` (skipped without
  `ldap-utils`), reload and signals, `gen-ca`/`gen-cert`,
  `TestNoSecretsInOutput_Daemon`.
