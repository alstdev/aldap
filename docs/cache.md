# Cache and replica (`internal/cache`, SPEC §5.1)

`[profile.<name>.cache]` decides where the searches of a proxy profile are answered from. `mode = mock` and
`mode = honeypot` have no upstream: `cache.mode` is ignored there (`aldap check` warns).

| `mode` | Searches | Binds |
|---|---|---|
| `none` (default) | every search goes to the upstream; group membership is reused for `cache.ttl` | upstream |
| `ttl` | upstream results are kept for `ttl` and served from memory; stale results while every server is down | upstream |
| `replica` | only from the in-memory copy of the profile, synced in the background | upstream |

**User binds never use the cache or the replica**: the credential check, the lookup of a virtual DN and
`require_membership` always go to the upstream, so a bind with the upstream down is answered `unavailable` (52)
in every mode. Passwords are never stored (the negative cache of the rate limiter keeps only salted hashes,
`docs/security.md`).

## `ttl`

- The cache sits between the directory and the upstream: one entry per upstream request after the profile
  rewrote it. Key = canonical base DN, scope, normalized filter (profile filter, `exclude_filter`, attribute
  map and the client filter included), lower-cased sorted attributes and size limit; the time limit is not part
  of it. A store belongs to one profile, so the key covers SPEC's (profile, filter, bases, attrs, scope, base).
- Group membership queries go through the same cache; membership itself is also reused for `ttl`.
- `max_entries` bounds the directory entries held over all results (an empty result counts 1); the least
  recently used results are evicted first, a single result larger than the bound is not cached. Errors are
  never cached.
- `stale_while_down = true`: an expired result not older than `stale_max` (age counted from the fetch) is
  served when every server of the upstream is `down`, or when the upstream answers `unavailable` (no server
  could take the request). `unknown` (before the first health check) is not down. The search then emits
  `stale_served{age_s, entries}` (medium) with the connection context; the `search` event carries
  `cache_hit: true`. Without `stale_while_down`, or with nothing cached for the request, the client gets
  `unavailable`.
- Results that can no longer be served (older than `ttl`, or than `stale_max` with stale serving) are dropped
  every second.

## `replica`

- A sync reads every `bases` × `filter`/`exclude_filter` with every attribute the profile can return
  (allowlist, map, computed dependencies, `objectGUID` for AD), then evaluates the virtual groups against the
  upstream, and builds the virtual entries. The copy is replaced only by a complete successful sync; a failed
  one keeps the last copy and emits `replica_sync_failed{age_s, entries}` (medium, `reason` =
  `upstream_unavailable`, `upstream_error` or `canceled`); a successful one emits
  `replica_synced{age_s, entries}` (low; `age_s` is the age of the copy it replaced, 0 for the first).
- Schedule: at once when there is no copy, then every `sync_interval` ± `sync_jitter` (default 5 min ± 20 %);
  after a failure the next attempt comes after at most 30 s. `aldapctl sync <profile>` /
  `POST /v1/profiles/{name}/sync` asks for a sync now (202; the outcome is the event).
- Searches are answered from memory only, never from the upstream: the client filter is evaluated on the
  virtual entries (the local matcher of `docs/vdir.md`, as for honeytokens and mock profiles), then masking,
  size limits and paging as usual; `upstream_queries` is 0 and `cache_hit` true. Before the first successful
  sync every search of the virtual tree is answered `unavailable`.
- **RDN collisions** are decided over the whole copy (every user of the profile, every group member and the
  honeytokens): a user whose `rdn_attr` value is shared gets the `+objectGUID` suffix in every search and in
  every group `member` value. In `none`/`ttl` the suffix is decided per result set and per membership set
  (DECISIONS «RDN collision suffix scope»).

## Reload

A cache survives a reload when its profile section and the section of its upstream are unchanged (SHA-256 of
both, secrets rendered `***`): the ttl results and the replica copy are kept, a replica keeps its schedule. Any
change of either section replaces the cache with an empty one (log `profile changed, cache invalidated`);
a replica then syncs at once. A reload that fails to start keeps the running caches.

## Metrics

`aldap_cache_entries{profile}` (ttl: directory entries held; replica: users of the copy),
`aldap_replica_age_seconds{profile}`, `aldap_searches_total{profile,cache}` with `cache` =
`replica`, `stale`, `hit`, `miss` (ttl), `local` (nothing asked upstream) or `none`.
