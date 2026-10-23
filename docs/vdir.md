# internal/vdir — virtual directory (Stage 5)

Implements SPEC §4.1–§4.6 and §3.4 `[profile.<name>]` on top of the Stage 4
pipeline described in `docs/listener.md`: virtual groups, computed and
masked attributes, object class mapping, local post-filtering, honeytokens,
`mode = honeypot` and `mode = mock`, and the client-view diagnostics behind
`aldap check --as-client` (later `POST /v1/profiles/{name}/test`).

## Search pipeline (SPEC §4.2)

1. Parse the client filter (depth/length limits) and classify the requested
   attributes: allowed, mapped, computed and `memberOf` are returned;
   anything else is `attrs_denied`.
2. Classify the base (`profile.Rules.ClassifyBase`): root DSE, subschema,
   `<virtual_base>`, `ou=users`, `ou=groups`, one user, one group.
3. Detect a honeytoken target (see below).
4. Split the filter (`ldapfilter.Split`) by attribute class:
   - **upstream** — `attrs.allow`, `attrs.map` keys and `objectClass`;
   - **local** — computed attributes and `memberOf` (post-filter);
   - **denied** — everything else: the term becomes absolute false, the
     attribute is listed in `search.denied_terms`, no error is returned.
   The upstream part is rewritten to upstream names (`attrs.map`,
   `objectclass.map` reversed for `objectClass` values), AND `filter`, AND NOT
   `exclude_filter`, AND `(rdn_attr=value)` for a single-user base.
5. Fetch from every base in parallel (`limits.upstream_parallel`): `rdn_attr`,
   `objectGUID`, the requested allowed attributes, the dependencies of every
   computed template and the allowed attributes the post-filter reads.
   With a post-filter the size limit is applied after filtering, so the
   whole candidate set is fetched.
6. Merge with de-duplication (`objectGUID` for `kind = ad`, canonical DN
   otherwise); append the honeytoken entries.
7. Transform each entry: virtual DN `cn=<rdn_attr>,ou=users,<virtual_base>`
   (`+objectGUID=<hex>` on an RDN collision within the result, WARN),
   allowed attributes renamed, `objectClass` values mapped, computed
   templates evaluated (a non-empty result replaces the upstream value),
   `memberOf` set from the group membership snapshot.
8. Post-filter: upstream entries are checked against the local part of the
   filter; honeytoken entries, which never went upstream, against the whole
   client filter. Post-filtering happens **before** masking, so filters on a
   masked attribute compare the real (or computed) value (SPEC §4.6).
9. Mask (`attrs.mask`), project the requested attributes, sort by DN, apply
   `sizeLimit`/`limits.max_result_size`, page (unchanged from Stage 4).

The local matcher (`match.go`) supports equality, substring, presence,
ordering (numeric when both sides are integers), approx, DN equality for
`member`/`memberOf`/`distinguishedName`/`manager`, bare `objectCategory`
names and the AD bit rules `1.2.840.113556.1.4.803/804`; other extensible
matches never match. `(objectClass=*)` matches every entry.

## Attributes

- **`attrs.computed`** — `name = "go-template"` evaluated with `text/template`
  over a map of upstream attribute names → first value (missing → `""`).
  Functions: `or`, `printf` (built in), `lower`, `upper`, `trim`,
  `default DEF V`, `first V...`, `join SEP V...`, `regexReplace PATTERN REPL V`
  (`$1` groups). The template's `.Field` references are its dependencies
  and are fetched automatically. A template error drops the attribute for
  that entry (debug log). Computed names are client-visible without being
  listed in `attrs.allow`; a computed name that is also allowed overrides
  the upstream value.
- **`attrs.mask`** — `name = "pattern"` applied to the client attribute after
  computed: literal text plus `{first<N>}`, `{last<N>}` (runes) and
  `{domain}` (text after the last `@`, empty when none). Unknown
  placeholders are configuration errors.
- **`objectclass.map`** — `upstream_class = "client_class"`; values of
  `objectClass` are rewritten in entries and reversed in filters.
- **`memberOf`** is always virtual: it lists the virtual groups of the user
  and never the upstream's groups (SPEC §4.4). Without groups it is absent.

## Virtual groups (SPEC §4.4)

Membership of every group is computed together and cached for
`cache.ttl` (default 60 s, also for `cache.mode = none`), so `member` and
`memberOf` agree within that window; with `cache.mode = replica` it is part
of the synced copy (`docs/cache.md`). Sources per group, every one
intersected with the profile `filter`/`exclude_filter`:

| Source | Evaluation |
|---|---|
| `members.bases` + `members.filter` | subtree search per base; default: the profile bases and filter (a group without any source contains every user of the profile) |
| `members.ad_groups` | `kind = ad`: `(memberOf=<dn>)`, or `(memberOf:1.2.840.113556.1.4.1941:=<dn>)` with `nested_groups = true`, over the profile bases; `kind = generic`: the group's `member`/`uniqueMember` values are walked (nested groups recurse up to `nested_depth`, loops are cut), each user is read base-scope with the profile filter and must lie in a profile base |
| `members.include` | UPN or mail (`a@b`), `sAMAccountName`/`uid`, or an upstream DN inside a profile base |
| `members.exclude` | the same forms, matched against the members found |
| honeytokens | added when `honeytoken_in_groups = true` |

Group entries: `objectClass: top, <objectclass>`, `cn`, `description`,
`member` (virtual user DNs); `group` adds `sAMAccountName` and
`groupType`; `posixGroup` adds `gidNumber` and `memberUid` (rdn values).
Searches under `ou=groups` and `cn=<name>,ou=groups` are evaluated locally
(`(member=<dn>)` is DN-compared); `(memberOf=<dn>)` on users is a
post-filter. A membership computation failure is answered like an upstream
error and is not cached.

## Honeytokens (SPEC §4.5)

`honeytokens` are rendered once at compile time as upstream-like entries
(`profile.Honeytoken`): `cn`, `sn`, `givenName`, `displayName`, `name`,
`sAMAccountName`, `userPrincipalName`, `mail`, `uid`, `title`,
`objectCategory`, `userAccountControl`, `objectClass`, a stable pseudo
`objectGUID` and a DN under the first profile base. `honeytoken_template`
overrides any of them with templates over `.account`, `.user`, `.domain`,
`.given`, `.sn`; an empty template removes the attribute. They go through
the same transformation as real users.

A hit is a bind on the account in any form (UPN, bare name, `DOMAIN\user`,
virtual DN, rdn value) or a search whose filter has an equality term on an
identity attribute (`sAMAccountName`, `userPrincipalName`, `mail`, `cn`,
`uid`, `displayName`, `name`, mapped names too) with a trap value, or
whose base is the trap's user DN. A hit emits `honeytoken{account, op}`
(level high) and locks the client IP for `ids.honeytoken.lock_duration`
(`lock{target=ip, key, until, source=honeytoken}`, recorded and reported by
the rate limiter behind `vdir.Guard`, see `docs/security.md`); binds from a
locked IP are refused with `lock_response` and `bind_blocked{reason=ip_locked}`,
searches with `unwillingToPerform` and `rate_limited{reason=ip_locked}`.
Trap binds never reach the upstream (`bind_fail{unknown_account}` is
emitted as well). The `search` event carries `honeytoken=<account>`.

`mode = honeypot`: no upstream is used; the root DSE and subschema answer
normally, every search of the virtual tree and every non-anonymous bind
(the client bind included) is a hit; the tree contains only the trap users
and the groups they populate.

## `mode = mock`

`mock.file` is a TOML file (`base_dn`, `[[users]]` tables whose keys are
attributes; values: string, array, integer, boolean) or a CSV file (header =
attribute names, `|` separates values in a cell, `dn` column optional).
Users without `dn` are placed at `cn=<cn>,<base_dn>`; without
`objectClass` they get `top/person/organizationalPerson/user`. The base
defaults to the profile's first `bases` entry (required for CSV). Binds
compare `userPassword` (constant time); the attribute is never returned.
The profile pipeline (allowlist, map, computed, groups, honeytokens) runs
unchanged over the mock source; the upstream name in events is `mock`.

## `aldap check --as-client`

`aldap check --as-client --profile NAME [--base DN] [--scope base|one|sub]
[--filter F] [--attrs a,b] [--size N] [--json]` validates the configuration
(strict files), connects to the profile's upstream (or loads the mock
file), runs the search through `vdir.Directory.Test` and prints the entries
as LDIF-like text followed by diagnostics: result code, entry count,
upstream queries, `upstream_filter`, `post_filter`, `denied_attrs`,
`denied_terms`, `honeytoken`. With `--json` the same lands in
`client_test`. Exit 1 when the search fails (e.g. a base outside the
virtual tree or an unreachable upstream).

## Tests

- `internal/vdir/stage5_test.go`: Virola scenario (two bases, no computers,
  `virola-users` with everyone, `memberOf`/`(memberOf=)`/`(member=)`),
  group sources (ad_groups nested/flat, include/exclude forms, posixGroup,
  group, TTL and invalidation, upstream failure), generic `member` walk
  with depth limits and loops, computed/mask/objectclass with
  post-filtering, honeytokens (listing, every targeting form, locks,
  `bind_blocked`, `honeytoken_in_groups`), honeypot, mock (TOML/CSV, binds,
  errors), `Test()` and the guard defaults; `match_test.go` for the local matcher.
- `cmd/aldap/stage5_test.go` (`-tags integration`): the Virola scenario
  end to end over ldaps with go-ldap (user bind UPN with
  `require_membership`, memberOf, nested `staff`, computed mail filter,
  object class map, honeytoken lock, paging), honeypot and mock profiles,
  `aldap check --as-client`, and `TestDaemon_Ldap3`, which runs
  `testdata/ldap3_test.py` (simple bind UPN over ldaps, paged search of 5,
  `memberOf`) with the local `python3` + `ldap3` (CI installs it), else in
  `python:3-slim` through Docker, else skips.
