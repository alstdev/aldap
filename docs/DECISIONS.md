# Decisions log

Format: `YYYY-MM-DD | STATUS (OPEN/DECIDED) | topic | decision | rationale`

| Date | Status | Topic | Decision | Rationale |
|---|---|---|---|---|
| 2026-10-18 | DECIDED | Config format | TOML only | Owner requirement; YAML forbidden |
| 2026-10-18 | DECIDED | Upstream writes | Never | Scope; safety |
| 2026-10-18 | DECIDED | Compare op | Denied (`compareFalse` + `op_denied`) | Compare allows attribute-value enumeration |
| 2026-10-18 | DECIDED | Denied filter terms | Replace with FALSE, no error | Do not leak schema/allowlist |
| 2026-10-18 | OPEN | Virola custom CA | Verify on real install whether CA can be added or verification disabled | Affects TLS deployment docs |
| 2026-10-18 | OPEN | DHI tags | Verify `dhi.io/golang` and `dhi.io/static` tags at build time | Catalog changes |
| 2026-10-18 | DECIDED | Module path | `github.com/alstdev/aldap` | CLAUDE.md: org from `git remote` |
| 2026-10-18 | DECIDED | `build.sh` location | Repository root, not `scripts/build.sh` | SPEC §10.2, Makefile, Dockerfile and CI reference `./build.sh`; TASKS.md wording treated as a typo |
| 2026-10-18 | DECIDED | CGO in Makefile | `CGO_ENABLED=0` only for `go build`; `CGO_ENABLED=1` for `test`/`integration` | `-race` requires cgo; binaries stay static |
| 2026-10-18 | DECIDED | errcheck on `fmt.Fprint*` | Excluded via `exclude-functions` | CLI stdout/stderr write errors are not actionable; keeps `check-blank` strict elsewhere |
| 2026-10-18 | DECIDED | Licence report | Own module filtered out in `scripts/licenses.tpl` | `go-licenses report` lists the root module itself |
| 2026-10-18 | OPEN | Local `make vuln` | Blocked in the agent environment (proxy denies `vuln.go.dev`); runs in CI | Re-check when environment network policy changes |
| 2026-10-18 | OPEN | Local Docker build | Blocked in the agent environment (no Docker daemon); `docker-plain` job runs in CI | Verify `--target plain` on the first CI run |
| 2026-10-18 | DECIDED | Offline `aldap check` and missing files | Unreadable secret or certificate file is a warning offline, an error with `Validator.StrictFiles` (used by `run`/`--online`) | KP of Stage 1 requires 0 errors on `aldap.toml.example`, whose `/run/secrets/*` exist only at run time |
| 2026-10-18 | DECIDED | Env overlay of secrets | Setting any form (`X`, `X_file`, `X_env`) from `ALDAP_*` clears the other two forms | SPEC §3.1: environment outranks files and TOML |
| 2026-10-18 | DECIDED | Table names from env | Existing names match case-insensitively with `-`→`_`; a new table created from env is named lower case with `_`→`-` | SPEC §3.3 example maps `ad-main` to `AD_MAIN`; names with `_`, `.` or upper case get a warning |
| 2026-10-18 | DECIDED | Env coverage | Free-form tables (`attrs.map`, `computed`, `mask`, `groups`, `headers`) and arrays of tables (`[[events.webhook]]`, `[[notify.channel]]`, `[[api.token]]`) are not settable from env; unknown `ALDAP_*` is an error (except `ALDAP_CONFIG`, `ALDAP_TEST_*`) | SPEC §3.3 defines only section/name/key addressing; prohibition 7 |
| 2026-10-18 | DECIDED | `profile.transport` default | Always `ldaps`, regardless of port | Secure default; SPEC says "ldaps (default for 636)" without a rule for other ports |
| 2026-10-18 | DECIDED | `mode = honeypot` | `upstream`, `bases` and `attrs.allow` are optional | A honeypot never queries the upstream |
| 2026-10-18 | DECIDED | `[[api.token]]` validation | Tokens are validated even when `api.enabled = false` | Catches misconfiguration before the API is switched on |
| 2026-10-18 | DECIDED | Filter and DN syntax in `check` | `Validator.ParseFilter`/`ParseDN` default to `ldapfilter.Parse`/`ParseDN` (Stage 2); structural stand-ins removed | Parsers belong to `internal/ldapfilter`; hooks kept for tests |
| 2026-10-18 | OPEN | `aldap check --quick` as container HEALTHCHECK | Currently an offline config check; a liveness probe of the running process comes with `aldap run` (Stage 4) | Dockerfile/compose already reference `check --quick` |
| 2026-10-18 | DECIDED | BuildKit attestations in `build.sh` | `--provenance/--sbom` only with `ATTEST=1`; CI `docker-plain` builds without them | Default docker driver rejects attestations ("Attestation is not supported for the docker driver"); syft already produces the CycloneDX SBOM |
| 2026-10-18 | DECIDED | Filter attribute descriptions | RFC 4512 strict: keystring (`ALPHA *(ALPHA/DIGIT/"-")`) or numeric OID, `;options`; `_` and spaces rejected | Safe default; OpenLDAP rejects them too; unknown input is refused, not guessed |
| 2026-10-18 | DECIDED | Filter value escapes | Only `\XX` (RFC 4515); legacy `\*` (RFC 1960) rejected; serializer also escapes C0 controls and DEL | Canonical form is safe to log and round-trips exactly |
| 2026-10-18 | DECIDED | `Normalize()` scope | Lower-case attribute descriptions and matching rules; sort and dedupe and/or members by text; values untouched; no boolean simplification | Values compare per attribute syntax, which the proxy does not know; `Simplify()` is a separate, explicit step |
| 2026-10-18 | DECIDED | `Split()` of mixed Or/Not | Upstream gets absolute true, the whole node is evaluated locally; only And is split member-wise | Splitting an Or/Not containing local terms would change its meaning; superset from upstream is always safe |
| 2026-10-18 | DECIDED | Denied filter terms in `Split()` | Replaced by `(|)` before simplification; And with a denied member becomes `(|)` (no upstream query), Or drops it | SPEC §4.2 step 3; empty result, no error, no schema leak |
| 2026-10-18 | DECIDED | DN parsing leniency | Unescaped spaces around `,`, `+`, `=` are ignored; `;` separator and `\<letter>` escapes rejected; `#hex` kept as raw BER bytes | AD tools write `CN=x, OU=y`; RFC 4514 §3 allows accepting it; strictness elsewhere |
| 2026-10-18 | DECIDED | DN equality | Types case-insensitive; values compared with caseIgnoreMatch folding (trim, collapse spaces, lower-case) for every attribute type | DN attribute types in scope (cn, ou, dc, o, uid) are all caseIgnore; per-syntax matching would need schema knowledge |
| 2026-10-18 | DECIDED | `IsUnder(base)` includes equality | A DN is under itself; every DN is under the empty root | Matches LDAP scope semantics (base/sub include the base entry) |
| 2026-10-18 | DECIDED | Fuzz and round-trip corpus location | `internal/ldapfilter/testdata/filters.txt` (round-trip + fuzz seeds) and Go-managed `internal/ldapfilter/testdata/fuzz/` | `go test -fuzz` only reads `<pkg>/testdata/fuzz`; TASKS.md `testdata/fuzz` read as package-relative |
| 2026-10-18 | DECIDED | Fuzz round-trip length limit | Re-parse in fuzz uses 3× the default length limit | Canonical escaping can triple the text of a 4096-byte input; the limit is a policy, not a syntax property |
