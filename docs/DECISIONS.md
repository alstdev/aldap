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
| 2026-10-18 | OPEN | Filter and DN syntax in `check` | Structural checks until Stage 2 wires the RFC 4515/4514 parsers into `Validator.ParseFilter`/`ParseDN` | Parsers belong to `internal/ldapfilter` |
| 2026-10-18 | OPEN | `aldap check --quick` as container HEALTHCHECK | Currently an offline config check; a liveness probe of the running process comes with `aldap run` (Stage 4) | Dockerfile/compose already reference `check --quick` |
| 2026-10-18 | DECIDED | BuildKit attestations in `build.sh` | `--provenance/--sbom` only with `ATTEST=1`; CI `docker-plain` builds without them | Default docker driver rejects attestations ("Attestation is not supported for the docker driver"); syft already produces the CycloneDX SBOM |
