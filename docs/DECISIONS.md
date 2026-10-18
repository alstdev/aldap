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
