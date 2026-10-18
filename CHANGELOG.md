# Changelog

## [Unreleased]
- Stage 2: `internal/ldapfilter` — RFC 4515 filter parser (AST for and/or/not/equality/substring/ge/le/present/approx/extensible with `:dn:` and matching-rule OIDs, RFC 4526 `(&)`/`(|)`), canonical serializer and `Normalize()` (`filter_norm`), `EscapeValue`/`UnescapeValue`, depth/length limits (`ErrTooDeep`/`ErrTooLong`); AST operations `Inject`, `Exclude`, `MapAttrs`, `Walk`, `Split` (upstream/local/denied terms, denied → absolute false) and `Simplify`; RFC 4514 DN parser/normalizer with `Equal`, `Canonical`, `IsUnder`, `Rewrite`, `EscapeRDNValue`; fuzz targets `FuzzParseFilter`/`FuzzParseDN`; 300+ filter round-trip corpus. `config.Validator` now uses these parsers instead of structural checks.
- CI: `docker-dhi` reads `DHI_USERNAME` from job `env` (secrets cannot be used in step `if:`); the workflow also runs on `claude/**` branches and `workflow_dispatch`; `build.sh` BuildKit attestations are opt-in (`ATTEST=1`).
- `aldap check`: reports `(environment only)` instead of a non-existent default path when the configuration comes from `ALDAP_*` only.
- Stage 1: `internal/config` (TOML model of every section, defaults, `include`, strict unknown keys, `ALDAP_*` env overlay, offline `Validate()` with key paths), `internal/secret` (inline/file/env forms, redaction in fmt/JSON/slog), `aldap check [--json]`, generated `docs/config.md` with `TestConfigDocsInSync`.
- Project scaffold from SPEC.md v1.0.
- Stage 0: Go module `github.com/alstdev/aldap`, `cmd/aldap` and `cmd/aldapctl` with `version` (ldflags), `internal/*` package skeleton, `make ci` targets verified, `THIRD_PARTY_LICENSES.md`, `.claude/settings.json`, `docs/STATE.md`.
