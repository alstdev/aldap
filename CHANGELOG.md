# Changelog

## [Unreleased]
- Stage 1: `internal/config` (TOML model of every section, defaults, `include`, strict unknown keys, `ALDAP_*` env overlay, offline `Validate()` with key paths), `internal/secret` (inline/file/env forms, redaction in fmt/JSON/slog), `aldap check [--json]`, generated `docs/config.md` with `TestConfigDocsInSync`.
- Project scaffold from SPEC.md v1.0.
- Stage 0: Go module `github.com/alstdev/aldap`, `cmd/aldap` and `cmd/aldapctl` with `version` (ldflags), `internal/*` package skeleton, `make ci` targets verified, `THIRD_PARTY_LICENSES.md`, `.claude/settings.json`, `docs/STATE.md`.
