# STATE — де ми зараз

Оновлюється наприкінці кожного етапу (5–10 рядків). Читати першим після `CLAUDE.md`.

## Stage 2 — Парсер фільтрів і DN (завершено 2026-10-18)
- Зроблено: `internal/ldapfilter` — парсер RFC 4515 (`Parse`, `ParseWithLimits`, ліміти глибини 20/64 і довжини 4096), `String()`/`Normalize()` (канонічна форма для `filter_norm`), `EscapeValue`/`UnescapeValue`; операції `Inject`, `Exclude`, `MapAttrs`, `Walk`, `Split` (Upstream/Local/Denied → `(|)`), `Simplify`; DN RFC 4514 (`ParseDN`, `String`, `Equal`, `Canonical`, `IsUnder`, `Rewrite`, `Parent/Child`, `EscapeRDNValue`); fuzz `FuzzParseFilter`/`FuzzParseDN`; корпус 334 фільтри у `internal/ldapfilter/testdata/filters.txt`. `config.Validator` тепер використовує ці парсери; структурні перевірки видалено. Опис — `docs/ldapfilter.md`.
- Покриття: `ldapfilter` 98.9%. Fuzz 2 хв на обидві цілі — без падінь.
- Супутнє: виправлено CI (`secrets` в `if:` → job `env`; тригер на `claude/**`; `build.sh` атестації лише з `ATTEST=1`), `aldap check` показує `(environment only)` без файлу.
- Відкрите: конвертація BER ↔ AST для фільтрів із wire (Stage 4, listener); обчислення `postfilter` над entry (Stage 5, vdir).
- Зупинився: після коміту `stage-2: filter and DN parser` у гілці `claude/adoring-brahmagupta-ce3wwz`.
- Далі: Stage 3 — `internal/upstream` (пул, failover).

## Stage 1 — Конфіг і секрети (завершено 2026-10-18)
- Зроблено: `internal/secret` (форми `X`/`X_file`/`X_env`, взаємовиключність, обрізання `\n`, warn на права > 0640, редагування в fmt/JSON/slog), `internal/config` (модель усіх секцій SPEC §3.4 з тегами `toml`/`doc`, дефолти, `include` з glob, невідомі ключі → помилка, env-overlay `ALDAP_*` через reflection, `Validate()` з шляхами ключів), `aldap check [--config] [--json] [--quick]`, `docs/config.md` + `TestConfigDocsInSync`.
- Покриття: `config` 90.6%, `secret` 97%, `cmd/aldap` 95%.
- Нова залежність: `github.com/BurntSushi/toml` (MIT, SPEC §2.2).
- Відкрите: синтаксис фільтрів/DN поки структурний (Stage 2 підключає парсери через `Validator.ParseFilter/ParseDN`); `--online` повертає код 2 до Stage 3.
- Зупинився: після коміту `stage-1: config and secrets` у `main`.
- Далі: Stage 2 — `internal/ldapfilter` (читати SPEC §0, §4.2, §9, §12; TESTING «Рівні», «Безпека»).

## Stage 0 — Каркас репозиторію (завершено 2026-10-18)
- Зроблено: `go.mod` (`github.com/alstdev/aldap`, Go 1.25), `cmd/aldap` і `cmd/aldapctl` з командою `version` (ldflags), заглушки `internal/*` за CLAUDE.md, `.gitignore`, `.claude/settings.json`, `THIRD_PARTY_LICENSES.md`.
- Виправлено в існуючому каркасі: Makefile (CGO лише для тестів з `-race`, shellcheck без обов'язкового `scripts/*.sh`), `.golangci.yml` (local-prefixes, errcheck для `fmt.Fprint*`), `scripts/licenses.tpl`.
- Перевірено локально: `make lint vet licenses test integration shellcheck build` зелені, покриття 92%.
- Не перевірено локально: `make vuln` (proxy блокує `vuln.go.dev`), `docker build --target plain` (немає Docker daemon) — обидва виконуються в CI.
- Зупинився: після коміту `stage-0: scaffold` у `main`.
- Далі: Stage 1 (виконано, див. вище).
