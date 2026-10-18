# STATE — де ми зараз

Оновлюється наприкінці кожного етапу (5–10 рядків). Читати першим після `CLAUDE.md`.

## Stage 0 — Каркас репозиторію (завершено 2026-10-18)
- Зроблено: `go.mod` (`github.com/alstdev/aldap`, Go 1.25), `cmd/aldap` і `cmd/aldapctl` з командою `version` (ldflags), заглушки `internal/*` за CLAUDE.md, `.gitignore`, `.claude/settings.json`, `THIRD_PARTY_LICENSES.md`.
- Виправлено в існуючому каркасі: Makefile (CGO лише для тестів з `-race`, shellcheck без обов'язкового `scripts/*.sh`), `.golangci.yml` (local-prefixes, errcheck для `fmt.Fprint*`), `scripts/licenses.tpl`.
- Перевірено локально: `make lint vet licenses test integration shellcheck build` зелені, покриття 92%.
- Не перевірено локально: `make vuln` (proxy блокує `vuln.go.dev`), `docker build --target plain` (немає Docker daemon) — обидва виконуються в CI.
- Зупинився: після коміту `stage-0: scaffold` у `main`.
- Далі: Stage 1 — `internal/config` і `internal/secret` (читати SPEC §3, TESTING «Рівні»).
