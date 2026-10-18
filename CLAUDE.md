# CLAUDE.md — правила роботи над ALDAP

Ти реалізуєш проєкт **ALDAP** за `SPEC.md`. SPEC.md — єдине джерело істини щодо вимог. `TASKS.md` — порядок етапів. `TESTING.md` — що і як тестувати. Якщо щось у SPEC.md суперечливе або неповне — не вигадуй: зафіксуй питання у `docs/DECISIONS.md` з позначкою `OPEN` і обери найбезпечніший варіант (менше прав, менше даних назовні, явна відмова замість мовчазного дозволу).

## Стек (фіксований)
- Go ≥ 1.25, модуль `github.com/alstdev/aldap` (org з `git remote`).
- Залежності тільки з `SPEC.md §2.2`. Нова залежність → спочатку перевір ліцензію (`go-licenses report`), додай у `THIRD_PARTY_LICENSES.md`, запиши причину в `docs/DECISIONS.md`. Copyleft (GPL/LGPL/AGPL/SSPL) — заборонено.
- Конфіг **TOML**. YAML у коді/конфігу проєкту — заборонено (виняток: `.golangci.yml`, GitHub Actions, `docker-compose.yml`, `openapi.yaml` — це формат інструментів, не наш конфіг).
- Логи — `log/slog`. Помилки — `fmt.Errorf("...: %w", err)`, сентинели через `errors.Is`.
- Жодного `panic` у runtime-шляхах; `recover` на межі з'єднання з редагуванням секретів.

## Структура репозиторію
```
cmd/aldap, cmd/aldapctl
internal/{config,secret,listener,profile,vdir,ldapfilter,upstream,cache,ratelimit,ids,events,notify,api,tlsutil,record,metrics,testdir}
docs/            SPEC-похідна документація, openapi.yaml, events.schema.json
deploy/          aldap.service, seccomp.json, docker-compose.yml, samba-dc/ (тестовий DC)
testdata/        LDIF, конфіги, записи replay
scripts/         допоміжні bash (shellcheck-чисті)
```
Один пакет — одна відповідальність. `internal/` не експортується. Публічний API пакетів мінімальний; інтерфейси визначаються на стороні споживача.

## Заборони (жорсткі)
1. **Ніякого запису в upstream.** Жодного коду, що формує Add/Modify/Delete/ModifyDN/PasswordModify до upstream. Такі запити від клієнта → `unwillingToPerform` + подія `op_denied`.
2. **Паролі не логуються.** Жоден `slog`, подія, panic trace, тест-вивід не містить паролів/токенів. Є обов'язковий тест `TestNoSecretsInOutput`.
3. **Немає `*` в allowlist атрибутів.** Валідатор відхиляє.
4. **`tls_insecure_skip_verify` за замовчуванням `false`** і ніколи не вмикається «для тестів» у продакшн-коді; тести використовують тестовий CA.
5. **Не «спрощувати» rate limit/IDS** заради проходження тестів — замість цього виправляти тест або логіку.
6. **Не додавати веб-UI, SCIM, Kerberos, запис паролів** — поза scope.
7. **Невідомі ключі конфігу — помилка**, не попередження.

## Стиль
- `gofmt`, `goimports`, `golangci-lint` за `.golangci.yml` — нуль попереджень.
- Коментарі до експортованих ідентифікаторів англійською. Повідомлення користувачу (CLI/TUI) — англійською; локалізацію не робимо.
- Тести `table-driven`, назви `TestXxx_Case`. Інтеграційні — під build tag `integration`, Samba — `integration_samba`.
- Контексти (`context.Context`) — перший аргумент усюди, де є I/O.
- Конфіг-структури: теги `toml:"snake_case"`, `Validate() error` на кожній.
- Час — `time.Duration` у конфігу як рядок (`"15m"`), парсинг через `toml` `UnmarshalText`.

## Робочий цикл
1. Читай тільки поточний Stage у `TASKS.md` і розділи `SPEC.md`/`TESTING.md`, вказані в його рядку «Читати:». Решту документів не відкривай, поки етап того не вимагає. Поточний стан — у `docs/STATE.md`.
2. Виконуй етапи `TASKS.md` по порядку; кожен етап = окрема гілка/PR або окремий коміт-серія з повідомленням `stage-N: <subject>`.
3. Перед завершенням етапу: `make ci` зелений, критерії приймання етапу виконані, `docs/` оновлено.
4. Після кожного етапу — оновити `TASKS.md` (позначка `[x]`) і `CHANGELOG.md`. Наприкінці кожного етапу записати в `docs/STATE.md` 5–10 рядків: що зроблено, де зупинився, що далі.
5. Не переходь до наступного етапу з червоним CI.
6. Якщо для етапу потрібне щось, чого немає (Docker, доступ до dhi.io, Windows) — реалізуй, що можна, помічай `BLOCKED: <що потрібно>` у `TASKS.md`, продовжуй наступне.

## Definition of Done (для будь-якої задачі)
- [ ] Код + unit-тести + (де є I/O) інтеграційний тест.
- [ ] `golangci-lint`, `go vet`, `govulncheck` — чисто.
- [ ] Покриття пакета не впало нижче порогу з `TESTING.md`.
- [ ] Жодних TODO без issue-посилання/запису в `docs/DECISIONS.md`.
- [ ] Документація ключів конфігу у `docs/config.md` синхронізована з кодом (тест `TestConfigDocsInSync` генерує список ключів з структур і порівнює з docs).
- [ ] OpenAPI (`docs/openapi.yaml`) синхронізовано з роутами (тест `TestOpenAPIRoutes`).
- [ ] Події валідні за `docs/events.schema.json` (тест).

## Команди
```
make build          # бінарники у dist/
make test           # unit
make integration    # in-memory LDAP (gldap testdirectory)
make integration-samba   # Samba AD DC у Docker (повільно)
make lint vet vuln licenses
make ci             # усе, крім samba
make docker-dhi / make docker-plain
make fuzz           # 2 хв fuzz на ldapfilter/dn/ber
```

## Економія контексту
- Не читай `dist/`, `artifacts/`, `go.sum`, `testdata/fuzz/`, `THIRD_PARTY_LICENSES.md`, `secrets/` (заборонено в `.claude/settings.json`).
- Тести й лінтер у процесі запускай лише для пакета, з яким працюєш (`go test ./internal/<pkg>/`, `golangci-lint run ./internal/<pkg>/...`). Повний `make ci` — тільки наприкінці етапу.
- Виводи команд обрізай до помилок: `2>&1 | grep -E 'FAIL|ERROR|error' -A5 | head -100`.
- Шумні задачі (fuzz, govulncheck, великі логи) віддавай субагенту і повертай лише висновок.

# Compact instructions
При стисненні контексту зберігати:
- номер поточного етапу (`Stage N`) і які його пункти вже виконані;
- перелік змінених/створених файлів;
- тести, що падають, з назвою тесту і однією строкою причини;
- ухвалені рішення (і ті, що записані в `docs/DECISIONS.md`) та відкриті питання.
Викидати: виводи логів, трейси, повні діффи, вміст прочитаних файлів.
