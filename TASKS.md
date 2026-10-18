# TASKS.md — етапи реалізації ALDAP

Виконувати по порядку. Кожен етап має критерії приймання (КП). Позначати `[x]` після зеленого `make ci`.

---

## Stage 0 — Каркас репозиторію
Читати: SPEC §2.2, §10; TESTING «CI», «Артефакти тестів».
- [x] `go mod init`, структура каталогів за `CLAUDE.md`, `Makefile`, `.golangci.yml`, `.github/workflows/ci.yml`, `LICENSE` (MIT), `CHANGELOG.md`, `docs/DECISIONS.md`.
- [x] `cmd/aldap version`, `cmd/aldapctl version` з ldflags.
- [x] `scripts/build.sh`, `Dockerfile` (DHI + plain), `docker-compose.yml`, `deploy/aldap.service`, `deploy/seccomp.json`.
- [x] `make licenses` → `THIRD_PARTY_LICENSES.md`; CI падає на ліцензіях поза allowlist.
- BLOCKED: `docker build --target plain` — у середовищі агента немає Docker daemon; перевіряється job `docker-plain` у CI.
- BLOCKED: `make vuln` локально — proxy середовища агента не пропускає `vuln.go.dev`; виконується в job `lint` у CI.
**КП:** `make ci` зелений на порожньому проєкті; `docker build --target plain` проходить; `shellcheck` чистий.

## Stage 1 — Конфіг і секрети
Читати: SPEC §3 (3.1–3.6, приклад 3.4 повністю); TESTING «Рівні».
- [x] `internal/config`: модель усіх секцій зі `SPEC.md §3`, `UnmarshalText` для duration, `include`, strict (невідомі ключі → помилка).
- [x] `internal/secret`: `X`/`X_file`/`X_env`, взаємовиключність, обрізання `\n`, перевірка прав файлу (warn).
- [x] Env-overlay `ALDAP_*` за схемою §3.3; мінімальний конфіг повністю з env.
- [x] `Validate()`: усі правила §3.5 (офлайн-частина). Повідомлення з шляхом до ключа (`profile.virola.attrs.allow: '*' is not allowed`).
- [x] `aldap check` (офлайн), `--json` вивід.
- [x] `docs/config.md` генерується/перевіряється тестом `TestConfigDocsInSync`.
- [x] (закрито у Stage 2) синтаксис фільтрів/DN перевіряється парсерами RFC 4515/4514 з `internal/ldapfilter` через `Validator.ParseFilter/ParseDN`.
**КП:** unit-покриття `config` ≥ 85%; `aldap check` на `aldap.toml.example` — 0 помилок; тести на кожне правило валідації; тест «секрет у двох джерелах → помилка».

## Stage 2 — Парсер фільтрів і DN
Читати: SPEC §0, §4.2, §9, §12; TESTING «Рівні», «Безпека».
- [x] `internal/ldapfilter`: парсер RFC 4515 у AST (and/or/not/equality/substring/ge/le/present/approx/extensible з dnAttributes і matching rule OID), серіалізатор (канонічна нормалізація: lower-case атрибутів, стабільний порядок у and/or для `filter_norm`), escape/unescape, ліміти глибини/довжини.
- [x] Операції над AST: `Inject(and)`, `Exclude(not)`, `MapAttrs(map)`, `Walk`, `Split(executable, postfilter)` — відділити терми, які не можна виконати в upstream (computed/virtual memberOf/denied → `FALSE`).
- [x] DN: парсер/нормалізатор (RFC 4514), `IsUnder(base)`, `Rewrite(oldBase→newBase)`, RDN escape.
- [x] Fuzz-тести (`go test -fuzz`) для парсера фільтрів і DN; corpus у `testdata/fuzz`.
**КП:** покриття ≥ 90%; fuzz 2 хв без падінь; round-trip parse→serialize→parse ідентичний для corpus із 200 фільтрів (включно з AD bit-match `:1.2.840.113556.1.4.803:`).

## Stage 3 — Upstream, пул, failover
Читати: SPEC §2.1, §3.4 `[upstream.<name>]`, §5.2, §5.3; TESTING «In-memory тестовий каталог», «Failover, кеш».
- [x] `internal/upstream`: URL-парсинг `ldap://`/`ldaps://`, StartTLS, CA, SNI; пул з'єднань (сервісний bind) + окремий bind-only пул; таймаути.
- [x] Health-check (`rootdse`/`bind`/`search`), стани `up/down`, пороги, `prefer_primary`/`roundrobin`, події `upstream_down/up`.
- [x] Paged search (control 1.2.840.113556.1.4.319), referrals ігноруються (`kind=ad`), `generic` — follow вимкнено.
- [x] Мапінг кодів bind-помилок AD (52e/533/775/701/773) у `reason`.
- [x] Аудит сервісного акаунта (`audit_service_account`).
- [x] `aldap check --online`.
- [x] Абсолютні фільтри RFC 4526 ніколи не йдуть в upstream (`SerializeFilter`: false → порожній результат без запиту, true → `(objectClass=*)`).
- [x] `internal/testdir` за TESTING.md: два in-memory сервери, AD-схема з `testdata/ad.ldif`, paging, chain/bit-match, AD-коди bind, хуки (лічильники, затримка, Kill/Restart).
**КП:** інтеграційні тести на `internal/testdir` (два in-memory сервери): failover при зупинці першого, повернення на primary, paged по 2 сторінки, мапінг reason; покриття ≥ 80%. — виконано (`upstream` 92%, `testdir` 93%).

## Stage 4 — Listener і базовий проксі (без віртуалізації)
Читати: SPEC §3.4 `[server]`, `[tls]`, `[profile.<name>]`, §4.2, §4.3, §9, §12; TESTING «Транспорт», «Bind», «Сумісність».
- [ ] `internal/listener` на gldap: `ldap`/`starttls`/`ldaps`/`ldap+starttls`, `starttls_required`, ліміти з'єднань (глобально/на IP), idle timeout, read deadline, `max_request_bytes`.
- [ ] Маршрутизація → профіль; RootDSE; `cn=Subschema` мінімальний.
- [ ] Bind: anonymous/client/user (нормалізація UPN/`DOMAIN\u`/sAM/virtual DN), прокидання в upstream, обнулення паролів у пам'яті.
- [ ] Search прохідний: валідація base/scope, AND з `filter`, allowlist атрибутів, map, злиття кількох `bases`, дедуплікація по objectGUID/DN, sizeLimit, paged results до клієнта.
- [ ] Усі write-операції/extended → `unwillingToPerform` + `op_denied`; Compare → `compareFalse` + `op_denied` (compare заборонено, бо дозволяє enumeration).
- [ ] `internal/tlsutil`: вбудований CA (`gen-ca`), серверний сертифікат з SAN, auto-init, auto-renew, `cert_expiring`.
- [ ] `aldap run` з graceful shutdown, SIGHUP reload (поки без hot-swap listener'ів допустимо повний перезапуск listener'ів).
**КП:** e2e з `ldapsearch -x -ZZ`, `ldaps://`, `-E pr=100/noprompt` проти ALDAP→testdir; тест «запит з `telephoneNumber` поза allow → атрибут відсутній, пошук по ньому → 0 результатів без помилки»; TLS-термінація: клієнт ldaps, upstream ldap.

## Stage 5 — Віртуальний каталог
Читати: SPEC §4 (4.1–4.6), §3.4 `[profile.<name>]`; TESTING «Віртуальна база», «Bind».
- [ ] `internal/vdir`: `virtual_base`, `ou=users`/`ou=groups`, переписування DN в обидва боки, `rdn_attr`, колізії RDN.
- [ ] `attrs.computed` (шаблони + функції), `attrs.mask`, `objectclass.map`, пост-фільтрація по computed.
- [ ] Віртуальні групи (§4.4): bases+filter ∪ ad_groups ∪ include − exclude ∩ profile.filter; `member`/`memberOf`; пошук по `(member=)`/`(memberOf=)`; `groupOfNames`/`group`/`posixGroup`.
- [ ] Nested groups: AD через `LDAP_MATCHING_RULE_IN_CHAIN`, generic — рекурсія з лімітом.
- [ ] Honeytokens (§4.5), `mode=honeypot`, `mode=mock` (TOML/CSV).
- [ ] `user_bind.require_membership`.
- [ ] `aldap check --profile X --as-client`, `POST /v1/profiles/{x}/test` (API пізніше, зараз — внутрішня функція).
**КП:** інтеграційні тести: Virola-сценарій (два bases, computer виключено, група `virola-users` зі всіма, user bind UPN, `memberOf` у користувача); колізія RDN; computed mail; mask телефону; honeytoken bind → lock; покриття `vdir` ≥ 85%.

## Stage 6 — Події, rate limit, IDS
Читати: SPEC §3.4 `[ratelimit]`, `[ids]`, `[events]`, §6, §9, §11; TESTING «Rate limit / IDS», «Події, API, notify», «Безпека».
- [ ] `internal/events`: шина, ULID, seq, кільцевий буфер, sinks stdout/file(ротація)/syslog/webhook(батчі, ретраї, HMAC, overflow policy), `hash_accounts`, редагування значень `unicodePwd`/`userPassword` у фільтрах; `docs/events.schema.json` + тест валідації кожної події.
- [ ] `internal/ratelimit`: IP/акаунт token bucket + вікна невдач, lock/unlock з подіями, негативний кеш, затримки, `constant_time_bind_fail`, `lock_response`, allowlists, tarpit, lockdown (ручний/авто).
- [ ] `internal/ids`: spray, stuffing, slow_brute, enumeration, recon-сигнатури, baseline/anomaly (learn), fingerprint (TLS ClientHello hash + LDAP first-packet), `attack_start/summary/end`, `session_summary`.
- [ ] `/v1/indicators` модель (score = зважена сума спрацювань з decay).
- [ ] Метрики `internal/metrics`.
**КП:** тести: 3 невдачі → lock → 4-та не йде в upstream (mock upstream рахує виклики); негативний кеш; spray-детектор на 5 акаунтах з одним хешем; recon на `(objectClass=*)` від кореня; anomaly new_ip після learn; webhook отримує батч з валідним HMAC; overflow drop_oldest; покриття `ratelimit`,`ids`,`events` ≥ 85%; тест `TestNoSecretsInOutput`.

## Stage 7 — API, метрики, IPC
Читати: SPEC §3.4 `[api]`, §7, §11, `docs/openapi.yaml`; TESTING «Події, API, notify».
- [ ] `internal/api`: усі ендпоїнти §7, OpenAPI `docs/openapi.yaml` + тест `TestOpenAPIRoutes`; токени/scopes/allow_cidrs; TLS обов'язковий поза loopback; IPC unix socket 0600 / named pipe; SSE з `Last-Event-ID`; `PUT /v1/config` атомарно з бекапом; `api_call` події; `/healthz`, `/readyz`, `/metrics`.
- [ ] `POST /v1/locks`, `DELETE`, `POST /v1/lockdown`, `/v1/indicators` формати `json|stix-lite|plain`.
**КП:** httptest-тести на кожен ендпоїнт і scope (403 без scope); SSE відновлення з seq; PUT config з помилкою не змінює файл; покриття ≥ 80%.

## Stage 8 — Notify
Читати: SPEC §3.4 `[notify]`, §6 (типи подій для шаблонів); TESTING «Події, API, notify».
- [ ] `internal/notify`: telegram, virola (`POST /api/v1/rooms/{id}/messages`, Bearer), email (SMTP STARTTLS/TLS), custom webhook; шаблони, cooldown, digest під час атаки, ретраї.
**КП:** тести з httptest/smtp-mock: cooldown не шле дубль; digest агрегує; шаблони рендеряться для кожного типу події; помилка каналу → метрика + лог, не блокує шину.

## Stage 9 — Кеш і репліка
Читати: SPEC §5.1, §5.2; TESTING «Failover, кеш».
- [ ] `internal/cache`: `ttl` (ключ, TTL, max_entries, stale_while_down), `replica` (повний sync, jitter, примусовий sync, `replica_age_seconds`), групи TTL для `none`.
**КП:** тест stale при всіх upstream down; replica відповідає при вимкненому upstream; user bind у replica йде в upstream; інвалідaція при reload профілю.

## Stage 10 — `aldapctl` CLI + TUI
Читати: SPEC §7, §8; TESTING «Рівні».
- [ ] CLI-команди §8 через API-клієнт (IPC/TCP).
- [ ] TUI (Bubble Tea): вкладки, live events, locks unlock/lock, config view/validate/apply, підтвердження, `?`.
- [ ] `bundle`, `record start/stop`, `replay`, `baseline learn`.
**КП:** `go test` з `teatest`/модельними тестами на навігацію та unlock; CLI golden-тести виводу; `aldapctl --help` повний.

## Stage 11 — Record/replay, shadow
Читати: SPEC §8 (`record`, `replay`), §4.2 (`shadow`); TESTING «Рівні».
- [ ] `internal/record`: JSONL запис запитів (без паролів), replay проти профілю з порівнянням результатів (кількість, DN-набір) і звітом; `shadow.filter/bases` → `shadow_diff`.
**КП:** replay на записаному corpus дає 0 diff до змін і n diff після зміни фільтра; shadow не впливає на відповідь клієнту.

## Stage 12 — Hot reload без розриву, graceful, служба
Читати: SPEC §3.6, §5.3, §10.4, §10.5; TESTING «Транспорт».
- [ ] Hot-swap listener'ів (додати/прибрати порт без рестарту), атомарна заміна правил профілю, збереження стану rate limit.
- [ ] Graceful drain з `unavailable` notice; `kardianos/service` (install/uninstall/start/stop), Windows named pipe ACL, Event Log.
**КП:** тест: reload зі зміною `attrs.allow` під час активного paged search — поточний пошук завершується за старими правилами, наступний — за новими; тест drain з активним запитом.

## Stage 13 — Samba AD інтеграція, DHI, реліз
Читати: SPEC §10, §13, §14; TESTING «Samba AD стенд», «CI», «Артефакти тестів».
- [ ] `deploy/samba-dc/`: compose з Samba AD DC, LDIF-провізія (2 OU, CN=Users, 20 користувачів, 5 комп'ютерів, 3 групи з вкладеністю, 2 вимкнені акаунти), `make integration-samba` (`integration_samba` tag), другий DC для failover (або 2 контейнери Samba join — якщо нестабільно, емулювати failover через iptables/зупинку контейнера і документувати).
- [ ] Повний прогін КП §13 SPEC проти Samba.
- [ ] `build.sh --dhi` з перевіркою логіну, SBOM (syft/cyclonedx-gomod), cosign-підпис (ключ з CI secret, локально — `--no-sign`), GitHub Release workflow з артефактами linux/windows + образ.
- [ ] `docs/`: README (compose за 5 хв), virola.md, windows.md, security.md, api.md, events.md.
**КП:** `make integration-samba` зелений; release workflow проходить у dry-run; README-сценарій відтворюється з нуля на чистій машині з Docker.

---

## Позначки
- `BLOCKED: <причина>` — поруч із пунктом, якщо не можна виконати в поточному середовищі.
- `OPEN: <питання>` — рішення зафіксоване в `docs/DECISIONS.md`.
