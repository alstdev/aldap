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
- [x] `internal/listener` (власний BER-фронтенд на `go-asn1-ber`, див. DECISIONS; gldap лишається для testdir): `ldap`/`starttls`/`ldaps`/`ldap+starttls`, `starttls_required`, ліміти з'єднань (глобально/на IP), idle timeout, read deadline, `max_request_bytes`.
- [x] Маршрутизація → профіль; RootDSE; `cn=Subschema` мінімальний.
- [x] Bind: anonymous/client/user (нормалізація UPN/`DOMAIN\u`/sAM/virtual DN), прокидання в upstream, обнулення паролів у пам'яті.
- [x] Search прохідний: валідація base/scope, AND з `filter`, allowlist атрибутів, map, злиття кількох `bases`, дедуплікація по objectGUID/DN, sizeLimit, paged results до клієнта.
- [x] Усі write-операції/extended → `unwillingToPerform` + `op_denied`; Compare → `compareFalse` + `op_denied` (compare заборонено, бо дозволяє enumeration).
- [x] `internal/tlsutil`: вбудований CA (`gen-ca`), серверний сертифікат з SAN, auto-init, auto-renew, `cert_expiring`.
- [x] `aldap run` з graceful shutdown, SIGHUP reload (поки без hot-swap listener'ів допустимо повний перезапуск listener'ів).
- [x] (закрито у Stage 5) `mode = honeypot|mock` обслуговуються; Python `ldap3` — `TestDaemon_Ldap3`.
**КП:** e2e з `ldapsearch -x -ZZ`, `ldaps://`, `-E pr=100/noprompt` проти ALDAP→testdir; тест «запит з `telephoneNumber` поза allow → атрибут відсутній, пошук по ньому → 0 результатів без помилки»; TLS-термінація: клієнт ldaps, upstream ldap.

## Stage 5 — Віртуальний каталог
Читати: SPEC §4 (4.1–4.6), §3.4 `[profile.<name>]`; TESTING «Віртуальна база», «Bind».
- [x] `internal/vdir`: `virtual_base`, `ou=users`/`ou=groups`, переписування DN в обидва боки, `rdn_attr`, колізії RDN.
- [x] `attrs.computed` (шаблони + функції), `attrs.mask`, `objectclass.map`, пост-фільтрація по computed.
- [x] Віртуальні групи (§4.4): bases+filter ∪ ad_groups ∪ include − exclude ∩ profile.filter; `member`/`memberOf`; пошук по `(member=)`/`(memberOf=)`; `groupOfNames`/`group`/`posixGroup`.
- [x] Nested groups: AD через `LDAP_MATCHING_RULE_IN_CHAIN`, generic — рекурсія з лімітом.
- [x] Honeytokens (§4.5), `mode=honeypot`, `mode=mock` (TOML/CSV).
- [x] `user_bind.require_membership`.
- [x] `aldap check --profile X --as-client`, `POST /v1/profiles/{x}/test` (API пізніше, зараз — внутрішня функція `vdir.Directory.Test`).
- [x] Python `ldap3`-тест (перенесений зі Stage 4): `TestDaemon_Ldap3` — локальний `python3`+`ldap3` (CI), інакше Docker `python:3-slim`, інакше skip.
- OPEN: lock IP за honeytoken зберігається в `vdir.MemoryLocks` до появи rate limiter (Stage 6); пошуки з заблокованого IP не блокуються (DECISIONS).
**КП:** інтеграційні тести: Virola-сценарій (два bases, computer виключено, група `virola-users` зі всіма, user bind UPN, `memberOf` у користувача); колізія RDN; computed mail; mask телефону; honeytoken bind → lock; покриття `vdir` ≥ 85%.

## Stage 6 — Події, rate limit, IDS
Читати: SPEC §3.4 `[ratelimit]`, `[ids]`, `[events]`, §6, §9, §11; TESTING «Rate limit / IDS», «Події, API, notify», «Безпека».
- [x] `internal/events`: шина, ULID, seq, кільцевий буфер, sinks stdout/file(ротація)/syslog/webhook(батчі, ретраї, HMAC, overflow policy), `hash_accounts`, редагування значень `unicodePwd`/`userPassword` у фільтрах; `docs/events.schema.json` + тест валідації кожної події.
- [x] `internal/ratelimit`: IP/акаунт token bucket + вікна невдач, lock/unlock з подіями, негативний кеш, затримки, `constant_time_bind_fail`, `lock_response`, allowlists, tarpit, lockdown (ручний/авто).
- [x] `internal/ids`: spray, stuffing, slow_brute, enumeration, recon-сигнатури, baseline/anomaly (learn), fingerprint (TLS ClientHello hash + LDAP first-packet), `attack_start/summary/end`, `session_summary`.
- [x] `/v1/indicators` модель (score = зважена сума спрацювань з decay).
- [x] Метрики `internal/metrics`.
- Закрито OPEN Stage 5: lock IP живе в `ratelimit.Limiter` (реалізує `vdir.Guard`), заблокований IP відсікається і на пошуку.
**КП:** тести: 3 невдачі → lock → 4-та не йде в upstream (mock upstream рахує виклики); негативний кеш; spray-детектор на 5 акаунтах з одним хешем; recon на `(objectClass=*)` від кореня; anomaly new_ip після learn; webhook отримує батч з валідним HMAC; overflow drop_oldest; покриття `ratelimit`,`ids`,`events` ≥ 85%; тест `TestNoSecretsInOutput`.

## Stage 7 — API, метрики, IPC
Читати: SPEC §3.4 `[api]`, §7, §11, `docs/openapi.yaml`; TESTING «Події, API, notify».
- [x] `internal/api`: усі ендпоїнти §7, OpenAPI `docs/openapi.yaml` + тест `TestOpenAPIRoutes`; токени/scopes/allow_cidrs; TLS обов'язковий поза loopback; IPC unix socket 0600 / named pipe (Windows: `go-winio`, ACL SYSTEM+Administrators; запуск на Windows — ручний чекліст `docs/windows.md`); SSE з `Last-Event-ID`; `PUT /v1/config` атомарно з бекапом; `api_call` події; `/healthz`, `/readyz`, `/metrics`.
- [x] `POST /v1/locks`, `DELETE`, `POST /v1/lockdown`, `/v1/indicators` формати `json|stix-lite|plain`.
**КП:** httptest-тести на кожен ендпоїнт і scope (403 без scope); SSE відновлення з seq; PUT config з помилкою не змінює файл; покриття ≥ 80%.

## Stage 8 — Notify
Читати: SPEC §3.4 `[notify]`, §6 (типи подій для шаблонів); TESTING «Події, API, notify».
- [x] `internal/notify`: telegram, virola (`POST /api/v1/rooms/{id}/messages`, Bearer — OPEN: шлях звірити з реальним Virola, DECISIONS), email (SMTP STARTTLS/TLS), custom webhook; шаблони, cooldown, digest під час атаки, ретраї.
**КП:** тести з httptest/smtp-mock: cooldown не шле дубль; digest агрегує; шаблони рендеряться для кожного типу події; помилка каналу → метрика + лог, не блокує шину.

## Stage 9 — Кеш і репліка
Читати: SPEC §5.1, §5.2; TESTING «Failover, кеш».
- [x] `internal/cache`: `ttl` (ключ, TTL, max_entries, stale_while_down), `replica` (повний sync, jitter, примусовий sync, `replica_age_seconds`), групи TTL для `none`.
**КП:** тест stale при всіх upstream down; replica відповідає при вимкненому upstream; user bind у replica йде в upstream; інвалідaція при reload профілю.

## Stage 10 — `aldapctl` CLI + TUI
Читати: SPEC §7, §8; TESTING «Рівні».
- [x] CLI-команди §8 через API-клієнт (IPC/TCP).
- [x] TUI (Bubble Tea): вкладки, live events, locks unlock/lock, config view/validate/apply, підтвердження, `?`.
- [x] `bundle`, `record start/stop`, `replay`, `baseline learn`. (`record start/stop` і формат `replay` — закрито у Stage 11.)
**КП:** `go test` з `teatest`/модельними тестами на навігацію та unlock; CLI golden-тести виводу; `aldapctl --help` повний.

## Stage 11 — Record/replay, shadow
Читати: SPEC §8 (`record`, `replay`), §4.2 (`shadow`); TESTING «Рівні».
- [x] `internal/record`: JSONL запис запитів (без паролів), replay проти профілю з порівнянням результатів (кількість, DN-набір) і звітом; `shadow.filter/bases` → `shadow_diff`.
- [x] Формат запису = формат replay (`record.Search`/`Read`/`Compare`, спільні з `aldapctl replay`); `POST /v1/profiles/{name}/record` і `aldapctl record start/stop` працюють (OPEN Stage 10 закрито).
- [x] Записи без паролів, токенів, cookie paged results; файл 0600, ліміт розміру з ротацією; shadow у фоні з `max_parallel`/`timeout`, не впливає на відповідь і її час (тести).
**КП:** replay на записаному corpus дає 0 diff до змін і n diff після зміни фільтра; shadow не впливає на відповідь клієнту.

## Stage 12 — Hot reload без розриву, graceful, служба
Читати: SPEC §3.6, §5.3, §10.4, §10.5; TESTING «Транспорт».
- [x] Hot-swap listener'ів (додати/прибрати порт без рестарту), атомарна заміна правил профілю, збереження стану rate limit.
- [x] Graceful drain з `unavailable` notice; `kardianos/service` (install/uninstall/start/stop), Windows named pipe ACL, Event Log. (Windows — лише cross-compile + ручний чекліст `docs/windows.md`; `aldapctl stop` — OPEN у DECISIONS.)
- [x] Rootless Podman (доручення власника): `build.sh --podman`, Quadlet `deploy/podman/aldap.container`, `docs/podman.md`, детектор `[ids.client_ip_masked]`. BLOCKED: перевірка на реальному хості з podman (у середовищі немає podman).
**КП:** тест: reload зі зміною `attrs.allow` під час активного paged search — поточний пошук завершується за старими правилами, наступний — за новими; тест drain з активним запитом.

## Stage 12b — Socket activation, PROXY protocol, Virola-сценарій
Читати: SPEC §3.4 `[profile.<name>]`, `[ratelimit]`, `[ids]`, §9; `docs/podman.md`; TESTING «Транспорт», «Rate limit / IDS».
- [x] systemd socket activation (доручення власника): успадковані сокети через `LISTEN_FDS`/`LISTEN_PID`/`LISTEN_FDNAMES` без нових залежностей; профіль прив'язується до сокета за іменем (`listen = ["systemd:virola"]`); hot reload не закриває успадковані сокети. `deploy/podman/aldap-virola.socket` + Quadlet з socket activation; у `docs/podman.md` — system-сервіс з `User=` для портів < 1024 з попередженням, що Podman позначає його як непідтримуваний.
- [x] PROXY protocol v1/v2 на вході, вимкнений за замовчуванням: `proxy_protocol = { enabled = true, trusted_cidrs = [...] }` на профілі; заголовок приймається лише від `trusted_cidrs`, від решти — розрив з'єднання і `insecure_config`; без `trusted_cidrs` конфіг невалідний; без нових залежностей. Документація з прикладом Traefik ≥ 3.5.2 (окремий entrypoint, TCP-роутер ``HostSNI(`*`)`` з TLS passthrough, `serversTransport` з `proxyProtocol` version 2 у file provider, посилання `@file`).
- [x] `client_ip_masked` не спрацьовує при socket activation і при довіреному PROXY protocol.
- [x] `ratelimit.allow_cidrs` звільняє лише від IP-лімітів (`ip.*`, tarpit, IP-lock), але не від `account.*` і не від IDS-детекторів по акаунтах; виправлення — у DECISIONS. (Було не так: `PreBind` пропускав заблокований акаунт з `allow_cidrs` — виправлено.)
- [x] `client_ip_masked` ігнорує адреси з `ratelimit.allow_cidrs` профілю (на додачу до `ids.client_ip_masked.ignore_cidrs`).
- [x] `docs/virola.md`: «Virola і ALDAP в одному стеку» — `ldaps://aldap:636` по внутрішній мережі, порт назовні не публікується, фіксована IP контейнера Virola в `allow_cidrs`, `aldap` у `tls.san`, CA ALDAP у довірених Virola.
- BLOCKED: перевірка socket activation і system-сервісу з `User=` на реальному хості з Podman/systemd (у середовищі їх немає; OPEN у DECISIONS).
**КП:** тести: профіль на успадкованому сокеті з `LISTEN_FDNAMES` обслуговує запити, reload (зміна правил і прибирання/повернення `systemd:<name>`) не закриває успадкований сокет; відсутній `systemd:<name>` → помилка старту/reload без змін; PROXY v1 і v2 від довіреної адреси — rate limit/IDS/події бачать IP із заголовка; підроблений заголовок від недовіреної адреси → розрив + `insecure_config`; `proxy_protocol.enabled` без `trusted_cidrs` → помилка валідації; Virola-сценарій: усі bind'и з однієї IP у `allow_cidrs`, перебір одного акаунта → lock акаунта (наступний bind не йде в upstream), інші акаунти працюють, IP не блокується, spray з цієї IP → `attack_start`; `client_ip_masked` мовчить для `allow_cidrs`, socket activation і довіреного PROXY, але спрацьовує для решти.

## Stage 13 — Samba AD інтеграція, DHI, реліз
Читати: SPEC §10, §13, §14; TESTING «Samba AD стенд», «CI», «Артефакти тестів».
- [x] `deploy/samba-dc/`: compose з Samba AD DC, LDIF-провізія (2 OU, CN=Users, 20 користувачів, 5 комп'ютерів, 3 групи з вкладеністю, 2 вимкнені акаунти), `make integration-samba` (`integration_samba` tag), другий DC для failover (`dc2` — незалежний DC з тим самим LDIF, не join: LIMITATION у DECISIONS, `docs/samba.md`). Паролі генерує `init.sh` у `deploy/samba-dc/secrets/` (git-ignored), LDAPS з власним CA, експорт у `testdata/samba-ca.pem`.
- [x] Повний прогін КП §13 SPEC проти Samba (`cmd/aldap/samba_test.go`): Virola-сценарій, bind UPN/sAMAccountName/DOMAIN\user/віртуальний DN, lock після 3 невдач без lockout в AD (`badPwdCount` = 3), негативний кеш, honeytoken, recon, PROXY protocol, failover dc1 → dc2 → dc1, webhook HMAC, SSE, `check --online`. CI: `.github/workflows/samba.yml` (nightly, ≤ 15 хв).
- [x] `build.sh --dhi` з перевіркою логіну, SBOM (syft), cosign-підпис (ключ або keyless після push, локально — `NO_SIGN=1`), DHI-теги закріплено (`TestDHITagsPinned`), GitHub Release workflow `.github/workflows/release.yml` з артефактами linux/windows + образ DHI у GHCR. BLOCKED: pull DHI-образів у середовищі агента (`dhi.io` недоступний) — перевіряє CI з `DHI_USERNAME`/`DHI_TOKEN`.
- [x] `docs/`: README (швидкий старт: Docker Compose, rootless Podman Quadlet, Virola в одному стеку), virola.md, windows.md, security.md, api.md, events.md, samba.md, release.md, limitations.md. Перевірено з нуля: Compose (образ `plain` з цього Dockerfile, Samba-стенд), Virola-стек зі стенд-ін клієнтом, Quadlet — `quadlet -dryrun` (Podman 4.9.3). BLOCKED: образ Virola Server (virola.io недоступний), Podman під systemd (немає systemd).
- [x] Усі OPEN у `docs/DECISIONS.md` закрито (CLOSED/DECIDED) або переведено в LIMITATION (`docs/limitations.md`).
**КП:** `make integration-samba` зелений; release workflow проходить у dry-run; README-сценарій відтворюється з нуля на чистій машині з Docker.

## Stage 14 — Аудит безпеки і відповідності ТЗ
Читати: усе (CLAUDE.md, SPEC.md повністю, TESTING.md, docs/DECISIONS.md, docs/security.md); обмеження «читай лише поточний Stage» не діє.
Метод: код вважається чужим і ворожим; кожна область перевіряється окремим субагентом зі свіжим контекстом; кожна знахідка підтверджується тестом, який падає до виправлення (без відтворення — «не підтверджено»); заборонено «виправляти» знахідку видаленням/послабленням тестів, лімітів, перевірок або правил CLAUDE.md.
- [x] А.1 Автентифікація: unauthenticated bind (DN + порожній пароль, RFC 4513 §5.1.2) ніколи не йде в upstream і не дає сесію; anonymous, пароль із пробілів/NUL, дуже довгий, не-UTF-8; client_bind constant-time/argon2id без витоку існування DN; один ключ rate limit/lock/негативного кешу для всіх форм акаунта (UPN/`DOMAIN\user`/sAM/віртуальний DN/регістр/юнікод-двійники/пробіли) — тест: 3 невдачі в різних формах → lock.
- [x] А.2 Ін'єкції: клієнтські значення у фільтрах до upstream (rdn_attr, віртуальний DN → реальний, require_membership, honeytoken) екрануються за RFC 4515/4514 (`*`, `(`, `)`, `\`, NUL); шаблони notify (telegram MarkdownV2, email subject/body CRLF, webhook body_template → JSON, virola content) не ламаються значеннями нападника; події JSONL/syslog не розриваються CRLF/керівними символами.
- [x] А.3 Протокол і DoS: BER (глибина, оголошена довжина > реальної, гігантські довжини, нескінченні SEQUENCE), max_request_bytes, first-packet deadline, idle timeout, max_conns_per_ip, глобальний ліміт; StartTLS — байти відкритим текстом між запитом і handshake відкидаються, повторний StartTLS, StartTLS на ldaps; PROXY protocol (підробка, по частинах, v2 TLV-сміття, відсутній від довіреного); paged cookie (прив'язка до з'єднання/профілю, не вгадується, межа пам'яті, чужа/стара → відмова); межі пам'яті (великий результат, replica, кільцевий буфер, черги webhook/notify); алгоритмічна складність (OR/вкладеність, пост-фільтрація, цикли nested groups, regex у шаблонах).
- [x] А.4 Обхід правил віртуального каталогу: base поза virtual_base, scope, аліаси, `(objectClass=*)` від кореня, `*`/`+`/`1.1`/`;binary`/`;range=`; атрибут поза allow у фільтрі → FALSE без витоку, у т.ч. всередині NOT (NOT(FALSE) не стає TRUE); computer/вимкнені/exclude_filter не прослизають через пошук, групи, bind з require_membership; compare/modify/add/delete/modrdn/extended (Password Modify, WhoAmI) — відмова; жоден шлях коду не формує write до upstream (grep + тест).
- [x] А.5 Rate limit і IDS: обхід через паралельні з'єднання, reload, різні профілі, PROXY-заголовок, IPv4-mapped IPv6; allow_cidrs звільняє лише від IP-лімітів; блок ALDAP раніше за lockout AD; lockdown/tarpit не можна використати проти легітимних клієнтів чужими руками.
- [x] А.6 TLS і секрети: мін. версія, перевірка сертифіката upstream, SNI, tls_insecure_skip_verify лише явно з WARN; права файлів CA/ключів/секретів/IPC/record/events; TestNoSecretsInOutput покриває логи, події, panic, bundle, GET /v1/config, record/replay, помилки валідації, метрики, notify, headers; обнулення секретів у пам'яті там, де заявлено.
- [x] А.7 API: кожен маршрут × кожен scope; токен у query string не приймається; allow_cidrs; без TLS поза loopback; PUT config не пише поза шляхом конфігу і не дозволяє include на довільні шляхи; SSE не вічне; розмір тіла обмежено.
- [x] А.8 Upstream: referrals не follow (SSRF); сервісний акаунт лише читання + аудит прав; LDAP signing / channel binding — задокументована поведінка проти DC з вимогою підпису (Windows Server 2025): ldaps працює, plain — коректна помилка, не мовчазний збій.
- [x] А.9 Ланцюг постачання і CI: govulncheck чистий, ліцензії за allowlist; GitHub Actions закріплені за повним SHA, `permissions:` мінімальні на кожному job, секрети недоступні з pull_request з форків; Dockerfile non-root/read-only/без shell, DHI за digest; seccomp достатній і не надмірний (тест запуску); reproducible build (-trimpath, без VCS), SBOM, підпис.
- [x] А.10 Конфіг і валідація: невідомі ключі → помилка; небезпечні комбінації → помилка/WARN за SPEC; include-glob не виходить за теку конфігу без явного дозволу.
- [x] Б. Відповідність ТЗ: `docs/TRACEABILITY.md` (кожна вимога SPEC → файл/функція → тест → статус); 49 сценаріїв TESTING.md → назва тесту або «немає»; `docs/config.md`, `docs/openapi.yaml`, `docs/events.schema.json` звірено з кодом в обох напрямках; КП §13 SPEC пункт за пунктом.
- [x] В. `docs/THREAT_MODEL.md` (активи, межі довіри, нападники, STRIDE по компонентах); `docs/AUDIT.md` (ID, серйозність, компонент, опис, відтворення — тест, виправлення — коміт або прийнятий ризик; розділ «Залишкові ризики» з ручним чеклістом для AD/Podman/Windows/Virola); Critical/High виправлені окремими комітами `sec: <опис>` з регресійним тестом; Medium виправлені або прийняті; Low/Info перелічені.
- [x] Фінальний незалежний прохід: субагент зі свіжим контекстом отримав лише код і SPEC.md (без AUDIT.md); знайдено й виправлено FP-1 (Critical), FP-2, FP-6 (High), FP-7b (Medium); FP-8 прийнято з WARN; FP-9, FP-10 не підтверджено (`docs/AUDIT.md`, «Фінальний незалежний прохід»).
**КП:** CI зелений (локально; govulncheck/licenses/shellcheck — у GitHub CI на PR); BLOCKED: прогони fuzz і samba через `workflow_dispatch` потрібно запустити вручну (у сесії немає доступу до запуску workflow); коміт `stage-14: security audit`; PR у main з підсумком знахідок за серйозністю; PR не зливається агентом.

---

## Позначки
- `BLOCKED: <причина>` — поруч із пунктом, якщо не можна виконати в поточному середовищі.
- `OPEN: <питання>` — рішення зафіксоване в `docs/DECISIONS.md`.
