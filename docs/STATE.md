# STATE — де ми зараз

Оновлюється наприкінці кожного етапу (5–10 рядків). Читати першим після `CLAUDE.md`.

## Stage 6 — Події, rate limit, IDS (завершено 2026-10-19)
- Зроблено: `internal/events` — envelope `aldap.event.v1` (ULID без залежностей, `seq` на процес, `host`), `Bus` (кільцевий буфер, `Since/Last/Subscribe/Flush`, include/exclude, `hash_accounts`, редагування паролів у фільтрах), sinks stdout/file(ротація+gzip)/syslog(RFC 5424)/webhook(батчі, ретраї, HMAC `X-ALDAP-Signature`, `drop_oldest|block`), `schematest` (власний валідатор підмножини JSON Schema для `docs/events.schema.json`). `internal/ratelimit` — `Limiter` (спільний стан) + `Policy` (конфіг профілю через `config.Ratelimit.With`): вікна невдач IP/акаунт → `lock`/`unlock`, token bucket bind/search, негативний кеш, прогресивна затримка, constant-time fail, `lock_response`, allowlists, tarpit, lockdown (ручний/auto); реалізує `vdir.Guard` (MemoryLocks видалено; заблокований IP не може й шукати). `internal/ids` — spray/stuffing/slow_brute/enumeration → `attack_start/summary/end`, recon-сигнатури, baseline/anomaly (learn), fingerprint, індикатори зі згасанням; реалізує `vdir.Observer` і `listener.Fingerprinter`. `internal/listener` — `session_summary`, відбиток TLS ClientHello + перший LDAP-пакет. `internal/metrics` — реєстр Prometheus (нова залежність `prometheus/client_golang`), підключено до listener/vdir/upstream/events/ratelimit/ids/tlsutil. Демон: `runtimeState` (bus/limiter/ids/metrics) переживає reload, sweep-цикл 1 с. Документація: `docs/events.md`, `docs/security.md`.
- Покриття: `events` 92%, `ratelimit` 97%, `ids` 95%, `metrics` 100%, загальне ≈92%. Тести: unit у кожному пакеті з валідацією подій за схемою; `cmd/aldap/stage6_test.go` (`integration`): TESTING 24–34 e2e (lock після 3 невдач без upstream, негативний кеш, IP lock, lockdown, spray+summary+end, enumeration, recon, honeytoken 24h, anomaly new_filter/new_ip, tarpit, валідність усіх подій і `session_summary`).
- Рішення (DECISIONS 2026-10-19): envelope/bus, schematest, Guard замість MemoryLocks, ключ акаунта, lock поглинає вікно невдач, scope негативного кешу, заблоковані bind'и живлять IDS, lockdown/tarpit, модель атак, recon/anomaly, score індикаторів, залежність prometheus.
- Попередній коміт `ci: fix flaky tests` (PR #5): гонка WaitGroup у gldap через `testdir.Stop`, лічильники health-probe у тестах upstream, sleep → очікування стану, gotestsum v1.13.0 + `::error`-анотації, runner `ubuntu-24.04`, `setup-go@v6`.
- Відкрите: `/v1/indicators`, `/v1/locks`, `/v1/lockdown`, SSE, `/metrics` — маршрути Stage 7 (моделі готові); `make licenses` локально лише з GOROOT-трюком, URL ліцензій `go.yaml.in/yaml/v3`/`protobuf` виставлені вручну — звірити з CI; hot reload без розриву (Stage 12).
- Зупинився: після коміту `stage-6: events, rate limit, IDS` у гілці `claude/nifty-hypatia-ic1gmk` (та сама гілка, що й PR #5 — push після злиття PR #5), PR у main.
- Далі: Stage 7 — `internal/api` (ендпоїнти §7, OpenAPI, токени/scopes, IPC, SSE з `Last-Event-ID` через `Bus.Since`, `/metrics` через `metrics.Handler`, `POST /v1/locks`/`lockdown` через `Limiter`, `/v1/indicators` через `ids.Indicators`).

## Stage 5 — Віртуальний каталог (завершено 2026-10-19)
- Зроблено: `internal/vdir` — віртуальні групи (`groups.go`: bases+filter ∪ ad_groups (AD in-chain / generic обхід `member` з `nested_depth`) ∪ include − exclude, ∩ profile.filter; кеш membership на `cache.ttl`; `member`/`memberOf` завжди віртуальні; `(member=)`/`(memberOf=)`), `attrs.computed`/`attrs.mask`/`objectclass.map` (`internal/profile/attrs.go`), локальний матчер `match.go` і пост-фільтрація до маскування, honeytokens (`honeytoken.go`: entry-пастки у пошуку/групах, події `honeytoken`+`lock`, `MemoryLocks`, `bind_blocked{ip_locked}`), `mode=honeypot` (без upstream), `mode=mock` (`mock.go`, TOML/CSV), `Directory.Test` + `aldap check --as-client` (`cmd/aldap/asclient.go`), `listener.NewConn`. Опис — `docs/vdir.md`.
- Покриття: `vdir` ≈95%, `profile` ≈96%. Тести: `internal/vdir/stage5_test.go` (Virola, джерела груп, generic nested, computed/mask/objectclass, honeytokens, honeypot, mock, Test/locks), `cmd/aldap/stage5_test.go` (`integration`: Virola e2e через ldaps/go-ldap, honeypot+mock, `check --as-client`, `TestDaemon_Ldap3` з `testdata/ldap3_test.py`; CI ставить `ldap3` через pip).
- Рішення (DECISIONS 2026-10-19): memberOf завжди віртуальний; TTL membership = `cache.ttl`; computed читають upstream-імена; post-filter до mask; honeypot-семантика; формат mock; `--as-client`.
- Спостережено: `TestIntegration_FailoverAndReturnToPrimary` (`internal/upstream`, Stage 3) один раз упав у повному `make integration` під `-race`, 4 повтори пройшли — ймовірний flake за часом, код Stage 3 не змінювався.
- Відкрите: IP-lock за honeytoken живе в `vdir.MemoryLocks` до Stage 6 (пошуки з заблокованого IP не блокуються); суфікс колізії RDN визначається в межах result set / membership set (Stage 9); `require_membership` перевіряє лише `filter` (членство в групі ⊂ filter).
- Зупинився: після коміту `stage-5: virtual directory` у гілці `claude/practical-feynman-kkki1p`, PR у main.
- Далі: Stage 6 — `internal/events` (шина, envelope `aldap.event.v1`, sinks), `internal/ratelimit` (реалізує `vdir.Locker`), `internal/ids`.

## Stage 4 — Listener і базовий проксі (завершено 2026-10-18)
- Зроблено: `internal/listener` — власний LDAP-фронтенд на `go-asn1-ber` (gldap v0.1.14 не дає `Serve(net.Listener)`, ліміту розміру пакета, дедлайнів на запит, IP клієнта — записано OPEN у DECISIONS, gldap лишається для `testdir`): транспорти `ldap/ldaps/starttls/ldap+starttls`, `starttls_required`, `max_request_bytes` по BER-заголовку, дедлайни 5s/`idle_timeout`, ліміти з'єднань (глобально/на IP), послідовна обробка запитів, StartTLS, Notice of Disconnection, усі write/compare/extended → `op_denied`. `internal/profile` (правила, argon2id client_bind, нормалізація bind-імен). `internal/vdir` (RootDSE, `cn=Subschema`, контейнери, пошук користувачів по кількох bases з дедуплікацією, allowlist/map, paged results до клієнта, bind усіх форм, `require_membership`, події `search`/`bind_ok`/`bind_fail`). `internal/tlsutil` (вбудований CA, auto-init/renew, `cert_expiring`, external, mTLS). `internal/events` (спільний `Event`/`Sink`, slog-sink до Stage 6). `aldap run` (graceful, SIGHUP reload повним перезапуском), `gen-ca`, `gen-cert`. Конфіг: `tls.key_type`, `client_bind.password_hash`. Опис — `docs/listener.md`.
- Покриття: `listener` 88%, `vdir` 92%, `profile` 98%, `tlsutil` 88%, `events` 100%, `cmd/aldap` 90%, загальне 92%. Тести: go-ldap як клієнт, `ldapsearch -x/-ZZ/-E pr=5` (скіп без ldap-utils), TLS-термінація ldaps→ALDAP→plain upstream з `insecure_config{plaintext_upstream}`, `TestNoSecretsInOutput_Daemon`, fuzz `FuzzParseMessage`.
- Закрито OPEN: govulncheck закріплено на `golang.org/x/vuln` v1.9.0 (Makefile `GOVULN_VERSION`, CI `make vuln`); базова версія Go піднята до 1.26 (`toolchain go1.26.9`, Dockerfile `GO_MINOR=1.26`), бо govulncheck знайшов 7 вразливостей stdlib у go1.25.14, виправлених лише в go1.26.9.
- Відкрите: підтвердження власником відмови від gldap як сервера; `mode = honeypot|mock` пропускаються з WARN; hot-swap listener'ів при reload; `ldap3`-тест (Stage 5); локально `make vuln` і Docker блоковані (CI).
- Зупинився: після коміту `stage-4: listener and basic proxy` у гілці `claude/cool-brahmagupta-j6yty2`, PR у main.
- Далі: Stage 5 — `internal/vdir`: віртуальні групи (`groups.*`, `member`/`memberOf`, nested), computed/mask/objectclass.map, honeytokens, `ldap3`-тест.

## Stage 3 — Upstream, пул, failover (завершено 2026-10-18)
- Зроблено: `internal/upstream` (`New/Start/Close`, `Search` з paging і failover, `UserBind` на bind-only пулі з `BindError{Reason, Data}`, `RootDSE`, `AuditServiceAccount`, `Check` для `--online`, `Status/Healthy`; стани `unknown/up/down` з порогами, події `upstream_down/up/insecure_config` через `EventSink`; `SerializeFilter` — абсолютні фільтри не йдуть в upstream). `internal/testdir` (gldap + TCP-проксі, LDIF-фікстура `testdata/ad.ldif`, paging, 803/804/1941, AD bind-коди, хуки `Calls/SetDelay/Kill/Restart`). `aldap check --online`. Опис — `docs/upstream.md`.
- Покриття: `upstream` 92.5%, `testdir` 93.4%, `cmd/aldap` 91%. Інтеграційні (`-tags integration`): failover/повернення на primary, 2 сторінки paging, reason-мапінг, ldaps/StartTLS, аудит, `check --online`.
- Залежності: `gldap` v0.1.14, `go-ldap/v3` v3.4.14 (v3.4.15 вимагає Go 1.26), `go-hclog` (MIT, через gldap).
- Рішення (DECISIONS): StartTLS-невдача = збій з'єднання без fallback; лише транспортні помилки рахуються проти сервера; bind-only пул без явного reset; referrals не follow; errcheck вимкнено для тестів/testdir.
- Відкрите: `make licenses` локально лише з toolchain 1.25 у PATH; `govulncheck@latest` вимагає Go ≥ 1.26 (CI через GOTOOLCHAIN=auto); URL ліцензії `yaml.v3` у звіті не резолвився офлайн — звірити з CI.
- Зупинився: після коміту `stage-3: upstream pool and failover` у гілці `claude/relaxed-maxwell-e19c85`, PR у main.
- Далі: Stage 4 — `internal/listener` (gldap-сервер, TLS/StartTLS, маршрутизація до профілю, BER↔AST фільтрів, `unwillingToPerform` на write-операції).

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
