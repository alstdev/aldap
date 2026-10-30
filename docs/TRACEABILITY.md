# ALDAP — матриця трасованості вимог (SPEC.md v1.0 → код → тести)

> **Походження і межі.** Матрицю склав субагент зі свіжим контекстом за станом коду на коміті `2cc919b`
> (до виправлень аудиту); координатор перевірив механічно, що **248 із 248** названих тестів існують у
> репозиторії (решта збігів — префікси-шаблони `TestEngine_`, `TestSamba_` тощо), а зміст рядків — вибірково, не повністю.
> Зміни після аудиту, що впливають на рядки: SEC-05 (глибина BER > 64) — **виконано** (`sec: refuse BER nesting deeper than 64`);
> нові ключі й поведінка: `api.max_streams`, `client_bind.password_hash` маскується як секрет, `include` лише upstream/profile,
> правила валідатора A.10 — див. `docs/AUDIT.md`.


Дата аудиту: 2026-10-26. Репозиторій: `/home/user/aldap` (модуль `github.com/alstdev/aldap`), стан робочого дерева на момент аудиту.
Метод: кожна вимога перевірена читанням/grep коду та відкриттям тесту, який її реально асертить (а не лише викликає). Твердження `docs/STATE.md`, `CHANGELOG.md`, `TASKS.md` не бралися до уваги. `docs/DECISIONS.md` використано лише для рядків, що обґрунтовують свідомі відхилення (цитуються як `DECISIONS YYYY-MM-DD «topic»`).
Покриття шести пакетів §13.6 виміряно командою `go test -cover` під час аудиту.

Статуси: `виконано` / `частково` / `не виконано` / `свідомо змінено (DECISIONS YYYY-MM-DD «topic»)`.

---

## 1. §1 Цілі, не-цілі та заборони CLAUDE.md

| ID | Вимога (коротко, укр.) | SPEC § | Реалізація (файл/функція) | Тест | Статус | Примітка |
|---|---|---|---|---|---|---|
| G-01 | Вибірка користувачів з кількох OU/CN за канонічними фільтрами без зміни AD | 1.1.1 | `internal/vdir/directory.go:705` `fetchUsers` (паралельно по `bases`), `:766` `dedupeKey`; `internal/ldapfilter/filter.go:95` `Parse` | `TestSearch_MergeDedupeExclude` (`internal/vdir/vdir_test.go`), `TestDaemon_Virola` (`cmd/aldap/stage5_test.go`), `TestSamba_VirolaDirectory` | виконано | |
| G-02 | Транспорт клієнт→ALDAP: ldap, ldap+StartTLS, ldaps | 1.1.2 | `internal/listener/listener.go:120` `newGeneration`, `conn.go:578` `startTLS`; `config.go:239` `transport` | `TestBindSearch_Plain`, `TestLDAPS`, `TestStartTLS_Flows` (`internal/listener/listener_test.go`); `TestDaemon_Ldapsearch` (`-ZZ`) | виконано | |
| G-03 | Транспорт ALDAP→upstream: ldap, ldap+StartTLS, ldaps; термінація TLS своїм сертифікатом | 1.1.2 | `internal/upstream/conn.go:66` `dialer.dial`, `:37` `buildTLSConfig`; `internal/tlsutil/manager.go` | `TestIntegration_TLS` (`internal/upstream/integration_test.go`), `TestDaemon_TLSTermination` (`cmd/aldap/daemon_test.go`) | виконано | |
| G-04 | Віртуальна база: злиття bases, map атрибутів/objectClass, computed, групи, nested, маскування | 1.1.3 | `internal/vdir/directory.go:779` `transform`, `:816` `mask`; `internal/vdir/groups.go`; `internal/profile/attrs.go` | `TestTransform_ComputedMaskObjectClass`, `TestGroups_Virola`, `TestGroups_Generic` (`internal/vdir/stage5_test.go`) | виконано | |
| G-05 | Блокування у ALDAP спрацьовує раніше за lockout AD | 1.1.4 | `internal/ratelimit/ratelimit.go:676` `PostBind` (`account.max_failures=3`), `validate.go:388` warn при ≥5 | `TestPolicy_AccountLock` (`internal/ratelimit/ratelimit_test.go`), `TestStage6_AccountLockAndNegativeCache`, `TestSamba_AccountLock` | виконано | |
| G-06 | Телеметрія для IDS/IPS/ITSM: події, вебхуки, pull-API, активні дії (блок через API) | 1.1.5 | `internal/events/bus.go`, `webhook.go`; `internal/api/handlers.go:193` `handleLockCreate` | `TestWebhookSink_Cases`, `TestEvents_SinceLimitTypes`, `TestLocks_CreateListDeleteLockdown` (`internal/api/api_test.go`) | виконано | |
| G-07 | Повна конфігурація без UI; секрети через файли/змінні | 1.1.6 | `internal/config/load.go:74` `Load`, `env.go:109` `applyEnv`; `internal/secret/secret.go:176` `Resolve` | `TestEnv_MinimalWithoutFile`, `TestResolver_Resolve` | виконано | |
| G-08 | TUI `aldapctl` | 1.1.7 | `cmd/aldapctl/tui.go`, `tui_keys.go:9` (7 вкладок) | `TestTUI_Navigation`, `TestTUI_UnlockConfirm`, `TestRunTUI_Interactive` (`cmd/aldapctl/tui_test.go`) | виконано | |
| G-09 | Failover між DC, кеш/репліка, hot-reload | 1.1.8 | `internal/upstream/upstream.go:212` `candidates`, `:242` `do`; `internal/cache/ttl.go`, `replica.go`; `cmd/aldap/run.go:126` `reload` | `TestIntegration_FailoverAndReturnToPrimary`, `TestTTL_StaleWhileDown`, `TestReplica_SyncKeepsLastCopy`, `TestStage12_ListenAddRemove` | виконано | |
| N-01 | Жодного запису в upstream; add/modify/delete/modDN/password change → `unwillingToPerform` | 1.2 | `internal/listener/conn.go:483` `deny` (compare → `compareFalse`), `message.go:384` `deniedOp`; жодного `Add/Modify/Del/ModifyDN/PasswordModify` на go-ldap-клієнті (grep) | `TestDenied_Operations` (`internal/listener/listener_test.go`: коди + `op_denied` на кожну з 7 операцій) | виконано | Compare → `compareFalse` + `op_denied` (DECISIONS 2026-10-18 «Compare op») |
| N-02 | Жодної зміни паролів | 1.2 | `conn.go:563` `handleExtended` → будь-який extended (крім StartTLS) → `deny` з `oid` | `TestDenied_Operations` (`PasswordModify` → `unwillingToPerform`, `op_denied{oid}`) | виконано | |
| N-03 | Без Kerberos/GSSAPI до upstream; лише simple bind | 1.2 | `internal/upstream/upstream.go:513` `UserBind` → `c.Bind(dn, password)`; `listener/conn.go:518` SASL → `authMethodNotSupported` | `TestProtocol_Edges/sasl` (`internal/listener/listener_test.go:504`) | виконано | |
| N-04 | Без веб-UI/SCIM/зовнішньої БД/кластера | 1.2 | Пакети `internal/*` (перелік) — HTML/SCIM/SQL відсутні (grep `sqlclosecheck`-лінтер увімкнено, але SQL-коду немає) | немає (негативна вимога) | виконано | |
| N-05 | Без YAML у конфігурації | 1.2 | `internal/config/load.go:142` `decode` — лише `BurntSushi/toml`; `yaml` у коді зустрічається тільки як назва файлу `openapi.yaml` | `TestLoad_Errors` (приймає лише TOML) | виконано | `go.yaml.in/yaml/v3` — лише indirect (prometheus/common) |
| B-01 | Заборона 1: ніякого запису в upstream; клієнтські запити → `unwillingToPerform` + `op_denied` | CLAUDE.md | як N-01 | `TestDenied_Operations` | виконано | |
| B-02 | Заборона 2: паролі/токени ніколи не логуються; обов'язковий `TestNoSecretsInOutput` | CLAUDE.md | `internal/secret/secret.go:36-55` `Inline/Value.String/LogValue/MarshalText` → `***`; `internal/events/redact.go:12`; `internal/vdir/directory.go:936` `redactFilter`; `listener/conn.go:355` recover друкує лише тип | `TestNoSecretsInOutput_Config`, `_Headers`, `_Daemon` (`cmd/aldap/daemon_test.go:600`), `_API`, `_Notify`, `_Upstream`, `_Bundle`; `TestRunCheck_NoSecretsInOutput`; CI крок `go test -run TestNoSecretsInOutput -tags integration ./...` | виконано | |
| B-03 | Заборона 3: `*` в `attrs.allow` відхиляється | CLAUDE.md | `internal/config/validate.go:632` (`*` та `+` → помилка) | `TestValidate_Rules/profile_attrs_star` | виконано | |
| B-04 | Заборона 4: `tls_insecure_skip_verify` дефолт `false`, ніколи не вмикається «для тестів» | CLAUDE.md | `config.go:64` (zero-value false); єдине `InsecureSkipVerify = true` — `internal/upstream/conn.go:53` під `if cfg.TLSInsecureSkipVerify`; тести використовують CA `internal/testdir/tls.go` | `TestLoad_DefaultsAndTypes`, `TestIntegration_TLS` | виконано | |
| B-05 | Заборона 5: не спрощувати rate limit/IDS заради тестів | CLAUDE.md | Логіка `ratelimit.go:603/676`, `ids.go:322-410` відповідає SPEC-порогам | `TestPolicy_*`, `TestEngine_*` | виконано | Перевірено, що тести асертять SPEC-пороги (6 акаунтів для spray, 3 невдачі для lock) |
| B-06 | Заборона 6: без веб-UI, SCIM, Kerberos, запису паролів | CLAUDE.md | як N-02…N-04 | — | виконано | |
| B-07 | Заборона 7: невідомі ключі конфігу — помилка | CLAUDE.md | `internal/config/load.go:169` `md.Undecoded()` → `ErrUnknownKey`; `env.go:109` невідома `ALDAP_*` → помилка | `TestLoad_Errors/unknown_*` (`config_test.go:188-190`), `TestEnv_Overrides/unknown*` (`:395-397`), `TestRunCheck_Cases/unknown_key` | виконано | |

## 2. §2.1 Пакети та §2.2 Залежності

| ID | Вимога (коротко, укр.) | SPEC § | Реалізація (файл/функція) | Тест | Статус | Примітка |
|---|---|---|---|---|---|---|
| P-01 | `cmd/aldap`: демон; підкоманди `run`, `check`, `version`, `gen-ca`, `gen-cert`, `service install/uninstall` | 2.1 | `cmd/aldap/main.go:42-55`; `service.go:137-141` (також `start/stop/restart/status/run`) | `TestRun_Commands` (`cmd/aldap/main_test.go`), `TestRunService_Actions`, `TestGenCA_GenCert` | виконано | |
| P-02 | `cmd/aldapctl`: TUI (Bubble Tea) + CLI тільки через API (unix socket/TCP) | 2.1 | `cmd/aldapctl/main.go:157` `commands`, `client.go:60` `newClient` (IPC або `--url`) | `TestCLI_Golden`, `TestContract_RealAPI`, `TestClient_Transport` | виконано | |
| P-03 | `internal/config`: модель TOML, env/secret-files, валідація, hot-reload, `include` | 2.1 | `internal/config/{config,load,env,validate,defaults}.go` | `TestLoad_Include`, `TestEnv_Overrides`, `TestValidate_Rules` | виконано | |
| P-04 | `internal/secret`: резолвер `*_file`, `*_env`, inline | 2.1 | `internal/secret/secret.go:176` `Resolve`, `:219` `Probe` | `TestResolver_Resolve`, `TestSource_Check` | виконано | |
| P-05 | `internal/listener`: власний LDAP-фронтенд на `go-asn1-ber` + кодеки go-ldap; gldap не використовується | 2.1 | `internal/listener/message.go:115` `parseMessage` (`ber.DecodePacketErr`, `ldap.DecodeControl`); імпортів `gldap` у listener немає | `TestBindSearch_Plain`, `FuzzParseMessage` | виконано | DECISIONS 2026-10-18 «Listener not on gldap» |
| P-06 | `internal/profile`: bases, обов'язковий фільтр, allowlist, мапінги | 2.1 | `internal/profile/rules.go:84` `Compile` | `TestCompile_Errors`, `TestAttrs`, `TestClassifyBase` | виконано | |
| P-07 | `internal/vdir`: переписування DN/фільтрів, злиття, групи, nested, computed/masked, honeytokens | 2.1 | `internal/vdir/{directory,groups,honeytoken,bind,static,replica,mock}.go` | `TestSearch_Users`, `TestGroups_*`, `TestHoneytokens` | виконано | |
| P-08 | `internal/ldapfilter`: парсер/серіалізатор RFC 4515 з AST, переписування, AND-ін'єкція, перевірка допустимості | 2.1 | `internal/ldapfilter/filter.go:95`, `ops.go:20 Inject`, `:55 MapAttrs`, `:140 Split` | `TestParse_Shapes`, `TestInjectExclude_Cases`, `TestSplit_Cases`, `TestCorpus_RoundTrip` | виконано | |
| P-09 | `internal/upstream`: пул, health-check, failover, paged results, referral handling | 2.1 | `internal/upstream/{pool,health,upstream}.go`; referrals ігноруються (`upstream.go:427,440`) | `TestPool_Lifecycle`, `TestHealth_KindsAndEvents`, `TestSearch_PagingAndFailover` | виконано | Referrals: DECISIONS 2026-10-18 «Referrals» |
| P-10 | `internal/cache`: `none`/`ttl`/`replica`, stale-while-down | 2.1 | `internal/cache/ttl.go:192`, `replica.go:109` | `TestTTL_StaleWhileDown`, `TestReplica_RunAndTrigger` | виконано | |
| P-11 | `internal/ratelimit`: token bucket IP/акаунт, негативний кеш, затримки, tarpit, lockdown, honeypot | 2.1 | `internal/ratelimit/ratelimit.go:603 PreBind`, `:577 tarpit`, `:388 SetLockdown` | `TestPolicy_BucketsLockdownTarpit`, `TestPolicy_NegativeCache` | виконано | |
| P-12 | `internal/ids`: spray, stuffing, slow brute, enumeration, recon, baseline/anomaly, fingerprint | 2.1 | `internal/ids/{ids,recon,baseline,indicators,masked}.go` | `TestEngine_Spray`, `TestEngine_StuffingAndSlowBrute`, `TestEngine_Enumeration`, `TestEngine_Recon`, `TestEngine_Baseline` | виконано | |
| P-13 | `internal/events`: шина, схема `aldap.event.v1`, кільцевий буфер, sinks stdout/jsonl/syslog/webhook | 2.1 | `internal/events/{bus,record,sinks,syslog,webhook,configure}.go` | `TestBus_WrapAndRing`, `TestFileSink_Rotation`, `TestSyslogSink_Cases`, `TestWebhookSink_Cases` | виконано | |
| P-14 | `internal/notify`: telegram, virola, email, webhook; cooldown/дайджест | 2.1 | `internal/notify/{notify,channels,template}.go` | `TestScenario39_CooldownAndDigest`, `TestEmail_Modes`, `TestVirola_Path`, `TestWebhook_BodyTemplate` | виконано | |
| P-15 | `internal/api`: HTTP/JSON + SSE + `/metrics`; токени зі scope; OpenAPI | 2.1 | `internal/api/{api,auth,handlers,stream,indicators}.go` | `TestScopes_EveryRoute`, `TestStream_LastEventID`, `TestOpenAPIRoutes` | виконано | |
| P-16 | `internal/tlsutil`: вбудований CA, випуск/перевипуск, імпорт зовнішнього, перевірка строку | 2.1 | `internal/tlsutil/ca.go`, `manager.go:255 Check` | `TestCA_GenerateLoad`, `TestManager_BuiltinLifecycle`, `TestManager_ExternalExpiring` | виконано | |
| P-17 | `internal/record`: record/replay, shadow-режим | 2.1 | `internal/record/{recorder,shadow,compare,format}.go` | `TestRecorder_StartStopAndMode`, `TestShadow_Diff`, `TestStage11_RecordReplayShadow` | виконано | |
| P-18 | `internal/metrics`: Prometheus | 2.1 | `internal/metrics/metrics.go:46 New` | `TestMetrics_Exposition` | виконано | |
| P-19 | `internal/testdir`: in-memory LDAP на gldap (єдине місце gldap) з AD-подібною схемою | 2.1 | `internal/testdir/{server,handlers,match}.go` (єдині імпорти `gldap`) | `TestBind_ADCodes`, `TestSearch_Paging`, `TestServer_StartTLSAndLDAPS` | виконано | |
| D-01 | `github.com/jimlambrt/gldap` — лише testdir; MIT | 2.2 | `go.mod` v0.1.14; імпорт тільки в `internal/testdir` | — | виконано | |
| D-02 | `github.com/go-ldap/ldap/v3` — клієнт до upstream + кодеки; MIT | 2.2 | `go.mod` v3.4.14; `internal/upstream`, `internal/listener` | — | виконано | |
| D-03 | `github.com/go-asn1-ber/asn1-ber` — BER фронтенда; MIT | 2.2 | `go.mod` v1.5.8; `internal/listener/message.go` | — | виконано | |
| D-04 | `github.com/BurntSushi/toml`; MIT | 2.2 | `go.mod` v1.6.0; `internal/config/load.go` | — | виконано | |
| D-05 | `charmbracelet/bubbletea`, `bubbles`, `lipgloss`; MIT | 2.2 | `go.mod` v1.3.10 / v1.0.0 / v1.1.0 | — | виконано | DECISIONS 2026-10-23 «Bubble Tea v1» |
| D-06 | `github.com/kardianos/service`; zlib | 2.2 | `go.mod` v1.3.0; `cmd/aldap/service.go` | `TestServiceConfig_Platforms` | виконано | |
| D-07 | `github.com/prometheus/client_golang`; Apache-2.0 | 2.2 | `go.mod` v1.25.0 | — | виконано | DECISIONS 2026-10-19 «New dependency prometheus/client_golang» |
| D-08 | `github.com/Microsoft/go-winio`; MIT | 2.2 | `go.mod` v0.6.4; `internal/api/ipc_windows.go` | `TestListenIPC_Pipe` (windows) | виконано | DECISIONS 2026-10-23 «Named pipe on Windows» |
| D-09 | Правило ліцензій: лише MIT/BSD/ISC/Apache-2.0/zlib/MPL-2.0; `make licenses` генерує `THIRD_PARTY_LICENSES.md`; CI перевіряє allowlist | 2.2 | `Makefile` `ALLOWED_LICENSES`, `scripts/licenses.sh`; `.github/workflows/ci.yml:36-37` (`make licenses` + `git diff --exit-code`) | немає (CI-крок) | виконано | `Unlicense` додано до allowlist (пермісивна, не copyleft) |
| D-10 | Модулі в `go.mod` require (direct), яких немає в таблиці §2.2 | 2.2 | `github.com/hashicorp/go-hclog` v1.6.3 (testdir, через gldap) — DECISIONS 2026-10-18 «Stage 3 dependencies»; `github.com/prometheus/client_model` v0.6.3 (`internal/metrics/metrics.go:14` `dto`) — DECISIONS не згадує окремо (транзитивна до client_golang, Apache-2.0); `golang.org/x/crypto` v0.57.0 (`internal/profile/argon2.go:11`, argon2id, SPEC §9) — у §2.2 згадана як транзитивна BSD-3 | — | частково | `client_model` та прямий `x/crypto` не мають рядка в DECISIONS; ліцензії допустимі, `THIRD_PARTY_LICENSES.md` генерується автоматично |

## 3. §3 Конфігурація

### 3.1–3.3 Джерела, секрети, env

| ID | Вимога (коротко, укр.) | SPEC § | Реалізація (файл/функція) | Тест | Статус | Примітка |
|---|---|---|---|---|---|---|
| C-01 | Пріоритет: env > файли секретів > toml(+include) > дефолти | 3.1 | `internal/config/load.go:74` `Load` (Default → файл → include → `applyEnv`); секрети резолвляться при старті (`cmd/aldap/daemon.go:252`) | `TestEnv_Overrides`, `TestLoad_DefaultsAndTypes` | виконано | |
| C-02 | Три взаємовиключні форми секрету `X`/`X_file`/`X_env`; валідатор забороняє >1 | 3.2 | `internal/secret/secret.go:118` `Source.Check`; `validate.go:232` `checkSecret` | `TestSource_Check`, `TestValidate_Rules/upstream_two_sources` | виконано | |
| C-03 | Inline дозволено, але `aldap check` попереджає | 3.2 | `validate.go:247` warn «inline secret» | `TestValidate_Rules/upstream_inline_warn` | виконано | |
| C-04 | `X_file`: прочитати файл, обрізати кінцевий `\n` | 3.2 | `secret.go:209` `TrimRight "\r\n"` | `TestResolver_Resolve` | виконано | |
| C-05 | Перелік чутливих ключів (bind_password, client_bind.password, api.tokens[].token, notify.*.token/bot_token, email.password, webhook.hmac_secret) — усі типу секрет | 3.2 | `config.go:67,315,490,528,537,551,564,640` — тип `secret.Inline` + `_file/_env` | `TestConfigDocsInSync` (type=secret без дефолту) | виконано | `tls.key` — шлях (string), вміст читається `tlsutil` |
| C-06 | Секрети не потрапляють у логи/події/API (`GET /v1/config` → `***`)/`aldapctl bundle` | 3.2 | `secret.go:36-55`; `cmd/aldap/control.go:124` `ConfigTOML`; `cmd/aldapctl/bundle.go:116` `redactTOML` | `TestNoSecretsInOutput_API`, `TestNoSecretsInOutput_Bundle`, `TestBundle_Redact` | виконано | |
| C-07 | Схема env `ALDAP_<SECTION>_<KEY>`, іменовані таблиці `ALDAP_UPSTREAM_<NAME>_<KEY>`, верхній регістр, `-`→`_`, списки через кому | 3.3 | `env.go:109` `applyEnv`, `:98` `normalizeName`, `:275` `splitList` | `TestEnv_Overrides`, `TestEnv_Leaves` | виконано | DECISIONS 2026-10-18 «Table names from env», «Env coverage» (вільні таблиці та масиви таблиць з env не задаються) |
| C-08 | Мінімальна конфігурація повністю через env (один upstream + один профіль) | 3.3 | `env.go:198` `namedEntry` створює таблиці | `TestEnv_MinimalWithoutFile` (`config_test.go:299`) | виконано | |

### 3.4 Ключі конфігурації (поле Go → дефолт → валідація)

Усі поля — `internal/config/config.go` (рядок), дефолти — `internal/config/defaults.go` (`Default()` :58, `DefaultUpstream()` :128, `DefaultProfile()` :144, `DefaultWebhook()` :167, `DefaultChannel()` :176), валідація — `internal/config/validate.go`. Документація — `docs/config.md`, синхронізована тестом `TestConfigDocsInSync`.

| ID | Вимога (коротко, укр.) | SPEC § | Реалізація (файл/функція) | Тест | Статус | Примітка |
|---|---|---|---|---|---|---|
| K-S1 | `server.log_level` дефолт `info` | 3.4 | `config.go:33`; дефолт :62 = info ✓; `validate.go:281` oneOf | `TestValidate_Rules/server_log_level` | виконано | |
| K-S2 | `server.log_format` дефолт `text` | 3.4 | `config.go:34`; дефолт ✓; `validate.go:280-290` oneOf | `TestLoad_DefaultsAndTypes` | виконано | |
| K-S3 | `server.ipc_socket` дефолт `/run/aldap/aldap.sock` / `\\.\pipe\aldap`; права 0600 | 3.4 | `config.go:35`; `defaults.go:49` `DefaultIPCSocket`; `internal/api/ipc_unix.go:46` chmod 0600 | `TestIPC_Socket` (`ipc_unix_test.go:41` перевіряє 0600) | виконано | |
| K-S4 | `server.shutdown_timeout` дефолт `30s` | 3.4 | `config.go:36`; дефолт ✓; `validate.go:280` positive | `TestValidate_Rules/server_timeout` | виконано | |
| K-S5 | `server.max_connections` дефолт `1024` | 3.4 | `config.go:37`; дефолт ✓; `internal/listener/listener.go:549` `Limiter` | `TestLimits` (listener), `TestLoad_DefaultsAndTypes` | виконано | |
| K-S6 | `server.include` glob-шаблони; дублювання імен — помилка | 3.4 | `config.go:38`; `load.go:113` `loadFile` (вкладені include не слідуються) | `TestLoad_Include` (`config_test.go:213`) | виконано | |
| K-T1 | `tls.mode` `builtin-ca` (дефолт) / `external` | 3.4 | `config.go:43`; дефолт ✓; `validate.go:296` | `TestValidate_Rules/tls_external_no_cert` | виконано | |
| K-T2 | `tls.ca_dir`; створюється `gen-ca` або авто при `auto_init=true` | 3.4 | `config.go:44-45`; дефолт `/var/lib/aldap/ca`, `AutoInit=true`; `cmd/aldap/genca.go:31`; `tlsutil/manager.go` | `TestGenCA_GenCert`, `TestManager_BuiltinLifecycle` | виконано | |
| K-T3 | `tls.cert`, `tls.key` для `external` | 3.4 | `config.go:46-47`; `validate.go:302-307` required + `checkCertFile` | `TestValidate_Rules/tls_external_no_cert` | виконано | |
| K-T4 | `tls.auto_renew_before` дефолт `720h` | 3.4 | `config.go:48`; дефолт ✓; `manager.go:195` `dueForRenewal` | `TestManager_BuiltinLifecycle` | виконано | |
| K-T5 | `tls.expiry_alert_before` дефолт `336h` → `cert_expiring` | 3.4 | `config.go:49`; дефолт ✓; `manager.go:268-278` | `TestManager_ExternalExpiring` | виконано | |
| K-T6 | `tls.san` додаткові SAN | 3.4 | `config.go:50`; `cmd/aldap/daemon.go:479` → `tlsutil.Options.SANs` | `TestParseSANs_Covers` | виконано | DECISIONS 2026-10-18 «Server certificate SANs» |
| K-T7 | `tls.min_version` `1.2` (дефолт) / `1.3` | 3.4 | `config.go:52`; дефолт ✓; `manager.go:121-127`; `validate.go:311` | `TestValidate_SectionMethods` | виконано | |
| K-T8 | `tls.client_auth` `none/request/require` + `client_ca` | 3.4 | `config.go:53-54`; `validate.go:312-314`; `manager.go:129-133` | `TestManager_ClientAuth`, `TestValidate_Rules/tls_client_ca` | виконано | |
| K-U1 | `upstream.servers` []URL `ldap://`/`ldaps://`; схема визначає транспорт | 3.4 | `config.go:59`; `validate.go:472-487`; `internal/upstream/url.go:23` | `TestParseServerURL_Cases`, `TestValidate_Rules/upstream_bad_url` | виконано | |
| K-U2 | `starttls`, `starttls_required` | 3.4 | `config.go:61-62`; `validate.go:488-493`; `upstream/conn.go:66` | `TestIntegration_TLS`, `TestValidate_Rules/upstream_starttls_required` | виконано | DECISIONS 2026-10-18 «StartTLS failure» (без fallback у plaintext) |
| K-U3 | `tls_ca_file` | 3.4 | `config.go:63`; `upstream/conn.go:39` | `TestIntegration_TLS` | виконано | |
| K-U4 | `tls_insecure_skip_verify` дефолт `false`; WARN при кожному старті + `insecure_config` | 3.4 | `config.go:64`; `upstream/upstream.go:148-150` | `TestValidate_Rules/upstream_insecure_warn`; `TestHealth_KindsAndEvents` (insecure_config) | виконано | |
| K-U5 | `tls_server_name` | 3.4 | `config.go:65`; `upstream/conn.go:38` `ServerName` | `TestIntegration_TLS` | виконано | |
| K-U6 | `bind_dn`, `bind_password[_file|_env]` тільки читання | 3.4 | `config.go:66-69`; `validate.go:499-507` | `TestValidate_Rules/upstream_pw_without_dn`, `upstream_dn_without_pw` | виконано | |
| K-U7 | `base_dn` | 3.4 | `config.go:70`; `validate.go:507` DN syntax; `check.go` порівняння з `defaultNamingContext` | `TestValidate_Rules/upstream_bad_dn`, `TestCheck_Findings` | виконано | |
| K-U8 | `kind` `ad` (дефолт) / `generic`; AD-специфіки (objectCategory-фільтр, bit-match, memberOf, IN_CHAIN, paged, referrals ignored) | 3.4 | `config.go:60`; `defaults.go:130`; `load.go:183` `DefaultADFilter`; `vdir/groups.go:219` `ruleInChain`; `upstream.go:406` paging завжди; referrals `:427,440` | `TestEnv_MinimalWithoutFile` (default filter), `TestGroups_Virola`, `TestSearch_PagingAndFailover` | виконано | |
| K-U9 | `health_interval` дефолт `10s` | 3.4 | `config.go:71`; дефолт ✓; `health.go:13` | `TestHealth_KindsAndEvents` | виконано | |
| K-U10 | `health_check` `rootdse` (дефолт)/`bind`/`search` | 3.4 | `config.go:72`; дефолт ✓; `health.go:47` `probe`; `validate.go:457-461` | `TestHealth_KindsAndEvents` (`upstream_test.go:630-641` перевіряє dial/bind/search для кожного виду) | виконано | |
| K-U11 | `failover.fail_threshold=3`, `recover_threshold=2`, `prefer_primary=true` | 3.4 | `config.go:87-89`; дефолт ✓; `upstream/server.go:87` `record` | `TestServer_Record`, `TestIntegration_FailoverAndReturnToPrimary` | виконано | `unknown→up` без `upstream_up` — DECISIONS 2026-10-18 «unknown → up» |
| K-U12 | `pool.size=4`, `pool.max_idle=5m` | 3.4 | `config.go:95-96`; дефолт ✓; `pool.go:33` | `TestPool_Lifecycle` | виконано | |
| K-U13 | `timeouts.connect/bind/search` = `5s/5s/30s` | 3.4 | `config.go:101-103`; дефолт ✓ | `TestLoad_DefaultsAndTypes` | виконано | |
| K-U14 | `page_size` дефолт `500` | 3.4 | `config.go:73`; дефолт ✓; `upstream.go:414` | `TestIntegration_PagedSearch` | виконано | |
| K-U15 | `audit_service_account=true`: членство у Domain Admins/Enterprise Admins/Administrators/Account Operators → WARN + `insecure_config` | 3.4 | `config.go:74`; `upstream/audit.go:12` `AdminGroups`, `:35`, `:64` `runAudit` | `TestAudit_Cases` (`upstream_test.go:697-708`), `TestIntegration_AuditAndCheck` | виконано | DECISIONS 2026-10-18 «audit_service_account timing» (асинхронно) |
| K-R1 | `ratelimit.enabled=true` | 3.4 | `config.go:108`; дефолт ✓; `ratelimit.go:604` | `TestPolicy_ConstantTimeAndDisabled` | виконано | |
| K-R2 | `ip.max_failures=20`, `ip.window=5m`, `ip.lock_duration=15m` | 3.4 | `config.go:123-125`; дефолт ✓; `validate.go:379-381`; `ratelimit.go:685` | `TestPolicy_IPLockAndAllowlists` | виконано | |
| K-R3 | `ip.bind_rps=10` burst `20`; `ip.search_rps=50` burst `100` | 3.4 | `config.go:126-129`; дефолт ✓; `ratelimit.go:637,787` | `TestPolicy_BucketsLockdownTarpit` | виконано | |
| K-R4 | `account.max_failures=3` (< AD lockout; warn ≥5), `window=10m`, `lock_duration=15m` | 3.4 | `config.go:134-136`; дефолт ✓; `validate.go:387-389` | `TestValidate_Rules/ratelimit_account_warn`, `TestPolicy_AccountLock` | виконано | |
| K-R5 | `negative_cache_ttl=60s` (акаунт, SHA-256(salt‖пароль)) | 3.4 | `config.go:109`; дефолт ✓; `ratelimit.go:226` `HashPassword`, `:622-633` | `TestPolicy_NegativeCache` | виконано | Кешуються лише незмінні причини — DECISIONS 2026-10-19 «Negative cache scope» |
| K-R6 | `delay.base=250ms` ×2 до `delay.max=4s` | 3.4 | `config.go:141-142`; дефолт ✓; `ratelimit.go:742` `failureDelay` | `TestPolicy_ConstantTimeAndDisabled` (cap 4s) | виконано | |
| K-R7 | `constant_time_bind_fail=true` → p95 успішних | 3.4 | `config.go:110`; дефолт ✓; `ratelimit.go:752` | `TestPolicy_ConstantTimeAndDisabled` (pad 25ms) | виконано | |
| K-R8 | `lock_response` `invalidCredentials` (дефолт) / `busy` | 3.4 | `config.go:111`; дефолт ✓; `validate.go:377` | `TestPolicy_BucketsLockdownTarpit` (`busy`) | виконано | |
| K-R9 | `allow_cidrs` (IP без лімітів), `allow_accounts` (без блокування) | 3.4 | `config.go:112-113`; `ratelimit.go:557,617` | `TestPolicy_IPLockAndAllowlists`, `TestPolicy_AllowCIDRsKeepAccountLimits` | виконано | DECISIONS 2026-10-26 «allow_cidrs lifts only IP limits» |
| K-R10 | `tarpit.enabled=false`, `delay=30s`, `max_conns=64` для IP у стані attack | 3.4 | `config.go:147-149`; дефолт ✓; `ratelimit.go:577` | `TestPolicy_BucketsLockdownTarpit`, `TestStage6_Tarpit` | виконано | |
| K-R11 | `lockdown.auto=false` при `attack_start` рівня high; `lockdown.allow_cidrs/allow_accounts` | 3.4 | `config.go:154-156`; `cmd/aldap/daemon.go:105-110` `onAttack` → `SetLockdown`; `ratelimit.go:560` | `TestStage6_IPLockAndLockdown`, `TestPolicy_BucketsLockdownTarpit` | виконано | DECISIONS 2026-10-19 «Lockdown and tarpit semantics» |
| K-R12 | `[profile.<name>.ratelimit]` перевизначає будь-який ключ | 3.4 | `config.go:263,374-422` `RatelimitPatch`; `ratelimit_patch.go` `With` | `TestRatelimit_With`, `TestValidate_Rules/profile_patch_warn` | виконано | |
| K-R13 | Стан лише в пам'яті; `aldapctl locks`/`unlock` | 3.4 | `ratelimit.go:175` `Limiter` (мапи); `cmd/aldapctl/main.go:161-162` | `TestCLI_Golden` (locks), `TestCLI_Mutating` (unlock) | виконано | |
| K-I1 | `ids.spray` `window=10m`, `min_accounts=5`, `same_password_hash=true` → `attack_start{kind=spray}` | 3.4 | `config.go:196-199`; дефолт ✓; `ids.go:322` | `TestEngine_Spray` | виконано | |
| K-I2 | `ids.stuffing` `window=5m`, `min_pairs=20` | 3.4 | `config.go:204-206`; дефолт ✓; `ids.go:362` | `TestEngine_StuffingAndSlowBrute` | виконано | |
| K-I3 | `ids.slow_brute` `window=6h`, `min_failures=30`, `max_rate_per_min=2` | 3.4 | `config.go:211-214`; дефолт ✓; `ids.go:386` | `TestEngine_StuffingAndSlowBrute` | виконано | |
| K-I4 | `ids.enumeration` `min_accounts=10` послідовно без успіху | 3.4 | `config.go:219-220`; дефолт ✓; `ids.go:306` (streak) | `TestEngine_Enumeration` | виконано | |
| K-I5 | `ids.recon` сигнатури (root dump, nTSecurityDescriptor, sIDHistory, trustPartner, msDS-*, adminCount, SPN sweep, base поза профілем) → `recon{signature}` | 3.4 | `config.go:167`; `ids/recon.go:107` `Signatures` (усі 8) | `TestEngine_Recon` (`ids_test.go:218-231`) | виконано | DECISIONS 2026-10-19 «Recon and anomaly details» |
| K-I6 | `ids.anomaly` базова лінія (IP, фільтри, bases, attrs, RPS p95), `learn_for=24h`, `aldapctl baseline learn` → `anomaly{reason}` | 3.4 | `config.go:225-226`; дефолт ✓; `ids/baseline.go:92`; `ids.go:182` `Learn` | `TestEngine_Baseline`, `TestAdmin_ConfigReloadSyncTestLearn` | виконано | |
| K-I7 | `ids.honeytoken` → `honeytoken` + негайний `lock_ip` | 3.4 | `config.go:231-232` (`enabled`, `lock_duration=24h`); `vdir/honeytoken.go:66` | `TestHoneytokens`, `TestStage6_ReconHoneytokenAnomaly` | виконано | |
| K-I8 | `ids.fingerprint` (вимкнено за замовчуванням): TLS ClientHello JA3-подібний + LDAP перший пакет → `anomaly{reason=fingerprint}` | 3.4 | `config.go:170`; дефолт false ✓; `listener/conn.go:85` `HelloFingerprint`, `:134`; `ids/baseline.go:53` | `TestEngine_IndicatorsAndNote` (`ids_test.go:337-344`), `TestConn_Helpers` | виконано | |
| K-I9 | `attack_summary` кожні `summary_interval=5m`; `attack_end` після `quiet_period=15m`; рівні low/medium/high | 3.4 | `config.go:161-162`; дефолт ✓; `ids.go:501` `Tick`, `:450` `level` | `TestEngine_Spray` (summary після 5m, end після 15m) | частково | Рівень `low` не присвоюється атакам (лише medium/high, `ids.go:450-468`); DECISIONS 2026-10-19 «Attack model of the IDS» описує medium/high |
| K-P1 | `profile.listen` один або список | 3.4 | `config.go:237`; `validate.go:561` | `TestValidate_Rules/profile_bad_listen` | виконано | + `systemd:<name>` (DECISIONS 2026-10-26 «Socket activation») |
| K-P2 | `profile.transport` `ldaps` (дефолт для 636)/`ldap`/`starttls`/`ldap+starttls`; `starttls_required=true` → `confidentialityRequired` | 3.4 | `config.go:239-240`; дефолт завжди `ldaps` (`defaults.go:146`); `listener/conn.go:521,553` | `TestStartTLS_Flows`, `TestValidate_Rules/profile_transport` | свідомо змінено (DECISIONS 2026-10-18 «`profile.transport` default») | Дефолт `ldaps` незалежно від порту |
| K-P3 | `profile.tls.*` перевизначення `[tls]` | 3.4 | `config.go:241,280-291` `TLSOverride`; `cmd/aldap/daemon.go:410-435` | `TestEffectiveTLS_Overrides` | виконано | |
| K-P4 | `profile.upstream` ім'я upstream | 3.4 | `config.go:242`; `validate.go:614-616` | `TestValidate_Rules/profile_unknown_upstream` | виконано | |
| K-P5 | `profile.mode` `proxy`/`honeypot`/`mock` (+`mock.file` TOML/CSV) | 3.4 | `config.go:243-244,296`; `vdir/mock.go:43` `LoadMock`; `cmd/aldap/daemon.go:290` | `TestHoneypot`, `TestMock`, `TestDaemon_HoneypotMock` | виконано | DECISIONS 2026-10-18 «mode = honeypot», 2026-10-19 «Mock file format» |
| K-P6 | `profile.virtual_base`; усі DN переписуються; bases поза → `noSuchObject` | 3.4 | `config.go:245`; `profile/rules.go:390` `ClassifyBase`; `vdir/directory.go:355-358` | `TestClassifyBase`, `TestSearch_Users` | виконано | |
| K-P7 | `profile.bases` реальні DN (scope sub) | 3.4 | `config.go:246`; `directory.go:721` `ScopeSub` | `TestSearch_MergeDedupeExclude` | виконано | |
| K-P8 | `profile.filter` AND до клієнтського; дефолт для `ad` — person/user/not disabled | 3.4 | `config.go:247`; `load.go:181-186` `finalize`; `defaults.go:9` `DefaultADFilter`; `vdir/groups.go:184` `profileFilter` | `TestEnv_MinimalWithoutFile`, `TestSearch_Users` | виконано | |
| K-P9 | `profile.exclude_filter` NOT-ується | 3.4 | `config.go:248`; `ldapfilter/ops.go:43` `Exclude` | `TestInjectExclude_Cases`, `TestSearch_MergeDedupeExclude` | виконано | |
| K-P10 | `attrs.allow` allowlist, `*` заборонено; операційні — лише якщо перелічені | 3.4 | `config.go:301`; `validate.go:630-634`; `vdir/directory.go:517` `requestedAttrs` | `TestValidate_Rules/profile_attrs_star`, `TestSearch_Users` (`attrs_denied`) | виконано | `objectClass` у фільтрі приймається завжди — DECISIONS 2026-10-18 «objectClass in filters» |
| K-P11 | `attrs.map` `client = "upstream"` | 3.4 | `config.go:302`; `profile/rules.go:232` `compileAttrs`, `:319` `UpstreamAttr` | `TestAttrs`, `TestMapAttrs_Cases` | виконано | |
| K-P12 | `attrs.computed` go-template з функціями `or, printf, lower, upper, trim, default, first, join, regexReplace` | 3.4 | `config.go:303`; `profile/attrs.go:89` `CompileComputed`; `defaults.go:30` `ProfileTemplateFuncs`; `validate.go:1041` | `TestComputed` (`attrs_test.go:22`), `TestTemplateFuncsInSync`, `TestValidate_ProfileTemplateFuncs` | виконано | DECISIONS 2026-10-19 «Computed attributes» (шаблон читає upstream-імена) |
| K-P13 | `attrs.mask` патерни | 3.4 | `config.go:304`; `profile/attrs.go:179` `CompileMask` | `TestMask` | виконано | див. §4.6 |
| K-P14 | `objectclass.map` | 3.4 | `config.go:309`; `rules.go:198` `MapObjectClass` | `TestTransform_ComputedMaskObjectClass` | виконано | |
| K-P15 | `rdn_attr` дефолт `cn`; користувач → `cn=<rdn>,ou=users,<vb>` | 3.4 | `config.go:251`; дефолт ✓; `rules.go:427` `UserDN` | `TestClassifyBase` (`profile_test.go:208`) | виконано | |
| K-P16 | `client_bind.dn/password[_file|_env]`; без нього — лише user bind | 3.4 | `config.go:314-318`; `rules.go:263`; `validate.go:645` | `TestClientBind`, `TestBind_Fixture` | виконано | + `password_hash` (DECISIONS 2026-10-18 «client_bind.password_hash and tls.key_type») |
| K-P17 | `user_bind.allow=true`; форми UPN, `DOMAIN\user`, sAMAccountName(+`default_domain`), віртуальний DN | 3.4 | `config.go:328-329`; `rules.go:464` `NormalizeBindName` | `TestNormalizeBindName` (`profile_test.go:218-238`), `TestBind_Fixture` | виконано | Реальні DN відхиляються — DECISIONS 2026-10-18 «Real DNs in binds» |
| K-P18 | `user_bind.require_membership` | 3.4 | `config.go:330`; `vdir/bind.go:278` `requireMembership` (reason `not_member`) | `TestBind_Policies` (`vdir_test.go:661-677`), `TestSamba_UserBind` | виконано | |
| K-P19 | `anonymous_bind=false` | 3.4 | `config.go:254`; `vdir/bind.go:138` `anonymousBind`; `validate.go:661` warn | `TestBind_Fixture`, `TestDaemon_Ldapsearch` (anonymous → Invalid credentials), `TestAudit14_FP1_*` (пошук без bind → `strongAuthRequired`) | виконано | DECISIONS 2026-10-18 «Anonymous and unauthenticated binds» |
| K-P20 | `groups.<gname>` віртуальні групи | 3.4 | `config.go:255,335-347`; `profile/groups.go:69` | `TestGroups_Sources` | виконано | див. §4.4 |
| K-P21 | `nested_groups` (ad → IN_CHAIN; generic → рекурсія з `nested_depth=10`) | 3.4 | `config.go:256-257`; дефолт 10 ✓; `vdir/groups.go:219-296` | `TestGroups_Virola` (nested Staff), `TestGroups_Generic` | виконано | DECISIONS 2026-10-19 «Generic nested groups» |
| K-P22 | `honeytokens` []string + `honeytoken_template` | 3.4 | `config.go:258-260`; `profile/groups.go:102` | `TestHoneytokens`, `TestCompile_Stage5` | виконано | |
| K-P23 | `cache.mode` `none`/`ttl`/`replica` | 3.4 | `config.go:352-358`; дефолти ✓ (ttl 60s, 10000, stale true, 1h, 5m, 20%) | `TestTTL_SecondSearchFromCache`, `TestReplica_ServesWithoutUpstream` | виконано | |
| K-P24 | `limits.max_result_size=5000` | 3.4 | `config.go:363`; дефолт ✓; `directory.go:502` | `TestSearch_Limits` | виконано | |
| K-P25 | `limits.max_filter_depth=20`, `max_filter_len=4096`, `max_request_bytes=1MiB` | 3.4 | `config.go:364-366`; дефолти ✓; `directory.go:344` `ParseWithLimits`; `listener/message.go:52` | `TestParseWithLimits_Cases`, `TestProtocol_Edges/oversize` | виконано | |
| K-P26 | `limits.max_conns_per_ip=32` | 3.4 | `config.go:367`; дефолт ✓; `listener.go:586` `IPLimiter` | `TestLimits` | виконано | |
| K-P27 | `limits.idle_timeout=10m` | 3.4 | `config.go:368`; дефолт ✓; `listener/conn.go:365` | `TestTimeouts/idle` | виконано | |
| K-P28 | `ratelimit.*` перевизначення у профілі | 3.4 | як K-R12 | | виконано | |
| K-P29 | `shadow.filter`, `shadow.bases` → `shadow_diff`, клієнт бачить основні | 3.4 | `config.go:427-430`; `internal/record/shadow.go` | `TestShadow_Diff`, `TestShadow_DirectoryAnswerUnchanged`, `TestValidate_RecordShadow` | виконано | DECISIONS 2026-10-25 «Shadow execution» |
| K-P30 | `record.enabled`, `record.file` JSONL без паролів | 3.4 | `config.go:438-441`; `record/recorder.go`; `validate.go:542` | `TestRecorder_StartStopAndMode`, `TestIsSecretAttr`, `TestRedactFilter` (record) | виконано | DECISIONS 2026-10-25 «Recorder», «What a recording holds» |
| K-E1 | `events.schema` фіксовано `aldap.event.v1` | 3.4 | `config.go:446`; дефолт ✓; `events/record.go` `SchemaID` | `TestBus_WrapAndRing` | виконано | |
| K-E2 | `events.buffer_size=100000` кільцевий буфер | 3.4 | `config.go:447`; дефолт ✓; `bus.go:173` `store` | `TestBus_WrapAndRing` | виконано | |
| K-E3 | `events.hash_accounts` + `salt_file` → `sha256(salt‖account)` | 3.4 | `config.go:448-449`; `bus.go:131-139`; `validate.go:845` | `TestBus_FiltersHashingSubscriptions`, `TestValidate_Rules/events_salt` | виконано | |
| K-E4 | `events.include`/`exclude` | 3.4 | `config.go:450-451`; `bus.go:146` `Accepts`; `validate.go:848` | `TestBus_FiltersHashingSubscriptions`, `TestValidate_Rules/events_include_exclude` | виконано | |
| K-E5 | `[events.stdout]` `enabled`, `format=json` | 3.4 | `config.go:460-461`; `sinks.go:17` `WriterSink`; `configure.go:65` | `TestWriterSink_Lines`, `TestBusFromConfig_Cases` | виконано | |
| K-E6 | `[events.file]` `path`, `max_size_mb=100`, `max_files=10`, `compress=true` | 3.4 | `config.go:466-470`; дефолти ✓; `sinks.go:49,109` | `TestFileSink_Rotation` | виконано | |
| K-E7 | `[events.syslog]` `network=udp/tcp/unix`, `address`, `facility`, RFC5424 | 3.4 | `config.go:475-478`; `events/syslog.go:71` `Message` | `TestSyslogSink_Cases` (`sinks_test.go:140` формат `<PRI>1 …`) | виконано | |
| K-E8 | `[[events.webhook]]` `url`, `events`, `batch_size=100`, `batch_interval=2s`, `timeout=5s`, `retry.max=5`, `retry.backoff=1s..60s`, `hmac_secret[_file]` → `X-ALDAP-Signature: sha256=<hex>`, `headers`, `tls_ca_file`, `queue_size=10000`, `on_overflow=drop_oldest/block` | 3.4 | `config.go:483-497,507-509`; `defaults.go:167`; `webhook.go:21,94,107,147`; `bus.go:356` `offer` | `TestWebhookSink_Cases`, `TestBus_Overflow`, `TestBus_SinkBatching`, `TestValidate_Rules/events_webhook_*` | виконано | Backoff як `retry.backoff` + `retry.max_backoff`; + `name`, `headers_file`, `hmac_secret_env` |
| K-N1 | `notify.cooldown=10m` на (канал, тип, ключ) | 3.4 | `config.go:514`; дефолт ✓; `notify.go:259,349` | `TestCooldown_PerKeyAndExpiry` | виконано | DECISIONS 2026-10-23 «Cooldown key» |
| K-N2 | `notify.digest_interval=15m` під час атаки | 3.4 | `config.go:515`; дефолт ✓; `notify.go:231-300` | `TestScenario39_CooldownAndDigest` | виконано | DECISIONS 2026-10-23 «Digest semantics» |
| K-N3 | `channel.name`, `channel.type` telegram/virola/email/webhook | 3.4 | `config.go:521-522`; `validate.go:943`; `notify.go:398` `build` | `TestValidate_Rules/notify_type`, `TestConfigure_KeepsDigestAndRejects` | виконано | |
| K-N4 | `channel.events` дефолт `[attack_start, attack_summary, attack_end, lock_account, upstream_down, upstream_up, cert_expiring, honeytoken, lockdown]` | 3.4 | `config.go:523`; `defaults.go:40` `DefaultChannelEvents` ✓; `lock_account`→alias `lock{target=account}` (`defaults.go:24`) | `TestMatches_LevelsAndAliases` | свідомо змінено (DECISIONS 2026-10-23 «`lock_account` in the default channel events») | Події `lock_account` не існує; alias вибирає `lock` за `data.target` |
| K-N5 | `channel.min_level` | 3.4 | `config.go:524`; `notify.go:481` | `TestMatches_LevelsAndAliases` | виконано | DECISIONS 2026-10-23 «min_level» (до всіх подій) |
| K-N6 | `channel.template_dir` | 3.4 | `config.go:525`; `template.go:142` `loadTemplates` | `TestTemplateDir_OverrideNotEscaped` | виконано | |
| K-N7 | telegram: `bot_token[_file]`, `chat_id`, `parse_mode=MarkdownV2`, `api_base` | 3.4 | `config.go:528-533`; дефолти ✓; `channels.go:196` | `TestTelegram_ParseModes`, `TestTelegram_RetryAfterAndExhausted` | виконано | |
| K-N8 | virola: `base_url`, `token[_file]` (Bearer), `room_id`/`user_id`, `POST /api/v1/rooms/{room_id}/messages` / `/users/{user_id}/messages` `{"content"}`, `path_template`, `tls_ca_file`, `tls_insecure_skip_verify` | 3.4 | `config.go:536-544`; `channels.go:246-270`; `validate.go:965-1001` | `TestVirola_Path`, `TestValidate_Rules/notify_virola_*` | виконано | DECISIONS 2026-10-23 «Virola message endpoint» |
| K-N9 | email: `smtp_host`, `smtp_port`, `tls=starttls/tls/none`, `username`, `password[_file]`, `from`, `to`, `subject_template` | 3.4 | `config.go:547-556`; `channels.go:325-470`; `validate.go:1003` | `TestEmail_Modes` (tls/starttls/none) | виконано | |
| K-N10 | webhook: `url`, `method=POST`, `headers`, `body_template`, `hmac_secret[_file]`, `timeout`, `retry.*` | 3.4 | `config.go:559-568`; `channels.go:279-320`; `validate.go:1128` | `TestWebhook_BodyTemplate`, `TestWebhook_HeadersFile`, `TestRetry_TransientAndPermanent` | виконано | |
| K-N11 | Шаблони отримують подію + `Hostname`, `Version` | 3.4 | `template.go:35` `Data{Record, Hostname, Version, Digest}` | `TestTemplateDir_OverrideNotEscaped` (`{{.Hostname}} v{{.Version}}`), `TestTemplates_EveryEventType` | виконано | |
| K-A1 | `api.enabled=false` (IPC завжди працює) | 3.4 | `config.go:612`; дефолт ✓; `cmd/aldap/control.go:345` | `TestStage7_IPCAndTCPWithoutToken` | виконано | |
| K-A2 | `api.listen=127.0.0.1:8636` | 3.4 | `config.go:613`; дефолт ✓ | `TestLoad_DefaultsAndTypes` | виконано | |
| K-A3 | `api.tls.cert/key` або `tls.builtin=true` обов'язково, якщо `listen` не loopback; інакше старт відхиляється | 3.4 | `config.go:625-627`; `validate.go:1177-1181`; `internal/api/api.go:440` `CheckTransport` | `TestValidate_Rules/api_tls_required`, `TestTransport_LoopbackOnlyWithoutTLS`, `TestServe_APIStartFailures` | виконано | DECISIONS 2026-10-23 «TLS rule checked twice» |
| K-A4 | `api.client_auth` `none/require` + `client_ca` | 3.4 | `config.go:615-616`; `validate.go:1147-1150`; `cmd/aldap/control.go:419-428` | `TestValidate_Rules/api_client_ca` | виконано | |
| K-A5 | `[[api.token]]` `name`, `token[_file]` (≥32 байти), `scopes`, `allow_cidrs` | 3.4 | `config.go:639-644`; `validate.go:1190-1204`; `auth.go:45,86,106` | `TestValidate_Rules/api_loopback_ok_token_short`, `api_token_scope`; `TestAuth_CIDRsRateLimitAndConfigure` | виконано | Мінімум 32 байти перевіряється лише для inline (файл — ні) |
| K-A6 | `api.rate_limit_rps=50` | 3.4 | `config.go:617`; дефолт ✓; `auth.go:138` `buckets.take` | `TestAuth_CIDRsRateLimitAndConfigure`, `TestBuckets_Bounded` | виконано | |
| K-A7 | `api.metrics.enabled=true`, `metrics.listen`, `/metrics` вимагає `status:read` або `metrics.public=true` | 3.4 | `config.go:632-634`; `api.go:309-318` | `TestMetrics_ScopeAndPublic` | виконано | |
| K-A8 | `api.cors` вимкнено | 3.4 | `config.go:619`; `validate.go:1142` (`true` → помилка) | `TestValidate_Rules/api_cors` | виконано | |

### 3.5 Валідація (`aldap check`)

| ID | Вимога (коротко, укр.) | SPEC § | Реалізація (файл/функція) | Тест | Статус | Примітка |
|---|---|---|---|---|---|---|
| V-01 | Ненульовий код і список помилок/попереджень | 3.5 | `cmd/aldap/check.go:107-151` (0 OK / 1 помилки / 2 usage), `:230-241` вивід | `TestRunCheck_Cases` (`check_test.go:66-81`), `TestRunCheck_JSON` | виконано | |
| V-02 | Синтаксис TOML, невідомі ключі (помилка), типи | 3.5 | `load.go:142-179` `decode` | `TestLoad_Errors`, `TestTypes_Parse` | виконано | |
| V-03 | Унікальність імен, портів, `virtual_base` | 3.5 | `validate.go:783` `validateProfilesCross` | `TestValidate_Rules/cross_*` | виконано | |
| V-04 | Парсинг усіх фільтрів (RFC 4515) і DN | 3.5 | `validate.go:694-716` `checkDN/checkFilter` → `ldapfilter.Parse/ParseDN` | `TestValidate_Rules/profile_bad_filter`, `profile_bad_base` | виконано | DECISIONS 2026-10-18 «Filter and DN syntax in check» |
| V-05 | Секрети: ≤1 джерела, файли існують і читаються, права ≤0640 (warn) | 3.5 | `validate.go:232` `checkSecret`; `secret.go:22` `MaxFileMode`, `:201` | `TestValidate_SecretFiles`, `TestResolver_Probe` | виконано | Відсутній файл офлайн — warn, при `run`/`--online` — помилка (DECISIONS 2026-10-18 «Offline aldap check and missing files») |
| V-06 | TLS: сертифікати читаються, строк дії, SAN містить listen-хости (warn) | 3.5 | `validate.go:319` `checkCertFile` | `TestValidate_SectionMethods` | частково | Тест на SAN-попередження для listen-хостів не знайдено (перевіряється лише в `TestParseSANs_Covers` з боку tlsutil) |
| V-07 | warn: `account.max_failures≥5`, `tls_insecure_skip_verify`, `transport=ldap` без StartTLS, inline-пароль | 3.5 | `validate.go:388,495,579,247` | `TestValidate_Rules/ratelimit_account_warn`, `upstream_insecure_warn`, `profile_plain_warn`, `upstream_inline_warn` | виконано | |
| V-08 | `--online`: з'єднання з кожним upstream, bind, RootDSE, тестовий пошук по кожному `bases`, аудит прав | 3.5 | `check.go:67`; `internal/upstream/check.go:37` `Check`, `:56` `checkServer` | `TestRunCheck_Online`, `TestCheck_Findings`, `TestSamba_CheckOnline` | виконано | DECISIONS 2026-10-18 «aldap check --online scope» |
| V-09 | `--profile <name> --as-client`: емуляція клієнтського запиту | 3.5 | `check.go:68-74`; `cmd/aldap/asclient.go`; `vdir/test.go:44` `Test` | `TestRunCheck_AsClient` | виконано | DECISIONS 2026-10-19 «aldap check --as-client» |

### 3.6 Hot reload

| ID | Вимога (коротко, укр.) | SPEC § | Реалізація (файл/функція) | Тест | Статус | Примітка |
|---|---|---|---|---|---|---|
| H-01 | `SIGHUP`, `POST /v1/reload`, `aldapctl reload` | 3.6 | `cmd/aldap/run.go:39,107`; `internal/api/handlers.go:358`; `cmd/aldapctl/main.go:166` | `TestServe_Signals`, `TestAdmin_ConfigReloadSyncTestLearn`, `TestCLI_Mutating` | виконано | |
| H-02 | Нова конфігурація валідується; при помилці стара лишається, `config_reload{ok=false}` | 3.6 | `run.go:126-147` `reload` | `TestServe_Signals`, `TestController_ApplyConfig` | виконано | |
| H-03 | Зміна `listen` відкриває/закриває listener'и без розриву решти | 3.6 | `cmd/aldap/sockets.go` (пул сокетів), `listener.go:233` `Reconfigure` | `TestStage12_ListenAddRemove`, `TestReconfigure_TransportChangeEndsOldConnections` | виконано | DECISIONS 2026-10-25 «Hot reload without dropping connections» |
| H-04 | Зміна правил атомарна: нові запити — нові правила, поточні завершуються за старими | 3.6 | `listener.go:106` `generation`, `:210` `acquire` | `TestReconfigure_InFlightKeepsOldHandler`, `TestStage12_ReloadDuringPagedSearch` | виконано | |
| H-05 | Стан rate limit не скидається | 3.6 | `cmd/aldap/daemon.go` `runtimeState` (процесний стан); `ids.go:175` `Reconfigure` | `TestStage12_ReloadKeepsRateLimitState` | виконано | |

## 4. §4 Віртуальний каталог

| ID | Вимога (коротко, укр.) | SPEC § | Реалізація (файл/функція) | Тест | Статус | Примітка |
|---|---|---|---|---|---|---|
| VD-01 | Дерево `<vb>` (organizationalUnit/domain) → `ou=users` → `cn=<rdn>`; `ou=groups` → `cn=<gname>` з `member` | 4.1 | `vdir/static.go:81` `containerEntry`; `directory.go:418` `containerEntries`; `rules.go:427-432` | `TestSearch_Static` (`vdir_test.go:209-221`), `TestSearch_Users` | виконано | DECISIONS 2026-10-18 «Container entries in Stage 4» |
| VD-02 | RootDSE: `namingContexts`=virtual_base, `supportedLDAPVersion=3`, `supportedControl`=paged (1.2.840.113556.1.4.319)+реальні, `supportedSASLMechanisms` порожньо, `vendorName=ALDAP` | 4.1 | `static.go:108` `rootDSE` | `TestSearch_Static` (`vdir_test.go:185-187`), `TestDaemon_Ldapsearch` (namingContexts, supportedControl) | виконано | `supportedSASLMechanisms` не публікується (порожній атрибут в LDAP ≡ відсутній); один профіль на listener → один `namingContexts` |
| VD-03 | `cn=Subschema` мінімальний набір objectClasses/attributeTypes | 4.1 | `static.go:178` `subschema` | `TestSearch_Static` (`:199-203`) | виконано | DECISIONS 2026-10-18 «Subschema OIDs» |
| VS-01 | Крок 1: валідація розміру запиту, глибини/довжини фільтра, base у межах, scope | 4.2 | `listener/message.go:52` (розмір); `directory.go:344-358` | `TestProtocol_Edges/oversize`, `TestParseWithLimits_Cases`, `TestSearch_Limits` | виконано | |
| VS-02 | Крок 2: класифікація base (RootDSE/vb/ou=users/ou=groups/одна група/один користувач за `rdn_attr`) | 4.2 | `rules.go:390` `ClassifyBase`; `directory.go:390` `entriesFor` | `TestClassifyBase`, `TestSearch_Users` (`:331` lookup одного користувача) | виконано | |
| VS-03 | Крок 3: AST → map client→upstream, computed/virtual memberOf пост-фактум, denied → FALSE + `recon`, AND filter, AND NOT exclude | 4.2 | `directory.go:561` `splitFilter`; `ldapfilter/ops.go:140` `Split`, `:191` `denyLeaves`; `groups.go:184` | `TestSplit_Cases`, `TestSearch_Users` (`vdir_test.go:299` `denied_terms`, 0 upstream queries) | виконано | DECISIONS 2026-10-18 «Denied filter terms», «Split() of mixed Or/Not»; подія для denied — у `search.data.denied_terms`, окремої `recon` на denied-атрибут немає (recon тільки за сигнатурами) |
| VS-04 | Крок 4: paged search по кожному `bases` лише потрібними атрибутами + `distinguishedName`,`objectGUID`,`memberOf`; паралельно `limits.upstream_parallel=4` | 4.2 | `directory.go:593` `upstreamAttrs`, `:705` `fetchUsers` (semaphore `UpstreamParallel`) | `TestSearch_MergeDedupeExclude`, `TestIntegration_PagedSearch` | виконано | `memberOf` з upstream не запитується — завжди віртуальний (DECISIONS 2026-10-19 «memberOf is always virtual») |
| VS-05 | Крок 5: дедуплікація за `objectGUID` (ad) / DN (generic); стабільний порядок за DN | 4.2 | `directory.go:766` `dedupeKey`; `:700` `sort.SliceStable` за DN | `TestSearch_MergeDedupeExclude` (`vdir_test.go:545`) | виконано | |
| VS-06 | Крок 6: map → computed → mask → objectclass.map → віртуальний DN; колізії RDN → суфікс `+objectGUID` і WARN; `memberOf` = віртуальні групи | 4.2 | `directory.go:779` `transform`, `:686-688` WARN, `groups.go:403` `virtualUserDN` | `TestSearch_RDNCollision` (`vdir_test.go:412-423`), `TestReplica_RDNCollisionStable`, `TestTransform_ComputedMaskObjectClass` | виконано | У replica-режимі колізії вирішуються над усією копією (DECISIONS 2026-10-19/23 «RDN collision suffix scope») |
| VS-07 | Крок 7: пост-фільтрація по computed/virtual memberOf | 4.2 | `directory.go:690-694` `matches(sc.post)`; `match.go:25` | `TestEntryMatches`, `TestGroups_Virola` (`stage5_test.go:106-117` `(memberOf=)`, негація) | виконано | Post-filter до маскування (DECISIONS 2026-10-19 «Post-filter before mask») |
| VS-08 | Крок 8: `sizeLimit` та `max_result_size` → `sizeLimitExceeded`; paged results до клієнта (opaque cookie, прив'язаний до з'єднання; злитий результат у пам'яті) | 4.2 | `directory.go:502` `sizeLimit`, `:873` `firstPage`, `:893` `nextPage` | `TestSearch_Limits`, `TestSearch_Paging` (`vdir_test.go:435-469`: cookie, невідомий cookie → unwillingToPerform, abandon) | виконано | DECISIONS 2026-10-18 «Paged results state» (≤8 курсорів на з'єднання) |
| VS-09 | Крок 9: подія `search` (profile, conn_id, base, scope, filter_norm, attrs_requested, attrs_denied, results, upstream_queries, duration_ms, cache_hit) | 4.2 | `directory.go:957` `emitSearch` | `TestSearch_Users` (`vdir_test.go:287-300`), `TestStage6_EventsValid` | виконано | + `denied_terms`, `result_code`, `honeytoken` |
| VB-01 | Anonymous → `invalidCredentials`, `bind_fail{reason=anonymous}` при `anonymous_bind=false` | 4.3 | `bind.go:138` `anonymousBind` | `TestBind_Fixture`, `TestDaemon_Ldapsearch` | виконано | |
| VB-02 | Client bind (DN == `client_bind.dn`): constant-time перевірка argon2id-хешу з конфігу; сесія з правами пошуку | 4.3 | `bind.go:161-168`; `rules.go:299` `VerifyClientPassword`; `argon2.go:89` `Verify` (`subtle.ConstantTimeCompare`) | `TestClientBind`, `TestArgon2_PHC`, `TestBind_Fixture` | виконано | SPEC згадує bcrypt/argon2id — реалізовано argon2id (§9) |
| VB-03 | User bind: UPN як є; `DOMAIN\user` → `user@default_domain` або як є; sAMAccountName → UPN з `default_domain`; віртуальний DN → пошук за `rdn_attr` → реальний DN | 4.3 | `rules.go:464` `NormalizeBindName`; `bind.go:187-193` `lookupUser` | `TestNormalizeBindName`, `TestBind_Fixture`, `TestSamba_UserBind` | виконано | |
| VB-04 | Перед upstream: rate limit (IP/акаунт), negative cache, lockdown, honeytoken | 4.3 | `bind.go:29-52` (`PreBind`), `:174-177` honeytoken | `TestBind_Policies`, `TestStage6_AccountLockAndNegativeCache`, `TestStage6_IPLockAndLockdown` | виконано | |
| VB-05 | Bind в upstream окремим bind-only пулом; після відповіді — повернення/закриття | 4.3 | `upstream.go:88` `s.bind = newPool(... plainDialer)`, `:513` `UserBind` | `TestUserBind_Cases`, `TestIntegration_UserBindReasons` | виконано | Без re-bind сервісним — DECISIONS 2026-10-18 «Bind-only pool reuse» |
| VB-06 | `require_membership`: після успіху пошук з `filter`; не пройшов → `invalidCredentials`, `bind_fail{reason=not_member}` | 4.3 | `bind.go:278` `requireMembership` (`:292` `not_member`) | `TestBind_Policies` (`vdir_test.go:661-677`) | виконано | |
| VB-07 | Мапінг AD data: 52e → invalid_password; 533 disabled; 775 locked_in_ad; 701 expired; 773 must_change → клієнту `invalidCredentials`, у подію справжня причина | 4.3 | `upstream/bindreason.go:32` `adData`, `:78` `ClassifyBindError`; `bind.go:216` `bindError` | `TestClassifyBindError_Cases` (`upstream_test.go:114-150`: усі коди), `TestBind_ADCodes` (testdir) | виконано | + 525/530/531/532 (DECISIONS 2026-10-18 «AD data codes beyond SPEC §4.3») |
| VB-08 | `locked_in_ad` → подія рівня `medium` | 4.3 | `bind.go:78-81`; `bindreason.go:68` `Level` | `TestClassifyBindError_Cases` (`be.Level()=="medium"`), `TestIntegration_UserBindReasons` | виконано | |
| VB-09 | `constant_time_bind_fail`: невдалі відповіді не раніше p95 успішних | 4.3 | `ratelimit.go:742-755`; `bind.go:53-66` `Sleep(wait)` | `TestPolicy_ConstantTimeAndDisabled` | виконано | |
| VG-01 | Синтаксис групи: `description`, `objectclass` (groupOfNames/group/posixGroup), `gid_number`, `members.bases/filter/ad_groups/include/exclude` | 4.4 | `config.go:335-347`; `profile/groups.go:69`; `validate.go:736` | `TestValidate_Rules/profile_group_*`, `TestGroups_Sources` | виконано | Атрибути за objectclass — DECISIONS 2026-10-19 «Group entry attributes» |
| VG-02 | Членство = (bases+filter) ∪ ad_groups ∪ include − exclude, ∩ profile.filter | 4.4 | `vdir/groups.go:132` `groupMembers`, `:184` `profileFilter` | `TestGroups_Sources`, `TestGroups_Virola` | виконано | DECISIONS 2026-10-19 «include/exclude forms» |
| VG-03 | Дефолти `members.bases`=profile.bases, `members.filter`=profile.filter | 4.4 | `profile/groups.go:90-95`; `groups.go:184` | `TestGroups_Virola` (група «з усіма») | виконано | |
| VG-04 | `ad_groups` з nested за `profile.nested_groups` | 4.4 | `vdir/groups.go:219` `adGroupMembers` (IN_CHAIN / `walkGroup`) | `TestGroups_Virola` (nested Staff), `TestGroups_Generic` | виконано | |
| VG-05 | Ліниве обчислення, кеш за `cache` профілю; для `none` — `groups.ttl=60s` мінімум | 4.4 | `groups.go:60` `membership` (TTL = `cache.ttl`, дефолт 60s; `rules.go:108` мін. 1m) | `TestNone_MembershipTTL` | свідомо змінено (DECISIONS 2026-10-19 «Group membership TTL») | Ключа `groups.ttl` немає; використовується `cache.ttl` |
| VG-06 | `member` — віртуальні DN; `memberOf` — віртуальні DN груп | 4.4 | `groups.go:417` `groupEntry`; `directory.go:808` `set(memberOf)` | `TestGroups_Virola` (`stage5_test.go:100-103`) | виконано | |
| VG-07 | Пошук `(member=<dn>)` і `(memberOf=<dn>)` | 4.4 | `match.go:68` `equal` (DN-порівняння); `directory.go:628` `needMembership` | `TestGroups_Virola` (`:106-119`) | виконано | |
| HT-01 | `honeytokens` як користувачі з атрибутами з `honeytoken_template`, у пошуку і у групах (`honeytoken_in_groups=true`) | 4.5 | `profile/groups.go:102` `compileHoneytokens`; `directory.go:667-671`; `groups.go:168-172` | `TestHoneytokens`, `TestDaemon_Virola` (`stage5_test.go:184-185`) | виконано | DECISIONS 2026-10-19 «Honeytoken entries and filters» |
| HT-02 | Bind по них або search з однозначним фільтром (`sAMAccountName`/`mail`/`cn`=…) → `honeytoken{level=high}` + `lock_ip` на `honeytoken_lock=24h` | 4.5 | `honeytoken.go:66` `honeytokenHit` (LevelHigh, `LockIP`), `:84` `honeytokenTarget`; дефолт `ids.honeytoken.lock_duration=24h` | `TestHoneytokens`, `TestStage6_ReconHoneytokenAnomaly`, `TestSamba_ReconAndHoneytoken` | частково | Ключ називається `ids.honeytoken.lock_duration`, не `honeytoken_lock`; рядка DECISIONS про перейменування немає (функціонально відповідає) |
| HT-03 | `mode=honeypot` — увесь профіль пастка | 4.5 | `bind.go:156-161`; `directory.go:376-382` | `TestHoneypot`, `TestDaemon_HoneypotMock` | виконано | DECISIONS 2026-10-19 «Honeypot semantics» |
| MK-01 | Патерни `{first<N>}`, `{last<N>}`, `{domain}`, `***` | 4.6 | `profile/attrs.go:179` `CompileMask`, `:221` `Apply` | `TestMask` (`attrs_test.go:58-64`) | виконано | |
| MK-02 | Маскування після computed; фільтрація в upstream по оригіналу | 4.6 | `directory.go:690-695` (`matches` до `mask`), `:816` | `TestTransform_ComputedMaskObjectClass`, `TestDaemon_Ldapsearch` (`(telephoneNumber=*)`) | виконано | DECISIONS 2026-10-19 «Post-filter before mask» |

## 5. §5 Кеш, репліка, failover

| ID | Вимога (коротко, укр.) | SPEC § | Реалізація (файл/функція) | Тест | Статус | Примітка |
|---|---|---|---|---|---|---|
| CA-01 | `none`: кожен запит → upstream (крім membership TTL) | 5.1 | `cmd/aldap/cache.go`; `vdir/groups.go:60` | `TestNone_MembershipTTL` | виконано | |
| CA-02 | `ttl`: ключ (profile, normalized filter, bases, attrs, scope, base); `ttl=60s`; `max_entries=10000` | 5.1 | `cache/ttl.go:221` `Key` (base, scope, Normalize(), attrs, size); один TTL на профіль | `TestKey_Normalized`, `TestTTL_HitAndExpiry`, `TestTTL_MaxEntriesAndSweep`, `TestStage9_TTL` | виконано | DECISIONS 2026-10-23 «TTL cache layer and key», «max_entries unit» |
| CA-03 | `stale_while_down=true`: усі сервери down → протухлі записи до `stale_max=1h` з подією `stale_served` | 5.1 | `ttl.go:192-211`; `directory.go:1012` `emitStale` | `TestTTL_StaleWhileDown`, `TestStage9_StaleWhileDown` | виконано | DECISIONS 2026-10-23 «When a stale result is served» |
| CA-04 | `replica`: фоновий повний sync кожні `sync_interval=5m` з `sync_jitter=20%`; відповіді з пам'яті; невдача → остання копія + `replica_sync_failed`; `aldapctl sync` примусово | 5.1 | `cache/replica.go:109` `Sync`, `:176` `Run`, `:100` `Trigger`; `vdir/replica.go:37` `SyncReplica` | `TestReplica_SyncKeepsLastCopy`, `TestReplica_Jitter`, `TestReplica_RunAndTrigger`, `TestStage9_Replica`, `TestCLI_Mutating` (sync) | виконано | DECISIONS 2026-10-23 «Replica evaluation», «Replica events» |
| CA-05 | User bind завжди йде в upstream (паролі не кешуються) | 5.1 | `vdir/directory.go:124` `New` (окремий `up` для bind), `bind.go:201` `d.up.UserBind` | `TestCache_BindAlwaysUpstream`, `TestReplica_BindGoesUpstream` | виконано | DECISIONS 2026-10-23 «Binds and the cache» |
| FO-01 | Стан `up/down/unknown`, лічильники послідовних успіхів/невдач, остання помилка, p50/p95 | 5.2 | `upstream/server.go:39` `server`, `:87` `record`, `:133` `percentiles`, `:147` `status` | `TestServer_Record`, `TestEndpoints_StatusProfilesUpstreamsHealth` | виконано | |
| FO-02 | Запит на перший `up` (prefer_primary) або round-robin (`strategy=roundrobin`) | 5.2 | `upstream.go:212` `candidates`; `config.go:90` `strategy` | `TestCandidates_Strategies`, `TestIntegration_RoundRobin` | виконано | |
| FO-03 | Невдача операції = невдача health (fail-fast), повтор на наступному up лише для ідемпотентних; user bind повторюється лише при мережевій помилці | 5.2 | `upstream.go:242` `do` (`isConnError`, `retry`), `:278` `observe` (`requestCheck`), `:513` `UserBind` | `TestSearch_PagingAndFailover`, `TestUserBind_Cases`, `TestIntegration_UserBindReasons` | виконано | DECISIONS 2026-10-18 «Server failure classification» |
| FO-04 | Події `upstream_down/up` з `server`, `reason` | 5.2 | `upstream.go:290-300`; `cmd/aldap/daemon.go:269` `upstreamEvent` | `TestHealth_KindsAndEvents`, `TestIntegration_FailoverAndReturnToPrimary`, `TestSamba_Failover` | виконано | + `consecutive` |
| GR-01 | SIGTERM/`aldapctl stop`: закрити listener'и, дочекатись активних до `shutdown_timeout`, `unavailable` notice, скинути черги подій (webhook — до таймауту) | 5.3 | `run.go:39,84`; `listener.go:478` `Shutdown` (`:517` notice); `daemon.go:664` `stop` → `bus.Flush()` (`bus.go:311`) | `TestShutdown_Graceful`, `TestShutdown_WaitsForDrain`, `TestStage12_DrainActiveRequest`, `TestServe_Signals` | частково | `aldapctl stop` не реалізовано — LIMITATION DECISIONS 2026-10-25 «`aldapctl stop`»; SIGTERM-шлях виконано (DECISIONS 2026-10-25 «Graceful drain») |

## 6. §6 Події

### Конверт

| ID | Вимога (коротко, укр.) | SPEC § | Реалізація (файл/функція) | Тест | Статус | Примітка |
|---|---|---|---|---|---|---|
| EV-01 | JSONL, усі поля snake_case; обов'язкові `schema`, `ts`, `id`, `event`, `level`, `host` | 6 | `events/record.go:16` `Record` (json-теги); схема `required` (+`seq`) | `TestBus_WrapAndRing`, `TestSchema_EveryKindValidates` | виконано | Схема вимагає також `seq` |
| EV-02 | `schema=aldap.event.v1` | 6 | `record.go` `SchemaID`; `bus.go:121` `Wrap` | `TestBus_WrapAndRing` | виконано | |
| EV-03 | `ts` ISO-8601 UTC мс | 6 | `record.go:61` `newRecord` | `TestBus_WrapAndRing` (`2026-10-19T10:21:33.412Z`) | виконано | |
| EV-04 | `id` ULID | 6 | `events/ulid.go:16` `NewULID` | `TestNewULID_Format` | виконано | |
| EV-05 | `seq` монотонний у межах процесу | 6 | `bus.go:116` `Seq`, `:131` `b.seq.Add(1)` | `TestBus_WrapAndRing` (`bus_test.go:91,111`) | виконано | |
| EV-06 | `host` | 6 | `bus.go:113`, `Options.Host` (os.Hostname) | `TestBus_WrapAndRing` | виконано | |
| EV-07 | `profile`, `conn_id`, `client_ip`, `client_port`, `tls` | 6 | `event.go:57` `Event`; `listener/conn.go:252` `Conn.Event` | `TestDenied_Operations` (ConnID, ClientIP, TLS), `TestSchema_EveryKindValidates` | виконано | |
| EV-08 | `account`, `account_hash` (при `hash_accounts`) | 6 | `bus.go:132-135` | `TestBus_FiltersHashingSubscriptions` | виконано | |
| EV-09 | `reason`, `failures`, `upstream`, `upstream_server`, `duration_ms` | 6 | `record.go:24-34`; заповнюються у `vdir/bind.go`, `ratelimit.go:289` | `TestSchema_EveryKindValidates`, `TestBind_Fixture` | виконано | `failures` у конверті лише для `lock` |
| EV-10 | `data` — специфічні поля | 6 | `record.go:35` (`{}` коли порожньо) | `TestBus_WrapAndRing` | виконано | |

### Типи подій (код емітує → схема → SPEC)

| ID | Вимога (коротко, укр.) | SPEC § | Реалізація (файл/функція) | Тест | Статус | Примітка |
|---|---|---|---|---|---|---|
| ET-01 | `bind_ok` low `{bind_kind, upstream_dn}` | 6 | `vdir/bind.go:68-76` | `TestBind_Fixture`, `TestStage6_EventsValid` | виконано | |
| ET-02 | `bind_fail` low/medium `{reason, failures}` | 6 | `bind.go:77-93`: `reason` у конверті (схема вимагає enum), `data={bind_kind, form, ad_data}` | `TestBind_Fixture`, `TestSchema_EveryKindValidates` | частково | `failures` не емітується ні в конверті, ні в `data` для `bind_fail` (лічильник є лише у `lock`) |
| ET-03 | `bind_blocked` medium `{reason: ip_locked|account_locked|negative_cache|lockdown|rate_limited}` | 6 | `bind.go:39-46` | `TestBind_Policies`, `TestPolicy_NegativeCache` | виконано | |
| ET-04 | `lock` medium `{target, key, until, failures, source: ratelimit|ids|api|honeytoken}` | 6 | `ratelimit.go:289-299` | `TestPolicy_AccountLock`, `TestLocks_CreateListDeleteLockdown`, схема `allOf` для `lock` | виконано | + `source=tui` у схемі; + `reason` |
| ET-05 | `unlock` low `{target, key, source: expiry|api|tui}` | 6 | `ratelimit.go:333` `emitUnlock` | `TestLimiter_LockWithReason`, `TestLocks_CreateListDeleteLockdown` | виконано | |
| ET-06 | `attack_start/summary/end` medium/high `{kind, attack_id, ips[], accounts_count, failures, rate_per_min, first_seen, last_seen}` | 6 | `ids.go:481` `emitAttack` (усі 8 полів) | `TestEngine_Spray`, схема `allOf` (required `kind`, `attack_id`) | виконано | |
| ET-07 | `recon` medium `{signature, filter_norm, base, attrs}` | 6 | `ids/recon.go:30-31` | `TestEngine_Recon` | виконано | Схема не має `allOf` для `recon` (поля не required) |
| ET-08 | `anomaly` medium `{reason: new_ip|new_filter|new_base|new_attrs|rps_spike|fingerprint, observed, baseline}` | 6 | `ids/baseline.go:159-161` | `TestEngine_Baseline`, `TestEngine_IndicatorsAndNote` | виконано | Схема без `allOf` для `anomaly` |
| ET-09 | `honeytoken` high `{account, op: bind|search}` | 6 | `vdir/honeytoken.go:67-70` | `TestHoneytokens` | виконано | |
| ET-10 | `search` low `{base, scope, filter_norm, attrs_requested[], attrs_denied[], results, upstream_queries, cache_hit, denied_terms[]}` | 6 | `directory.go:957-980` | `TestSearch_Users`, схема `allOf` (required `base, scope, filter_norm, results`) | виконано | `attrs_requested/attrs_denied/denied_terms` лише коли непорожні; + `result_code`, `honeytoken` |
| ET-11 | `op_denied` medium `{op: add|modify|delete|modrdn|compare|extended, oid}` | 6 | `listener/conn.go:491-495` | `TestDenied_Operations` | виконано | |
| ET-12 | `session_summary` low `{binds_ok, binds_fail, searches, results_total, denied, duration_ms, bytes_in, bytes_out, fingerprint}` | 6 | `listener.go:432` `sessionSummary` (усі 9) | `TestConn_Helpers`/`TestBindSearch_Plain` (listener_test) | виконано | Схема без `allOf` |
| ET-13 | `rate_limited` low `{target, key, rps}` | 6 | `directory.go:289-291` `{target, key, op, reason}`; `listener.go:461` `{target:"conn", key, limit}`; `conn.go:444` oversize | `TestLimits`, `TestPolicy_BucketsLockdownTarpit` | частково | Поле `rps` не емітується (замість нього `reason`/`op`/`limit`); схема не фіксує `data` для `rate_limited` |
| ET-14 | `tarpit` low `{ip, conns}` | 6 | `ratelimit.go:590` | `TestPolicy_BucketsLockdownTarpit`, `TestStage6_Tarpit` | виконано | |
| ET-15 | `lockdown` high `{state: on|off, source}` | 6 | `ratelimit.go:400` | `TestLocks_CreateListDeleteLockdown`, `TestStage6_IPLockAndLockdown` | виконано | |
| ET-16 | `upstream_down` high / `upstream_up` medium `{server, reason, consecutive}` | 6 | `upstream.go:291-300` | `TestHealth_KindsAndEvents` | виконано | |
| ET-17 | `stale_served` / `replica_sync_failed` medium, `replica_synced` low `{age_s, entries}` | 6 | `directory.go:1012`; `cache/replica.go:128-136` | `TestTTL_StaleWhileDown` (vdir), `TestReplica_SyncKeepsLastCopy`, схема `allOf` ×3 | виконано | |
| ET-18 | `cert_expiring` medium / `cert_renewed` low `{subject, not_after, days_left}` | 6 | `tlsutil/manager.go:283` `certData`, `:219`, `:277` | `TestManager_BuiltinLifecycle`, `TestManager_ExternalExpiring` | виконано | Схема без `allOf` |
| ET-19 | `config_reload` low/high `{ok, errors[]}` | 6 | `cmd/aldap/run.go:131-147` | `TestServe_Signals`, `TestStage6_EventsValid` | виконано | |
| ET-20 | `insecure_config` medium `{what}` | 6 | `upstream.go:150,162` (`tls_insecure_skip_verify`, `plaintext_upstream`); `audit.go` (`service_account_admin`); `ids/masked.go:212` (`client_ip_masked`) | `TestHealth_KindsAndEvents`, `TestAudit_Cases`, `TestClientIPMasked_Detects` | виконано | Для inline-паролів і `transport=ldap` події немає — див. SEC-08 |
| ET-21 | `shadow_diff` low `{added[], removed[]}` (кількості + до 20 прикладів) | 6 | `record/shadow.go:107,` `run` (+`added_count`, `removed_count`, `results`, `shadow_results`, `result_code`) | `TestShadow_Diff`, `TestShadow_SamplesAndCodes`, схема `allOf` (`maxItems: 20`) | виконано | |
| ET-22 | `startup` / `shutdown` low `{version, profiles[]}` | 6 | `daemon.go:555` (`version`, `profiles`); `:681` shutdown — лише `{version}` | `TestServe_Signals`, `TestStage6_EventsValid` | частково | `shutdown` не містить `profiles[]` |
| ET-23 | Події в коді/схемі, яких немає у таблиці SPEC §6 | 6 | `api_call` (SPEC §7; `api.go:342`), у схемі є; `insecure_config{what=client_ip_masked}` (DECISIONS 2026-10-25 «Masked client addresses») | `TestAudit_APICall`, `TestEventKindsInSync` | виконано | Усі 30 kind'ів `config.EventKinds` = enum схеми (`TestEventKindsInSync`) |
| ER-01 | Паролі, токени, cookie — ніколи; значення `unicodePwd`/`userPassword` у фільтрі → `***` | 6 | `events/redact.go:12` `RedactFilter`, `bus.go:131` `redactData`; `vdir/directory.go:936` | `TestRedactFilter_Cases`, `TestRedactFilter` (vdir), `TestNoSecretsInOutput_Daemon` (`userpassword=***`) | виконано | |
| ER-02 | `seq` монотонний; `GET /v1/events?since=<seq>` | 6 | `bus.go:184` `Since`; `handlers.go:273` | `TestBus_WrapAndRing`, `TestEvents_SinceLimitTypes` | виконано | |
| ER-03 | Схема `docs/events.schema.json` (draft 2020-12); тест перевіряє всі події проти схеми | 6 | `docs/events.schema.json`; `internal/events/schematest` | `TestSchema_EveryKindValidates`, `TestSchema_RejectsInvalid`, `schematest.Check` у 12 тестових файлах (api, cache, ids, listener, ratelimit, record, vdir, cmd/aldap stage6/7/9/samba) | виконано | DECISIONS 2026-10-19 «Schema validation in tests» (власний валідатор підмножини JSON Schema) |

## 7. §7 API

| ID | Вимога (коротко, укр.) | SPEC § | Реалізація (файл/функція) | Тест | Статус | Примітка |
|---|---|---|---|---|---|---|
| API-01 | `GET /v1/status` status:read — версія, аптайм, профілі, upstream'и зі станами, лічильники | 7 | `api.go:132`; `handlers.go:99` `handleStatus`; `openapi.yaml:138` | `TestEndpoints_StatusProfilesUpstreamsHealth`, `TestScopes_EveryRoute`, `TestOpenAPIRoutes` | виконано | + `go_version`, `events_seq` |
| API-02 | `GET /v1/upstreams` status:read | 7 | `api.go:133`; `handlers.go:126`; `openapi.yaml:143` | те саме | виконано | |
| API-03 | `GET /v1/profiles` status:read, без секретів | 7 | `api.go:134`; `handlers.go:134`; `openapi.yaml:147` | `TestEndpoints_StatusProfilesUpstreamsHealth`, `TestNoSecretsInOutput_API` | виконано | |
| API-04 | `GET /v1/locks` locks:read | 7 | `api.go:135`; `handlers.go:157`; `openapi.yaml:151` | `TestLocks_CreateListDeleteLockdown` | виконано | |
| API-05 | `POST /v1/locks` locks:write `{target, key, duration, reason}` | 7 | `api.go:136`; `handlers.go:193`; `openapi.yaml:156` | `TestLocks_CreateListDeleteLockdown`, `TestAudit_APICall` | виконано | |
| API-06 | `DELETE /v1/locks/{target}/{key}` locks:write | 7 | `api.go:137`; `handlers.go:226`; `openapi.yaml:163` | `TestLocks_CreateListDeleteLockdown` | виконано | |
| API-07 | `GET /v1/indicators` locks:read, score/причини/first_seen/last_seen, `?format=json|stix-lite|plain` | 7 | `api.go:138`; `indicators.go:42`; `ids/indicators.go:112`; `openapi.yaml:170` | `TestIndicators_Formats` (`api_test.go:581-599`) | виконано | DECISIONS 2026-10-23 «Indicator score», «Indicator formats» |
| API-08 | `GET /v1/events` events:read `?since&limit=1000&types` | 7 | `api.go:139`; `handlers.go:273`; `openapi.yaml:187` | `TestEvents_SinceLimitTypes` | виконано | |
| API-09 | `GET /v1/events/stream` events:read SSE, `Last-Event-ID`=seq | 7 | `api.go:140`; `stream.go:16,112` `resumeFrom`; `openapi.yaml:197` | `TestStream_LastEventID`, `TestStream_SinceTypesErrorsAndGaps`, `TestStage7_SSEResume`, `TestSamba_WebhookAndSSE` | виконано | DECISIONS 2026-10-23 «SSE» |
| API-10 | `POST /v1/lockdown` locks:write `{state}` | 7 | `api.go:141`; `handlers.go:240`; `openapi.yaml:208` | `TestLocks_CreateListDeleteLockdown` | виконано | |
| API-11 | `GET /v1/config` admin, `***` замість секретів | 7 | `api.go:142`; `handlers.go:306`; `cmd/aldap/control.go:124`; `openapi.yaml:216` | `TestAdmin_ConfigReloadSyncTestLearn`, `TestNoSecretsInOutput_API` | виконано | Content-Type `application/toml` (не JSON) — узгоджено в OpenAPI; `headers` маскуються (DECISIONS 2026-10-25 «Secret headers») |
| API-12 | `PUT /v1/config` admin: повний TOML, валідація, атомарний запис `.tmp`+rename, reload, бекап `aldap.toml.bak.<ts>` | 7 | `api.go:143`; `handlers.go:317`; `control.go:211` `ApplyConfig`, `:261` `backup` (O_EXCL), `:297-315` tmp+fsync+rename | `TestStage7_PutConfig` (`stage7_test.go:265-308` бекап), `TestController_ApplyConfig`, `TestReadOnly_ConfigWrite` | виконано | + `?dry_run=true` (DECISIONS 2026-10-23 «Config validation over the API»); EROFS → 409 (DECISIONS 2026-10-25 «Read-only configuration») |
| API-13 | `POST /v1/reload` admin | 7 | `api.go:144`; `handlers.go:358`; `openapi.yaml:237` | `TestAdmin_ConfigReloadSyncTestLearn` | виконано | |
| API-14 | `POST /v1/profiles/{name}/sync` admin | 7 | `api.go:145`; `handlers.go:366`; `openapi.yaml:241` | `TestAdmin_ConfigReloadSyncTestLearn`, `TestStage9_Replica` | виконано | 404/409 `not_replica` (DECISIONS 2026-10-23 «Forced sync») |
| API-15 | `POST /v1/profiles/{name}/test` admin `{base, scope, filter, attrs}` → що побачить клієнт + `denied_terms`, `upstream_queries` | 7 | `api.go:146`; `handlers.go:429`; `vdir/test.go:44`; `openapi.yaml:263` | `TestAdmin_ConfigReloadSyncTestLearn`, `TestTestAndLocks` | виконано | `upstream_queries` — число (DECISIONS 2026-10-23 «OpenAPI corrections») |
| API-16 | `POST /v1/baseline/{profile}/learn` admin `{duration}` | 7 | `api.go:148`; `handlers.go:472`; `ids.go:182`; `openapi.yaml:272` | `TestAdmin_ConfigReloadSyncTestLearn` | виконано | Baseline-вікно процесне, не на профіль (DECISIONS 2026-10-23 «Endpoints before their stage») |
| API-17 | `GET /metrics` status:read / public | 7 | `api.go:131`; `handlers.go:66`; `api.go:309-318`; `openapi.yaml:133` (`x-scope`) | `TestMetrics_ScopeAndPublic` | виконано | |
| API-18 | `GET /healthz` 200 якщо живий; `/readyz` 200 якщо ≥1 upstream up для кожного proxy-профілю | 7 | `api.go:129-130`; `handlers.go:54-64`; `control.go:82` `Ready` | `TestEndpoints_StatusProfilesUpstreamsHealth`, `TestController_Views` | виконано | |
| API-19 | Автентифікація `Authorization: Bearer <token>`; IPC без токена зі scope admin | 7 | `api.go:298` `authorize`; `auth.go:75` `bearer`, `:86` `match` (constant-time) | `TestScopes_EveryRoute`, `TestIPC_NoTokenAdmin`, `TestStage7_IPCAndTCPWithoutToken` | виконано | DECISIONS 2026-10-23 «Token comparison» |
| API-20 | Усі відповіді `application/json`; помилки `{error, code}` | 7 | `api.go:395` `writeJSON`, `:406` `writeError` (`apiError{Error, Code}`) | `TestBackendError_Mapping` | частково | Винятки: `GET /v1/config` → `application/toml`, `/metrics` і `indicators?format=plain` → `text/plain` (задокументовано в OpenAPI, DECISIONS 2026-10-23 «OpenAPI corrections») |
| API-21 | Audit: кожен виклик зі scope locks:write/admin → `api_call{method, path, token_name, client_ip}` | 7 | `api.go:342` `audit` (+`status`; також для 401/403/429) | `TestAudit_APICall` (`api_test.go:307-345`), `TestStage7_ScopesAndAudit` | виконано | DECISIONS 2026-10-23 «Audit of refused calls» |
| API-22 | OpenAPI 3.1 у `docs/openapi.yaml` нормативний; код і тести звіряються | 7 | `docs/openapi.yaml`; `internal/api/openapi_test.go:77` | `TestOpenAPIRoutes` (двостороння звірка routes↔operations+scope) | виконано | |

## 8. §8 `aldapctl`

| ID | Вимога (коротко, укр.) | SPEC § | Реалізація (файл/функція) | Тест | Статус | Примітка |
|---|---|---|---|---|---|---|
| CT-01 | Підключення `--socket` (дефолт IPC) або `--url https://host:8636 --token-file` | 8 | `cmd/aldapctl/client.go:60` `newClient`, `:78` IPC, `:93` TCP (`http://` лише loopback) | `TestClient_Transport`, `TestClient_NoRedirect` | виконано | DECISIONS 2026-10-23 «aldapctl transport» |
| CT-02 | CLI `status`, `upstreams`, `profiles` | 8 | `main.go:158-160` | `TestCLI_Golden` (`cli_status.golden`, `cli_upstreams.golden`, `cli_profiles.golden`) | виконано | |
| CT-03 | `locks [--json]`, `unlock <ip|account>`, `lock <ip|account> --for 1h` | 8 | `main.go:161-163`; `cli.go:274` (`--for` обов'язковий) | `TestCLI_Golden` (locks), `TestCLI_Mutating`, `TestCLI_JSONOutput` | виконано | Підтвердження `[y/N]`/`--yes` (DECISIONS 2026-10-23 «aldapctl confirmations and exit codes») |
| CT-04 | `lockdown on|off` | 8 | `main.go:164`; `cli.go:297-301` | `TestCLI_Mutating` | виконано | |
| CT-05 | `events [--follow] [--types]` | 8 | `main.go:165`; `cli.go:368` `cmdEvents` | `TestCLI_Golden` (events), `TestContract_FollowEvents` | виконано | |
| CT-06 | `indicators` | 8 | `main.go:166`; `cli.go:424-438` (`--format table|json|stix-lite|plain`) | `TestCLI_Golden` (indicators) | виконано | |
| CT-07 | `reload` | 8 | `main.go:167` | `TestCLI_Mutating` | виконано | |
| CT-08 | `config get|set <file>` | 8 | `main.go:168-170` (+`config validate`) | `TestCLI_ConfigGetOut`, `TestCLI_Mutating` | виконано | |
| CT-09 | `test <profile> --base --filter --attrs` | 8 | `main.go:171`; `cli.go:575` `cmdTest` | `TestCLI_Golden` (test) | виконано | |
| CT-10 | `sync <profile>` | 8 | `main.go:172` | `TestCLI_Mutating` | виконано | |
| CT-11 | `baseline learn <profile> --for 24h` | 8 | `main.go:173`; `cli.go:645` | `TestCLI_Mutating` | виконано | |
| CT-12 | `record start|stop <profile>` | 8 | `main.go:174-175` | `TestStage11_AldapctlRecordReplay` | виконано | |
| CT-13 | `replay <file> --profile` | 8 | `main.go:176`; `replay.go:55` `cmdReplay`; `internal/record/compare.go` | `TestCLI_Golden` (replay), `TestStage11_AldapctlRecordReplay` | виконано | DECISIONS 2026-10-25 «Record format = replay format» |
| CT-14 | `bundle --out aldap-bundle.tgz`: конфіг без секретів, останні 10k подій, версії, health, `go version`, метрики | 8 | `bundle.go:27` (10000), `:116` `redactTOML`, `:180-219` (health, config, events, metrics), версії+`go_version` зі `/v1/status` | `TestNoSecretsInOutput_Bundle`, `TestBundle_Redact`, `TestStage10_Aldapctl` | виконано | DECISIONS 2026-10-23 «Support bundle» |
| CT-15 | `version` | 8 | `main.go:179` | `TestVersionLine_UsesLdflags` (aldapctl) | виконано | |
| CT-16 | `stop` (згаданий у §5.3) | 5.3/8 | відсутній у `commands` | немає | свідомо змінено (DECISIONS 2026-10-25 «`aldapctl stop`») | §8 команду не перелічує; зупинка через сигнал/service manager |
| TU-01 | TUI без аргументів; вкладки Status, Upstreams, Profiles, Locks, Events, Indicators, Config | 8 | `tui_keys.go:9-16` (7 вкладок); `main.go:178` `tui` | `TestTUI_Navigation` (`tui_test.go:303`), `TestRunTUI_Interactive` | виконано | |
| TU-02 | Events — live-стрім з фільтром за типом/профілем/IP, пошук, пауза | 8 | `tui.go:263` `runStream`; фільтр/пошук/пауза у `tui.go` | `TestTUI_EventsFilterPauseSearch`, `TestTUI_StreamStartsFromBacklog` | виконано | |
| TU-03 | Locks — список, `u` unlock, `l` lock | 8 | `tui_keys.go:45-46` | `TestTUI_UnlockConfirm`, `TestTUI_LockInputAndActions` | виконано | |
| TU-04 | Config — перегляд, `$EDITOR`, валідувати, застосувати | 8 | `tui.go:238` `editorCmd`; `tui_keys.go:52-54` (`e`, `v`, `a`) | `TestTUI_ConfigEditValidateApply` | виконано | |
| TU-05 | Гарячі клавіші Bubble Tea, `?` довідка | 8 | `tui_keys.go`; `tui.go:574` `globalKey` | `TestTUI_HelpListsEveryKey` | виконано | |
| TU-06 | Усі дії підтверджуються (`y/n`) | 8 | `tui.go:382` `pending`, `:541` `confirmKey`; клавіші з «(confirm)» | `TestTUI_UnlockConfirm` (`Unlock account jdoe? [y/n]`), `TestTUI_LockInputAndActions` | виконано | |
| TU-07 | Кольори lipgloss, адаптивні до теми, без 256 кольорів | 8 | `tui.go:228-229` (`NO_COLOR`, `TERM=dumb`); 16 ANSI через `AdaptiveColor` | `TestTUI_NoColor`, `TestTUI_Fits80x24` | виконано | DECISIONS 2026-10-23 «TUI design» |

## 9. §9 Безпека

| ID | Вимога (коротко, укр.) | SPEC § | Реалізація (файл/функція) | Тест | Статус | Примітка |
|---|---|---|---|---|---|---|
| SEC-01 | Процес non-root (UID 65532), read-only FS, `cap_net_bind_service` або порти >1024, seccomp `deploy/seccomp.json` | 9 | `Dockerfile` `USER 65532:65532`; `docker-compose.yml` `read_only`, `cap_drop: [ALL]`, `seccomp:./deploy/seccomp.json`; `deploy/aldap.service` `AmbientCapabilities=CAP_NET_BIND_SERVICE`; `deploy/seccomp.json` | `TestSystemdUnitInSync` | виконано | Compose покладається на `cap_drop ALL` + порти; DHI static UID 65532 |
| SEC-02 | TLS мін. 1.2, шифри Go-дефолт без RC4/3DES; серверний сертифікат ECDSA P-256 (дефолт) або RSA-2048 (`tls.key_type`), 825 днів (CA — 10 років); ключі 0600 | 9 | `tlsutil/manager.go:121-125` (CipherSuites не задаються → Go-дефолт); `ca.go:36-37` (`CAValidity`, `ServerValidity`), `:45-46,81-83`, `:297` 0600 | `TestCA_GenerateLoad` (`tlsutil_test.go:81-86,153`), `TestParseKeyType_Cases` | виконано | |
| SEC-03 | client_bind у пам'яті як argon2id (t=3, m=64MiB, p=4), constant-time; `password_hash = "$argon2id$..."` як альтернатива | 9 | `profile/argon2.go:24` `DefaultArgon2{3, 64*1024, 4}`, `:89` `Verify`; `config.go:318` `password_hash`; `validate.go:649-657` | `TestArgon2_PHC`, `TestClientBind` | виконано | |
| SEC-04 | Паролі user bind — `[]byte`, обнуляються; не потрапляють у рядки логів/подій/panic traces (recover редагує) | 9 | `listener/conn.go:536` `wipe`, `:507` `handleBind`; `:355` recover друкує тип; `upstream/bindreason.go:56` `Error()` без пароля | `TestPanicRecovery`, `TestNoSecretsInOutput_Daemon`, `TestNoSecretsInOutput_Upstream` | виконано | go-ldap потребує `string` до GC — DECISIONS 2026-10-18 «Password memory» |
| SEC-05 | BER: ліміт `max_request_bytes`; відмова на вкладеність >64; fuzz фільтрів і DN | 9 | `listener/message.go:52` `readMessage`; `FuzzParseFilter`, `FuzzParseDN` (`ldapfilter/fuzz_test.go`), `FuzzParseMessage` (`listener/fuzz_test.go`); `make fuzz` | `TestProtocol_Edges/oversize`, fuzz-таргети | частково | Явного ліміту глибини BER (64) у `parseMessage`/`go-asn1-ber` немає; глибина обмежується лише для фільтрів (`max_filter_depth=20`) і загальним розміром пакета |
| SEC-06 | DoS: ліміти з'єднань на IP/глобально, idle timeout, read deadline на перший пакет 5s, ліміт одночасних пошуків на з'єднання 4 | 9 | `listener.go:29` `defaultFirstPacket=5s`, `:549/586` лімітери; `conn.go:362-366` deadlines; запити з'єднання обробляються послідовно (`conn.go:352` `serve`) | `TestTimeouts/first-packet`, `TestTimeouts/idle`, `TestLimits` | свідомо змінено (DECISIONS 2026-10-18 «Request concurrency») | Замість ліміту 4 паралельних пошуків — суворо послідовна обробка, Abandon ігнорується |
| SEC-07 | Негативні відповіді не розкривають існування акаунта/атрибута/бази (один код, вирівняний час) | 9 | `bind.go` → `invalidCredentials` для всіх причин; `directory.go:357` `noSuchObject`; denied terms → FALSE; `ratelimit.go:752` | `TestBind_Fixture`, `TestDaemon_Ldapsearch` (denied attribute/term без помилки), `TestPolicy_ConstantTimeAndDisabled` | виконано | |
| SEC-08 | Конфіг: невідомі ключі — помилка | 9 | як B-07 | `TestLoad_Errors` | виконано | |
| SEC-09 | `tls_insecure_skip_verify`, `transport=ldap` без TLS, inline-паролі → WARN при старті + `insecure_config` | 9 | WARN при старті: `cmd/aldap/daemon.go:214-215` логує всі попередження валідатора; подія `insecure_config`: лише `tls_insecure_skip_verify` і `ldap://` upstream без StartTLS (`upstream.go:148-165`), `service_account_admin`, `client_ip_masked` | `TestHealth_KindsAndEvents`, `TestValidate_Rules/*_warn` | частково | Для `profile.transport=ldap` (клієнтська сторона) та inline-паролів емітується лише WARN, події `insecure_config{what=…}` немає |
| SEC-10 | `govulncheck` у CI; `go.sum` закріплений; `-trimpath -buildvcs=false`; `CGO_ENABLED=0` | 9 | `.github/workflows/ci.yml:35` `make vuln`; `Makefile:8-9` `GOFLAGS`, `CGO_ENABLED=0` у `build`; `Dockerfile` `GOFLAGS=-trimpath`, `-buildvcs=false`, `CGO_ENABLED=0` | немає (CI) | виконано | Тести з `CGO_ENABLED=1` (`-race`) — DECISIONS 2026-10-18 «CGO in Makefile» |
| SEC-11 | SBOM (CycloneDX) і підпис образу/бінарників (`cosign`) у release-пайплайні | 9 | `.github/workflows/release.yml:80-85` (anchore/sbom-action cyclonedx), `:134-170` (cosign keyless для образу та `SHA256SUMS`); `build.sh:51-83` `sbom`/`sign` | немає (CI) | виконано | DECISIONS 2026-10-26 «Release workflow», «build.sh signs after push» |

## 10. §10 Збірка та розгортання

| ID | Вимога (коротко, укр.) | SPEC § | Реалізація (файл/функція) | Тест | Статус | Примітка |
|---|---|---|---|---|---|---|
| BD-01 | `make build` → `dist/aldap_<os>_<arch>`, `dist/aldapctl_<os>_<arch>` для linux/amd64, linux/arm64, windows/amd64 | 10.1 | `Makefile:14` `PLATFORMS`, `:36-45` `build` | `.github/workflows/ci.yml:62` `make build`; `TestVersionLine_UsesLdflags` | виконано | |
| BD-02 | `-ldflags "-s -w -X main.version -X main.commit -X main.date"` | 10.1 | `Makefile:8` `LDFLAGS`; `Dockerfile` `go build -ldflags …` | `TestVersionLine_UsesLdflags` (`cmd/aldap/main_test.go:41`, `cmd/aldapctl/main_test.go:9`) | виконано | |
| DK-01 | Multi-stage: build `dhi.io/golang:<GO_MINOR>-debian13-dev` (ARG `DHI_GOLANG_TAG`), `CGO_ENABLED=0` | 10.2 | `Dockerfile:7-21` | `TestDHITagsPinned` (`cmd/aldap/release_test.go:30`) | виконано | Теги закріплені: DECISIONS 2026-10-26 «DHI tags» |
| DK-02 | Runtime `dhi.io/static:<DHI_STATIC_TAG>`, non-root, `COPY --chown=65532:65532`, `HEALTHCHECK` через `aldap check --quick`, `VOLUME /etc/aldap /var/lib/aldap`, без `EXPOSE` | 10.2 | `Dockerfile:46-63` (`USER 65532`, `VOLUME [... /run/aldap]`, `HEALTHCHECK … check --quick`); `EXPOSE` відсутній | `TestDHITagsPinned` | виконано | HEALTHCHECK — офлайн-перевірка конфігу (LIMITATION DECISIONS 2026-10-18 «aldap check --quick as container HEALTHCHECK») |
| DK-03 | `build.sh --dhi` вимагає `docker login dhi.io`; `--plain` golang-alpine + scratch; `--windows`, `--linux`, `--all` | 10.2 | `build.sh:3-9,96-101` (підказка при невдалому pull), `:153-158` | `TestDHITagsPinned`; CI `docker-plain` (`ci.yml:72`), `docker-dhi` (`ci.yml:97-111`) | виконано | + `--podman` (DECISIONS 2026-10-25 «Rootless Podman») |
| DK-04 | Теги DHI як змінні `DHI_GOLANG_TAG`, `DHI_STATIC_TAG` з підказкою при невдачі pull | 10.2 | `build.sh:25-26,97-101` | `TestDHITagsPinned` | виконано | |
| CP-01 | compose: сервіс `aldap`, `read_only`, `tmpfs /tmp`, `cap_drop [ALL]`, `no-new-privileges`, `secrets`, volume для toml і CA, `healthcheck` | 10.3 | `docker-compose.yml:4-56` | немає | виконано | |
| CP-02 | Приклад з двома профілями | 10.3 | `docker-compose.yml:19-21` (порти `virola` 636, `honeypot` 1389) + `aldap.toml.example` | `TestLoad_Example`, `TestRunCheck_Example` | виконано | |
| CP-03 | Опційно сервіс `samba-dc` для локального тестування | 10.3 | `deploy/samba-dc/compose.yml`, `deploy/quickstart/compose.bench.yml` (окремі файли, не в кореневому compose) | `make integration-samba`, `TestSamba_*` | виконано | Реалізовано як окремий compose-стек (DECISIONS 2026-10-26 «Samba AD bench») |
| SD-01 | `DynamicUser=yes` | 10.4 | `deploy/aldap.service:15` | `TestSystemdUnitInSync` (явно) | виконано | |
| SD-02 | `LoadCredential=ad_pass:/etc/aldap/secrets/ad_pass` → `bind_password_file=${CREDENTIALS_DIRECTORY}/ad_pass` | 10.4 | `aldap.service:18` (+ `virola_bind`, `api_admin`) | `TestSystemdUnitInSync` (порівняння з шаблоном) | виконано | |
| SD-03 | `AmbientCapabilities=CAP_NET_BIND_SERVICE` | 10.4 | `aldap.service:44` | те саме | виконано | |
| SD-04 | `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes` | 10.4 | `aldap.service:28-30` | те саме | виконано | |
| SD-05 | `NoNewPrivileges=yes` | 10.4 | `aldap.service:43` | `TestSystemdUnitInSync` (явно) | виконано | |
| SD-06 | `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` | 10.4 | `aldap.service:46` | порівняння з шаблоном | виконано | |
| SD-07 | `SystemCallFilter=@system-service` | 10.4 | `aldap.service:53-54` | порівняння з шаблоном | виконано | |
| SD-08 | `RuntimeDirectory=aldap` (сокет), `StateDirectory=aldap` | 10.4 | `aldap.service:24,26` | порівняння з шаблоном | виконано | |
| SD-09 | `Restart=on-failure`, `ExecReload=/bin/kill -HUP $MAINPID` | 10.4 | `aldap.service:10-11` | `TestSystemdUnitInSync` (ExecReload явно) | виконано | `Type=notify` + sd_notify READY (DECISIONS 2026-10-25 «sd_notify», `TestSDNotify`) |
| WN-01 | `aldap.exe service install --config …` через `kardianos/service` | 10.5 | `cmd/aldap/service.go:62` `serviceConfig`, `:97` `runService` | `TestRunService_Actions`, `TestServiceConfig_Platforms`, `TestServiceRun` | виконано | DECISIONS 2026-10-25 «aldap service» |
| WN-02 | Лог у Event Log + файл | 10.5 | `cmd/aldap/syslog.go:10` `systemLogger`/`teeHandler`; `service.go:87` `defaultLogFile`, `:197` `serviceRun` | `TestSystemLog_WarningsAndErrors` | виконано | |
| WN-03 | IPC — named pipe з ACL «Administrators + SYSTEM» | 10.5 | `internal/api/ipc_windows.go:19` `pipeSDDL = D:P(A;;GA;;;SY)(A;;GA;;;BA)`, `:31` `winio.ListenPipe` | `TestListenIPC_Pipe` (windows-only), `make windows-ctl` (компіляція) | виконано | Не запускається в CI (LIMITATION, `docs/limitations.md`) |
| WN-04 | Не тестується у CI; best effort; ручний чекліст `docs/windows.md` | 10.5 | `docs/windows.md` (чекліст ACL, Event Log, service) | `make windows-ctl` у lint job | виконано | DECISIONS 2026-10-23 «aldapctl for Windows in CI» |

## 11. §11 Метрики

Реєстрація: `internal/metrics/metrics.go:46-71` (`New`). Тест експозиції всіх метрик: `TestMetrics_Exposition` (`metrics_test.go:12`).

| ID | Вимога (коротко, укр.) | SPEC § | Реалізація (файл/функція) | Тест | Статус | Примітка |
|---|---|---|---|---|---|---|
| M-01 | `connections_active{profile}` | 11 | reg `metrics.go:49`; спостереження `listener/listener.go:414,422` `Connection` | `TestMetrics_Exposition` | виконано | labels ✓ |
| M-02 | `binds_total{profile,result}` | 11 | reg `:50`; `vdir/bind.go:40,58,60` `Bind` (ok/fail/blocked) | те саме | виконано | |
| M-03 | `bind_duration_seconds{profile}` | 11 | reg `:51`; `vdir/bind.go` через `Bind` | те саме | виконано | |
| M-04 | `searches_total{profile,cache}` | 11 | reg `:52`; `vdir/directory.go:983` `Search` | те саме | виконано | Значення `cache`: replica/stale/hit/miss/local/none (DECISIONS 2026-10-23 «searches_total cache label») |
| M-05 | `search_results{profile}` histogram | 11 | reg `:53`; `directory.go:983` | те саме | виконано | |
| M-06 | `upstream_queries_total{upstream,server,op,result}` | 11 | reg `:55`; `upstream/upstream.go:256,263,267` `Upstream` | те саме | виконано | |
| M-07 | `upstream_latency_seconds{upstream,server,op}` | 11 | reg `:56`; `upstream.go` через `Upstream` | те саме | виконано | |
| M-08 | `upstream_up{upstream,server}` | 11 | reg `:57`; `upstream.go:287` `SetUpstreamUp` | те саме | виконано | |
| M-09 | `locks_active{target}` | 11 | reg `:58`; `ratelimit.go:470` `SetLocks` (у `Sweep`, періодично з `daemon.go:632`) | те саме | виконано | |
| M-10 | `attack_active{kind}` | 11 | reg `:59`; `ids.go:441,528` `SetAttack` | те саме | виконано | |
| M-11 | `events_total{event}` | 11 | reg `:60`; `events/bus.go:159` `Event` | те саме | виконано | |
| M-12 | `events_dropped_total{sink}` | 11 | reg `:61`; `bus.go:460` `Dropped`; `notify.go:189` (`sink=notify`) | те саме, `TestBus_Overflow` | виконано | |
| M-13 | `notify_total{channel,result}` | 11 | reg `:62`; `notify.go:256,261,324,331,532,536` | те саме | виконано | |
| M-14 | `cache_entries{profile}` | 11 | reg `:63`; `cmd/aldap/cache.go:95,98` `SetCache` | те саме (`SetCache` не викликається у тесті метрик, але викликається в `TestCacheSet_Fingerprint`) | виконано | |
| M-15 | `replica_age_seconds{profile}` | 11 | reg `:64`; `cmd/aldap/cache.go:98` | `TestCacheSet_Fingerprint` | виконано | |
| M-16 | `profile_cost{profile}` histogram upstream_queries на запит | 11 | reg `:54`; `directory.go:983` `Search(..., sc.queries)` | `TestMetrics_Exposition` | виконано | |
| M-17 | `cert_expiry_seconds{listener}` | 11 | reg `:65`; `tlsutil/manager.go:261` `SetCertExpiry(m.o.Profile, …)` | те саме | виконано | Мітка `listener` = ім'я профілю |
| M-18 | `build_info` | 11 | reg `:66-67` (labels version, commit, date) | те саме | виконано | |
| M-19 | Текстовий лог демона — про роботу процесу, `log_format=json` | 11 | `cmd/aldap/daemon.go:184-200` (slog text/json) | `TestDaemon_BuildErrors`/`TestNoSecretsInOutput_Daemon` (логи) | виконано | |

## 12. §12 Сумісність з клієнтами

| ID | Вимога (коротко, укр.) | SPEC § | Реалізація (файл/функція) | Тест | Статус | Примітка |
|---|---|---|---|---|---|---|
| CL-01 | `ldapsearch` з `-x`, `-ZZ`, `ldaps://`, `-E pr=100/noprompt` | 12 | — (інтеграційний) | `TestDaemon_Ldapsearch` (`cmd/aldap/daemon_test.go:305-356`: `-x`, `ldaps://`, `-ZZ`, `-E pr=5/noprompt`); CI встановлює `ldap-utils` | виконано | Розмір сторінки 5 замість 100 (функціонально те саме) |
| CL-02 | Python `ldap3` (simple bind, paged search, `memberOf`) | 12 | `testdata/ldap3_test.py` | `TestDaemon_Ldap3` (`stage5_test.go:272`; CI `pip install ldap3`) | виконано | DECISIONS 2026-10-18 «Python ldap3 compatibility test» |
| CL-03 | Go `go-ldap` як клієнт | 12 | — | `TestDaemon_Virola`, `TestDaemon_TLSTermination` (`SearchWithPaging`), усі listener-тести | виконано | |
| CL-04 | Virola — ручний чекліст `docs/virola.md`: Base DN, `userPrincipalName`, сервісний акаунт = `client_bind.dn`, порт 636 + свій CA | 12 | `docs/virola.md` (§«Virola client checklist»), `deploy/virola-stack/` | `TestStage12b_VirolaAllowCIDRs` (stand-in клієнт) | частково | Не перевірено на реальній Virola (LIMITATION DECISIONS 2026-10-26 «Virola: own CA»; `docs/limitations.md`) |
| CL-05 | `objectClass=*` по `virtual_base` scope sub → `ou=users`, `ou=groups`, усі користувачі, усі групи | 12 | `directory.go:418` `containerEntries` | `TestSearch_Users` (`vdir_test.go:236`), `TestSearch_Static` | виконано | |

## 13. §13 Критерії приймання

| ID | Вимога (коротко, укр.) | SPEC § | Реалізація (файл/функція) | Тест | Статус | Примітка |
|---|---|---|---|---|---|---|
| AC-01 | `make ci` (lint, vet, vuln, licenses, unit, integration-inmem) зелений | 13.1 | `Makefile:123` `ci: lint vet vuln licenses windows-ctl test integration shellcheck`; `.github/workflows/ci.yml` jobs lint/test/build/docker-plain | CI на push/PR | виконано | Не запускалось під час аудиту (лише `go test -cover` 6 пакетів — зелено) |
| AC-02 | `make integration-samba` проти Samba AD DC: злиття bases, виключення computer, bind UPN/sAM, група member/memberOf, nested, paged, failover, lock після 3, негативний кеш, honeytoken, recon, webhook HMAC, SSE | 13.2 | `Makefile` `integration-samba`; `deploy/samba-dc/`; `.github/workflows/samba.yml` (nightly 03:41, PR на зміни bench) | `TestSamba_VirolaDirectory` (bases, computers, група, nested, paged), `TestSamba_UserBind`, `TestSamba_AccountLock` (lock 3, negative cache), `TestSamba_ReconAndHoneytoken`, `TestSamba_Failover`, `TestSamba_WebhookAndSSE`, `TestSamba_ProxyProtocol`, `TestSamba_CheckOnline` | виконано | Два незалежні DC, не репліки (LIMITATION DECISIONS 2026-10-26 «Samba bench: two independent DCs») |
| AC-03 | `aldap check --online` на тестовому стенді без помилок | 13.3 | `cmd/aldap/check.go` | `TestSamba_CheckOnline`, `TestRunCheck_Online` | виконано | |
| AC-04 | `docker build` з DHI проходить (у CI з секретом логіну або `--plain` fallback з явним повідомленням) | 13.4 | `.github/workflows/ci.yml:70-72` (`docker-plain`), `:97-111` (`docker-dhi` з `DHI_USERNAME/DHI_TOKEN`, інакше `::warning::`) | CI | виконано | Локально DHI недоступний (CLOSED DECISIONS 2026-10-26 «Local Docker build») |
| AC-05 | `aldapctl` TUI запускається, показує статус/locks/events, unlock працює | 13.5 | `cmd/aldapctl/tui*.go` | `TestRunTUI_Interactive`, `TestTUI_Navigation`, `TestTUI_UnlockConfirm`, `TestStage10_Aldapctl` | виконано | |
| AC-06 | Покриття unit ≥80% для `ldapfilter`, `vdir`, `ratelimit`, `ids`, `config`, `events` | 13.6 | Виміряно під час аудиту: ldapfilter 99.0%, vdir 95.0%, ratelimit 96.5%, ids 95.9%, config 90.7%, events 90.2% | `Makefile:64` — gate лише на загальне покриття `COVER_MIN=80` | частково | Фактичні значення вище порогів (також вище порогів TESTING.md 85–90%), але автоматичний gate у CI перевіряє тільки сукупне покриття, а не кожен пакет окремо |
| AC-07 | `docs/`: README (compose за 5 хвилин), `config.md` (усі ключі), `events.md`, `api.md` (з OpenAPI), `virola.md`, `windows.md`, `security.md`, `THIRD_PARTY_LICENSES.md` | 13.7 | `README.md` («Docker Compose (about 5 minutes)»), `docs/config.md` (генерується `RenderDocs`), `docs/events.md`, `docs/api.md`, `docs/openapi.yaml`, `docs/virola.md`, `docs/windows.md`, `docs/security.md`, `THIRD_PARTY_LICENSES.md` | `TestConfigDocsInSync`, `TestOpenAPIRoutes`; CI `git diff --exit-code THIRD_PARTY_LICENSES.md` | виконано | |
| AC-08 | Жоден тест/лог/подія не містить паролів (grep-тест по артефактах CI) | 13.8 | `TestNoSecretsInOutput_*` (8 тестів у config, api, notify, upstream, cmd/aldap, cmd/aldapctl); `.github/workflows/ci.yml:50` окремий прогін `-run TestNoSecretsInOutput -tags integration` | те саме | частково | Grep саме по артефактах CI (`artifacts/*.json`) не робиться; перевірка — у тестах над захопленими логами/подіями |

## 14. §14 Відкриті питання (статус за `docs/limitations.md`)

| ID | Вимога (коротко, укр.) | SPEC § | Реалізація (файл/функція) | Тест | Статус | Примітка |
|---|---|---|---|---|---|---|
| OQ-01 | Чи приймає Virola власний CA / перемикач перевірки | 14 | `docs/virola.md` додає `ca.crt` у довіру (власне налаштування або OS store контейнера), заборона вимикати перевірку | немає | свідомо змінено (DECISIONS 2026-10-26 «Virola: own CA») | LIMITATION: не перевірено на реальній інсталяції; `docs/limitations.md` «Not verified on real systems» |
| OQ-02 | Точні теги DHI (`golang`, `static`) | 14 | `Dockerfile:9-10`, `build.sh:25-26`: `1.26.10-debian13-dev`, `20250419-debian13` | `TestDHITagsPinned` | виконано | DECISIONS 2026-10-26 «DHI tags» (закрито) |
| OQ-03 | Формат cookie paged results, який очікує Virola | 14 | Стандартний opaque cookie (`directory.go:873`) | `TestSearch_Paging`, `TestDaemon_Ldapsearch` | свідомо змінено (DECISIONS 2026-10-26 «Release: open items») | LIMITATION: припущення не перевірено з Virola (`docs/limitations.md`) |
| OQ-04 | `kardianos/service` на Windows Server 2012 R2 | 14 | `cmd/aldap/service.go` | `TestServiceConfig_Platforms` (без запуску на Windows) | свідомо змінено (DECISIONS 2026-10-25 «aldap service») | LIMITATION у `docs/limitations.md` «Windows»: не тестовано |

---

## Підсумок

Кількість рядків за статусами (усього 373):

| Статус | Кількість |
|---|---|
| виконано | 351 |
| частково | 14 |
| не виконано | 0 |
| свідомо змінено (з посиланням на DECISIONS) | 8 |

Рядки `частково`: D-10, K-I9, V-06, HT-02, GR-01, ET-02, ET-13, ET-22, API-20, SEC-05, SEC-09, CL-04, AC-06, AC-08.

Рядки `не виконано`: немає.

Рядки `свідомо змінено`: K-P2, K-N4, VG-05, CT-16, SEC-06, OQ-01, OQ-03, OQ-04, а також обґрунтовані DECISIONS відхилення, відзначені у примітках виконаних рядків (N-01 compare→compareFalse, K-U11 unknown→up без події, VS-04 memberOf завжди віртуальний, VB-05 без re-bind, API-16 baseline процесний, HT-03 honeypot semantics, DK-02 HEALTHCHECK офлайн).

Що саме бракує у «частково»:
- **D-10** — `prometheus/client_model` і прямий `golang.org/x/crypto` у `go.mod` без рядка DECISIONS (ліцензії допустимі).
- **K-I9** — рівень `low` для атак не присвоюється (лише medium/high).
- **V-06** — немає тесту на попередження «certificate does not cover listen host».
- **HT-02** — ключ `ids.honeytoken.lock_duration` замість `honeytoken_lock` без запису в DECISIONS.
- **GR-01** — `aldapctl stop` відсутній (LIMITATION задокументована), SIGTERM-шлях повний.
- **ET-02** — `bind_fail` без `failures`.
- **ET-13** — `rate_limited` без `rps`.
- **ET-22** — `shutdown` без `profiles[]`.
- **API-20** — не всі відповіді `application/json` (`/v1/config` TOML, `/metrics`, `indicators?format=plain` — задокументовано).
- **SEC-05** — немає явної відмови на вкладеність BER > 64.
- **SEC-09** — `insecure_config` не емітується для `profile.transport=ldap` та inline-паролів (лише WARN).
- **CL-04** — Virola не перевірено на реальній інсталяції.
- **AC-06** — покриття фактично ≥90% у всіх шести пакетах, але CI-gate перевіряє лише сукупний поріг.
- **AC-08** — перевірка «без паролів» — тестами над захопленим виводом, а не grep по артефактах CI.

## Зайве в коді (є в коді/доках, немає у SPEC)

| Елемент | Де | Обґрунтування |
|---|---|---|
| Ключі `tls.auto_init`, `tls.key_type` | `config.go:45,51` | SPEC §3.4 згадує `auto_init` у описі `ca_dir`; `key_type` — §9; DECISIONS 2026-10-18 «client_bind.password_hash and tls.key_type» |
| Ключ `profile.*.client_bind.password_hash` | `config.go:318` | §9; DECISIONS 2026-10-18 (там само) |
| Ключ `upstream.*.failover.strategy` | `config.go:90` | §5.2 згадує `strategy=roundrobin` |
| Ключі `profile.*.limits.upstream_parallel`, `nested_depth`, `honeytoken_in_groups`, `honeytoken_template`, `cache.ttl/max_entries/stale_while_down/stale_max/sync_interval/sync_jitter`, `mock.file` | `config.go` | Згадані в тексті SPEC §3.4/§4.2/§4.5/§5.1 поза таблицями ключів |
| Ключі `profile.*.shadow.max_parallel`, `shadow.timeout`, `record.max_size_mb`, `record.max_files` | `config.go:429-430,440-441` | DECISIONS 2026-10-25 «Shadow execution», «Recording file» |
| Ключі `profile.*.proxy_protocol.{enabled,trusted_cidrs}`; `listen = "systemd:<name>"` | `config.go:238,274-275,270` | DECISIONS 2026-10-26 «PROXY protocol», «Socket activation» (рішення власника) |
| Секція `[ids.client_ip_masked]` (6 ключів) та `insecure_config{what=client_ip_masked}` | `config.go:171,181-186`; `ids/masked.go` | DECISIONS 2026-10-25 «Masked client addresses», 2026-10-26 «Known sources and client_ip_masked» |
| Ключі `events.webhook[].name`, `headers_file`, `hmac_secret_env`, `retry.max_backoff`; `notify.channel[].headers_file`, `*_env` форми | `config.go:483-497,562-566` | DECISIONS 2026-10-25 «Secret headers»; `_env` — загальна форма секретів §3.2 |
| Ключі `events.file.enabled`, `events.syslog.enabled`, `events.stdout.enabled` | `config.go:460-475` | Прапорці ввімкнення sink'ів (SPEC згадує `enabled` лише для stdout) |
| Ключ `api.metrics.listen` | `config.go:633` | SPEC §3.4 згадує |
| Подія `api_call` | `api.go:342`, схема | SPEC §7 (не в таблиці §6) |
| Поля подій `search.result_code/honeytoken`, `bind_fail.data.{bind_kind, form, ad_data}`, `lock.data.reason`, `unlock.source=tui`, `shadow_diff.{added_count,…}`, `api_call.status`, `rate_limited.{op, reason, limit}` | відповідні емітери | Розширення; схема дозволяє додаткові поля `data` |
| Ендпоінт `POST /v1/profiles/{name}/record`; `PUT /v1/config?dry_run=true` | `api.go:147`; `handlers.go:317` | DECISIONS 2026-10-23 «aldapctl record», 2026-10-25 «Recorder»; «Config validation over the API» |
| CLI `config validate`, `tui`, `help`; `aldap service start/stop/restart/status/run` | `cmd/aldapctl/main.go:170,178-180`; `cmd/aldap/service.go:137-141` | DECISIONS 2026-10-23 «Config validation over the API», 2026-10-25 «aldap service» |
| Метрика `aldap_events_dropped_total{sink="notify"}` | `notify.go:189` | DECISIONS 2026-10-23 «Notifier is process-wide and never blocks the bus» |
| `build.sh --podman`, `deploy/podman/*`, `deploy/quickstart/`, `deploy/virola-stack/` | репозиторій | DECISIONS 2026-10-25 «Rootless Podman», 2026-10-26 «Quick starts» |
| Залежності `go-hclog`, `client_model`, прямий `x/crypto` | `go.mod` | див. D-10 |

---

## Додаток: 49 сценаріїв TESTING.md та sync-тести документації

Репо: `github.com/alstdev/aldap`, worktree чистий після аудиту (`git status` порожній). Кожен тест відкрито і перевірено, що саме він assert-ить.
Теги: **unit** = без тегу; **int** = `//go:build integration`; **samba** = `//go:build integration_samba`.
Файли: `A/` = `cmd/aldap/`, `<pkg>/` = `internal/<pkg>/`.

### Сценарії TESTING.md (1–49) — покриття 49 обов'язкових сценаріїв

| № | Сценарій (коротко) | Тест(и) (функція, файл, tag) | Статус | Що не покрито | Samba-тест (`A/samba_test.go`, samba) |
|---|---|---|---|---|---|
| 1 | Search virtual_base sub → ou=users/ou=groups, користувачі з 2 bases, групи, 0 computer | `TestDaemon_Virola` A/stage5_test.go int (3+20+2 entries, 20 users, 2 groups, 0 objectClass computer/user); `TestSearch_Users` vdir/vdir_test.go unit | повністю | — | `TestSamba_VirolaDirectory` (DN ou=users/ou=groups/virola-users, 17 uid, `(objectClass=computer)`/`PC-OFFICE-01$` → 0) |
| 2 | `(sAMAccountName=jdoe)` → 1 запис, DN переписано, лише `attrs.allow`, `uid`←sAMAccountName | `TestSearch_Users` vdir unit (uid/cn/mail, forbidden attrs=nil, DN `cn=alice.adams,ou=users,…`); `TestDaemon_TLSTermination` A/daemon_test.go unit-tag (in-memory DC) | повністю | — | `TestSamba_VirolaDirectory` (`(uid=alice.adams)`, DN, UPN/cn/department, заборонені атрибути відсутні) |
| 3 | Атрибут поза allow → 0, success, `search{denied_terms}`, `recon` якщо сигнатура | `TestSearch_Users` vdir unit (Code 0, 0 entries, `denied_terms=[telephoneNumber]`, `upstream_queries=0`, upstream не викликано); `TestDaemon_TLSTermination`, `TestDaemon_Ldapsearch` | частково | подія `recon` для denied-терму не перевіряється жодним тестом (у `ids.Signatures` немає сигнатури «denied attr») | немає |
| 4 | Disabled не повертається; клієнтський `(userAccountControl:…803:=2)` → 0 | `TestSearch_Users` vdir unit (carol відсутня, lookup carol → 0); `TestDaemon_Virola` int (bind carol → invalidCredentials); `TestEntryMatches` vdir/match_test.go unit (лише matcher) | частково | in-memory немає end-to-end search з `(userAccountControl:1.2.840.113556.1.4.803:=2)` від клієнта (тільки unit matcher) | `TestSamba_VirolaDirectory` (цей фільтр → 0, `(uid=heidi.hill)` → 0) — повністю |
| 5 | Колізія RDN між bases → обидва з суфіксом, WARN | `TestSearch_RDNCollision` vdir unit (DN `cn=it+objectguid=…`, унікальний без суфікса); `TestReplica_RDNCollisionStable` vdir/stage9_test.go unit | частково | WARN-лог `virtual RDN collision` (directory.go:688) не assert-иться; колізія моделюється через `rdn_attr=department` в одному base, не між двома bases | немає |
| 6 | Computed `mail`, mask телефону, фільтр по computed через пост-фільтрацію | `TestTransform_ComputedMaskObjectClass` vdir/stage5_test.go unit (`n***@corp.local`, `***4567`, masked не матчить); `TestDaemon_Virola` int (`(mail=alice.adams@test.aldap)` → 1) | повністю | — | `TestSamba_VirolaDirectory` (computed mail frank.fox); mask/фільтр по computed — немає |
| 7 | `virola-users` member з обох bases; `(memberOf=…)` ті самі; nested Directors∈Staff | `TestDaemon_Virola` int (20 member, memberOf 20, staff містить alice з Directors); `TestGroups_Virola` vdir/stage5_test.go unit (nested 16 vs direct 10) | повністю | — | `TestSamba_VirolaDirectory` (member=9, memberOf той самий, eve.evans Directors⊂Managers⊂Staff) — повністю |
| 8 | Paged 10 → 3 сторінки, cookie, порожній у кінці; чужий cookie → unwillingToPerform | `TestSearch_Paging` vdir unit (8/8/3, 2-а сторінка з пам'яті, порожній cookie, finished/bogus/evicted cookie → unwilling); `TestDaemon_Virola`, `TestDaemon_Ldapsearch` | частково | cookie **іншого з'єднання** явно не перевіряється (усі сторінки через той самий `listener.Conn`; є лише bogus/finished/evicted) | `TestSamba_VirolaDirectory` (17 у сторінках по 5 → 4 сторінки) |
| 9 | sizeLimit клієнта < результат → `sizeLimitExceeded` + часткові дані | `TestSearch_Limits` vdir unit (SizeLimit 3 → code 4, 3 entries; max_result_size; static) | повністю | — | немає |
| 10 | Add/Modify/Delete/ModDN/Compare/Extended(passwd) → відмова + `op_denied` | `TestDenied_Operations` listener/listener_test.go unit (усі 6 op, код, подія з `op`/`oid`, level medium); `TestDaemon_TLSTermination` (add, compare) | повністю | — (Compare → `compareFalse` за SPEC) | немає |
| 11 | Client bind вірний/невірний; anonymous → відмова | `TestBind_Fixture` vdir unit (client ok, wrong → invalid_password, 3 anonymous-варіанти → invalidCredentials/reason anonymous); `TestDaemon_Ldapsearch` | повністю | — | `TestSamba_*` (client bind ok у `client()`); невірний/anonymous — немає |
| 12 | 4 форми user bind → успіх; невірний → `invalidCredentials`, `reason=invalid_password` | `TestBind_Fixture` vdir unit (UPN, `TEST\`, sAM, virtual DN, wrong → reason, `ad_data=52e`, `form=upn`); `TestDaemon_TLSTermination` (4 форми end-to-end) | повністю | — | `TestSamba_UserBind` — повністю |
| 13 | Disabled/locked/must_change → клієнту invalidCredentials, в події справжній reason; `locked_in_ad` medium | `TestBind_Fixture` vdir unit (disabled/low, locked_in_ad/**medium**); `TestIntegration_UserBindReasons` upstream/integration_test.go int (533/775/773 → reasons) | частково | `must_change` перевіряється лише на рівні `upstream` (BindError), не на рівні vdir/клієнта (код + подія) | `TestSamba_UserBind` (disabled → invalidCredentials + `reason=disabled`); locked/must_change — немає |
| 14 | `require_membership`: не у фільтрі → відмова | `TestBind_Policies` vdir unit (dan.davis 3 форми → fail, reason not_member/unknown_account) | повністю | — | `TestSamba_UserBind` (outside.user → invalidCredentials + bind_fail) |
| 15 | Constant-time: 100 невдалих bind, медіани <10%, `-short` skip | `TestPolicy_ConstantTimeAndDisabled` ratelimit unit — лише детермінований розрахунок pad/delay | немає | немає статистичного тесту (100 bind, медіани, `testing.Short()` — жодного входження в репо) | немає |
| 16 | ldaps клієнт → upstream plain: працює + WARN `insecure_config{plaintext_upstream}` | `TestDaemon_TLSTermination` A/daemon_test.go (`"event":"insecure_config"`, `"what":"plaintext_upstream"`, `"level":"WARN"`) | повністю | — | n/a (Samba ldaps) |
| 17 | `ldap`+`starttls_required`, bind без StartTLS → `confidentialityRequired` | `TestDaemon_TLSTermination` (plain profile); `TestStartTLS_Flows` listener unit (bind і search → code 13, після StartTLS ok) | повністю | — | немає |
| 18 | Upstream ldaps з невірним CA → down, `/readyz` 503; `tls_insecure_skip_verify` → працює + `insecure_config` | `TestIntegration_TLS` upstream int (`ldaps_untrusted` → ErrUnavailable/tls; `ldaps_insecure_skip_verify` → ok + 1 insecure_config); `TestEndpoints_StatusProfilesUpstreamsHealth` api unit (`/readyz` 503 `not_ready` з фейковим backend) | частково | немає end-to-end: невірний CA у конфігу → всі сервери down → `/readyz` 503 на живому демоні | немає |
| 19 | mTLS `client_auth=require` → без сертифіката відхилено | `TestManager_ClientAuth` tlsutil unit (handshake через net.Pipe без cert → fail, з cert → ok; `request` без cert → ok) | частково | лише `tls.Config` рівня tlsutil; немає тесту listener/daemon, де з'єднання без client cert реально відхиляється | немає |
| 20 | Два upstream; стоп першого → `upstream_down`, запити на другий; підняти → назад (`prefer_primary`) | `TestIntegration_FailoverAndReturnToPrimary` upstream int (Server==dc2, 3 запити на dc2, `upstream_up`, назад dc1, all-down → ErrUnavailable) | повністю | — | `TestSamba_Failover` (docker stop/start dc1; skip без 2 серверів + COMPOSE) — повністю |
| 21 | `ttl`: другий запит не ходить в upstream; після TTL — ходить | `TestStage9_TTL` A/stage9_test.go int (лічильник searches, `cache_hit=true`, `upstream_queries=0`, інший запит → upstream, після TTL → upstream); `TestTTL_SecondSearchFromCache` vdir unit | повністю | — | немає (`cache.mode="none"`) |
| 22 | Усі down + `stale_while_down` → `stale_served`; без → `unavailable` | `TestStage9_StaleWhileDown` int (обидва варіанти, level medium, entries=1, schema check) | повністю | — | немає |
| 23 | `replica`: upstream off → search працює, user bind → `unavailable` | `TestStage9_Replica` int (19 entries без upstream-запитів, bind → code 52, `replica_sync_failed`) | повністю | — | немає |
| 24 | 3 невдачі → `lock{account}`; 4-та з ПРАВИЛЬНИМ паролем → `bind_blocked`, upstream не викликано; після `lock_duration` → успіх | `TestStage6_AccountLockAndNegativeCache` A/stage6_test.go int (lock source/failures=3, Binds лічильник не змінився, reason account_locked, unlock source=expiry, успіх) | повністю | — | `TestSamba_AccountLock` (badPwdCount=3, без AD lockout, unlock → успіх) — повністю |
| 25 | Негативний кеш: (акаунт,пароль) двічі → 2-й раз без upstream | `TestStage6_AccountLockAndNegativeCache` int (Binds +1 за 2 спроби, `bind_blocked{negative_cache}`); `TestPolicy_NegativeCache` ratelimit unit | повністю | — | `TestSamba_AccountLock` (badPwdCount +1 за 2 спроби) |
| 26 | 20 невдач з IP по різних акаунтах → `lock{ip}`; `allow_accounts` не лочаться; `allow_cidrs` не лімітуються | `TestStage6_IPLockAndLockdown` int (`ip.max_failures=8` → lock ip, bind/search з IP відхилені); `TestStage6_AccountLockAndNegativeCache` int (svc-monitor 5 невдач → без lock); `TestPolicy_IPLockAndAllowlists` ratelimit unit (192.168.1.9 50 невдач → без лімітів, fd00::1) | повністю | `allow_cidrs` лише unit (поріг 8 замість 20 — конфігурований) | немає |
| 27 | Spray 1 пароль × 6 акаунтів → `attack_start{spray}`; через quiet → `attack_end`; summary між | `TestStage6_SprayAndEnumeration` int (accounts_count≥5, summary і end за тим самим attack_id); `TestEngine_Spray` ids unit | повністю | — | немає |
| 28 | Enumeration 12 акаунтів → `attack_start{enumeration}` | `TestStage6_SprayAndEnumeration` int; `TestEngine_Enumeration` ids unit | повністю | — | немає |
| 29 | `(objectClass=*)` sub + `nTSecurityDescriptor` → `recon{sd_dump}` | `TestStage6_ReconHoneytokenAnomaly` int (sd_dump + root_dump, base, client_ip); `TestEngine_Recon` ids unit | повністю | — | `TestSamba_ReconAndHoneytoken` — повністю |
| 30 | Honeytoken bind → `honeytoken{high}` + `lock{ip,honeytoken}` 24h; search `(mail=<honey>)` → те саме | `TestStage6_ReconHoneytokenAnomaly` int (search op, level high, lock until ≥23h, bind op без upstream, lock 127.0.0.5); `TestDaemon_Virola` int | повністю | — | `TestSamba_ReconAndHoneytoken` (bind high + lock, правильний пароль з того IP → відмова, search op) — повністю (24h не перевіряється) |
| 31 | Baseline learn → bind з нового IP → `anomaly{new_ip}`; новий фільтр → `anomaly{new_filter}` | `TestStage6_ReconHoneytokenAnomaly` int (`learn_for=1s`, reason new_filter, new_ip observed=127.0.0.4); `TestEngine_Baseline` ids unit | повністю | — | немає |
| 32 | Lockdown on → bind поза `allow_cidrs` → `bind_blocked{lockdown}` без upstream; off → працює | `TestStage6_IPLockAndLockdown` int (Binds не змінився, reason lockdown, 127.0.0.2 ok, allow_accounts доходять, off → ok, ≥2 `lockdown` подій) | повністю | — | немає |
| 33 | Tarpit: attack-IP → відповідь ≥ `delay`, ≤ `max_conns` одночасно | `TestStage6_Tarpit` int (≥300ms, `tarpit` подія, 1 з 2 паралельних → unwilling) | повністю | — | немає |
| 34 | Кожна подія валідна за `events.schema.json` | `TestStage6_EventsValid` int (усі події демона); `schematest.Check/CheckEvents` у `TestStage7_*` (`served.events`), `TestStage9_StaleWhileDown/Replica`, listener fixture cleanup, vdir/ratelimit/cache/api/ids/record fixtures; `TestSchema_EveryKindValidates` schematest unit; `TestSamba_WebhookAndSSE` | частково | не валідуються події в `stage5/8/10/11/12/12b`, `daemon_test`; схема не має `additionalProperties:false` для `data` → зайві поля не ловляться (мутація 5) | `TestSamba_WebhookAndSSE` (усі події + webhook-батчі) |
| 35 | Webhook: батч 100/2с; HMAC; 500 → retry/backoff; переповнення → `events_dropped_total` + `drop_oldest` | `TestBus_SinkBatching` events unit (batch size/interval параметризовано, Dropped); `TestBus_Overflow` unit (drop_oldest зберігає найновіший; block); `TestWebhookSink_Cases` unit (HMAC verify, 5xx → 3 виклики, backoff 10/15ms, 4xx без retry); `TestLoad_DefaultsAndTypes` config unit (BatchSize=100, drop_oldest); `TestMetrics_Exposition` metrics unit (`aldap_events_dropped_total{sink="webhook"} 2`) | частково | немає in-memory end-to-end webhook (демон → HTTP приймач); default `batch_interval=2s` не assert-иться; зв'язок bus.Dropped → метрика не перевірено end-to-end | `TestSamba_WebhookAndSSE` (HMAC на кожному батчі, обидва bind_ok доставлені) |
| 36 | SSE: відключення на seq=N, `Last-Event-ID: N` → N+1… | `TestStage7_SSEResume` A/stage7_test.go int (seq locks[2],[3], next[0]>first[1]); `TestStream_LastEventID` api unit | повністю | — | `TestSamba_WebhookAndSSE` — повністю |
| 37 | Scopes: `events:read` на `POST /v1/locks` → 403; `admin` → 200 + `api_call` | `TestStage7_ScopesAndAudit` int (403, 201, api_call token_name/status/client_ip); `TestScopes_EveryRoute` api unit | повністю | — | немає |
| 38 | `PUT /v1/config` невалідний → 400, файл не змінено; валідний → бекап, reload, `config_reload{ok=true}` | `TestStage7_PutConfig` int (3 невалідні → 400 `invalid_config`, файл/бекапи незмінні, 0 reload; валідний → бекап 0600 = orig, файл оновлено, `config_reload ok=true`; rollback при start failure) | повністю | — | немає |
| 39 | Notify: `attack_start` → tg+virola+email по разу; повтор у cooldown — ні; digest раз на інтервал | `TestStage8_NotifyAttack` int (по 1 на кожен канал, digest tg+virola, Bearer/bot path, секрети не в логах); `TestScenario39_CooldownAndDigest` notify unit (cooldown count=1, digest по інтервалу на 3 канали, порожній digest не шлеться) | повністю | cooldown-повтор і email-digest — лише unit | немає |
| 40 | `aldapctl unlock` через IPC знімає lock; TCP без токена → 401 | `TestStage10_Aldapctl` A/stage10_test.go int (`unlock --yes` через `--socket` і `--token-file`); `TestStage7_IPCAndTCPWithoutToken` int (raw HTTP DELETE без токена → 401, через IPC → 204, `unlock{source=api}`); `TestCLI_*` aldapctl unit (fake 401) | частково | немає кейсу `aldapctl` по TCP **без токена** → 401 (перевірено лише raw HTTP і fake-сервер) | немає |
| 41 | `TestNoSecretsInOutput`: маркери `S3CR3T-*` → stdout/stderr/події/лог-файли/бандл = 0 | `TestNoSecretsInOutput_Daemon` A/daemon_test.go (5 маркерів у bind/filter/compare, `userpassword=***`); `_API`, `_Config`, `_Headers`×2, `_Notify`, `_Upstream`, `_Bundle` (aldapctl); `TestStage10_Aldapctl` (бандл); `TestStage7/8` (логи); cleanup `startSamba` | частково | немає перевірки **файлових** лог-синків (FileSink) на маркери; немає єдиного прогону «всіх сценаріїв» — покриття розподілене по пакетах | cleanup `startSamba` (6 секретів у виводі демона) |
| 42 | Fuzz 2 хв без panic: `ldapfilter.Parse`, `dn.Parse`, listener BER | `FuzzParseFilter`, `FuzzParseDN` ldapfilter/fuzz_test.go; `FuzzParseMessage` listener/fuzz_test.go; `make fuzz` (2m кожен), CI job `fuzz` | повністю | тривалість задається лише Makefile/CI, не тестом | n/a |
| 43 | Запит > `max_request_bytes` → з'єднання закрито, `rate_limited{oversize}` | `TestProtocol_Edges/oversize` listener unit (`MaxRequestBytes=512`, 2MiB SEQUENCE → protocolError, `rate_limited reason=oversize key=127.0.0.1`) | частково | **закриття з'єднання** після oversize явно не assert-иться (`closed()` викликається лише для indefinite-length) | немає |
| 44 | 40 з'єднань з IP при `max_conns_per_ip=32` → 33-тє відхилено | `TestLimits` listener unit (limit 2 → 3-тє закрито, `rate_limited{conn_limit_ip, limit=2}`, глобальний слот звільнено; global limit) | повністю | параметризовано (2 замість 32) — еквівалентно | немає |
| 45 | `aldap check`: `allow=["*"]` → помилка; inline-пароль → warn; `account.max_failures=5` → warn | `TestValidate_Rules` config unit (`profile_attrs_star` → error, `upstream_inline_warn`, `ratelimit_account_warn` max_failures=5 → warn); `TestRunCheck_NoSecretsInOutput` A/check_test.go unit (inline warning у виводі `aldap check`); `TestRunCheck_Cases` (формат ERROR) | частково | `*` і `max_failures=5` перевіряються лише через `config.Validate`, не через CLI `aldap check` | `TestSamba_CheckOnline` (`--online`, тільки exit 0 + імена серверів) |
| 46 | `ldapsearch -x -H ldaps:// -D … -b ou=users '(uid=*)' uid mail` → golden | `TestDaemon_Ldapsearch` A/daemon_test.go (skip без `ldapsearch`; substring `dn:`, `mail:`, `numEntries: 1`, paged 19, denied attr/term, root DSE, anonymous/wrong → Invalid credentials) | частково | немає golden-файлу (лише substring-перевірки); тест skip-ається без `ldapsearch`; у `testdata/` golden відсутній | немає |
| 47 | `ldapsearch -x -ZZ -H ldap://` StartTLS | `TestDaemon_Ldapsearch` (-ZZ → `dn: cn=bob.brown,…`) | повністю | skip без `ldapsearch` | немає |
| 48 | Python `ldap3` (Docker `python:3-slim`): bind UPN, paged 50, `memberOf` | `TestDaemon_Ldap3` A/stage5_test.go int (`testdata/ldap3_test.py`: python3+ldap3 або `docker run python:3-slim`; 20 entries, ≥4 pages, memberOf, namingContexts, paged control) | повністю | page size 5 (з 20 записів 50 не дало б пагінації); skip без python3/Docker | немає |
| 49 | Virola — ручний чекліст `docs/virola.md` | `docs/virola.md` існує; не автоматизується (за TESTING.md) | n/a | — | `TestSamba_VirolaDirectory` часткова автоматизація |

Підсумок: повністю 31; частково 16 (3,4,5,8,13,18,19,34,35,40,41,43,45,46 + 26/39 мають unit-only частини, але зараховані як повністю); немає 1 (15); n/a 1 (49).
Samba-покриття відповідає SPEC §13.2 (bases, computers, disabled, UPN/sAM/`DOMAIN\`/vDN bind, group member/memberOf, nested, paging, failover, lock після 3, negative cache, honeytoken, recon, webhook HMAC, SSE, proxy protocol, check --online). Не на Samba: 3,5,6(mask),9,10,11(відмови),13(locked/must_change),15–19,21–23,26–29,31–45.

### Sync-тести docs ↔ код — docs ↔ code sync-тести

### 2.1 Що перевіряє кожен тест

| Тест (файл) | code→docs | docs→code | Деталі / прогалини |
|---|---|---|---|
| `TestConfigDocsInSync` (config/config_test.go) | так | так | Порівнює **весь файл** `docs/config.md` байт-у-байт з `RenderDocs()` (таблиця Key/Type/Default/Description з reflect-обходу `Default()`, docgen.go): отже ключі, **типи, дефолти і doc-рядки** — обидва напрями. Плюс: кожен ключ має `doc`-тег, без дублікатів, 6 обов'язкових ключів присутні, у `secret` немає дефолту. `-update` перегенеровує. |
| `TestOpenAPIRoutes` (api/openapi_test.go) | так | так | Regex-парсер `paths:` (двопробільна розкладка, без YAML-залежності): порівнює множину `METHOD path scope` (x-scope або `security: []`→public, `ScopeMetrics`→`status:read`) з `Routes()`. **Не порівнює**: response codes, request/response schemas, параметри, `description`. `Route{Method,Path,Scope}` — більше нічого в коді немає. Перевірка дублікатів і `len≥19`. |
| `TestEventKinds_InSchema` (events/event_test.go) | частково | ні | Жорсткий список 14 з 30 констант проти `event.enum`; рівні. |
| `TestEventKindsInSync` (events/event_test.go) | так | так | `config.EventKinds` ↔ `event.enum` обидва напрями. Але `config.EventKinds` — окремий рукописний список, не константи `events.*`: нова константа без запису у `config.EventKinds` цим тестом не ловиться (ловиться `schematest.Check` лише якщо подія емітується у тесті, що валідує). |
| `TestSchema_EveryKindValidates`, `TestSchema_RejectsInvalid` (events/schematest) | — | — | Для кожного kind зі схеми будує мінімальну подію і валідує власним міні-валідатором `schematest.validate` (type/enum/const/required/format/if-then/additionalProperties/maxItems). 18 негативних кейсів. `enum≥25`. |
| `TestTemplateFuncsInSync` (notify/notify_test.go) | так | так | `funcs` map ↔ `config.NotifyTemplateFuncs` (slices.Equal) |
| `TestTemplateFuncsInSync` (profile/attrs_test.go) | так | так | `templateFuncs` ↔ `config.ProfileTemplateFuncs` (slices.Equal) |
| `TestSystemdUnitInSync` (A/service_test.go) | так | так | `systemdUnit` (шаблон у коді) == `deploy/aldap.service` з підстановкою ExecStart; 4 обов'язкові директиви. |
| `TestPodmanQuadlet` (A/service_test.go) | — | — | Лише `deploy/aldap.container`: hardening-ключі (`checkQuadletHardening`), `PublishPort` є, `HealthCmd` відсутній. Односторонній (файл сам по собі), не звіряє з кодом/Dockerfile/docs/podman.md. |
| `TestDHITagsPinned` (A/release_test.go) | — | — | `Dockerfile` ARG == `build.sh` default для `DHI_GOLANG_TAG`/`DHI_STATIC_TAG`; golang-тег == `go.mod toolchain`+`-debian13-dev`; теги не `latest`, містять цифру. Не перевіряє `.github/workflows` чи `docs/release.md`. |

### 2.2 events.schema.json vs SPEC §6

Схема: `additionalProperties:false` **лише на верхньому рівні** (1 входження); `data` = `{"type":"object"}` без обмежень, за винятком `if/then` для 11 kinds (bind_fail/bind_blocked — `reason` top-level; lock; attack_start/summary/end; search; op_denied; shadow_diff; stale_served; replica_synced; replica_sync_failed). Жоден `then.data` не має `additionalProperties:false`.

Розходження зі SPEC §6 (колонка `data`):

| event | SPEC §6 `data` | Схема | Статус |
|---|---|---|---|
| bind_ok | `{bind_kind, upstream_dn}` | без обмежень | немає |
| bind_fail | `{reason…, failures}` у data | `reason`/`failures` top-level (як у JSON-прикладі SPEC) + enum | SPEC внутрішньо суперечливий; схема = приклад |
| unlock | `{target, key, source: expiry\|api\|tui}` | без обмежень | немає |
| lock | `source: ratelimit\|ids\|api\|honeytoken` | + `tui` | схема ширша за SPEC |
| recon | `{signature, filter_norm, base, attrs}` | без обмежень | немає |
| anomaly | `{reason: new_ip…, observed, baseline}` | без обмежень; код кладе `reason` у top-level (тести `e.Reason=="new_ip"`), не в data | немає + розходження з SPEC |
| honeytoken | `{account, op}` | без обмежень | немає |
| session_summary | `{binds_ok,…,fingerprint}` | без обмежень | немає |
| rate_limited | `{target, key, rps}` | без обмежень; код використовує top-level `reason` + `data.limit/key/op` | немає |
| tarpit | `{ip, conns}` | без обмежень | немає |
| lockdown | `{state, source}` | без обмежень | немає |
| upstream_down/up | `{server, reason, consecutive}` | без обмежень | немає |
| stale_served/replica_* | `{age_s, entries}` | required age_s, entries ≥0 | ок |
| cert_expiring/renewed | `{subject, not_after, days_left}` | без обмежень | немає |
| config_reload | `{ok, errors[]}` | без обмежень | немає |
| insecure_config | `{what}` | без обмежень | немає |
| shadow_diff | `{added[], removed[]}` + кількості | required base/scope/filter_norm/added/removed/added_count/removed_count, maxItems 20 | схема суворіша — ок |
| startup/shutdown | `{version, profiles[]}` | без обмежень | немає |
| api_call | **відсутній у SPEC §6** | є в enum, без обмежень | SPEC розходиться зі схемою |
| search | як SPEC | required base/scope/filter_norm/results; усі поля типізовані | ок |
| op_denied | `{op, oid}` | required op, enum | ок |

Kinds, що **ніколи не емітуються/не спостерігаються у тестах**: **немає** — усі 30 констант зустрічаються як емітовані події хоча б в одному тесті (найслабше: `cert_expiring`/`cert_renewed` лише tlsutil unit; `shadow_diff` лише record; `anomaly` лише ids unit + stage6; `startup`/`shutdown` лише як literal у `daemon_test`). Але схемна валідація емітованих подій для `bind_ok, unlock, recon, anomaly, honeytoken, session_summary, rate_limited, tarpit, lockdown, upstream_*, cert_*, config_reload, insecure_config, startup, shutdown, api_call` перевіряє лише конверт — `data` будь-який.

### 2.3 Мутаційні перевірки (кожна відкочена `git checkout -- <file>`; `git status` порожній)

| # | Мутація | Запущений тест | Результат |
|---|---|---|---|
| 1 | `Audit14Bogus string \`toml:"audit14_bogus" doc:"x"\`` у `config.Server` (internal/config/config.go) | `go test ./internal/config -run TestConfigDocsInSync` | **caught** — `docs/config.md is stale` |
| 2 | `{Route{"GET","/v1/audit14bogus",ScopeStatusRead},…}` у `routeTable` (internal/api/api.go) | `go test ./internal/api -run TestOpenAPIRoutes` | **caught** — `route "GET /v1/audit14bogus status:read" is not in docs/openapi.yaml` |
| 3 | `x-scope: status:read` → `admin` для `GET /metrics` у docs/openapi.yaml | `go test -count=1 ./internal/api -run TestOpenAPIRoutes` | **caught** — обидва напрями: `"GET /metrics status:read" is not in docs` + `"GET /metrics admin" has no route` (єдиний тест, що читає openapi.yaml; cli_test згадує файл лише в коментарі) |
| 4 | Рядок `\| \`server.audit14_bogus\` \| string \| \| x \|` у docs/config.md | `go test -count=1 ./internal/config -run TestConfigDocsInSync` | **caught** — `docs/config.md is stale` |
| 5 | `op_denied` data += `"audit14": true` (internal/listener/conn.go:492) | `go test -count=1 -v ./internal/listener -run 'TestDenied_Operations$\|TestLDAPS$'`; `go test -count=1 -v -tags integration ./cmd/aldap -run TestStage6_EventsValid`; `go test ./internal/events/...` | **NOT caught** — усі PASS. Причина: у схемі `data` для op_denied (і всіх kinds) без `additionalProperties:false`. |
| 6 | `op_denied` data `"op"` → `"operation"` (прибрано required поле) | ті самі | **caught** — `TestDenied_Operations`, `TestLDAPS` (listener fixture cleanup `schematest.CheckEvents`: `$.data: missing required "op"`) і `TestStage6_EventsValid` FAIL |

### 2.4 Висновки Task 2
- `TestConfigDocsInSync`: двосторонній, включно з типами і дефолтами (повне порівняння рендера). Ловить і код→docs (мут. 1), і docs→код (мут. 4).
- `TestOpenAPIRoutes`: двосторонній за `method+path+scope` (мут. 2, 3); **не** звіряє response codes, схеми запитів/відповідей, параметри — їх дрейф не ловиться.
- `events.schema.json`: enum kinds синхронізовано двосторонньо (через `config.EventKinds`, не через константи `events.*`); `data`-контракти є лише для 11 з 30 kinds, без `additionalProperties:false` → зайві/перейменовані необов'язкові поля не ловляться (мут. 5); відсутність required-поля ловиться (мут. 6). SPEC §6 і схема розходяться по 17 kinds (див. 2.2) + `api_call` відсутній у SPEC.
- `TestTemplateFuncsInSync` ×2, `TestSystemdUnitInSync`: двосторонні. `TestPodmanQuadlet`, `TestDHITagsPinned`: односторонні перевірки артефактів (без звірки з docs).
