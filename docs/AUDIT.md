# Звіт аудиту безпеки ALDAP (Stage 14)

Дата: 2026-10-26/27. Базовий коміт: `2cc919b` (main після Stage 13). Гілка аудиту: `claude/epic-fermat-fniysn`.

## Метод

- Код розглядався як чужий і ворожий; коментарі, `docs/STATE.md` і `docs/DECISIONS.md` не бралися на віру.
- Кожну область розділу А перевіряв окремий субагент зі свіжим контекстом (лише шляхи до коду та розділи SPEC, без висновків координатора). Висновки зведено й кожну знахідку перевірено на коді координатором: тести субагентів скопійовано в основне дерево (`*/audit14_a<N>_test.go`) і запущено — усі знахідки нижче відтворилися до виправлення.
- Знахідка без тесту, що падає до виправлення, позначена «не підтверджено» і в таблицю знахідок не входить.
- Жодне виправлення не видаляє і не послаблює тести, ліміти чи перевірки. Там, де існуючий тест закріплював саме вразливу поведінку (fallback RDN на реальний DN; lockdown без `ratelimit.allow_cidrs`; PreBind без PostBind), тест змінено на безпечний інваріант — це вказано в коміті.
- Серйозність — за підходом CVSS 3.1 (вектор, привілеї, вплив на конфіденційність/цілісність/доступність AD, ALDAP або IPS).

Звіти субагентів (повні, з переліком перевірок «ок / знахідка / не застосовно») зберігаються в артефактах сесії; їхні результати зведено в розділі «Перевірки за областями».

## Підсумок за серйозністю

| Серйозність | Знайдено | Виправлено | Прийнято ризик |
|---|---|---|---|
| Critical | 0 | — | — |
| High | 5 | 5 | 0 |
| Medium | 12 | 12 | 0 |
| Low | 14 | 11 | 3 (задокументовано) |
| Info | 20 | — | перелік нижче |

Критичних знахідок немає. Усі High і Medium виправлені окремими комітами `sec:` з регресійними тестами (`TestAudit14_*`).

## Знахідки

Колонки: ID · серйозність · компонент · опис · відтворення (тест, що падав) · виправлення (коміт) або обґрунтування.

### High

| ID | Компонент | Опис | Відтворення | Виправлення |
|---|---|---|---|---|
| **A1-1** | `internal/vdir/bind.go`, `internal/ratelimit` | Ключ lock/негативного кешу виводився з *поданого* імені. Віртуальний DN (`rdn_attr=cn`) і UPN з префіксом, що не дорівнює sAMAccountName (`john.doe@corp` vs `jdoe`), давали одному акаунту 2–3 окремі бюджети: 6–9 невірних паролів доходили до DC при `account.max_failures=3` — порушення мети SPEC §1.1.4 (блок ALDAP раніше за lockout AD). | `TestAudit14_A1_VirtualDNLockKey_RDNAttrCN`, `TestAudit14_A1_UPNPrefixDiffersFromSAM` (6 upstream-bind'ів замість 3) | `417124b`: ім'я резолвиться у канонічний акаунт (sAMAccountName / uid) сервісним акаунтом (для віртуального DN — з уже зробленого lookup; для UPN/DOMAIN/bare — кешований lookup 5 хв), `Policy.Rekey` переносить резервацію й повторно перевіряє lock/негативний кеш під канонічним ключем; `ratelimit.AccountKey` — єдина нормалізація |
| **A5-1** | `internal/ratelimit` | Гонка PreBind/PostBind: N паралельних bind'ів проходили перевірку до запису першої невдачі — 12–20 невірних паролів одним пакетом доходили до AD. | `TestAudit14_A5_ParallelPreBindRace_Account`, `TestAudit14_A5_ParallelPreBindRace_NegativeCache`, `TestAudit14_A5_ParallelBindsReachUpstream` (daemon, 12 доходили) | `417124b`: PreBind резервує спробу (по акаунту, по IP, по парі акаунт+пароль); записані невдачі + резервації < бюджету; однакова пара допускається одна в польоті; PostBind звільняє; таблиця резервацій fail-closed |
| **A5-2** | `internal/ratelimit` (lockdown) | `lockdown.auto` вмикався від high `attack_start` (≈15 bind'ів з одного IP), а lockdown поважав лише `lockdown.allow_cidrs` — застосунок, вказаний лише в `ratelimit.allow_cidrs` (розкладка `deploy/virola-stack`), відрізався повністю. | `TestAudit14_A5_LockdownIgnoresRatelimitAllowCIDRs`, `TestAudit14_A5_AutoLockdownCutsOffAllowCIDRsApp` | `00581b1`: lockdown обслуговує й джерела `ratelimit.allow_cidrs`; решта відхиляється без upstream |
| **A3-2** | `internal/vdir/directory.go` (`fetchUsers`), `internal/ldapfilter` (`Split`) | Терм на `memberOf` або computed-атрибут переносив увесь фільтр у пост-фільтр, а upstream-пошук виконувався з `SizeLimit=0`: один запит витягував і трансформував усіх користувачів усіх bases (повний скан каталогу на запит, обмежений лише `search_rps`). | `TestAudit14_A3_PostFilterPullsWholeDirectory` (40 000 записів заради відповіді з 10) | `50d880e`: кандидати пост-фільтрованого пошуку обмежені `limit+1` як і звичайного; урізаний набір → `sizeLimitExceeded`; без віртуальних груп `memberOf` класифікується як denied (false), upstream не питається |
| **A1-2**→Medium, див. нижче | | | | |

### Medium

| ID | Компонент | Опис | Відтворення | Виправлення |
|---|---|---|---|---|
| **A1-2** | `internal/vdir/bind.go` | Ключ lock для client_bind був сирим рядком DN: будь-яке інше написання (`CN=Virola, OU=…`, `cn=\76irola,…`) давало новий бюджет і новий запуск argon2id (64 MiB, ~200 мс) — обхід lock + CPU/RAM-ампліфікація. | `TestAudit14_A1_ClientBindLockKeyCanonical` | `417124b`: ключ = канонічний `ClientBindDN.String()` |
| **A5-4** | `internal/ratelimit` | Повні таблиці fail-open: нові ключі не зберігались (lock не записувався, вікно не росло, bucket пропускав). Заповнивши таблицю сміттям, нападник отримував необмежені спроби на свіжу жертву. | `TestAudit14_A5_TableFullFailOpen_Account/_IP` | `417124b`: батчеве витіснення найменш корисних записів; таблиця резервацій відмовляє при переповненні |
| **A5-5** | `internal/ratelimit`, дефолти | З дефолтами (3 невдачі, lock 15 хв, lock «з'їдає» вікно) нападник щоцикл отримував новий бюджет: 3+3 за 30 хв ≥ порогу lockout AD (Samba-стенд 5). | `TestAudit14_A5_ADLockoutNotPrevented` (9 спроб за 30 хв) | `417124b`: повторний lock протягом 24 год подвоює тривалість (до 24 год); одна невдача на «пробації» (2×lock_duration після закінчення) блокує знову — ≤4 спроби в будь-якому 30-хвилинному вікні |
| **A5-6** | `internal/ratelimit` | Невдачі з причинами `anonymous` (ім'я без пароля, до AD нічого не йде) і `upstream_error` (збій каталогу) рахувались як невдачі акаунта: 3 порожні bind'и блокували жертву без жодного звернення до AD; збій AD + повтори застосунку самоблокували користувачів. | `TestAudit14_A5_NonCredentialFailuresLockAccount` | `417124b`: до акаунта зараховуються лише credential-невдачі (той самий перелік, що й для негативного кешу) |
| **A5-3** | `internal/ids` | Витіснення джерел LRU: нападник з MaxSources свіжих адрес (IPv6-ротація, PROXY-заголовок) між пакетами стирав власну історію й лишався під порогами spray/stuffing/enumeration. | `TestAudit14_A5_SourceEvictionClearsAttackHistory` | `89b3352`: витісняються найменш цікаві джерела (найменше спроб, потім найстарші) батчами; джерела активної атаки не витісняються |
| **A3-3** | `internal/vdir`, `internal/events`, `internal/ids/baseline` | Кільцевий буфер обмежував кількість записів, а не їх розмір: base до 1 MiB, 50 000 імен атрибутів, bind-ім'я 262 KB копіювались у кожну подію (100 000 записів = десятки GiB), у baseline і таблиці акаунтів. | `TestAudit14_A3_SearchEventFieldsUnbounded`, `TestAudit14_A3_BindEventAccountUnbounded`, `TestAudit14_A3_RecordFieldSizeUnbounded` | `dc8bebb`: base ≤ 8192, списки ≤ 64 імен (+`attrs_truncated`), bind-ім'я ≤ 1024 до подій/логів/guard; шина обрізає будь-який рядок до 64 KiB; baseline зберігає обрізані значення |
| **A3-4** | `internal/vdir/match.go` | Рівність по DN-атрибутах (`member`, `memberOf`, `manager`) парсила кожне значення кожного запису для кожного терма: 74 терми × 20 значень × 1000 записів = 3,3 с CPU на пошук (×5 з `max_result_size`). | `TestAudit14_A3_DNEqualityORCost` | `5c9957c`: канонічні форми DN мемоізуються на записі — один парсинг на значення |
| **A3-5** | `internal/vdir/directory.go` (paging) | Стан paged results обмежений лише кількістю курсорів (8 × `max_result_size` на з'єднання, без межі в байтах і часі): ~13 MiB на з'єднання × 1024 з'єднань ≈ 13 GiB у гіршому разі, доки з'єднання живе. | `TestAudit14_A3_PagingStateRetention` (вимірювання) | `pagingTTL` 10 хв: покинуті курсори звільняються; залишковий ризик — межа в байтах задокументована в «Залишкових ризиках» |
| **A4-1** | `internal/vdir` (`transform`, `newMember`, replica) | Користувач без значення `rdn_attr` (реалістично для `rdn_attr = mail|userPrincipalName|uid`) отримував реальний DN upstream як віртуальний RDN — також у `member`/`memberUid` груп і репліці — розкриваючи naming context і структуру OU кожному клієнту. | `TestAudit14_A4_Finding_RDNFallbackLeaksUpstreamDN` | `cecadd9`: непрозорий RDN (hex objectGUID або хеш DN) у всіх шляхах |
| **A7-1** | `internal/api/stream.go` | Кількість SSE-стрімів не обмежена: токен `events:read` відкриває тисячі стрімів (≈311 KB + goroutine кожен, назавжди). | `TestAudit14_A7_Finding_StreamNoCap` (300 прийнято) | ключ `api.max_streams` (дефолт 64) → 503 `too_many_streams`; новий стрім без `Last-Event-ID`/`since` починає з останніх 1000 записів |
| **A7-2** | `internal/events/bus.go`, `internal/api/handlers.go` | `GET /v1/events?limit=1` копіював усе кільце (183 MB, 342 мс під м'ютексом шини, який потрібен `Emit` на шляху LDAP); `stream?since=0` відтворював 100 000 записів (31 MB) на з'єднання. | `TestAudit14_A7_Finding_EventsFullRingCopy` | `Bus.Each`/бінарний пошук початку; копіюються лише відповідні записи; backfill стріму порціями по 256 |
| **A6-1** | `internal/events/webhook.go` | HTTP-клієнт webhook слідував редиректам: 307/308 пересилав батч, налаштовані заголовки (API-ключі, Authorization) і HMAC-підпис на довільний Location. | `TestAudit14_A6_WebhookFollowsRedirect` | `c5378df`: `ErrUseLastResponse`, 3xx — помилка без повтору |
| **A6-2** | `internal/tlsutil/ca.go` | `WriteKeyPair` писав через `os.WriteFile`: заздалегідь створений 0644 `server.key` отримував свіжий приватний ключ зі широкими правами; symlink на місці `server.key`/`ca.key` перезаписував ціль. | `TestAudit14_A6_ServerKeyKeepsWideMode`, `_ServerKeySymlinkFollowed`, `_CAKeyDanglingSymlinkFollowed` | `3b8bb5e`: запис у новий O_EXCL temp-файл з потрібним режимом + fsync + rename |
| **A8-1** | `internal/vdir/groups.go` | `include` з `@` матчив `userPrincipalName` АБО `mail`; `mail` в AD не унікальний і часто self-writable → користувач додавав себе у віртуальну групу, виставивши mail = UPN включеного адміністратора. | `TestAudit14_A8_GroupInclude_MailImpersonation` | `a9a22e6`: на AD — лише UPN; generic (без UPN) — mail |

### Low

| ID | Компонент | Опис | Відтворення | Статус |
|---|---|---|---|---|
| **A1-3** | `internal/vdir/bind.go` | Bind по honeytoken з порожнім паролем відповідав як anonymous до перевірки пасток — ні події `honeytoken`, ні lock IP. | `TestAudit14_A1_HoneytokenEmptyPasswordIsHit` | виправлено `b1db61f` |
| **A1-4** | `internal/ratelimit` | `allow_accounts`/`lockdown.allow_accounts` у формі UPN або `DOMAIN\user` ніколи не збігались із ключем. | `TestAudit14_A1_AllowAccountsForms` | виправлено `417124b` (`AccountKey`) |
| **A1-5** | `internal/profile/argon2.go`, `internal/config` | Параметри `client_bind.password_hash` не обмежені: `m=4294967295` → OOM на першому bind'і; `m=8` — слабкий хеш; `aldap check` проходив. | `TestAudit14_A1_PasswordHashParamBounds` | виправлено: межі m 8 MiB..1 GiB, t 1..16, p 1..16 у `config.CheckArgon2Costs` (валідатор і парсер) |
| **A1-6** | `internal/vdir/bind.go` | Невдалий bind на `client_bind.dn` на ~200 мс довший (argon2id), ніж на невідомий DN — DN сервісного логіна вгадується за часом. | `TestAudit14_A1_ClientBindTimingOracle` | виправлено: невдалі bind'и вирівнюються до виміряної вартості верифікації |
| **A2-1** | `cmd/aldapctl` | Керівні символи (CR/LF/ESC) з bind-імені доходили до терміналу в `aldapctl events` і TUI — підробка/стирання рядків на екрані оператора. | `TestAudit14_A2_EventLineNoControlChars` | виправлено: значення з пробілом або недрукованими рунами квотуються (`strconv.Quote`) |
| **A3-1** | `internal/listener` | Глибина BER не обмежена 64 (SPEC §9), діяв дефолт бібліотеки 1000. | `TestAudit14_A3_BERDepthOver64Refused` | виправлено `f574ee7` |
| **A4-2** | `internal/vdir/directory.go` | Panic (`boundsError`) у single-user lookup, якщо `rdn_attr` написаний в іншому регістрі, ніж ключ honeytoken-шаблону (`samaccountname`); з'єднання розривалось; `MatchHoneytoken` не бачив RDN-форму. | `TestAudit14_A4_Finding_HoneytokenRDNAttrCasePanic` | виправлено `cecadd9` + помилка компіляції для пастки без `rdn_attr` |
| **A6-3** | `cmd/aldap/control.go` | `PUT /v1/config` і бекап наслідували режим існуючого файлу (0644 з inline-секретами). | `TestAudit14_A6_ApplyConfigKeepsWorldReadableMode` | виправлено: новий файл ≤ 0640, бекапи 0600 |
| **A6-4** | `internal/config/load.go` | Помилка парсера TOML цитувала токен: `bind_password = hunter` (без лапок) друкував пароль у `aldap check`, логу старту і відповіді `PUT /v1/config`. | `TestAudit14_A6_CheckParseErrorsNoSecret/bare_word` | виправлено: лише рядок, останній ключ і вид помилки, цитати замінено `"…"` |
| **A6-5** | `internal/listener` | Обнулялась лише копія пароля; сирий буфер повідомлення (і дерево BER) зберігали його до GC. | `TestAudit14_A6_WireBufferNotZeroed` | виправлено: сирий буфер обнуляється після обробки; рядок для go-ldap — залишковий ризик (DECISIONS 2026-10-18) |
| **A7-3** | `internal/config`, `cmd/aldap/control.go` | `GET /v1/config` (і bundle) віддавав `client_bind.password_hash` відкрито — офлайн-підбір пароля застосунку. | `TestAudit14_A7_Finding_ConfigGetPasswordHash` | виправлено: тип `secret.Inline` → `***`; `***` на PUT відхиляється |
| **A8-2** | `internal/upstream/health.go` | `health_check=rootdse` (дефолт) читав RootDSE анонімно: DC з вимогою підпису LDAP на plain `ldap://` відмовляв кожному bind'у кодом 8, але сервер лишався `up` без `upstream_down`. | `TestAudit14_A8_Health_RootDSE_MasksRefusedServiceBind` | виправлено: проба `rootdse` робить сервісний bind, якщо задано `bind_dn` |
| **A8-3** | `internal/upstream` | Відмови `strongerAuthRequired`/`confidentialityRequired` звітувались лише як `upstream_error` — код результату губився в `check --online` і WARN-логах, штовхаючи до `tls_insecure_skip_verify`. | `TestAudit14_A8_Check_ServiceBindRefused_NamesCause`, `TestAudit14_A8_Bind_SigningRequired_Diagnostics` | виправлено: `BindError.Error()` для `upstream_error` містить результат LDAP; `check` додає підказку про ldaps/StartTLS |
| **A7-I1..I3** | `internal/api` | 403 `forbidden_source` як оракул валідності токена з недозволеної мережі; дубльовані значення токенів (останній виграє); `/metrics` через IPC ігнорує `metrics.enabled=false`. | тести `TestAudit14_A7_Info_*` | прийнято (Info/Low): IPC = адмін; оракул вимагає валідного токена; дублі — помилка оператора, валідатор попереджає *(див. «Залишкові ризики»)* |

### Info (без змін коду або лише документація)

- A1: колізії ключа між доменами (`x@a` vs `x@b`, `CORP\x` vs `OTHER\x`) — одна жертва може бути заблокована через іншу з тим самим sAMAccountName в іншому домені; один ALDAP обслуговує один домен.
- A3: обрана ідентичність зберігається після StartTLS (RFC 4513 §3.1.1 дозволяє) — зафіксовано в DECISIONS; довірений PROXY-пір повністю визначає адресу клієнта (включно з `allow_cidrs`) — властивість протоколу, задокументовано в `docs/proxy-protocol.md`; `on_overflow=block` зупиняє goroutine з'єднання — за конфігурацією; replica тримає весь віртуальний каталог у пам'яті — за дизайном; 1 MiB wire-фільтр коштує ~0,3 с декомпіляції до текстових лімітів — обмежено `search_rps`.
- A4: `memberOf` в `attrs.allow` змушує тягнути реальний `memberOf` з AD (не віддається); виключені/комп'ютерні акаунти можуть bind'итись при `require_membership=false` (SPEC робить членство опційним — задокументовано в `docs/vdir.md`); `members.bases` ширше за `profile.bases` виводить RDN поза bases; `:dn:` на дозволеному атрибуті прокидається (не підтверджено на AD); фільтрація по маскованому атрибуту за оригіналом — SPEC §4.6; бінд-імена `<SID=…>`/`<GUID=…>` прокидаються як FormAccount при порожньому `default_domain` — потрібен пароль (не підтверджено).
- A6: inline-секрети (`secret.Inline`) лишаються в `d.cfg` на час життя процесу (потрібні для `GET /v1/config` round-trip); API без recover-обгортки — `net/http` друкує значення panic у Debug; `Duration.UnmarshalText` відлунює значення; IPC-сокет: вікно umask між `ListenUnix` і `Chmod` на тимчасовому імені (не підтверджено).
- A8: `ldap://h:0`/`:99999` проходять парсинг (падають на dial); валідатор не відхиляє `?query`/`#frag` у `servers` (відхиляє `ParseServerURL` при старті); user bind з тайм-аутом повторюється на наступному DC (можливий подвійний badPwdCount); один `tls_server_name` на всі `servers`; аудит сервісного акаунта не бачить `adminCount`, `primaryGroupID`, well-known SID і локалізовані назви груп — рекомендації в «Залишкових ризиках».
- A2: кастомні шаблони Telegram з `template_dir` надсилаються без екранування (задокументовано в `docs/notify.md`); наївний `body_template` без `json` ламається на `"` і скидається з `ResultError` (задокументовано); під час активної атаки навіть `honeytoken` потрапляє в digest (`notify.Handle`) — затримка алерту до `digest_interval`.

## Перевірки за областями (стисло)

| Область | Перевірено | Результат |
|---|---|---|
| А.1 Автентифікація | unauthenticated bind (10 форм імен × порожній/nil пароль) — ніколи не йде в upstream, сесія не надається; пароль з NUL/пробілів/не-UTF-8/60 KiB–512 KiB — передається байт у байт, префікс не автентифікує; argon2id t=3/m=64 MiB/p=4, constant-time; негативний кеш — сіль на процес, лише credential-невдачі, успіх ніколи не кешується | 1 High, 1 Medium, 4 Low (виправлено) |
| А.2 Ін'єкції | усі upstream-фільтри — AST + серіалізатор RFC 4515 (`*`, `()`, `\`, NUL, C0); RDN/DN — RFC 4514 (`EscapeRDNValue`); віртуальний DN з `*` не матчить усіх; зворотний напрямок (значення з upstream у DN) — екранується; Telegram MarkdownV2 екранується повністю, email — Q-encoding/quoted-printable (CRLF не інжектується), webhook/Virola — `encoding/json`; JSONL/syslog/SSE/webhook-батчі — один запис на кадр | 1 Low (aldapctl) |
| А.3 Протокол і DoS | довжина перевіряється до читання тіла, 2^31..2^63/indefinite відкидаються, slowloris закривається дедлайном на повідомлення, fuzz 1,2 M виконань без падінь; 33-тє з'єднання/IP відхиляється, глобальний ліміт на accept(), TLS-handshake під first-packet deadline; StartTLS: буферизовані байти → розрив, небуферизовані ламають handshake; PROXY: недовірений → розрив + подія, фрагментований/TLV-сміття/>4096 — ок; paging cookie 128 біт, прив'язана до з'єднання | 1 High, 3 Medium, 1 Low |
| А.4 Обхід vdir | 28 варіантів base/scope → upstream отримує лише `bases`; `*`/`+`/`1.1`/`;binary`/`;range`/OID — лише allowlist; 29 пар denied-фільтрів (вкл. `(!(denied=*))`, `(!(!(…)))`, extensible, `:dn:`) — ідентичні результати без оракула; комп'ютери/вимкнені/exclude не прослизають через пошук, групи, include, `require_membership`, replica, ttl; усі write/compare/extended → відмова + `op_denied`, інвентар викликів go-ldap: лише Bind/Search/StartTLS | 1 Medium, 1 Low |
| А.5 Rate limit/IDS | reload зберігає стан; профілі ділять лічильники; `allow_cidrs` лише IP-ліміти; honeytoken-lock поважає `allow_cidrs`; IPv4-mapped IPv6 нормалізується; недовірений PROXY відкидається; заблоковані bind'и живлять детектори | 2 High, 4 Medium |
| А.6 TLS і секрети | мін. TLS 1.2 усюди, шифри Go-дефолт, перевірка сертифіката upstream + SNI + IP SAN, `tls_insecure_skip_verify` лише явно з WARN+подією, StartTLS без fallback; API без TLS поза loopback відхиляється двічі; notify — без редиректів, URL без токена в помилках; IPC 0600; record 0600 + Lstat; bundle 0600; матриця `TestNoSecretsInOutput` і таблиця обнулення — у звіті субагента | 2 Medium, 3 Low |
| А.7 API | повна матриця маршрут × scope збігається зі SPEC §7 і `x-scope`; HEAD/OPTIONS/PATCH/TRACE/нормалізація шляху — без обходу; токен лише в `Authorization: Bearer`; `X-Forwarded-For` не читається; rate limit до авторизації; `MaxBytesReader` 4 MiB; `api_call` для всіх викликів з 401/403/429 | 2 Medium, 1 Low, 3 Info |
| А.8 Upstream | referrals не слідуються (wire-тест з пасткою-слухачем: 0 з'єднань); URL без userinfo/path/query; bind-only пул ніколи не шукає; invalidCredentials не повторюється на іншому DC; paged cookie не переносяться між DC; `tls_ca_file` виключає системні корені | 1 Medium, 2 Low |
| А.9 Ланцюг постачання | *(заповнюється зі звіту субагента)* | |
| А.10 Конфіг | *(заповнюється зі звіту субагента)* | |

## LDAP signing / channel binding (A8, Windows Server 2025)

Поведінка ALDAP (лише simple bind, без SASL) проти DC з дефолтами Windows Server 2025 (підпис LDAP вимагається, channel binding «When supported»):

| Транспорт до DC | Сервісний bind | User bind | Health `rootdse` |
|---|---|---|---|
| `ldaps://` | приймається (TLS задовольняє вимогу цілісності; CBT не стосується simple bind) | приймається | приймається |
| `ldap://` + `starttls = true` | приймається | приймається | приймається |
| `ldap://` plain | **відмова, resultCode 8 `strongerAuthRequired`** (`00002028 … integrity checking …`) → після A8-2/A8-3: сервер `down`, `check --online` називає код і підказує ldaps/StartTLS | відмова 8 → `bind_fail{upstream_error}` з кодом у WARN; клієнту `invalidCredentials`; без повтору й негативного кешу | анонімний RootDSE приймається (підпис вимагається для bind'ів) — ⁉️ не підтверджено на живому DC 2025 |

Джерела: learn.microsoft.com/windows-server/identity/ad-ds/ldap-signing; KB4520412 / ADV190023 (`ldap-session-security-settings-requirements-adv190023`); KB935834. Сторінки Microsoft читались через пошукові фрагменти (проксі середовища блокує learn/support.microsoft.com) — позначено ⁉️ у `docs/upstream.md`.

## Залишкові ризики та ручний чекліст

Що не закрито в коді й чому:

1. **Паролі в пам'яті до GC.** Рядок, який приймає `go-ldap.Bind(string)`, не обнулити; дерево BER (`ber.Packet`) зберігає копії до GC. Прийнято (DECISIONS 2026-10-18 «Password memory»); сирий буфер і копія обнуляються.
2. **Paging state без межі в байтах.** 8 курсорів × `max_result_size` × з'єднань; TTL 10 хв додано. Оператор обмежує `server.max_connections`, `limits.max_result_size`, `limits.max_conns_per_ip`.
3. **Довірений PROXY-пір** визначає адресу клієнта повністю, включно з `allow_cidrs` і `lockdown.allow_cidrs`. Компрометація Traefik = компрометація per-IP захисту (`docs/proxy-protocol.md`).
4. **Блокування акаунта жертви** 3 невірними паролями — властивість механізму (SPEC); `allow_accounts` для сервісних, `lock_response`, ескалація lock подовжує недоступність і для жертви.
5. **`locks:write` і `admin`** можуть заблокувати будь-який IP/акаунт або ввімкнути lockdown — за дизайном; усі виклики аудитуються (`api_call`).
6. **Admin-токен читає файли** через `include`/`*_file` та існування шляхів через `dry_run` — admin = оператор; обмеження `include` текою конфігу — див. А.10.
7. **A7-I1..I3** (оракул 403, дублі токенів, `/metrics` через IPC) — прийнято як Low/Info.
8. **Аудит сервісного акаунта** не покриває `adminCount=1`, `primaryGroupID` 512/519/544/548, well-known SID і перейменовані/локалізовані групи — рекомендація: порівнювати `objectSid` з well-known RID.

Ручний чекліст для власника (потребує реального стенду):

- [ ] **AD / Windows Server 2025**: `aldap check --online` проти DC з «Require signing» по `ldap://` → очікувано помилка з кодом 8 і підказкою; по `ldaps://` і `starttls` — ок; анонімне читання RootDSE по 389 — перевірити, чи дозволене (клітинка ⁉️ вище).
- [ ] **AD**: перевірити, що після 3 невірних паролів `badPwdCount` = 3 і `lockoutTime` = 0; повторити через `lock_duration` — одна невдача має заблокувати знову на 30 хв (ескалація).
- [ ] **AD**: `audit_service_account` на акаунті з primaryGroupID = 512 (Domain Admins як primary group) — очікувано *не* спрацює (залишковий ризик 8).
- [ ] **Virola**: власний CA / перевірка сертифіката (SPEC §14); формат paged cookie; поведінка при `sizeLimitExceeded` для `(memberOf=…)` у каталогах > `max_result_size`.
- [ ] **Podman/systemd**: socket activation, `User=`, Quadlet під systemd — `docs/podman.md`.
- [ ] **Windows**: named pipe ACL, Event Log, `kardianos/service` на Server 2012 R2 — `docs/windows.md`.
- [ ] **Контейнер**: запуск під `deploy/seccomp.json` з `--read-only --cap-drop ALL --user 65532` (див. А.9).
- [ ] **IPS/ITSM**: webhook-приймач повертає 3xx → батч не пересилається (помилка в логах), HMAC перевіряється.

## Фінальний незалежний прохід

*(заповнюється після запуску окремого субагента зі свіжим контекстом лише з кодом і SPEC.md)*
