# Модель загроз ALDAP (Stage 14)

Дата: 2026-10-26. Основа: `SPEC.md` 1.0, код на момент аудиту (гілка `claude/epic-fermat-fniysn`). Знахідки аудиту, на які посилаються рядки STRIDE, описані в `AUDIT.md`.

## 1. Активи

| ID | Актив | Де живе | Наслідок компрометації |
|---|---|---|---|
| A1 | Паролі користувачів у транзиті (user bind) | клієнт → listener (TLS/StartTLS/plain), пам'ять `listener`/`vdir`, `upstream` bind-only pool → DC | викрадення облікових даних домену; повний доступ до AD від імені користувача |
| A2 | Пароль сервісного акаунта AD (`bind_dn`/`bind_password`) | файл секрету / env / inline у `aldap.toml`; пам'ять `upstream` (`secret.Value`); бекапи `aldap.toml.bak.*` | читання всього каталогу з правами сервісного акаунта; за надмірних прав — зміна AD |
| A3 | Приватний ключ вбудованого CA і серверні ключі (`ca.key`, `server.key`, `tls.key`) | `ca_dir` (0600), пам'ять `tlsutil` | MITM між застосунками й ALDAP, перехоплення A1 |
| A4 | Токени API (`[[api.token]]`), HMAC-секрети webhook, токени notify (Telegram, Virola), SMTP-пароль | файл/env/inline; пам'ять (`sha256` для API-токенів, `secret.Value` для решти) | керування блокуваннями/lockdown (DoS застосунку), запис конфігу (= A2, A3 через `*_file`), підробка подій для IPS, спам у канали сповіщень |
| A5 | Канал подій до IDS/IPS/ITSM (webhook, syslog, SSE, JSONL) | `events` sinks | підроблені або пропущені події → хибні блокування на IPS або сліпота під час атаки |
| A6 | Дані каталогу, які бачить клієнт (вибірка за профілем) і які НЕ має бачити (комп'ютери, вимкнені, атрибути поза allow, реальні DN) | `vdir`, кеш `ttl`/`replica`, record-файли, shadow | розвідка AD для подальшої атаки (recon), витік ПІБ/телефонів |
| A7 | Доступність ALDAP для застосунків (Virola) і доступність AD (без lockout) | процес, ліміти, lockdown/tarpit | відмова входу всім користувачам застосунку; масовий lockout в AD |
| A8 | Стан захисту (lock/негативний кеш/IDS) | пам'ять `ratelimit`/`ids` | обхід лімітів → перебір паролів проти AD |
| A9 | Конфігурація (`aldap.toml`, include, env) | диск, `PUT /v1/config` | вимкнення будь-якого контролю, SSRF/читання файлів через `*_file`/`servers` |
| A10 | Ланцюг постачання (CI, образи, бінарники, залежності) | GitHub Actions, GHCR, DHI | троянізований реліз у всіх користувачів |

## 2. Межі довіри

```
 [Клієнти LDAP: Virola, Zabbix, …]          недовірені (LAN; скомпрометований застосунок)
        │ ldap/ldaps/starttls (+ PROXY protocol від довіреного Traefik)
 ───────┼─────────────────────────────────────── TB1: мережа клієнтів → listener
        ▼
 [ALDAP процес: listener → ratelimit/ids → vdir → upstream]   довірений (один UID, одна пам'ять)
        │ ldap/ldaps до DC                      ▲ IPC-сокет 0600 (локальний адмін без токена)
 ───────┼────────────────────────────────────── ┼ TB3: localhost/API → процес
        ▼                                       │ HTTPS + Bearer (events:read … admin), allow_cidrs
 [AD DC1, DC2]  напівдовірені (можуть бути скомпрометовані/підмінені — дані каталогу недовірені)
 ───────────────────────────────────────────── TB2: процес → upstream

 [Sinks: webhook/IPS, syslog, Telegram, Virola, SMTP]  зовнішні; HTTPS; дані подій — наші, транспорт — їхній
 ───────────────────────────────────────────── TB4: процес → зовнішні сервіси
 [Диск: aldap.toml, secrets, ca_dir, events/record файли]  довірений лише за правами ФС
 ───────────────────────────────────────────── TB5: ФС/контейнер → процес
 [CI/GitHub/реєстри]                                           TB6: ланцюг постачання → бінарник
```

Правила на межах:
- TB1: будь-який байт від клієнта — ворожий (BER, DN, фільтри, паролі, PROXY-заголовок). Автентифікація клієнта не робить його довіреним щодо правил каталогу.
- TB2: відповідь upstream — дані, не команди: значення атрибутів екрануються при побудові DN/фільтрів, referrals не виконуються, коди результату мапляться у фіксований набір причин.
- TB3: токен визначає scope, IP — `allow_cidrs`; `admin` = еквівалент оператора (може прочитати будь-який файл, який прочитає процес, через `*_file`/`include` — див. AUDIT, це прийнятий ризик з обмеженням шляхів).
- TB4: усе, що потрапляє в шаблон/JSON/рядок syslog, екранується для цільового формату; секрети каналів не виходять за межі процесу (помилки без URL).
- TB5: файли з секретами 0600/0640; symlink не слідуємо при створенні; процес non-root, read-only ФС.
- TB6: усі зовнішні дії CI закріплені за SHA; секрети недоступні fork-PR; образи за digest.

## 3. Нападники

| ID | Нападник | Позиція | Мотивація/мета | Можливості |
|---|---|---|---|---|
| T1 | Зовнішній у LAN | TB1, без облікових даних | перебір/spray паролів AD, розвідка каталогу, DoS ALDAP або AD (lockout) | довільні LDAP-пакети, тисячі з'єднань, підробка IP лише якщо PROXY protocol неправильно налаштований |
| T2 | Скомпрометований застосунок (Virola/Zabbix) | TB1 з `client_bind` і/або валідними user bind, з IP в `allow_cidrs` | викачати більше даних, ніж дозволяє профіль; перебір паролів через довірену IP; обійти per-IP ліміти | легітимні bind/search у великій кількості, знає схему профілю |
| T3 | Скомпрометований Traefik/reverse proxy | TB1 як довірений PROXY-пір | підробити client_ip (отримати exempt `allow_cidrs`, сховати джерело атаки від IDS/IPS), MITM TLS passthrough неможливий без ключа | довільні PROXY-заголовки, спостереження за трафіком |
| T4 | Зловмисний/скомпрометований власник токена `events:read` (ITSM/IPS-інтеграція) | TB3 | читати події (містять акаунти, IP, фільтри), DoS API через SSE/`since=0`, спроба ескалації до `locks:write`/`admin` | HTTP-запити з токеном; можливо `allow_cidrs` обходиться з довіреної мережі |
| T5 | Власник токена `locks:write` (IPS) | TB3 | помилкові або зловмисні блокування (DoS застосунку), lockdown | API locks/lockdown |
| T6 | Скомпрометований DC / MITM до upstream | TB2 | підсунути referrals (SSRF), шкідливі значення атрибутів (ін'єкції у DN/шаблони/події), фальшиві коди bind | довільні LDAP-відповіді |
| T7 | Користувач AD, що редагує власні атрибути (`mail`, `displayName`) | TB2 (дані) | потрапити у віртуальну групу через `include` за `mail`, зіткнення RDN з жертвою, ламання шаблонів notify | зміна власних атрибутів |
| T8 | Локальний непривілейований користувач хоста | TB5 | читати секрети/ключі/record/events із занадто широкими правами, підкинути symlink у `ca_dir`/`record.file` | доступ до ФС без root |
| T9 | Атака на ланцюг постачання | TB6 | підмінити action/базовий образ/залежність | mutable теги, fork-PR, невалідовані завантаження |

## 4. STRIDE по компонентах

Позначення у колонці «Контроль»: ✅ реалізовано й покрито тестом; ⚠️ реалізовано частково / прийнятий ризик (див. `AUDIT.md`); ❌ не реалізовано. Посилання `A<n>-<m>` — ID знахідки в `AUDIT.md`.

### 4.1 `internal/listener` (BER, TLS/StartTLS, ліміти з'єднань, PROXY protocol)

| Загроза | Сценарій | Контроль |
|---|---|---|
| Spoofing | підробка PROXY-заголовка від недовіреного піра (T1) | ✅ заголовок лише з `trusted_cidrs`, інакше розрив + `insecure_config`; SASL bind → `authMethodNotSupported` |
| Spoofing | довірений проксі (T3) підробляє IP з `allow_cidrs` | ⚠️ за дизайном довіри до проксі; задокументовано (AUDIT «Залишкові ризики») |
| Tampering | plaintext-ін'єкція між StartTLS-відповіддю і handshake (T1) | ✅ буферизовані байти → розрив; небуферизовані байти ламають TLS handshake |
| Tampering | downgrade: bind без TLS при `starttls_required` | ✅ `confidentialityRequired` на bind і search (крім RootDSE) |
| Repudiation | з'єднання без `session_summary`/без IP | ✅ подія на кожне з'єднання; PROXY дає реальний IP |
| Information disclosure | діагностичні повідомлення з деталями upstream/стеками | ✅ фіксовані короткі рядки; panic → лише тип |
| DoS | оголошена довжина > реальна, гігантська довжина, глибина BER, slowloris, флуд з'єднань (T1) | ✅ `readMessage` відкидає до читання тіла; first-packet 5 s; idle timeout; `max_conns_per_ip`; `max_connections`; handshake timeout; `scanBER` до декодера (глибина 64, ≤ 10 000 елементів — FP-2) |
| Elevation | обробка write-операцій | ✅ dispatch → `deny` без виклику Handler |

### 4.2 `internal/vdir` + `internal/profile` + `internal/ldapfilter` (віртуальний каталог)

| Загроза | Сценарій | Контроль |
|---|---|---|
| Spoofing | unauthenticated bind (DN + порожній пароль) як сесія (T1) | ✅ `anonymousBind` → `invalidCredentials`, upstream не викликається |
| Elevation | пошук віртуального дерева без bind або після невдалого bind (T1) | ✅ `requireBind` → `strongAuthRequired` + `op_denied{search, not_bound}`; RootDSE/subschema/honeypot відкриті (FP-1) |
| Spoofing | різні форми імені одного акаунта → різні ключі lock (T1) | ⚠️ UPN/`DOMAIN\u`/`u` — один ключ; віртуальний DN — ключ за `rdn_attr` (AUDIT) |
| Tampering | ін'єкція у фільтр до upstream через RDN/bind name (T1, T2) | ✅ AST + серіалізатор RFC 4515; DN RFC 4514 |
| Tampering | значення атрибутів з AD (T6, T7) у віртуальному DN | ✅ escape RDN; колізії → суфікс objectGUID |
| Information disclosure | атрибути поза allow, `*`/`+`/`1.1`, `;range`, OID-імена, реальні DN у `member`/`memberOf` (T2) | ✅ allowlist за нормалізованим ім'ям; `memberOf` лише віртуальний; денні терми → `(|)` без помилки |
| Information disclosure | `(!(denied=x))` → TRUE | ✅ `Split` замінює терм на absolute false ДО `Simplify`, `(!(|))` залишається локальним і NOT обчислюється локально на звуженому результаті |
| Information disclosure | комп'ютери/вимкнені через групи, `include`, `require_membership` | ✅ ∩ `profile.filter` на всіх джерелах |
| DoS | фільтр з тисячами OR, цикли nested groups, великий результат | ✅ `max_filter_depth/len`, `nested_depth`, `max_result_size`, paged cursor ≤ 8 на з'єднання |
| Elevation | compare/extended (Password Modify, WhoAmI) | ✅ усі → відмова + `op_denied`; у `internal/` немає Add/Modify/Del/ModifyDN/PasswordModify до upstream |

### 4.3 `internal/ratelimit` + `internal/ids`

| Загроза | Сценарій | Контроль |
|---|---|---|
| Spoofing | обхід через паралельні з'єднання (T1) | ✅ резервації в `PreBind` (A5-1); таблиці евікують пакетно, не fail-open (A5-4, FP-7b) |
| Tampering | reload скидає стан | ✅ `Limiter`/`Engine` живуть у процесі |
| DoS | lockdown/tarpit проти легітимних (T1 викликає `attack_start high`) | ⚠️ `lockdown.auto=false` за замовчуванням; `lockdown.allow_cidrs` окремий ключ; tarpit поважає `allow_cidrs` |
| DoS | lock акаунта жертви 3 невірними паролями (T1) | ⚠️ властивість механізму; `allow_accounts`, `lock_duration` |
| Information disclosure | різниця відповідей/часу «акаунт існує / не існує» | ✅ один код; `constant_time_bind_fail` (p95) |
| Elevation | `allow_cidrs` звільняє від account-лімітів | ✅ лише IP-ліміти (Stage 12b) |

### 4.4 `internal/upstream`

| Загроза | Сценарій | Контроль |
|---|---|---|
| Spoofing | підмінений DC / MITM (T6) | ✅ перевірка сертифіката, `tls_ca_file`, SNI; `tls_insecure_skip_verify` лише явно + WARN + подія |
| Tampering | referral на `ldap://attacker` (SSRF) | ✅ не слідуємо; `ErrReferral` |
| Information disclosure | пароль у помилках go-ldap/логах | ✅ `TestNoSecretsInOutput_*` |
| DoS | DC вимагає підпису LDAP (plain) | ⚠️ `strongerAuthRequired` → `upstream_error`, WARN (AUDIT A8, документовано в `upstream.md`) |
| Elevation | сервісний акаунт з адмін-правами | ✅ `audit_service_account` → WARN + `insecure_config` |

### 4.5 `internal/events` + `internal/notify`

| Загроза | Сценарій | Контроль |
|---|---|---|
| Tampering | CRLF/керівні символи розривають JSONL/syslog/SSE (T1 через `account`/фільтр) | ✅ `encoding/json` екранує; syslog — один рядок на повідомлення; SSE — `data:` по рядках |
| Tampering | підробка webhook для IPS | ✅ HMAC `X-ALDAP-Signature`, TLS |
| Information disclosure | паролі у фільтрах подій (`unicodePwd`, `userPassword`) | ✅ redact → `***` |
| Information disclosure | токен бота в URL помилки | ✅ `url.Error.Err` без URL |
| DoS | переповнення черг (T1 генерує події) | ✅ кільцевий буфер `buffer_size`, `queue_size`/`on_overflow`, notify 256/канал |
| Spoofing | ін'єкція розмітки/заголовків у Telegram/email/Virola/webhook | ✅/⚠️ див. AUDIT A2 |

### 4.6 `internal/api` + IPC

| Загроза | Сценарій | Контроль |
|---|---|---|
| Spoofing | токен у query string потрапляє в логи проксі (T4) | ✅ лише `Authorization: Bearer` |
| Spoofing | `X-Forwarded-For` для `allow_cidrs` | ✅ не читається |
| Tampering | `PUT /v1/config` з `include`/`*_file` на довільні шляхи (admin) | ⚠️ admin = оператор; обмеження шляхів — див. AUDIT A7/A10 |
| Information disclosure | `GET /v1/config` секрети | ✅ `***` за типом (`secret.Inline`, `Headers`) |
| DoS | SSE без обмежень, `since=0`, тіло 1 GiB (T4) | ✅/⚠️ `MaxBytesReader`, ліміти підписок — див. AUDIT A7 |
| Elevation | маршрут без scope, method confusion, нормалізація шляху | ✅ матриця маршрут × scope (тест Stage 14) |
| Elevation | IPC-сокет ширше за 0600 | ✅ 0600, перевірка не-сокета |

### 4.7 `internal/tlsutil`, `internal/secret`, `internal/record`, файли

| Загроза | Сценарій | Контроль |
|---|---|---|
| Information disclosure | ключі/секрети/record/events із широкими правами (T8) | ✅ 0600 для ключів, record, IPC, бекапу конфігу; events.file — див. AUDIT |
| Tampering | symlink у `ca_dir`/`record.file` (T8) | ✅ record `Lstat`; CA — див. AUDIT A6 |
| Information disclosure | секрети в пам'яті довше за потрібне | ⚠️ wire-буфер обнуляється; рядок для go-ldap живе до GC (DECISIONS 2026-10-18 «Password memory») |

### 4.8 `cmd/aldap` (конфіг, reload, служба) і `cmd/aldapctl`

| Загроза | Сценарій | Контроль |
|---|---|---|
| Tampering | невідомий ключ/друкарська помилка вимикає контроль | ✅ strict TOML на всіх рівнях, невідомі `ALDAP_*` → помилка |
| Tampering | небезпечні комбінації проходять мовчки | ✅ WARN/ERROR за §3.5 |
| Information disclosure | bundle/`check --json` із секретами | ✅ маскування за ключами + тест |
| DoS | `*_file` на FIFO/`/dev/zero` (T8 через конфіг) | ⚠️ див. AUDIT A10 |

### 4.9 Ланцюг постачання (`.github/workflows`, `Dockerfile`, `deploy/`)

| Загроза | Сценарій | Контроль |
|---|---|---|
| Tampering | mutable тег action/образу (T9) | ⚠️ див. AUDIT A9 (SHA-пін actions, digest DHI) |
| Elevation | fork-PR з доступом до секретів | ✅ лише `pull_request` (без `pull_request_target`); `permissions: contents: read` |
| Elevation | контейнер з root/shell/capabilities | ✅ 65532, static, `cap_drop ALL`, read-only, seccomp |
| Repudiation | непідписаний реліз | ✅ cosign keyless + SBOM |

## 5. Припущення

1. Хост і контейнерний runtime довірені; інший процес з тим самим UID може читати пам'ять процесу — поза моделлю.
2. Traefik/проксі з `trusted_cidrs` довірений щодо IP-адрес клієнтів; його компрометація = T3.
3. AD поважає власний lockout; ALDAP лише зменшує кількість спроб, що доходять до DC.
4. Володар `admin`-токена або IPC-сокета еквівалентний оператору ALDAP (може змінити конфіг і прочитати все, що читає процес).
