# ALDAP — Технічне завдання

**ALDAP** — LDAP-проксі з віртуальним каталогом, захистом від перебору облікових даних та телеметрією для IDS/IPS.
Стоїть між застосунками (LDAP-клієнтами) та Active Directory / будь-яким LDAPv3-сервером.
Застосунок бачить лише той каталог, який описано у профілі, і ніколи не має прямого доступу до AD.

Ліцензія: **MIT**. Мова: **Go**. Конфіг: **TOML**. Контейнер: **Docker Hardened Images (DHI)**.

Версія ТЗ: 1.0 (2026-10-18). Автор вимог: власник проєкту. Виконавець: Claude Code.

---

## 0. Терміни

| Термін | Значення |
|---|---|
| **Upstream** | Реальний каталог: AD DC або інший LDAP-сервер. Може складатись із кількох серверів (failover). |
| **Profile** | Опис одного застосунку-клієнта: порт, TLS, upstream, правила віртуальної бази, ліміти. |
| **Virtual base** | Дерево DN, яке бачить клієнт (напр. `ou=virola,dc=aldap`). В AD його не існує. |
| **Virtual group** | Група, яку ALDAP збирає сам за фільтром/з груп AD і віддає клієнту як звичайний `groupOfNames`/`group`. |
| **Client bind** | Локальний логін/пароль застосунку для сервісного bind'у до ALDAP. До AD не має стосунку. |
| **User bind** | Bind кінцевого користувача (UPN/sAMAccountName/DN + пароль), який ALDAP прокидає в upstream. |
| **Event** | Структурована JSON-подія аудиту (схема `aldap.event.v1`). |
| **Lock** | Тимчасове блокування акаунта або IP усередині ALDAP (не в AD). |

---

## 1. Цілі та не-цілі

### 1.1 Цілі
1. Дати застосунку (першочергово — Virola Messenger) вибірку користувачів з кількох OU/CN, відфільтровану канонічними LDAP-фільтрами, без зміни структури AD.
2. Працювати в усіх комбінаціях транспорту:
   - клієнт → ALDAP: `ldap://` (389), `ldap://`+StartTLS, `ldaps://` (636);
   - ALDAP → upstream: `ldap://`, `ldap://`+StartTLS, `ldaps://`.
   ALDAP може термінувати TLS своїм сертифікатом, коли upstream LDAPS не має.
3. Віртуальна база: злиття кількох bases, мапінг атрибутів і objectClass, обчислювані атрибути, віртуальні групи, вкладені групи, маскування.
4. Захист AD від перебору облікових даних: блокування у ALDAP спрацьовує раніше, ніж lockout в AD.
5. Телеметрія для зовнішніх IDS/IPS/ITSM: події, вебхуки, pull-API, активні дії (блок через API).
6. Повна конфігурація без інтерфейсу (compose/systemd), секрети через файли/змінні.
7. Текстовий клієнт керування (TUI) `aldapctl`.
8. Failover між кількома DC, кеш/репліка, hot-reload.

### 1.2 Не-цілі (свідомо НЕ реалізується)
- Будь-який запис в upstream (add/modify/delete/modDN/password change). Усі такі запити відхиляються з `unwillingToPerform`.
- Зміна паролів користувачів будь-яким способом.
- Kerberos/GSSAPI bind до upstream. Лише simple bind (plain/StartTLS/LDAPS).
- Веб-UI. SCIM. Зовнішня БД. Кластер зі спільним станом.
- Підтримка YAML у конфігурації.

---

## 2. Архітектура

```
                         ┌──────────────────────────────────────────────────┐
  Virola  ──ldaps:636──▶ │ listener(profile.virola) ─┐                      │
  Zabbix  ──ldap:3389──▶ │ listener(profile.zabbix) ─┤                      │
  honeypot ─ldap:1389──▶ │ listener(profile.honey)  ─┤                      │
                         │                           ▼                      │
                         │   ┌──────────┐  ┌──────────────┐  ┌──────────┐  │
                         │   │ ratelimit│─▶│ virtual dir  │─▶│ upstream │──┼──▶ DC1 (ldap/ldaps)
                         │   │ + IDS    │  │ (rewrite,    │  │ pool +   │──┼──▶ DC2
                         │   └────┬─────┘  │  merge, map, │  │ failover │  │
                         │        │        │  groups,cache)│  └──────────┘  │
                         │        ▼        └──────────────┘                 │
                         │   ┌──────────┐      ┌────────┐   ┌───────────┐  │
                         │   │ events   │─────▶│ notify │   │ api (http)│◀─┼── aldapctl (TUI/CLI)
                         │   │ bus      │─────▶│ sinks  │   │ /metrics  │◀─┼── IPS / ITSM
                         │   └──────────┘      └────────┘   └───────────┘  │
                         └──────────────────────────────────────────────────┘
```

### 2.1 Компоненти (пакети Go)

| Пакет | Відповідальність |
|---|---|
| `cmd/aldap` | Демон: парсинг конфігу, запуск listener'ів, API, notify, graceful shutdown, служба (systemd/Windows). Підкоманди: `run`, `check`, `version`, `gen-ca`, `gen-cert`, `service install/uninstall`. |
| `cmd/aldapctl` | TUI (Bubble Tea) + CLI. Працює лише через API ALDAP (unix socket / TCP). |
| `internal/config` | Модель TOML, завантаження, злиття env/secret-files, валідація, hot-reload, `include`. |
| `internal/secret` | Резолвер значень `*_file`, `*_env`, inline. |
| `internal/listener` | Приймає з'єднання (gldap), TLS/StartTLS, ліміти з'єднань, маршрутизація до профілю. |
| `internal/profile` | Правила профілю: допустимі bases, обов'язковий фільтр, allowlist атрибутів, мапінги. |
| `internal/vdir` | Віртуальний каталог: переписування DN/фільтрів, злиття результатів, віртуальні групи, nested groups, computed/masked attrs, honeytokens. |
| `internal/ldapfilter` | Парсер/серіалізатор фільтрів RFC 4515 з AST, переписування атрибутів, AND-ін'єкція, перевірка допустимості. |
| `internal/upstream` | Пул з'єднань до upstream, health-check, failover, paged results, referral handling. |
| `internal/cache` | Режими `none`/`ttl`/`replica`, stale-while-down. |
| `internal/ratelimit` | Token bucket по IP/акаунту, негативний кеш, затримки, tarpit, lockdown, honeypot. |
| `internal/ids` | Детектори: spray, stuffing, slow brute, enumeration, recon-сигнатури, baseline/anomaly, fingerprint. |
| `internal/events` | Шина подій, схема `aldap.event.v1`, кільцевий буфер, sinks: stdout/jsonl/syslog/webhook-push. |
| `internal/notify` | Людські сповіщення: telegram, virola, email, custom webhook; cooldown/дайджест. |
| `internal/api` | HTTP/JSON API + SSE + `/metrics`; токени з правами; OpenAPI. |
| `internal/tlsutil` | Вбудований CA, випуск/перевипуск серверного сертифіката, імпорт зовнішнього, перевірка строку. |
| `internal/record` | Запис/відтворення запитів (record/replay), shadow-режим правил. |
| `internal/metrics` | Prometheus-лічильники/гістограми. |
| `internal/testdir` | In-memory LDAP для тестів (на базі `gldap/testdirectory`) з AD-подібною схемою. |

### 2.2 Залежності та ліцензії

| Модуль | Призначення | Ліцензія |
|---|---|---|
| `github.com/jimlambrt/gldap` | LDAP-сервер (listener, mux, BER) | MIT |
| `github.com/go-ldap/ldap/v3` | LDAP-клієнт до upstream | MIT (транзитивно BSD-3: x/crypto, sspi) |
| `github.com/go-asn1-ber/asn1-ber` | BER | MIT |
| `github.com/BurntSushi/toml` | TOML | MIT |
| `github.com/charmbracelet/bubbletea`, `bubbles`, `lipgloss` | TUI | MIT |
| `github.com/kardianos/service` | Служба Windows/systemd/launchd | zlib |
| `github.com/prometheus/client_golang` | /metrics | Apache-2.0 |
| стандартна бібліотека | HTTP, SMTP, TLS, шаблони, crypto | BSD-3 |

**Правило:** нову залежність можна додати лише з ліцензією MIT/BSD/ISC/Apache-2.0/zlib/MPL-2.0 (без copyleft GPL/AGPL/LGPL). `make licenses` генерує `THIRD_PARTY_LICENSES.md`, CI перевіряє allowlist.

---

## 3. Конфігурація

### 3.1 Джерела і пріоритет (вищий перекриває нижчий)
1. Змінні середовища `ALDAP_*`.
2. Файли секретів (`*_file`).
3. `aldap.toml` (+ `include`).
4. Вбудовані дефолти.

### 3.2 Секрети
Будь-який чутливий ключ `X` приймає три форми (взаємовиключні, валідатор забороняє більше однієї):
- `X = "value"` — inline (дозволено, але `aldap check` попереджає);
- `X_file = "/run/secrets/name"` — прочитати файл, обрізати кінцевий `\n`;
- `X_env = "VAR_NAME"` — прочитати змінну середовища.

Чутливі ключі: `bind_password`, `client_bind.password`, `api.tokens[].token`, `notify.*.token`, `notify.*.bot_token`, `notify.email.password`, `events.webhook.hmac_secret`, `tls.key` (шлях — не секрет, вміст — так).

Значення секретів ніколи не потрапляють у логи, події, API-відповіді (`GET /v1/config` повертає `"***"`), `aldapctl bundle`.

### 3.3 Змінні середовища
Схема: `ALDAP_<SECTION>_<KEY>`; вкладені секції через `_`; індексовані — через ім'я: `ALDAP_UPSTREAM_<NAME>_<KEY>`, `ALDAP_PROFILE_<NAME>_<KEY>`. Імена upstream/profile у env — верхній регістр, дефіс → `_`. Списки — через кому. Приклади:
```
ALDAP_UPSTREAM_AD_MAIN_SERVERS=ldaps://dc1.corp.local:636,ldaps://dc2.corp.local:636
ALDAP_UPSTREAM_AD_MAIN_BIND_PASSWORD_FILE=/run/secrets/ad_pass
ALDAP_PROFILE_VIROLA_LISTEN=:636
ALDAP_API_ENABLED=true
```
Мінімальна конфігурація повністю через env (без toml) має бути можливою для одного upstream і одного профілю.

### 3.4 Повний приклад `aldap.toml`
Файл `aldap.toml.example` у репозиторії є нормативним прикладом; кожен ключ там має коментар. Нижче — семантика секцій.

#### `[server]`
| Ключ | Тип | Дефолт | Опис |
|---|---|---|---|
| `log_level` | string | `info` | `debug/info/warn/error` |
| `log_format` | string | `text` | `text/json` |
| `ipc_socket` | string | `/run/aldap/aldap.sock` (Linux), `\\.\pipe\aldap` (Windows) | локальний канал для `aldapctl` без токена; права 0600 |
| `shutdown_timeout` | duration | `30s` | graceful drain |
| `max_connections` | int | `1024` | глобальний ліміт одночасних клієнтських з'єднань |
| `include` | []string | `[]` | glob-шаблони додаткових TOML (профілі/upstream'и окремими файлами). Дублювання імен — помилка. |

#### `[tls]` (глобальні дефолти для listener'ів, профіль перевизначає)
| Ключ | Опис |
|---|---|
| `mode` | `builtin-ca` (дефолт) або `external` |
| `ca_dir` | каталог вбудованого CA (`ca.crt`, `ca.key` 0600). Створюється `aldap gen-ca` або автоматично при першому старті, якщо `auto_init = true` |
| `cert`, `key` | шляхи для `external` |
| `auto_renew_before` | duration, дефолт `720h` (30 днів): перевипуск вбудованим CA |
| `expiry_alert_before` | duration, дефолт `336h` (14 днів): подія `cert_expiring` |
| `san` | []string додаткові SAN (DNS/IP) для серверного сертифіката |
| `min_version` | `1.2` (дефолт) / `1.3` |
| `client_auth` | `none` (дефолт) / `request` / `require` (mTLS від застосунків) + `client_ca` |

#### `[upstream.<name>]`
| Ключ | Опис |
|---|---|
| `servers` | []string URL у порядку пріоритету: `ldap://host:389`, `ldaps://host:636`. Схема визначає транспорт. |
| `starttls` | bool, для `ldap://` — підняти StartTLS; `starttls_required = true` → без StartTLS не працювати |
| `tls_ca_file` | CA для перевірки сертифіката upstream |
| `tls_insecure_skip_verify` | bool, дефолт `false`. При `true` — WARN у лог при кожному старті і подія `insecure_config` |
| `tls_server_name` | SNI/перевірка імені, якщо відрізняється від host |
| `bind_dn`, `bind_password[_file|_env]` | сервісний акаунт для пошуку. Тільки читання. |
| `base_dn` | корінь каталогу (для RootDSE/валідації bases у профілях) |
| `kind` | `ad` (дефолт) / `generic`. Для `ad` вмикаються AD-специфіки: `objectCategory`, `userAccountControl`, bit-матчі `:1.2.840.113556.1.4.803:`, `memberOf`, `LDAP_MATCHING_RULE_IN_CHAIN` для nested groups, paged control обов'язковий, referrals ігноруються. |
| `health_interval` | duration, дефолт `10s` |
| `health_check` | `rootdse` (дефолт) / `bind` / `search`. `bind` = bind сервісним акаунтом; `search` = bind + пошук `(objectClass=*)` base scope по `base_dn`. |
| `failover.fail_threshold` | int, дефолт `3` послідовних невдач → сервер `down` |
| `failover.recover_threshold` | int, дефолт `2` послідовних успіхів → `up` |
| `failover.prefer_primary` | bool, дефолт `true` — повертатись на перший живий у списку |
| `pool.size` | int, дефолт `4` з'єднань на сервер |
| `pool.max_idle` | duration, дефолт `5m` |
| `timeouts.connect/bind/search` | duration, дефолти `5s/5s/30s` |
| `page_size` | int, дефолт `500` |
| `audit_service_account` | bool, дефолт `true`: при старті перевірити членство сервісного акаунта в `Domain Admins`/`Enterprise Admins`/`Administrators`/`Account Operators` → WARN + подія `insecure_config` |

#### `[ratelimit]` (глобально; `[profile.<name>.ratelimit]` перевизначає будь-який ключ)
| Ключ | Дефолт | Опис |
|---|---|---|
| `enabled` | `true` | |
| `ip.max_failures` | `20` | невдалих bind'ів з IP за `ip.window` |
| `ip.window` | `5m` | |
| `ip.lock_duration` | `15m` | |
| `ip.bind_rps` | `10` | token bucket, burst = `ip.bind_burst` (`20`) |
| `ip.search_rps` | `50` | burst `100` |
| `account.max_failures` | `3` | **має бути менше за lockout threshold в AD**; `aldap check` попереджає, якщо ≥ 5 |
| `account.window` | `10m` | |
| `account.lock_duration` | `15m` | |
| `negative_cache_ttl` | `60s` | пара (акаунт, SHA-256(salt‖пароль)) після невдачі не ходить в upstream |
| `delay.base` | `250ms` | затримка після 1-ї невдачі; зростає ×2 до `delay.max` (`4s`) |
| `constant_time_bind_fail` | `true` | вирівняти час відповіді на будь-який невдалий bind до `p95` успішних (анти-enumeration) |
| `lock_response` | `invalidCredentials` | або `busy` |
| `allow_cidrs` | `[]` | IP без лімітів (сервісні джерела) |
| `allow_accounts` | `[]` | акаунти без блокування (сервісні) |
| `tarpit.enabled` | `false` | для IP у стані `attack`: тримати з'єднання, відповідати з затримкою `tarpit.delay` (`30s`), ліміт `tarpit.max_conns` (`64`) |
| `lockdown.auto` | `false` | авто-lockdown при події `attack_start` рівня `high` |
| `lockdown.allow_cidrs`, `lockdown.allow_accounts` | | хто працює під час lockdown; решта — відмова без upstream |

Стан: лише в пам'яті. При рестарті скидається. `aldapctl locks` показує, `aldapctl unlock` знімає.

#### `[ids]` — детектори (усі `enabled` за замовчуванням, крім `fingerprint`)
| Детектор | Параметри | Подія |
|---|---|---|
| `spray` | `window=10m`, `min_accounts=5`, `same_password_hash=true` | `attack_start{kind=spray}` |
| `stuffing` | `window=5m`, `min_pairs=20` з одного IP | `attack_start{kind=stuffing}` |
| `slow_brute` | `window=6h`, `min_failures=30`, `max_rate_per_min=2` | `attack_start{kind=slow_brute}` |
| `enumeration` | послідовні bind'и по ≥`min_accounts=10` різних акаунтах без успіху | `attack_start{kind=enumeration}` |
| `recon` | сигнатури у пошуках: `(objectClass=*)` subtree від кореня; запит `nTSecurityDescriptor`, `sIDHistory`, `trustPartner`, `msDS-*`, `adminCount`, масовий `servicePrincipalName`; base поза профілем | `recon{signature}` |
| `anomaly` | базова лінія на профіль: множина IP, фільтрів (нормалізований AST), bases, атрибутів, RPS p95. Навчання `learn_for=24h` після старту або `aldapctl baseline learn`; після — відхилення → `anomaly{reason}` | `anomaly` |
| `honeytoken` | список акаунтів у профілі `honeytokens=[...]`; bind/search по них | `honeytoken` + негайний `lock_ip` |
| `fingerprint` | TLS ClientHello (JA3-подібний хеш) + LDAP (версія, порядок controls, розмір BER першого пакета). Зміна відбитка на профілі → `anomaly{reason=fingerprint}` | `anomaly` |

`attack_summary` кожні `summary_interval=5m` під час атаки; `attack_end` після `quiet_period=15m` без спрацювань. Рівні: `low/medium/high` за кількістю/швидкістю.

#### `[profile.<name>]`
| Ключ | Опис |
|---|---|
| `listen` | `":636"` або `"10.0.0.5:636"`; кілька — список |
| `transport` | `ldaps` (дефолт для 636) / `ldap` / `starttls` / `ldap+starttls` (plain дозволений, StartTLS опційний). `starttls_required=true` → bind без TLS відхиляється `confidentialityRequired` |
| `tls.*` | перевизначення `[tls]` |
| `upstream` | ім'я upstream |
| `mode` | `proxy` (дефолт) / `honeypot` (будь-який запит → `honeytoken` + lock) / `mock` (відповіді з `mock.file` TOML/CSV без upstream) |
| `virtual_base` | DN, який бачить клієнт, напр. `ou=virola,dc=aldap`. Усі DN у відповідях переписуються під нього; вхідні bases поза ним → `noSuchObject` |
| `bases` | []string реальні DN upstream для пошуку користувачів (субдерева, scope `sub`) |
| `filter` | обов'язковий фільтр, AND-ується до будь-якого клієнтського; дефолт для `kind=ad`: `(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))` |
| `exclude_filter` | опційний, NOT-ується |
| `attrs.allow` | allowlist атрибутів, які віддаються. `*` заборонено. Операційні атрибути — тільки якщо перелічені |
| `attrs.map` | таблиця `client_name = "upstream_name"`: `uid = "sAMAccountName"`, `mail = "mail"` |
| `attrs.computed` | таблиця `name = "go-template"`: `mail = "{{ or .mail (printf \"%s@corp.local\" .sAMAccountName) }}"`, `displayName = "{{ .sn }} {{ .givenName }}"`. Доступні функції: `or`, `printf`, `lower`, `upper`, `trim`, `default`, `first`, `join`, `regexReplace` |
| `attrs.mask` | таблиця `name = "pattern"`: `telephoneNumber = "***{last4}"`, `mail = "{first1}***@{domain}"` |
| `objectclass.map` | `user = "inetOrgPerson"` тощо |
| `rdn_attr` | атрибут для RDN у віртуальних DN, дефолт `cn`; користувач → `cn=<rdn_attr>,ou=users,<virtual_base>` |
| `client_bind.dn`, `client_bind.password[_file|_env]` | локальний сервісний логін застосунку. Якщо не задано — сервісний bind застосунку неможливий, лише user bind |
| `user_bind.allow` | `true` (дефолт): прокидати bind користувачів в upstream. Форми: UPN, `DOMAIN\user`, sAMAccountName (+`user_bind.default_domain`), DN у віртуальній базі (переписується на реальний DN) |
| `user_bind.require_membership` | опційно: лише користувачі, що проходять `filter`/є у віртуальній групі |
| `anonymous_bind` | `false` (дефолт) |
| `groups.<gname>` | віртуальні групи, див. 4.4 |
| `nested_groups` | bool: транзитивний `memberOf` (для `ad` — через `LDAP_MATCHING_RULE_IN_CHAIN`; для `generic` — рекурсія з лімітом глибини `nested_depth=10`) |
| `honeytokens` | []string акаунтів-пасток (віддаються в пошуку як звичайні користувачі з правдоподібними атрибутами з `honeytoken_template`) |
| `cache.mode` | `none` / `ttl` / `replica` (див. 5) |
| `limits.max_result_size` | дефолт `5000` |
| `limits.max_filter_depth` | `20`; `limits.max_filter_len` `4096`; `limits.max_request_bytes` `1MiB` |
| `limits.max_conns_per_ip` | `32` |
| `limits.idle_timeout` | `10m` |
| `ratelimit.*` | перевизначення |
| `shadow.filter`, `shadow.bases` | тіньові правила: виконуються паралельно, у лог/подію `shadow_diff` іде різниця, клієнт бачить основні |
| `record.enabled`, `record.file` | запис запитів (без паролів) у JSONL для replay |

#### `[events]`
| Ключ | Опис |
|---|---|
| `schema` | фіксовано `aldap.event.v1` (інформаційно) |
| `buffer_size` | кільцевий буфер у пам'яті, дефолт `100000` подій |
| `hash_accounts` | bool: замінити `account` на `sha256(salt‖account)`; `salt_file` |
| `include` / `exclude` | списки типів подій (глобальний фільтр) |
| `[events.stdout]` | `enabled`, `format=json` |
| `[events.file]` | `path`, `max_size_mb=100`, `max_files=10`, `compress=true` |
| `[events.syslog]` | `network=udp/tcp/unix`, `address`, `facility`, RFC5424 |
| `[[events.webhook]]` | `url`, `events=[...]`, `batch_size=100`, `batch_interval=2s`, `timeout=5s`, `retry.max=5`, `retry.backoff=1s..60s`, `hmac_secret[_file]` → заголовок `X-ALDAP-Signature: sha256=<hex>`, `headers={}`, `tls_ca_file`, `queue_size=10000`, `on_overflow=drop_oldest/block` |

#### `[notify]` та `[[notify.channel]]`
| Ключ | Опис |
|---|---|
| `cooldown` | дефолт `10m` на (канал, тип події, ключ) |
| `digest_interval` | `15m`: під час атаки — зведення замість окремих повідомлень |
| `channel.name`, `channel.type` | `telegram` / `virola` / `email` / `webhook` |
| `channel.events` | список подій; дефолт `["attack_start","attack_summary","attack_end","lock_account","upstream_down","upstream_up","cert_expiring","honeytoken","lockdown"]` |
| `channel.min_level` | `low/medium/high` |
| `channel.template_dir` | перевизначення вбудованих шаблонів |
| **telegram** | `bot_token[_file]`, `chat_id`, `parse_mode=MarkdownV2`, `api_base` (дефолт `https://api.telegram.org`) |
| **virola** | `base_url` (`https://host:port`), `token[_file]` (Web API Access Token; заголовок `Authorization: Bearer <token>`), `room_id` або `user_id`; запит `POST /api/v1/rooms/{room_id}/messages` або `POST /api/v1/users/{user_id}/messages` з тілом `{"content": "..."}`; `tls_ca_file`, `tls_insecure_skip_verify` |
| **email** | `smtp_host`, `smtp_port`, `tls=starttls/tls/none`, `username`, `password[_file]`, `from`, `to=[...]`, `subject_template` |
| **webhook** | `url`, `method=POST`, `headers`, `body_template` (Go text/template → будь-який JSON), `hmac_secret[_file]`, `timeout`, `retry.*` |

Шаблони отримують структуру події (розділ 6) + `Hostname`, `Version`.

#### `[api]`
| Ключ | Опис |
|---|---|
| `enabled` | дефолт `false` (IPC-сокет для `aldapctl` працює завжди) |
| `listen` | `127.0.0.1:8636` |
| `tls.cert/key` або `tls.builtin=true` | **обов'язково**, якщо `listen` не loopback; інакше старт відхиляється |
| `client_auth` | mTLS: `none/require` + `client_ca` |
| `[[api.token]]` | `name`, `token[_file]` (мін. 32 байти), `scopes=["events:read","locks:read","locks:write","status:read","admin"]`, `allow_cidrs` |
| `rate_limit_rps` | `50` |
| `metrics.enabled` | `true`; `metrics.listen` окремо (дефолт той самий); `/metrics` вимагає scope `status:read` або `metrics.public=true` |
| `cors` | вимкнено |

### 3.5 Валідація (`aldap check`)
Повертає ненульовий код і список помилок/попереджень. Перевіряє:
- синтаксис TOML, невідомі ключі (помилка), типи;
- унікальність імен, портів, `virtual_base`;
- парсинг усіх фільтрів (RFC 4515) і DN;
- секрети: не більше одного джерела, файли існують і читаються, права файлів ≤ 0640 (warn);
- TLS: сертифікати читаються, строк дії, SAN містить listen-хости (warn);
- `account.max_failures` ≥ 5 → warn; `tls_insecure_skip_verify=true` → warn; `transport=ldap` без StartTLS → warn; inline-пароль → warn;
- `--online`: з'єднання з кожним upstream, bind, RootDSE, тестовий пошук по кожному `bases`, аудит прав сервісного акаунта;
- `--profile <name> --as-client`: емуляція клієнтського запиту і вивід, що клієнт побачить.

### 3.6 Hot reload
`SIGHUP`, `POST /v1/reload`, `aldapctl reload`. Нова конфігурація валідується; при помилці стара лишається, подія `config_reload{ok=false}`. Зміна `listen` — відкриває/закриває listener'и без розриву решти; зміна правил профілю — атомарна (нові з'єднання/запити бачать нові правила; поточні запити завершуються за старими). Стан rate limit не скидається.

---

## 4. Віртуальний каталог

### 4.1 Модель
Клієнт бачить дерево:
```
<virtual_base>                      objectClass: organizationalUnit (або domain)
├── ou=users,<virtual_base>         користувачі
│   └── cn=<rdn>,ou=users,...       кожен — з атрибутами за allow/map/computed/mask
└── ou=groups,<virtual_base>        віртуальні групи
    └── cn=<gname>,ou=groups,...    member: DN користувачів у віртуальній базі
```
RootDSE віддається ALDAP'ом: `namingContexts` = усі `virtual_base` активних профілів на цьому listener'і (зазвичай один), `supportedLDAPVersion=3`, `supportedControl` = paged results (1.2.840.113556.1.4.319) + те, що ALDAP реально підтримує, `supportedSASLMechanisms` порожньо, `vendorName=ALDAP`.
Subschema не емулюється повністю: `cn=Subschema` повертає мінімальний набір (objectClasses/attributeTypes, що використовуються у профілі), оскільки деякі клієнти його читають.

### 4.2 Обробка Search
1. **Валідація**: розмір запиту, глибина/довжина фільтра, base у межах `virtual_base`, scope.
2. **Класифікація base**: RootDSE → локальна відповідь; `<virtual_base>` / `ou=users` / `ou=groups` → відповідні гілки; `cn=...,ou=groups` → одна група; `cn=...,ou=users` → один користувач (RDN → пошук в upstream за `rdn_attr`).
3. **Переписування фільтра**: парсинг у AST → мапінг імен атрибутів (client→upstream за `attrs.map`, зворотний для computed/virtual-атрибутів: фільтр по computed-атрибуту обчислюється пост-фактум на стороні ALDAP, по `memberOf` віртуальної групи — через membership-набір групи); атрибут поза `attrs.allow`+`attrs.map`+computed → для `recon` подія і фільтр-терм замінюється на `FALSE` (а не помилка — щоб не підказувати схему); AND з `filter`, AND NOT з `exclude_filter`.
4. **Виконання**: для кожного `bases` — paged search в upstream із запитом тільки тих upstream-атрибутів, що потрібні для allow/map/computed/mask + `distinguishedName`,`objectGUID`,`memberOf` (якщо потрібно). Паралельно по bases, ліміт `limits.upstream_parallel=4`.
5. **Злиття**: дедуплікація по `objectGUID` (AD) або по upstream DN (`generic`); порядок — стабільний (за DN).
6. **Трансформація**: map → computed → mask → objectclass.map → переписування DN у віртуальний (user DN = `cn=<rdn_attr value>,ou=users,<virtual_base>`; колізії RDN → суфікс `+objectGUID` і WARN). `memberOf` = віртуальні групи, де користувач є членом.
7. **Пост-фільтрація** по термах, які не можна було виконати в upstream (computed, virtual memberOf).
8. **Ліміти**: `sizeLimit` клієнта і `limits.max_result_size` → `sizeLimitExceeded`. Paged results до клієнта підтримуються (cookie — opaque, прив'язаний до з'єднання; зберігаємо вже злитий результат у пам'яті з'єднання до завершення/таймауту).
9. **Події**: `search` (profile, conn_id, base, scope, filter_norm, attrs_requested, attrs_denied, results, upstream_queries, duration_ms, cache_hit).

### 4.3 Обробка Bind
- **Anonymous** → `invalidCredentials`, подія `bind_fail{reason=anonymous}` (якщо `anonymous_bind=false`).
- **Client bind** (DN == `client_bind.dn`): перевірка пароля constant-time (bcrypt/argon2id хеш у пам'яті з конфіг-значення). Успіх → сесія з правами «пошук по профілю».
- **User bind**: нормалізація ідентифікатора:
  - UPN `user@realm` → в upstream як є;
  - `DOMAIN\user` → `user@<user_bind.default_domain>` або як є (`kind=ad` приймає обидва);
  - `sAMAccountName` без домену → UPN з `default_domain`;
  - віртуальний DN `cn=...,ou=users,<virtual_base>` → пошук сервісним акаунтом користувача за `rdn_attr`, узяти реальний DN → bind цим DN.
  - Перед походом в upstream: rate limit (IP/акаунт), negative cache, lockdown, honeytoken.
  - Bind в upstream — окремим з'єднанням з пулу «bind-only» (не змішувати із сервісним), після відповіді з'єднання повертається в пул (re-bind сервісним) або закривається.
  - Опційно `user_bind.require_membership`: після успіху — пошук користувача з `filter`; не пройшов → `invalidCredentials`, подія `bind_fail{reason=not_member}`.
- Коди помилок upstream (`invalidCredentials`, `AcceptSecurityContext error, data 52e/533/775/701/773`) мапляться: 52e → невірний пароль; 533 (disabled), 775 (locked), 701 (expired), 773 (must change) → клієнту `invalidCredentials`, в подію — справжня причина `reason=disabled|locked_in_ad|expired|must_change`. **Важливо:** `locked_in_ad` → подія рівня `medium` (перебір дійшов до AD).
- `constant_time_bind_fail`: невдалі відповіді віддаються не раніше, ніж через ковзний p95 тривалості успішних bind'ів.

### 4.4 Віртуальні групи
```toml
[profile.virola.groups.virola-users]
description = "All Virola users"
objectclass = "groupOfNames"        # або "group" (AD-подібно), "posixGroup"
gid_number  = 10001                  # для posixGroup
[profile.virola.groups.virola-users.members]
bases      = ["OU=Office,DC=corp,DC=local", "CN=Users,DC=corp,DC=local"]   # дефолт: profile.bases
filter     = "(&(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"  # дефолт: profile.filter
ad_groups  = ["CN=Staff,OU=Groups,DC=corp,DC=local"]   # члени реальних груп (з nested за profile.nested_groups)
include    = ["admin@corp.local"]    # явно додати
exclude    = ["svc-backup@corp.local"]
```
Членство = (користувачі за `bases`+`filter`) ∪ (члени `ad_groups`) ∪ `include` − `exclude`, і обов'язково ∩ (користувачі, що проходять `profile.filter`).
Membership обчислюється ліниво і кешується за `cache` профілю (для `none` — TTL `groups.ttl=60s` мінімум, щоб `member`/`memberOf` були узгоджені в межах одного запиту). `member` — віртуальні DN; `memberOf` у користувачів — віртуальні DN груп. Пошук `(member=<dn>)` і `(memberOf=<dn>)` підтримується.

### 4.5 Honeytokens
`honeytokens = ["h.petrenko@corp.local", "backup-admin@corp.local"]`. Генеруються як користувачі з атрибутами з `honeytoken_template` (cn/sn/givenName/mail/title — правдоподібні), потрапляють у пошук і у віртуальні групи (якщо `honeytoken_in_groups=true`). Будь-який bind по них або search з фільтром, що однозначно таргетує їх (`(sAMAccountName=...)`, `(mail=...)`, `(cn=...)`) → подія `honeytoken{level=high}` + `lock_ip` на `honeytoken_lock=24h`. Якщо `mode=honeypot` — увесь профіль є пасткою.

### 4.6 Маскування
Патерни: `{first<N>}`, `{last<N>}`, `{domain}`, `***`. Маскування відбувається після computed, фільтрація по маскованому атрибуту в upstream виконується по оригіналу (це свідомо: маскування — для відображення).

---

## 5. Кеш, репліка, failover

### 5.1 `cache.mode`
| Режим | Поведінка |
|---|---|
| `none` | кожен запит → upstream (крім group-membership TTL) |
| `ttl` | ключ = (profile, normalized filter, bases, attrs, scope, base); `cache.ttl=60s`; `cache.max_entries=10000`; `cache.stale_while_down=true` — якщо всі сервери upstream `down`, віддавати протухлі записи до `cache.stale_max=1h` з подією `stale_served` |
| `replica` | фоновий повний sync профілю (усі `bases` × `filter`, усі потрібні атрибути) кожні `cache.sync_interval=5m` у пам'ять; відповіді — тільки з пам'яті; `cache.sync_jitter=20%`; при невдачі sync — остання копія лишається, подія `replica_sync_failed`; `aldapctl sync <profile>` — примусово. User bind завжди йде в upstream (паролі не кешуються). |

### 5.2 Failover
Кожен сервер upstream має стан `up/down/unknown`, лічильники послідовних успіхів/невдач, останню помилку, p50/p95 латентність. Health-check — за `health_check`. Запит іде на перший `up` у порядку списку (`prefer_primary`) або round-robin (`strategy=roundrobin`). Невдача операції на сервері = невдача health (fail-fast), повторити на наступному `up` (лише для ідемпотентних: search, bind сервісним; user bind повторюється лише при мережевій помилці, не при `invalidCredentials`). Події `upstream_down/up` з `server`, `reason`.

### 5.3 Graceful
SIGTERM/`aldapctl stop`: закрити listener'и, дочекатись активних запитів до `shutdown_timeout`, завершити з'єднання `unavailable` notice (RFC 4511 §4.4.1), скинути event-черги (webhook — dочекатись до таймауту), зупинитись.

---

## 6. Події (`aldap.event.v1`)

Кожна подія — один JSON-об'єкт (JSONL). Усі поля `snake_case`. Обов'язкові: `schema`, `ts`, `id`, `event`, `level`, `host`.

```json
{
  "schema": "aldap.event.v1",
  "ts": "2026-10-18T10:21:33.412Z",
  "id": "01J9ZK3...ULID",
  "seq": 48213,
  "event": "bind_fail",
  "level": "low",
  "host": "aldap-01",
  "profile": "virola",
  "conn_id": "c-7f3a",
  "client_ip": "10.0.5.12",
  "client_port": 51234,
  "tls": true,
  "account": "j.doe@corp.local",
  "account_hash": null,
  "reason": "invalid_password",
  "failures": 2,
  "upstream": "ad-main",
  "upstream_server": "ldaps://dc1.corp.local:636",
  "duration_ms": 42,
  "data": {}
}
```
`data` — специфічні поля події. Типи подій і їх `data`:

| event | level | data |
|---|---|---|
| `bind_ok` | low | `{bind_kind: client|user, upstream_dn}` |
| `bind_fail` | low/medium | `{reason: invalid_password|unknown_account|disabled|locked_in_ad|expired|must_change|anonymous|not_member|upstream_error, failures}` |
| `bind_blocked` | medium | `{reason: ip_locked|account_locked|negative_cache|lockdown|rate_limited}` |
| `lock` | medium | `{target: ip|account, key, until, failures, source: ratelimit|ids|api|honeytoken}` |
| `unlock` | low | `{target, key, source: expiry|api|tui}` |
| `attack_start` / `attack_summary` / `attack_end` | medium/high | `{kind, attack_id, ips[], accounts_count, failures, rate_per_min, first_seen, last_seen}` |
| `recon` | medium | `{signature, filter_norm, base, attrs}` |
| `anomaly` | medium | `{reason: new_ip|new_filter|new_base|new_attrs|rps_spike|fingerprint, observed, baseline}` |
| `honeytoken` | high | `{account, op: bind|search}` |
| `search` | low | `{base, scope, filter_norm, attrs_requested[], attrs_denied[], results, upstream_queries, cache_hit, denied_terms[]}` |
| `op_denied` | medium | `{op: add|modify|delete|modrdn|compare|extended, oid}` |
| `session_summary` | low | `{binds_ok, binds_fail, searches, results_total, denied, duration_ms, bytes_in, bytes_out, fingerprint}` |
| `rate_limited` | low | `{target, key, rps}` |
| `tarpit` | low | `{ip, conns}` |
| `lockdown` | high | `{state: on|off, source}` |
| `upstream_down` / `upstream_up` | high/medium | `{server, reason, consecutive}` |
| `stale_served` / `replica_sync_failed` / `replica_synced` | medium/low | `{age_s, entries}` |
| `cert_expiring` / `cert_renewed` | medium/low | `{subject, not_after, days_left}` |
| `config_reload` | low/high | `{ok, errors[]}` |
| `insecure_config` | medium | `{what}` |
| `shadow_diff` | low | `{added[], removed[]}` (кількості + до 20 прикладів) |
| `startup` / `shutdown` | low | `{version, profiles[]}` |

Правила:
- Паролі, токени, cookie — ніколи. Фільтр логується нормалізованим (без значень? — ні: значення лишаються, бо потрібні IDS; але значення атрибутів `unicodePwd`/`userPassword` у фільтрі редагуються у `***`).
- `seq` монотонний у межах процесу; `GET /v1/events?since=<seq>`.
- Схема описана у `docs/events.schema.json` (JSON Schema draft 2020-12); тест перевіряє всі події проти схеми.

---

## 7. API

OpenAPI 3.1 у `docs/openapi.yaml` (нормативний; код і тести звіряються з ним).

| Метод | Шлях | Scope | Опис |
|---|---|---|---|
| GET | `/v1/status` | status:read | версія, аптайм, профілі, upstream'и зі станами, лічильники |
| GET | `/v1/upstreams` | status:read | детально по серверах |
| GET | `/v1/profiles` | status:read | профілі без секретів |
| GET | `/v1/locks` | locks:read | активні блоки |
| POST | `/v1/locks` | locks:write | `{target: ip|account, key, duration, reason}` |
| DELETE | `/v1/locks/{target}/{key}` | locks:write | розблокувати |
| GET | `/v1/indicators` | locks:read | підозрілі IP/акаунти зі score, причинами, `first_seen/last_seen`; `?format=json|stix-lite|plain` |
| GET | `/v1/events` | events:read | `?since=<seq>&limit=1000&types=a,b` з буфера |
| GET | `/v1/events/stream` | events:read | SSE, `Last-Event-ID` = seq |
| POST | `/v1/lockdown` | locks:write | `{state: on|off}` |
| GET | `/v1/config` | admin | конфіг з `***` замість секретів |
| PUT | `/v1/config` | admin | повний TOML у тілі; валідація; атомарний запис (`.tmp`+rename) + reload; бекап попереднього `aldap.toml.bak.<ts>` |
| POST | `/v1/reload` | admin | |
| POST | `/v1/profiles/{name}/sync` | admin | примусовий replica sync |
| POST | `/v1/profiles/{name}/test` | admin | `{base, scope, filter, attrs}` → що побачить клієнт + діагностика (`denied_terms`, `upstream_queries`) |
| POST | `/v1/baseline/{profile}/learn` | admin | `{duration}` |
| GET | `/metrics` | status:read / public | Prometheus |
| GET | `/healthz` | public | 200, якщо процес живий; `/readyz` — 200, якщо ≥1 upstream `up` для кожного профілю `proxy` |

Автентифікація: `Authorization: Bearer <token>`; IPC-сокет — без токена, scope `admin`. Усі відповіді `application/json`; помилки `{error, code}`. Audit: кожен виклик зі scope `locks:write`/`admin` → подія `api_call{method,path,token_name,client_ip}`.

---

## 8. `aldapctl` (TUI + CLI)

Підключення: `--socket` (дефолт IPC) або `--url https://host:8636 --token-file`.

**CLI:** `status`, `upstreams`, `profiles`, `locks [--json]`, `unlock <ip|account>`, `lock <ip|account> --for 1h`, `lockdown on|off`, `events [--follow] [--types]`, `indicators`, `reload`, `config get|set <file>`, `test <profile> --base --filter --attrs`, `sync <profile>`, `baseline learn <profile> --for 24h`, `record start|stop <profile>`, `replay <file> --profile`, `bundle --out aldap-bundle.tgz` (конфіг без секретів, останні 10k подій, версії, health, `go version`, метрики), `version`.

**TUI** (`aldapctl` без аргументів): вкладки `Status | Upstreams | Profiles | Locks | Events | Indicators | Config`. Events — live-стрім з фільтром по типу/профілю/IP, пошук, пауза. Locks — список, `u` unlock, `l` lock. Config — перегляд, відкрити в `$EDITOR`, валідувати, застосувати. Гарячі клавіші за конвенцією Bubble Tea (`?` — довідка). Усі дії підтверджуються (`y/n`). Кольори — lipgloss, адаптивні до темної/світлої теми, працює без 256 кольорів.

---

## 9. Безпека

- Процес: non-root (UID 65532 у DHI static), read-only FS, `cap_net_bind_service` або порти > 1024 з мапінгом у compose; seccomp-профіль `deploy/seccomp.json`.
- TLS: мін. 1.2, набори шифрів Go-дефолт без RC4/3DES; серверний сертифікат ECDSA P-256 (дефолт) або RSA-2048 (`tls.key_type`), строк 825 днів (вбудований CA — 10 років); приватні ключі 0600.
- Паролі client_bind зберігаються у пам'яті як argon2id-хеш (параметри: t=3, m=64MiB, p=4), порівняння constant-time; у конфігурації — plaintext (бо застосунок все одно шле plaintext), але підтримується `client_bind.password_hash = "$argon2id$..."` як альтернатива.
- Пам'ять: паролі user bind — `[]byte`, обнуляються після використання; не потрапляють у рядки логів/подій/panic traces (recover-обгортка редагує).
- BER: ліміт розміру пакета `limits.max_request_bytes`; відмова на вкладеність > 64; fuzz-тести на парсер фільтрів і DN.
- Захист від DoS: ліміти з'єднань на IP/глобально, idle timeout, read deadline на перший пакет `5s`, ліміт одночасних пошуків на з'єднання `4`.
- Негативні відповіді не розкривають існування акаунта/атрибута/бази (один код `invalidCredentials`/`noSuchObject`, вирівняний час).
- Конфіг: невідомі ключі — помилка (захист від друкарських помилок у security-ключах).
- `tls_insecure_skip_verify`, `transport=ldap` без TLS, inline-паролі — WARN при старті + подія `insecure_config`.
- Залежності: `govulncheck` у CI; `go.sum` закріплений; `-trimpath -buildvcs=false`, `CGO_ENABLED=0`.
- SBOM (CycloneDX) і підпис образу/бінарників (`cosign`) у release-пайплайні.

---

## 10. Збірка та розгортання

### 10.1 Бінарники
`make build` → `dist/aldap_<os>_<arch>`, `dist/aldapctl_<os>_<arch>` для `linux/amd64`, `linux/arm64`, `windows/amd64`. `-ldflags "-s -w -X main.version=... -X main.commit=... -X main.date=..."`.

### 10.2 Docker (DHI)
`Dockerfile` — multi-stage:
- build: `dhi.io/golang:<GO_MINOR>-debian13-dev` (тег параметризований `ARG DHI_GOLANG_TAG`), `CGO_ENABLED=0`;
- runtime: `dhi.io/static:<DHI_STATIC_TAG>` (ARG), non-root, `COPY --chown=65532:65532`, `HEALTHCHECK` через `aldap check --quick` (не потребує shell), `VOLUME /etc/aldap /var/lib/aldap`, `EXPOSE` не фіксуємо (порти з профілів).
`build.sh --dhi` вимагає попереднього `docker login dhi.io`; `--plain` — `golang:1.x-alpine` + `scratch` для локальних тестів; `--windows`, `--linux` — бінарники; `--all`.
Теги DHI на момент написання підлягають перевірці в каталозі `https://hub.docker.com/hardened-images/catalog/` — скрипт приймає їх як змінні `DHI_GOLANG_TAG`, `DHI_STATIC_TAG` і виводить підказку, якщо pull не вдався.

### 10.3 compose
`docker-compose.yml`: сервіс `aldap`, `read_only: true`, `tmpfs: /tmp`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, `secrets:` для паролів, volume для `aldap.toml` і CA, `healthcheck`. Приклад з двома профілями. Опційно сервіс `samba-dc` для локального тестування (profile `test`).

### 10.4 systemd
`deploy/aldap.service`: `DynamicUser=yes`, `LoadCredential=ad_pass:/etc/aldap/secrets/ad_pass` (→ `bind_password_file=${CREDENTIALS_DIRECTORY}/ad_pass`), `AmbientCapabilities=CAP_NET_BIND_SERVICE`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `NoNewPrivileges=yes`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `SystemCallFilter=@system-service`, `RuntimeDirectory=aldap` (для сокета), `StateDirectory=aldap`, `Restart=on-failure`, `ExecReload=/bin/kill -HUP $MAINPID`.

### 10.5 Windows
`aldap.exe service install --config C:\ProgramData\ALDAP\aldap.toml` через `kardianos/service`; лог у Event Log + файл; IPC — named pipe з ACL «Administrators + SYSTEM». ⚠️ Не тестується у CI (немає Windows-раннера в базовій конфігурації) — позначено як best effort; ручний чекліст у `docs/windows.md`.

---

## 11. Спостережуваність

Prometheus-метрики (префікс `aldap_`): `connections_active{profile}`, `binds_total{profile,result}`, `bind_duration_seconds{profile}`, `searches_total{profile,cache}`, `search_results{profile}` (histogram), `upstream_queries_total{upstream,server,op,result}`, `upstream_latency_seconds{upstream,server,op}`, `upstream_up{upstream,server}`, `locks_active{target}`, `attack_active{kind}`, `events_total{event}`, `events_dropped_total{sink}`, `notify_total{channel,result}`, `cache_entries{profile}`, `replica_age_seconds{profile}`, `profile_cost{profile}` (histogram upstream_queries на один клієнтський запит), `cert_expiry_seconds{listener}`, `build_info`.

Текстовий лог демона (stdout/journald) — про роботу процесу, не аудит; `log_format=json` для збирачів.

---

## 12. Сумісність з клієнтами

Обов'язково перевірити (інтеграційні тести з реальними клієнтськими бібліотеками/утилітами):
- `ldapsearch` (OpenLDAP) з `-x`, `-ZZ`, `ldaps://`, `-E pr=100/noprompt`;
- Python `ldap3` (simple bind, paged search, `memberOf`);
- Go `go-ldap` (як клієнт);
- Virola Messenger — ручний чекліст `docs/virola.md`: Base DN = `ou=users,<virtual_base>` або `<virtual_base>`, атрибут автентифікації `userPrincipalName`, сервісний акаунт = `client_bind.dn`, порт 636 + свій CA.
Поведінка з `objectClass=*` по `virtual_base` scope `sub`: повернути `ou=users`, `ou=groups`, усіх користувачів, усі групи (у межах лімітів).

---

## 13. Критерії приймання (DoD проєкту)

1. `make ci` (lint, vet, vuln, licenses, unit, integration-inmem) — зелений.
2. `make integration-samba` проти Samba AD DC у Docker — зелений: злиття двох bases, виключення computer-об'єктів, user bind UPN/sAMAccountName, віртуальна група з `member`/`memberOf`, nested groups, paged results, failover між двома DC (зупинка одного контейнера), lock після 3 невдач, негативний кеш, honeytoken, recon-сигнатура, webhook з HMAC, SSE.
3. `aldap check --online` на тестовому стенді — без помилок.
4. `docker build` з DHI-образами проходить (у CI — з секретом логіну або `--plain` fallback з явним повідомленням).
5. `aldapctl` TUI запускається, показує статус/locks/events, unlock працює.
6. Покриття unit-тестами ≥ 80% для `ldapfilter`, `vdir`, `ratelimit`, `ids`, `config`, `events`.
7. `docs/`: README (швидкий старт compose за 5 хвилин), `config.md` (усі ключі), `events.md`, `api.md` (з OpenAPI), `virola.md`, `windows.md`, `security.md`, `THIRD_PARTY_LICENSES.md`.
8. Жоден тест/лог/подія не містить паролів (grep-тест по артефактах CI).

---

## 14. Відкриті питання (позначені для верифікації під час реалізації)

- ⁉️ Чи приймає Virola власний CA / чи є перемикач перевірки сертифіката — перевірити на реальній інсталяції; інакше CA додається в довірені ОС хоста Virola.
- ⁉️ Точні теги DHI (`golang`, `static`) на момент збірки.
- ⁉️ Формат cookie paged results, який Virola очікує між викликами (стандартний opaque — припущення).
- ⁉️ Поведінка `kardianos/service` на Windows Server 2012 R2 — не перевірено.
