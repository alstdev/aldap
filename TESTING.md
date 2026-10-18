# TESTING.md — стратегія тестування ALDAP

## Рівні

| Рівень | Tag | Що | Де запускається |
|---|---|---|---|
| Unit | — | чиста логіка: парсери, AST, rate limit, IDS, config, events, cache | `make test`, CI на кожен push |
| Fuzz | — | `ldapfilter`, DN, BER-вхід listener'а | `make fuzz` (2 хв), CI nightly 10 хв |
| Integration (in-memory) | `integration` | ALDAP ↔ `internal/testdir` (gldap testdirectory з AD-подібною схемою), 1–2 upstream-сервери в процесі | `make integration`, CI на кожен push |
| E2E clients | `integration` | `ldapsearch` (OpenLDAP utils у CI-образі), Python `ldap3` (у Docker), go-ldap як клієнт | `make integration` |
| Samba AD | `integration_samba` | ALDAP ↔ реальний Samba AD DC (Docker), 2 DC для failover | `make integration-samba`, CI nightly + перед релізом |
| Security | — | `govulncheck`, `gosec` (у golangci), ліцензії, `TestNoSecretsInOutput` | CI на кожен push |
| TUI | — | Bubble Tea model tests, golden-вивід CLI | `make test` |

Пороги покриття (`go test -coverprofile`, перевірка у `make ci`):
`ldapfilter` 90, `vdir` 85, `config` 85, `ratelimit` 85, `ids` 85, `events` 85, `upstream` 80, `api` 80, `cache` 80, `notify` 75, `listener` 70, загальне ≥ 80.

## In-memory тестовий каталог (`internal/testdir`)
На базі `gldap/testdirectory` з доповненнями:
- AD-подібна схема: `objectCategory`, `objectClass=user/computer/group`, `userAccountControl` з bit-match `:1.2.840.113556.1.4.803:`, `sAMAccountName`, `userPrincipalName`, `memberOf`, `member`, `objectGUID`, `distinguishedName`; `LDAP_MATCHING_RULE_IN_CHAIN` для груп (спрощена реалізація: транзитивне замикання).
- Paged results.
- Імітація кодів bind-помилок AD: user з `uac&2` → `data 533`, `lockoutTime>0` → `775`, `pwdLastSet=0` → `773`.
- Хуки: лічильник викликів (щоб довести, що негативний кеш/lock не ходять в upstream), штучна затримка, примусова «смерть» (для failover).
- Фікстура `testdata/ad.ldif`: 2 OU (`OU=Office`, `OU=Branch`), `CN=Users`, 25 users (3 disabled, 1 locked, 1 must-change), 6 computers, групи `Staff` ⊃ `Managers` ⊃ `Directors` (вкладені), `Contractors`.

## Обов'язкові сценарії (інтеграція, in-memory і Samba)

### Віртуальна база
1. Search по `<virtual_base>` sub `(objectClass=*)` → `ou=users`, `ou=groups`, усі користувачі з двох bases, групи; жодного `computer`.
2. Search `(sAMAccountName=jdoe)` → 1 запис, DN переписано у `cn=...,ou=users,<virtual_base>`, атрибути лише з `attrs.allow`, `uid` змаплено з `sAMAccountName`.
3. Search по атрибуту поза allow → 0 результатів, `resultCode=success`, подія `search{denied_terms}` і `recon` (якщо сигнатура).
4. Disabled користувач не повертається; `(userAccountControl:1.2.840.113556.1.4.803:=2)` від клієнта → 0.
5. Колізія RDN між bases → обидва повертаються з суфіксом, WARN.
6. Computed `mail` для користувача без `mail`; mask телефону; фільтр по computed атрибуту (`(mail=x@corp.local)`) працює через пост-фільтрацію.
7. Група `virola-users`: `member` містить усіх, хто пройшов фільтр, з обох bases; `(memberOf=cn=virola-users,...)` → ті самі; nested: член `Directors` є членом `Staff`.
8. Paged: клієнт просить 10 → 3 сторінки, cookie працює, після завершення cookie порожній; відкидання cookie іншого з'єднання → `unwillingToPerform`.
9. sizeLimit клієнта < результат → `sizeLimitExceeded` з частковими даними.
10. Будь-який Add/Modify/Delete/ModDN/Compare/Extended(passwd) → відмова + `op_denied`.

### Bind
11. Client bind вірний/невірний; anonymous → відмова.
12. User bind: UPN, `DOMAIN\user`, `sAMAccountName`+default_domain, віртуальний DN — усі 4 форми → успіх; невірний пароль → `invalidCredentials`, подія `reason=invalid_password`.
13. Disabled/locked/must_change → клієнту `invalidCredentials`, у події справжній reason; `locked_in_ad` level=medium.
14. `require_membership`: користувач не у фільтрі → відмова.
15. Constant-time: 100 невдалих bind'ів (неіснуючий vs невірний пароль) — різниця медіан < 10% (тест із толерансом, позначений `-short` skip).

### Транспорт
16. Клієнт `ldaps` → ALDAP → upstream `ldap` (plain): працює, WARN `insecure_config` про plaintext до upstream.
17. Клієнт `ldap` + `starttls_required` → bind без StartTLS → `confidentialityRequired`.
18. Upstream `ldaps` з невірним CA → всі сервери down, `/readyz` 503, при `tls_insecure_skip_verify=true` — працює + `insecure_config`.
19. mTLS від клієнта (`client_auth=require`) → без сертифіката з'єднання відхилено.

### Failover, кеш
20. Два upstream; зупинити перший → `upstream_down`, запити йдуть на другий; підняти → повернення на primary (`prefer_primary`).
21. `ttl`: другий однаковий запит не ходить в upstream (лічильник); після TTL — ходить.
22. Усі upstream down + `stale_while_down` → відповідь зі `stale_served`; без нього → `unavailable`.
23. `replica`: upstream вимкнено після sync → search працює, user bind → `unavailable`.

### Rate limit / IDS
24. 3 невдачі одного акаунта → `lock{account}`; 4-та спроба з ПРАВИЛЬНИМ паролем → `bind_blocked`, upstream не викликано; після `lock_duration` → успіх.
25. Негативний кеш: та сама (акаунт, пароль) двічі → другий раз upstream не викликано.
26. 20 невдач з IP по різних акаунтах → `lock{ip}`; акаунти з `allow_accounts` не лочаться; IP з `allow_cidrs` не лімітується.
27. Spray: 1 пароль × 6 акаунтів за 1 хв → `attack_start{kind=spray}`; через quiet_period → `attack_end`; summary між ними.
28. Enumeration: 12 різних акаунтів без успіху → `attack_start{kind=enumeration}`.
29. Recon: `(objectClass=*)` sub від `virtual_base` з атрибутом `nTSecurityDescriptor` → `recon{signature=sd_dump}`.
30. Honeytoken bind → `honeytoken{level=high}` + `lock{ip, source=honeytoken}` на 24h; search з `(mail=<honey>)` → те саме.
31. Baseline: learn 10 с (в тесті), потім bind з нового IP → `anomaly{new_ip}`; новий фільтр → `anomaly{new_filter}`.
32. Lockdown on → bind з IP поза `lockdown.allow_cidrs` → `bind_blocked{lockdown}` без upstream; off → працює.
33. Tarpit: IP у стані attack → відповідь не раніше `tarpit.delay`, не більше `max_conns` одночасно.

### Події, API, notify
34. Кожна згенерована подія валідна за `docs/events.schema.json`.
35. Webhook: батч 100 або 2 с; `X-ALDAP-Signature` перевіряється HMAC; 500 від приймача → ретрай з backoff; переповнення черги → `events_dropped_total` і `drop_oldest`.
36. SSE: клієнт відключився на seq=N, перепідключився з `Last-Event-ID: N` → отримує N+1…
37. Scopes: токен `events:read` на `POST /v1/locks` → 403; `admin` → 200 і подія `api_call`.
38. `PUT /v1/config` з невалідним TOML → 400, файл не змінено; валідний → бекап створено, reload, `config_reload{ok=true}`.
39. Notify: `attack_start` → telegram+virola+email (моки) по одному разу; повторна подія в cooldown → не шлеться; під час атаки — digest раз на інтервал.
40. `aldapctl unlock` через IPC знімає lock; через TCP без токена → 401.

### Безпека
41. `TestNoSecretsInOutput`: прогнати всі сценарії з паролями-маркерами `S3CR3T-<uuid>`, зібрати stdout/stderr/події/файли логів/бандл → grep маркерів = 0.
42. Fuzz: 2 хв без panic на `ldapfilter.Parse`, `dn.Parse`, listener BER-вхід (через gldap).
43. Великий запит > `max_request_bytes` → з'єднання закрито, подія `rate_limited{reason=oversize}`.
44. 40 з'єднань з одного IP при `max_conns_per_ip=32` → 33-тє відхилено.
45. `aldap check` на конфігу з `attrs.allow=["*"]` → помилка; з inline-паролем → warn; `account.max_failures=5` → warn.

### Сумісність
46. `ldapsearch -x -H ldaps://... -D cn=virola,ou=... -w ... -b ou=users,... '(uid=*)' uid mail` — очікуваний вивід (golden).
47. `ldapsearch -x -ZZ -H ldap://...` — StartTLS.
48. Python `ldap3` (Docker `python:3-slim`): simple bind UPN, paged search 50, читання `memberOf`.
49. Virola — ручний чекліст у `docs/virola.md` (не автоматизується).

## Samba AD стенд (`deploy/samba-dc/`)
- `docker compose -f deploy/samba-dc/compose.yml up -d` → `dc1` (+ опційно `dc2` як joined DC; якщо join у контейнерах нестабільний — `dc2` = другий незалежний Samba з тим самим LDIF і документоване обмеження).
- Провізія: `samba-tool domain provision --realm=TEST.ALDAP --domain=TEST --server-role=dc --use-rfc2307`; LDIF `testdata/ad.ldif` адаптований; `ldaps` з self-signed CA, експорт CA у `testdata/samba-ca.pem`.
- Тести під tag `integration_samba` читають `ALDAP_TEST_SAMBA_URL`, `..._BIND_DN`, `..._BIND_PASSWORD_FILE`.
- Failover-тест: `docker stop dc1` → перевірка → `docker start dc1`.

## CI (`.github/workflows/ci.yml`)
- `push`/`pull_request`: lint, vet, vuln, licenses, unit+integration (in-memory) з race detector, coverage gate, build matrix (linux/amd64, linux/arm64, windows/amd64), docker build `--plain`, shellcheck, `TestNoSecretsInOutput`.
- `schedule` nightly: fuzz 10 хв, `integration_samba`, docker build `--dhi` (якщо є secret `DHI_USERNAME`/`DHI_TOKEN`, інакше skip з попередженням).
- `release` (tag `v*`): бінарники, SBOM, cosign, образ DHI (якщо логін), GitHub Release.

## Артефакти тестів
`coverage.out`, `coverage.html`, `fuzz corpus`, `junit.xml` (через `gotestsum`), логи Samba — у `artifacts/`.
