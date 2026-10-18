# `internal/ldapfilter` — фільтри та DN

Пакет реалізує Stage 2: парсер фільтрів RFC 4515 у AST, канонічний серіалізатор,
операції над AST для SPEC §4.2 (крок 3 і 7) і парсер DN RFC 4514. Залежностей,
окрім stdlib, немає. Жодна функція не панікує на довільному вході (fuzz-цілі
`FuzzParseFilter`, `FuzzParseDN`, `make fuzz`).

## Фільтри

| API | Призначення |
|---|---|
| `Parse(s)` / `ParseWithLimits(s, Limits{MaxDepth, MaxLen})` | Рядок → `*Filter`. Дефолти: глибина 20 (жорсткий максимум 64, SPEC §9), довжина 4096 (`limits.max_filter_depth/len`). Помилки обгортають `ErrSyntax`, `ErrTooDeep`, `ErrTooLong`. |
| `(*Filter).String()` | Канонічний текст: значення екрановані `\XX` (`* ( ) \ NUL`, C0, DEL), решта байтів як є. |
| `(*Filter).Normalize()` | Копія з lower-case атрибутами/matching rule, відсортованими без дублікатів членами and/or. Це `filter_norm` у подіях. Значення не змінюються. |
| `EscapeValue` / `UnescapeValue` | Екранування значень RFC 4515 §3. |
| `Equal`, `Clone`, `Depth`, `Attrs`, `Walk` | Службові операції над AST. |
| `Inject(f, extra)` | `(&f extra)` — AND із `profile.filter`. |
| `Exclude(f, ex)` | `(&f(!ex))` — AND NOT із `exclude_filter`. |
| `MapAttrs(f, map)` | Перейменування атрибутів client→upstream (`attrs.map`), без урахування регістру, `;options` зберігаються. |
| `Split(f, classify)` | Ділить фільтр на `executable` (для upstream) і `postfilter` (для ALDAP). `classify(attr)` повертає `Upstream`, `Local` (computed, віртуальні `memberOf`/`member`) або `Denied` (поза allow/map/computed → `(|)`, без помилки). |
| `Simplify`, `True()`, `False()`, `IsTrue`, `IsFalse` | Згортання абсолютних `(&)`/`(|)` (RFC 4526). `executable.IsFalse()` означає, що запит в upstream не потрібен. |

Інваріанти `Split` (перевіряються тестами на корпусі): `executable` не містить
`Local`/`Denied` атрибутів; `postfilter` не містить `Denied`; множина, яку
повертає upstream за `executable`, є надмножиною результату; `executable AND
postfilter` еквівалентний `f` із заміною denied-термів на false. And ділиться
почленно; Or/Not із локальним термом цілком іде в `postfilter`, а upstream
отримує `(&)`.

Синтаксис атрибутів — суворий RFC 4512 (keystring або числовий OID, `;options`);
`_`, пробіли, старі екранування `\*` відхиляються. Extensible: `attr[:dn][:rule]:=v`
та `[:dn]:rule:=v`; AD bit-match `:1.2.840.113556.1.4.803:` і `:1.2.840.113556.1.4.1941:`
проходять round-trip (див. `testdata/filters.txt`, 300+ фільтрів).

## DN

| API | Призначення |
|---|---|
| `ParseDN(s)` / `ParseDNWithLimit(s, maxLen)` | Рядок → `*DN` (`RDNs[0]` — лист). Ліміт довжини 8192. Пробіли навколо `,`, `+`, `=` ігноруються (`CN=x, OU=y`); `;` як роздільник і `\<літера>` відхиляються; `#hex` зберігається як сирі байти BER. |
| `(*DN).String()` | Канонічний текст: lower-case типи, канонічне екранування, AVA в RDN відсортовані. |
| `Equal`, `Canonical()` | Порівняння caseIgnoreMatch (типи й значення без регістру, пробіли згорнуті). `Canonical()` — ключ для map/rate limit. |
| `IsUnder(base)` | `true`, якщо DN дорівнює base або лежить під ним; порожній base — корінь. |
| `Rewrite(oldBase, newBase)` | Заміна суфікса (upstream DN → віртуальний і навпаки); `ErrNotUnder`, якщо DN не під `oldBase`. |
| `RDN()`, `Parent()`, `Child(rdn)`, `Depth()`, `Clone()` | Навігація. |
| `EscapeRDNValue(v)` | Екранування значення RDN за RFC 4514 §2.4 (плюс `\XX` для керівних байтів). |

## Підключення

`config.Validator` використовує `ldapfilter.Parse`/`ParseDN` для всіх ключів
із фільтрами та DN (`profile.*.filter`, `exclude_filter`, `virtual_base`, `bases`,
`upstream.*.bind_dn`, `base_dn`, `client_bind.dn`, `groups.*.members.*`).
Перетворення BER ↔ AST з'являється разом із listener'ом (Stage 4).
