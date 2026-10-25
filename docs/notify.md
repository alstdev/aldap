# Notifications (`internal/notify`)

`[notify]` turns events of the bus into messages for people: Telegram, Virola, email and a custom webhook
(SPEC §3.4). Machine consumers (SIEM) use `[events]` sinks instead.

## Flow

```
Bus.Emit ──▶ Subscription (4096, drops when lagging) ──▶ Notifier.Handle
                                                        │ match: events, min_level
                                                        │ attack active? → channel digest
                                                        │ cooldown (channel, event, key)
                                                        ▼ render template
                                              channel queue (256) ──▶ worker ──▶ send + retries
```

- The notifier is process-wide (`runtimeState`): cooldowns and a pending digest survive a reload; a reload
  replaces the channels, queued messages of the old ones are still delivered.
- **Nothing blocks the bus.** The subscription drops records when the notifier lags
  (`aldap_events_dropped_total{sink="notify"}` + WARN); every channel has its own bounded queue and worker,
  so a hanging channel never delays the others.
- At shutdown the queues get up to 10 s to drain.

## Channel selection

| Key | Meaning |
|---|---|
| `events` | event types (SPEC §6); `lock_account` / `lock_ip` select `lock` events by `data.target`, `lock` selects both; an unknown name is a configuration error |
| `min_level` | `low` < `medium` < `high`; applies to every event |

## Cooldown

A message with the same (channel, event type, key) as one delivered less than `cooldown` ago is not sent
(`aldap_notify_total{result="cooldown"}`). The key:

| Event | Key |
|---|---|
| `attack_*` | `data.attack_id` |
| `lock` / `unlock` | `data.target` + `data.key` |
| `upstream_down` / `upstream_up` | upstream + `data.server` |
| `cert_expiring` / `cert_renewed` | profile + `data.subject` |
| `honeytoken` | `data.account` + client IP |
| `lockdown` | `data.state` |
| other | profile, client IP, account (or hash), reason, upstream |

## Digest during an attack

- An attack is active from `attack_start` (or a first `attack_summary`) until its `attack_end`.
  An attack without records for `max(1h, 4 × digest_interval)` is considered over, so a lost `attack_end`
  cannot keep the channels in digest mode.
- While any attack is active, `attack_start` and `attack_end` are sent at once (cooldown applies); every
  other matching event (summaries, binds, locks, …) is folded into the channel's digest
  (`result="digested"`).
- The digest is sent every `digest_interval` (the first one an interval after the attack began); an empty
  digest is not sent. When the last attack ends, the pending digest is sent before `attack_end`.
- Content: number of events per type, top 10 source IPs, number of accounts, the latest summary per attack.

## Templates

Built-in templates (`internal/notify/templates/*.tmpl`, Go `text/template`) exist for `attack_start`,
`attack_summary`, `attack_end`, `lock`, `unlock`, `honeytoken`, `lockdown`, `upstream_down`, `upstream_up`,
`cert_expiring`, `digest`, `subject` (email) and `default` (every other event).

`template_dir` overrides them per file name (`<event>.tmpl`, `digest.tmpl`, `default.tmpl`,
`subject.tmpl`). A template receives the event record (SPEC §6: `.Event`, `.Level`, `.TS`, `.Profile`,
`.ClientIP`, `.Account`, `.AccountHash`, `.Reason`, `.Upstream`, `.Data`, …) plus `.Hostname`, `.Version`
and, for digests, `.Digest` (`From`, `To`, `Total`, `Counts`, `IPs`, `Accounts`, `Attacks`).

Functions: `get .Data "key"` (empty when missing), `join list ", "`, `json v`, `md v` (Telegram MarkdownV2
escape), `html v`, `upper`, `lower`, `default "-" v`.

- **Telegram:** built-in text is escaped for `parse_mode` (`MarkdownV2` — default, `HTML`, `none`) and cut to
  3000 characters before escaping; text of a `template_dir` file is sent as rendered (escape with `md` /
  `html` yourself), cut to 4000 characters.
- **Virola:** plain text, cut to 4000 characters.
- **Email:** `subject_template` (default `[ALDAP] <level> <event> on <host>`, folded to one line, RFC 2047),
  body as UTF-8 quoted-printable.
- **Webhook:** `body_template` must render valid JSON (otherwise the message fails); without it the body is
  the record itself (`aldap.event.v1`) or, for digests, `{"event":"digest", "counts":…, "ips":…}`.

## Channels

| Type | Request |
|---|---|
| telegram | `POST {api_base}/bot<token>/sendMessage` `{"chat_id","text","parse_mode"}`; `retry_after` of a 429 is honoured |
| virola | `POST {base_url}/api/v1/rooms/{room_id}/messages` or `/api/v1/users/{user_id}/messages` (`path_template` overrides the path, e.g. `/api/v1/rooms/{room_id}/text-messages`; the id placeholder is required), `Authorization: Bearer <token>`, `{"content": "…"}`; `tls_ca_file`, `tls_insecure_skip_verify` (warned) |
| email | `tls = "tls"` (implicit TLS), `"starttls"` (STARTTLS mandatory, refused when not offered), `"none"` (warned; AUTH PLAIN is then refused unless the server is loopback) |
| webhook | `method` (`POST`/`PUT`/`PATCH`), `headers` (values render `***`), `headers_file` (TOML table of headers for credentials, merged with `headers`), `X-ALDAP-Signature: sha256=<hmac>` with `hmac_secret` (as `[[events.webhook]]`) |

- `timeout` and `retry` apply to every channel (`timeout` per SMTP command for email). `retry.max` counts the
  attempts after the first; the backoff doubles from `retry.backoff` up to `retry.max_backoff`; a delay
  requested by the server wins but is capped by `max_backoff`.
- Transient: network errors, HTTP 429/5xx, SMTP 4xx. Permanent (no retry): other HTTP 4xx, SMTP 5xx,
  Telegram `ok=false`.
- HTTP channels do not follow redirects and use TLS ≥ 1.2.

## Failures and metrics

`aldap_notify_total{channel,result}` with `result` = `ok`, `error` (after the retries, also a template
error), `cooldown`, `digested`, `dropped` (queue full). Every failure is logged as WARN with the channel,
type and event — never the token, password or the Telegram URL (it contains the bot token); errors of the
HTTP client are stripped of the URL. `TestNoSecretsInOutput_Notify` and `TestStage8_NotifyAttack` check it.
