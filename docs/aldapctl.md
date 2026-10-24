# aldapctl — CLI and TUI

`aldapctl` controls a running `aldap` through the management API only (SPEC §7, §8). It never reads
the daemon's configuration file, state or secrets on disk; the only thing it knows about the daemon
is the platform default of `[server].ipc_socket` (`config.DefaultIPCSocket`).

## Connection

| Transport | Flags | Authentication |
|---|---|---|
| IPC (default) | `--socket PATH` (default `/run/aldap/aldap.sock`; Windows `\\.\pipe\aldap`) | none: the socket is `0600` (pipe ACL SYSTEM + Administrators), the API grants scope `admin` |
| TCP | `--url https://host:8636 --token-file FILE` | `Authorization: Bearer` from the file |

- `--url` takes `https://`; plain `http://` only for a loopback host (the API itself serves plain HTTP on
  loopback only). Paths, queries and `user:pass@` in the URL are refused.
- The token is read from `--token-file` (one line, trimmed; ≤ 4 KiB; a file more permissive than
  `0640` is warned about, as for the daemon's `*_file` secrets). There is no flag or environment variable that takes the token itself, so it never
  appears in `ps`, shell history or error messages. Redirects are not followed (the token stays with
  the host named in `--url`).
- `--ca-file` adds the CA of the API certificate (e.g. the built-in CA, `[api].tls.builtin`);
  `--client-cert`/`--client-key` for `[api].client_auth`. TLS ≥ 1.2, verification is always on.
- `--timeout` bounds every API call (default 30 s); `events --follow` and the TUI stream have no
  timeout and reconnect with `Last-Event-ID` (backoff 1 s … 30 s).
- `--socket` together with `--url`, or TCP-only flags without `--url`, are usage errors.

## CLI

`aldapctl help` lists every command and flag; `aldapctl <command> --help` shows one. Flags may come
before or after the command (`--` ends the flags). A flag that does not belong to the command is a
usage error.

| Command | API |
|---|---|
| `status`, `upstreams`, `profiles`, `locks` (`--json`) | `GET /v1/status`, `/v1/upstreams`, `/v1/profiles`, `/v1/locks` |
| `unlock <ip\|account> [--account]` * | `DELETE /v1/locks/{target}/{key}` |
| `lock <ip\|account> --for 1h [--reason TEXT] [--account]` * | `POST /v1/locks` |
| `lockdown on\|off` * | `POST /v1/lockdown` |
| `events [--follow] [--types a,b] [--since SEQ] [--limit N] [--json]` | `GET /v1/events`, then `/v1/events/stream` |
| `indicators [--format table\|json\|stix-lite\|plain] [--min-score N]` | `GET /v1/indicators` |
| `reload` * | `POST /v1/reload` |
| `config get [--out FILE [--force]]` | `GET /v1/config` (secrets `***`) |
| `config set <file>` * | `PUT /v1/config` (validate, backup, atomic write, reload) |
| `config validate <file>` | `PUT /v1/config?dry_run=true` |
| `test <profile> --filter F [--base DN] [--scope base\|one\|sub] [--attrs a,b] [--size-limit N]` | `POST /v1/profiles/{name}/test` |
| `sync <profile>` * | `POST /v1/profiles/{name}/sync` |
| `baseline learn <profile> [--for 24h]` * | `POST /v1/baseline/{profile}/learn` |
| `record start\|stop <profile>` * | `POST /v1/profiles/{name}/record` (`501` until Stage 11) |
| `replay <file> --profile P [--json]` | `POST /v1/profiles/{name}/test` per recorded search |
| `bundle [--out aldap-bundle.tgz] [--force] [--events N]` | read-only endpoints, see below |
| `tui` (or no command) | all of the above |
| `version` | — |

`unlock`/`lock` decide the target from the key: an IP address (v4/v6) is `ip`, anything else an
`account`; `--account` forces `account`.

### Confirmation

Commands marked * change the daemon state. On a terminal (stdin and stdout are terminals) aldapctl
asks `…? [y/N]` on stderr and sends nothing unless the answer is `y`/`yes`. Without a terminal
(scripts, pipes, CI) the command runs only with `--yes` (`-y`); otherwise it stops with exit code 3
before any request.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | API error (the message is the API's `{error, code}` and the HTTP status), connection error, or `replay` found differences |
| 2 | usage error (unknown command or flag, missing argument) |
| 3 | not confirmed (no `--yes` without a terminal, or answered `n`), or interrupted |

Output for scripts: `--json` prints the API answer; `events --json` prints one event per line
(`aldap.event.v1`), also while following. Tables go to stdout, prompts, warnings and errors to stderr.

## Support bundle

`aldapctl bundle` writes a gzip tar (`0600`, an existing file only with `--force`) with:

| Member | Content |
|---|---|
| `manifest.json` | format `aldap-bundle.v1`, creation time, aldapctl version, transport, members, parts that failed |
| `version.json` | aldapctl version and Go version, aldap version and Go version (`/v1/status.go_version`) |
| `status.json`, `upstreams.json`, `profiles.json` | as the API answers |
| `health.json` | status code and body of `/healthz` and `/readyz` |
| `config.toml` | `GET /v1/config`, masked again by aldapctl |
| `events.jsonl` | the last `--events` (default 10000) buffered events |
| `metrics.txt` | `/metrics` |

No secret leaves through the bundle, even if the daemon's rendering missed one (`TestNoSecretsInOutput_Bundle`):

1. the daemon masks inline secrets (`***`) and the event bus redacts password terms in filters;
2. aldapctl parses the configuration and every event and replaces the value of every key that is an
   inline secret of the configuration types (found by reflection over `secret.Inline` fields), contains
   `password` (hashes included) or ends in `_secret`/`_token` — `*_file` and `*_env` keys stay, they
   name where a secret lives; every value of a `headers` table is masked;
3. a configuration that does not parse is left out instead of being copied;
4. the API token aldapctl used is replaced by `***` in every member.

A part that fails (e.g. metrics disabled) is listed under `errors` in the manifest; an unreachable daemon
fails the bundle.

## Replay

`aldapctl replay <file> --profile P` sends every recorded search to `POST /v1/profiles/P/test` and
compares it with the recording: the LDAP result code, the number of entries and the DN set
(case-insensitive). The report lists the differences (missing / extra DNs, at most five each) and the
command exits with 1 when there is any. The file is JSON lines (`#` comments and blank lines are
skipped):

```json
{"profile":"virola","base":"ou=users,dc=aldap","scope":"sub","filter":"(uid=jdoe)","attrs":["mail"],"result_code":0,"entries":1,"dns":["uid=jdoe,ou=users,dc=aldap"]}
```

Only `filter` is required; without `dns` only the count is compared, without `entries`/`dns` only the
result code. The recorder that writes this format comes with Stage 11 (docs/DECISIONS.md «replay
format», OPEN); `replay` searches go to the upstream like client searches, so replaying a large file
loads the directory.

## TUI

`aldapctl` without a command (on a terminal) opens the TUI: tabs
`Status | Upstreams | Profiles | Locks | Events | Indicators | Config`, a tab bar on the first line, a
status line on the last. `?` lists every key.

| Keys | Action |
|---|---|
| `q`, `Ctrl+C` | quit |
| `tab`/`→`, `shift+tab`/`←`, `1`–`7` | switch tabs |
| `↑`/`k`, `↓`/`j`, `pgup`, `pgdn`, `g`/`home`, `G`/`end` | move the selection / scroll |
| `r` | refresh now (the visible tab also refreshes every 3 s) |
| `R` | reload the configuration * |
| Status `d` | lockdown on/off * |
| Profiles `s`, `b` | replica sync *, baseline learning (duration prompt, default 24h) * |
| Locks `u`, `l` | unlock the selected lock *, lock `<ip\|account> [duration] [reason]` (default 1h; `ip …`/`account …` forces the target) * |
| Events `space`/`p`, `f`, `/`, `c` | pause/resume (new events are held and counted), filter `type=a,b profile=x ip=y account=z`, search text, clear |
| Indicators `l` | lock the selected key (duration prompt, default 1h) * |
| Config `e`, `v`, `a`, `x` | edit a draft in `$VISUAL`/`$EDITOR` (vi; Notepad on Windows), validate it on the daemon (dry run), apply it *, discard it |

\* asks `[y/n]` on the status line; `y` runs it, `n`/`esc` cancels, other keys keep the prompt. Input
prompts take `enter`/`esc`.

- **80×24 and up:** every line is cut to the width, the body to the height; the help fits in two
  columns. Lists keep the selection visible and show the full text of the selected row (last error of
  a server, reason of a lock, hits of an indicator) under the table.
- **Without 256 colors:** only the 16 ANSI colors are used (lipgloss `AdaptiveColor` for light and
  dark backgrounds), and nothing depends on color: the active tab is `[bracketed]`, the selected row
  starts with `>`, errors with `!`, lockdown is spelled out. `NO_COLOR` or `TERM=dumb` turns colors off.
- **Events:** the tab starts with the last 500 buffered events and follows `/v1/events/stream`; it keeps
  2000 events in memory; a lost stream is shown (`disconnected: …`) and resumed from the last sequence
  number without duplicates.
- **Config drafts:** `e` writes the running configuration (or the current draft) to a temporary file
  (`0600`), opens the editor and removes the file afterwards. Inline secrets appear as `***`; the daemon
  refuses a draft that still contains the placeholder, so give the secret or use `*_file`/`*_env`.
  `a` replaces the whole configuration file with the draft (backup `aldap.toml.bak.<ts>`, as `config set`).
