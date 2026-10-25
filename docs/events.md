# internal/events — event bus and sinks (Stage 6)

Implements SPEC §6 (`aldap.event.v1`) and §3.4 `[events]`.

## Producers

Packages emit `events.Event` values to an `events.Sink` (consumer-side
interface, Stage 4). The daemon's sink is the process-wide `runtimeState`
(`cmd/aldap/daemon.go`): every event goes to the bus and to the indicator
scoring of `internal/ids` (`Engine.Note`). Producers never see the envelope.

## Envelope (`events.Record`)

`Bus.Wrap` turns an `Event` into a `Record`:

| field | source |
|---|---|
| `schema` | fixed `aldap.event.v1` |
| `ts` | bus clock, UTC, millisecond precision |
| `id` | ULID (`events.NewULID`: 48-bit Unix ms + 80 random bits, Crockford base32) |
| `seq` | process-wide counter, monotonic; `GET /v1/events?since=<seq>` (Stage 7) |
| `host` | `os.Hostname()` (override: `Options.Host`) |
| `profile`, `conn_id`, `client_ip`, `client_port`, `tls`, `account`, `reason`, `failures`, `upstream`, `upstream_server`, `duration_ms` | the event fields; omitted when unset |
| `account_hash` | `hex(sha256(salt ‖ account))` when `hash_accounts = true`; `account` is then dropped |
| `data` | copied from the event (`{}` when empty) |

`data.filter_norm` / `data.filter` are passed through `events.RedactFilter`,
which replaces the values of `userPassword` and `unicodePwd` terms with
`***` (the virtual directory redacts them first; the bus is the second line).

The salt comes from `events.salt_file`; without it a random salt is drawn at
start (WARN: hashes change at every restart). The bus is created once per
process and survives `SIGHUP`: `seq` keeps counting, the ring buffer keeps
its history, only the sinks are rebuilt (`Bus.Configure`).

## Bus

- `Emit` never blocks producers: the record is stored in the ring buffer
  (`buffer_size`, default 100 000) and offered to every sink queue and
  subscription.
- `include` / `exclude` filter by event type before anything else.
- `Since(seq, max)` / `Last(n)` read the ring buffer (API, TUI).
- `Subscribe(n)` returns a channel for in-process consumers (SSE, notify);
  a lagging consumer loses records (counted in `Subscription.Dropped`).
- `Flush()` is a barrier: it returns once every record emitted before the
  call has been written (or dropped) by every sink; the daemon flushes on
  stop so the last events reach the files.
- `Dropped()` reports the per-sink drop counters; they are also published as
  `aldap_events_dropped_total{sink}`.

## Sinks

Each sink runs in its own goroutine behind a bounded queue
(`queue_size`, default 10 000) and receives batches
(`batch_size` / `batch_interval`). `on_overflow = drop_oldest` (default)
discards the oldest queued record; `block` makes `Emit` wait.

| sink | config | notes |
|---|---|---|
| stdout | `[events.stdout]` `enabled`, `format = json` | one JSON object per line on the process stdout |
| file | `[events.file]` `path`, `max_size_mb`, `max_files`, `compress` | append, 0600; rotation by size to `path.1[.gz] … path.<max_files>[.gz]`, gzip when `compress` |
| syslog | `[events.syslog]` `network = udp|tcp|unix`, `address`, `facility` | RFC 5424: `<PRI>1 ts host aldap pid <event> - <json>`; severity warning/notice/info for high/medium/low; newline framing on stream sockets; one reconnect per failed write |
| webhook | `[[events.webhook]]` `url`, `events`, `batch_size` (100), `batch_interval` (2s), `timeout` (5s), `retry.max/backoff/max_backoff`, `hmac_secret[_file|_env]`, `headers` (values render `***`), `headers_file` (TOML table of headers for credentials), `tls_ca_file`, `queue_size`, `on_overflow` | POST of a JSON array; `X-ALDAP-Signature: sha256=<hex HMAC of the body>`; retries on network errors, 429 and 5xx with doubling backoff; other 4xx drop the batch |

## Schema test

`docs/events.schema.json` (JSON Schema 2020-12) is checked by
`internal/events/schematest`, a small validator covering the constructs the
file uses (`type`, `const`, `enum`, `pattern`, `format: date-time`,
`required`, `properties`, `additionalProperties`, `items`, `allOf`,
`if/then`). Package tests of every producer (`listener`, `vdir`,
`ratelimit`, `ids`, `upstream` through the daemon) call
`schematest.CheckEvents` / `schematest.Check` on what they emitted; the
end-to-end test `TestStage6_EventsValid` validates everything the daemon
wrote (TESTING.md 34).

## Metrics

`aldap_events_total{event}` and `aldap_events_dropped_total{sink}`
(`internal/metrics`, served by `/metrics` from Stage 7).

## `shadow_diff`

Emitted by the shadow rules of a profile (docs/record.md) when the shadow answer differs from the one
the client got: `data.base`, `scope`, `filter_norm` (password-like values `***`), `added` / `removed`
(at most 20 DNs each: only the shadow answer has them / only the client answer has them),
`added_count`, `removed_count`, `results`, `shadow_results`, `result_code`, `shadow_result_code`;
`duration_ms` is the shadow search time; the connection fields are those of the client search.
