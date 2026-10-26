# Hot reload, graceful drain, service (Stage 12)

SPEC §3.6, §5.3, §10.4, §10.5.

## Hot reload (`SIGHUP`, `POST /v1/reload`, `aldapctl reload`)

The new configuration is loaded and validated first; on failure the running one stays and
`config_reload{ok=false}` is emitted (nothing else changes). Then the new generation **takes the
listeners over** (`cmd/aldap/sockets.go`, `daemon.takeOver`):

1. **Sockets.** Listening sockets live in a pool that outlives configurations, keyed by the
   configured address. Addresses that stay keep their socket and every client connection on it.
   Added addresses are bound before anything else changes — a bind failure (port in use) aborts
   the reload with `config_reload{ok=false}` and the running configuration keeps serving. Removed
   addresses stop accepting and are drained in the background (below) within `shutdown_timeout`.
   An ephemeral port (`:0`, tests) is never shared between profiles.
2. **Rules.** Every listener gets the new configuration atomically
   (`listener.Server.Reconfigure`): a request runs under the configuration that was current when it
   was read, so requests in flight finish under the old rules and every later request — new
   connections and the next request of an existing connection — uses the new ones. A paged search
   keeps its result on the connection (`vdir` paging state), so the remaining pages of a search
   started before the reload come from the old rules; the next search uses the new rules
   (`TestStage12_ReloadDuringPagedSearch`).
3. **Identity changes.** When an address now belongs to another profile or uses another
   transport (`ldap` ↔ `ldaps` …), its existing connections are ended with a Notice of
   Disconnection (`unavailable`, "listener reconfigured") after their current request: a plain
   connection is never kept on a listener that became `ldaps`.
4. **State.** Rate-limit tables (locks, counters, negative cache), detector state, the event bus
   (sequence numbers), notifier, recorders and caches whose profile is unchanged are process state
   and survive (`TestStage12_ReloadKeepsRateLimitState`). Connection limiters keep counting the
   open connections; a reload changes only their limits (`max_connections`, `max_conns_per_ip`) —
   a lower limit never cuts open connections, it refuses new ones.
5. **Retirement.** Background loops (upstream health checks, certificate checks, replica sync,
   sweeps) move to the new generation at once. The old upstream pools and shadow directories are
   closed once the requests still running under the old configuration have finished, at the
   latest after `shutdown_timeout`.

`config_reload{ok=true}` is emitted after the takeover; the log line lists the listen addresses.

## Graceful drain (`SIGTERM`, `SIGINT`, service stop)

There is no `aldapctl stop` (SPEC §5.3 names it, §8 does not; `docs/DECISIONS.md` OPEN): stopping
goes through the service manager or a signal. The management API stops first; then
`listener.Server.Shutdown` drains every listener in parallel (SPEC §5.3):

1. the listening sockets close — new connections are refused;
2. every connection finishes the request it is serving, then receives a Notice of Disconnection
   (`unavailable`, "server shutting down") and is closed; idle connections are ended at once;
3. connections still busy at `server.shutdown_timeout` get the notice, are closed and their
   requests canceled (logged as "connections cut at shutdown timeout");
4. then the background loops stop, the upstreams close, `shutdown` is emitted, the event sinks
   and webhook queues are flushed and queued notifications are delivered within their timeouts.

The same drain applies to the addresses a reload removes.

## systemd (`deploy/aldap.service`)

`Type=notify`: `aldap run` reports `READY=1` once every listener and the API serve,
`RELOADING=1` … `READY=1` around a reload and `STOPPING=1` when the drain starts (sd_notify(3) over
`$NOTIFY_SOCKET`, no library). `ExecReload=/bin/kill -HUP $MAINPID`, `TimeoutStopSec=45s` covers the
default `shutdown_timeout` of 30s. Hardening as SPEC §10.4 (`DynamicUser`, `LoadCredential`,
`ProtectSystem=strict`, `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`, `SystemCallFilter=@system-service`).
`LoadCredential=` lines name files that must exist (`/etc/aldap/secrets/...`), otherwise systemd
refuses to start the unit: remove the lines you do not use (`systemctl edit --full aldap`).

## `aldap service` (`kardianos/service`)

```
aldap service install   [--config FILE] [--name aldap] [--log-file FILE]
aldap service uninstall | start | stop | restart | status   [--name aldap]
aldap service run       [--config FILE] [--name aldap] [--log-file FILE]
```

- `install` loads the configuration first (an invalid file is refused, exit 1) and registers the
  absolute `--config` path.
  - **Linux (systemd):** writes `/etc/systemd/system/<name>.service` from the embedded copy of
    `deploy/aldap.service` (`cmd/aldap/aldap.service.tmpl`, `TestSystemdUnitInSync`) with
    `ExecStart=<aldap> "run" "--config" "<file>"`, enables it and reloads systemd. The binary must be
    readable by the dynamic user (e.g. `/usr/local/bin/aldap`).
  - **Windows (SCM):** service `<name>`, automatic start, restart 5 s after a failure, command line
    `aldap.exe service run --name <name> --config <file> --log-file <file>`; the Event Log source
    `<name>` is registered. Default log file: `aldap.log` next to the configuration.
- `run` is what the SCM starts: the daemon starts, the start is reported only when it serves (a
  configuration that does not start fails the service start with the cause in the log); stop
  drains as above. Log and stdout events go to `--log-file` (created `0600`); warnings and errors
  also go to the Event Log. Interactively (`aldap service run` in a console) it behaves like
  `aldap run` with `Ctrl+C`.
- `status` prints `running` (exit 0), `stopped` or `not installed` (exit 3).
- Exit codes: 0 done, 1 failed, 2 usage, 3 status not running.

The Windows checklist is in `docs/windows.md` (not tested in CI, SPEC §10.5). Rootless Podman:
`docs/podman.md`.
