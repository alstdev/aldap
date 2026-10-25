# Record, replay, shadow (`internal/record`, SPEC §3.4, §8)

Two observers of client searches, both `vdir.Tap`s of the profile directory, and the replay format they
share with `aldapctl replay`.

## Taps

`vdir.Directory.Search` hands every search that ran the pipeline to its taps **after the entries were
written** to the client: request (base, scope, raw and parsed filter, attributes, size limit) and the
whole result before paging. A paged search is reported once, at its first page, with every entry;
pages served from the cookie are not reported. Searches refused by the rate limiter are not reported.
A tap must not block: the recorder and the shadow only hand the search to their own goroutines.

## Recording

`[profile.<name>.record]`: `file` (required to record), `enabled` (state at start), `max_size_mb`
(100), `max_files` (5). At run time `aldapctl record start|stop <profile>` (`POST
/v1/profiles/{name}/record`) switches it; `409 no_record_file` without `file`. The state lasts until
the process exits or the record section changes on reload (a changed section replaces the recorder and
`enabled` applies again); it is not written to the configuration.

- One JSON line per search in the replay format below. The connection hands the search over a bounded
  queue (1024) without waiting; a full queue drops the search (logged at most once a minute with the
  total). `Stop` writes what is queued, then closes the file.
- **No secrets.** Values of password-like attributes in the filter become `***` (name contains `pwd`,
  `password`, `credential` or `secret`, case-insensitive, options included — `userPassword`,
  `unicodePwd`, `ms-Mcs-AdmPwd`, `msLAPS-Password`, `supplementalCredentials`, … — except the policy
  timestamps and counters `pwdLastSet`, `badPwdCount`, `badPasswordTime`, `pwdChangedTime`,
  `pwdAccountLockedTime`, `pwdFailureTime`), as do extensible matches without an attribute. A filter
  that does not parse is not recorded at all (its values could not be redacted). Binds, controls
  (paging cookies included), client addresses and account names are never recorded.
- **File.** Created `0600`; an existing file with other permissions is narrowed to `0600`; a path that
  is a symbolic link or not a regular file is refused. When the next line would exceed `max_size_mb`
  the file is rotated: `file` → `file.1` → … → `file.<max_files>`, the oldest goes. Rotated files are
  plain JSON lines (no compression) so each can be replayed. Two profiles, or a profile and
  `[events.file]`, cannot share a file (validator).
- A line longer than 1 MiB (thousands of DNs) is written without `dns`: replay then compares the count.

## Format (shared with `aldapctl replay`)

```json
{"ts":"2026-10-25T09:00:00.123Z","profile":"virola","base":"ou=users,dc=aldap","scope":"sub","filter":"(uid=jdoe)","attrs":["mail"],"size_limit":10,"result_code":0,"entries":1,"dns":["cn=jdoe,ou=users,dc=aldap"]}
```

`record.Search` (writer and reader), `record.Read` (`#` comments and blank lines skipped, `filter`
required), `record.Compare` (result code; DN set case-insensitive when `dns` is present, else the count
when `entries` is present). `aldapctl replay <file> --profile P` replays through `POST
/v1/profiles/P/test`: 0 differences against the unchanged profile, differences after a change of its
rules (docs/aldapctl.md «Replay»).

## Shadow

`[profile.<name>.shadow]`: `filter` and/or `bases` replace `filter` / `bases` for a second, shadow
directory of the profile; `max_parallel` (4), `timeout` (10s).

- The shadow directory is compiled from the profile with the shadow rules and has no events, rate
  limiter, detectors or metrics; it searches the same upstream (through the ttl cache when
  `cache.mode = ttl`, whose `max_entries` it then shares; with `replica` it asks the upstream, the
  replica holds the main bases only), so shadow rules add upstream load.
  `mode = honeypot` has no directory: the shadow section is ignored with a warning.
- For each client search (not root DSE / subschema / bases outside the tree, not unparsable filters)
  the shadow search runs on its own goroutine **after the client got its answer**. At most
  `max_parallel` run at once; a search arriving when all slots are busy is not shadowed (counted). A
  shadow search that hits `timeout` is abandoned and not reported. A panic in a shadow search is
  recovered and logged. Reload or shutdown cancels the running shadow searches.
- The client answer and its timing do not depend on the shadow: the answer is computed and written
  before the tap is called, and the tap never waits (`TestShadow_DirectoryAnswerUnchanged`,
  `TestShadow_NeverDelaysTheClient`).
- A different answer (DN set or result code) is reported as `shadow_diff` (docs/events.md): `added` /
  `removed` (at most 20 DNs each) with their counts, both result codes and entry counts.

## Tests

`internal/record`: format round trip, redaction, rotation and modes, symlink refusal, no blocking on a
full queue, shadow diff / limits / timeout / panic, real mock-mode directories with a hanging shadow
directory. `internal/vdir/stage11_test.go`: tap semantics. `cmd/aldap/record_test.go`: daemon recording
without passwords, bind data or cookies, replay 0 → n differences after a filter change, `shadow_diff`.
`cmd/aldap/stage11_test.go` (`integration`): the aldapctl binary — `record start/stop`, `replay`,
`config set`, `replay` with differences.
