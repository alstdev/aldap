# Samba AD test bench

`deploy/samba-dc/` runs two Samba AD domain controllers of the domain `TEST.ALDAP` in Docker.
`make integration-samba` starts them, runs the `integration_samba` tests of `cmd/aldap`
(`cmd/aldap/samba_test.go`) against them and removes them again. The quick starts
(`deploy/quickstart`, `deploy/virola-stack`) can use the same bench instead of a real AD.

Test bench only: generated passwords, a 30-day self-signed CA, no backups, no hardening beyond
what the containers need.

## What it contains

| Piece | Where | What |
|---|---|---|
| Image | `deploy/samba-dc/Dockerfile` | Ubuntu 24.04 (`ARG BASE`), Samba 4.19 AD DC packages |
| Provisioning | `entrypoint.sh` | `samba-tool domain provision --realm=TEST.ALDAP --domain=TEST --server-role=dc --use-rfc2307` on the first start of a container, then `samba --foreground` |
| Directory | `provision.ldif` + `provision.py` | `OU=Office` (10 users, 3 computers), `OU=Branch` (8 users, 2 computers), `CN=Users` (`svc-aldap`, `outside.user`, groups); `Staff` ⊃ `Managers` ⊃ `Directors` (nested); disabled `heidi.hill` and `olga.orlova`; computers are enabled, so only their object class excludes them |
| Secrets | `init.sh` → `deploy/samba-dc/secrets/` (git-ignored) | random `admin_pass`, `svc_pass`, `user_pass` (all test users); CA + one LDAPS certificate for `dc1`, `dc2`, `localhost`, `127.0.0.1`; the CA certificate is exported to `testdata/samba-ca.pem` (git-ignored) |
| Compose | `compose.yml` (project `aldap-samba`) | `dc1` on `127.0.0.1:6636`, `dc2` on `127.0.0.1:6637`, LDAPS only; network `aldap-samba_default` |

No password is in the repository: `init.sh` creates them on the first run (existing files are
kept, `init.sh --force` renews everything) and the containers read them as Compose secrets.
`provision.py` sets them with Samba's own `SamDB.setpassword`.

Choices that keep the containers small:

- **NT ACLs in a tdb.** `vfs objects = dfs_samba4 acl_xattr xattr_tdb` stores the sysvol ACLs in
  `xattr.tdb`; `security.*` extended attributes would need `CAP_SYS_ADMIN`. The containers drop
  every capability except the ones Samba needs to switch users and bind ports.
- **No NetBIOS, no DNS self-registration** (`disable netbios`, `dns update command = /bin/true`):
  two DCs of one domain on one bridge would fight over the names; the tests use LDAPS only.
- **AD lockout threshold 5** (`samba-tool domain passwordsettings`), above ALDAP's
  `account.max_failures = 3`, so the tests can show that ALDAP locks before AD does.

### Limitation: two independent DCs

`dc2` is **not** a replica of `dc1`: both are provisioned independently from the same LDIF and
the same secrets (TESTING.md allows this when a join in containers is not stable). Users, groups
and passwords are equal; `objectGUID`s and the per-DC state (`badPwdCount`, `lastLogon`) differ,
as they would on real DCs (`badPwdCount` is not replicated in AD either). The failover test
needs two servers with the same content, not replication.

## Running it

```sh
make integration-samba            # init.sh, compose up --wait, tests, logs → artifacts/samba.log, compose down -v
```

By hand (for the quick starts or a debugger):

```sh
deploy/samba-dc/init.sh
docker compose -f deploy/samba-dc/compose.yml up -d --wait
# ... tests or quick start ...
docker compose -f deploy/samba-dc/compose.yml down -v
```

The tests read:

| Variable | `make integration-samba` sets |
|---|---|
| `ALDAP_TEST_SAMBA_URL` | `ldaps://127.0.0.1:6636,ldaps://127.0.0.1:6637` (dc1 first) |
| `ALDAP_TEST_SAMBA_BIND_DN` | `CN=svc-aldap,CN=Users,DC=test,DC=aldap` (not an administrator) |
| `ALDAP_TEST_SAMBA_BIND_PASSWORD_FILE` | `deploy/samba-dc/secrets/svc_pass` |
| `ALDAP_TEST_SAMBA_USER_PASSWORD_FILE` | `deploy/samba-dc/secrets/user_pass` |
| `ALDAP_TEST_SAMBA_ADMIN_PASSWORD_FILE` | `deploy/samba-dc/secrets/admin_pass` (reads `badPwdCount` directly on dc1) |
| `ALDAP_TEST_SAMBA_CA` | `testdata/samba-ca.pem` |
| `ALDAP_TEST_SAMBA_COMPOSE` | `deploy/samba-dc/compose.yml` (the failover test stops and starts `dc1`) |

Without `ALDAP_TEST_SAMBA_URL` every Samba test is skipped.

Behind a TLS-intercepting proxy the image build can use a CA bundle for apt:
`SAMBA_APT_CA=/path/to/bundle.crt deploy/samba-dc/init.sh` (copied to the build secret
`secrets/apt_ca`, empty otherwise), then `SAMBA_BASE=<mirror>/ubuntu:24.04 docker compose -f deploy/samba-dc/compose.yml build`.

## Scenarios (SPEC §13.2)

`cmd/aldap/samba_test.go` runs `aldap run` (the real serve loop with the API) against the bench:

| Test | Checks |
|---|---|
| `TestSamba_VirolaDirectory` | docs/virola.md: two bases merged; computers, disabled accounts and `CN=Users` not exported (also for client filters on `userAccountControl`); DN rewrite, allowlist, map, computed `mail`; virtual group `virola-users` from nested `Staff` with `member`/`memberOf`/`(memberOf=)`; paged results 17 users / 4 pages; the primary DC serves |
| `TestSamba_UserBind` | UPN, `sAMAccountName` + `default_domain`, `TEST\user`, virtual DN; wrong password → `invalid_password`; disabled account with its right password → `invalidCredentials`, event reason `disabled` (AD data 533); account outside the profile refused |
| `TestSamba_AccountLock` | 3 failures → `lock{account}`; 6 more attempts (right password included) → `bind_blocked{account_locked}`; **Samba `badPwdCount` stays 3, no `lockoutTime`**; other accounts work; negative cache (same wrong pair twice → `badPwdCount` +1); after `lock_duration` the right password works and Samba resets the counter |
| `TestSamba_ReconAndHoneytoken` | `nTSecurityDescriptor` dump → `recon{sd_dump}`; honeytoken bind → `honeytoken{high}` + IP lock, the right password from that IP is refused; honeytoken search |
| `TestSamba_ProxyProtocol` | PROXY v1 and v2 from the trusted address: `bind_ok`/`bind_fail` carry the header's client address; a header from an untrusted address → connection cut + `insecure_config{proxy_protocol_untrusted}` |
| `TestSamba_Failover` | `docker compose stop dc1` → `upstream_down`, searches and user binds via dc2; `start dc1` → `upstream_up`, back on dc1 (`prefer_primary`) |
| `TestSamba_WebhookAndSSE` | bind events reach the webhook with a valid `X-ALDAP-Signature` HMAC; SSE resumes after `Last-Event-ID`; every event matches `docs/events.schema.json` |
| `TestSamba_CheckOnline` | `aldap check --online` on the bench configuration: exit 0, both servers checked |

Every test also checks that no password, token or HMAC key of the run appears in the daemon
output (TESTING.md 41).

## CI

`.github/workflows/samba.yml`: nightly, on pull requests that touch `deploy/samba-dc/**` or
`cmd/aldap/samba_test.go`, by hand (`workflow_dispatch`) and before every release (called by
`release.yml`). `timeout-minutes: 15`; the first run on GitHub (PR #14) took 2 minutes: image build about
40 s, both DCs healthy after 11 s, tests 19 s. Uploaded: `samba.log`, `samba.json`,
`junit-samba.xml` — never `deploy/samba-dc/secrets/`.
