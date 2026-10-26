# Known limitations

Every point here is a decision (`LIMITATION` in `docs/DECISIONS.md`), not an open question:
the behaviour is defined and documented, what is missing is a verification that the build
environment cannot do, or a feature deliberately left out. Status as of Stage 13 (2026-10-26).

## Not verified on real systems

| Topic | State | What would verify it |
|---|---|---|
| **Virola Messenger** (SPEC §12, §14) | `docs/virola.md`, `deploy/virola-stack/` checked with a stand-in client at Virola's fixed address (service bind, user binds, `allow_cidrs`, CA trust, no published port). Not run with the Virola server image: it is downloaded from virola.io, which the build environment cannot reach. Unverified: whether Virola has its own CA setting for LDAPS (otherwise the OS trust store of the Virola container), and the paged-results cookie it expects (standard opaque cookie assumed) | The checklist in `docs/virola.md` on a real installation |
| **Rootless Podman / Quadlet** | `deploy/podman/*.container` generate units with `quadlet -dryrun` of Podman 4.9.3 (Ubuntu 24.04); `build.sh --podman` checked by a stub. Not run under systemd: no systemd user manager in the build environment | `docs/podman.md`: `systemctl --user start aldap`, health, source IP in events, `Notify=true` |
| **systemd socket activation on a host** | descriptor handling tested with descriptors duplicated by the tests | `systemctl --user enable --now aldap-virola.socket` (`docs/podman.md`) |
| **Windows** (SPEC §10.5) | cross-compiled and vetted in CI; named pipe ACL and service code reviewed, not run (no Windows runner). Windows Server 2012 R2 with `kardianos/service` not tested | `docs/windows.md` checklist |
| **DHI image build** | tags pinned from the public DHI build log (`docs/DECISIONS.md` «DHI tags»); the agent environment cannot reach `dhi.io`. CI builds it nightly and in the release dry run when `DHI_USERNAME`/`DHI_TOKEN` exist | `make docker-dhi` after `docker login dhi.io` |

## By design

- **No `aldapctl stop`.** Stopping goes through the service manager or a signal (`SIGTERM`
  starts the graceful drain). A stop through the API would let a leaked admin token take the
  proxy down.
- **Container HEALTHCHECK is `aldap check --quick`**: it validates the configuration offline and
  needs no shell; it does not probe the running process. Liveness comes from the restart policy;
  readiness from `/readyz` when the API is enabled, or `aldapctl status` over the IPC socket.
- **Samba bench DCs are independent**, not replicas (`docs/samba.md`).
- **Lists from `ALDAP_*` variables are comma separated**, so DNs (which contain commas) cannot be
  given there, e.g. `profile.*.bases`; use the configuration file (`docs/config.md`).
- **Compose file secrets keep their host owner and mode** (uid/gid/mode apply in Swarm only):
  secret files for the containers must be owned by uid 65532 (README).
- **Client addresses behind Docker's userland proxy** (connections to a published port from the
  host itself) arrive as the bridge gateway; external clients keep their address. Behind proxies
  use PROXY protocol (`docs/proxy-protocol.md`); for Podman see `docs/podman.md`.

## Agent build environment only

`make vuln` (the proxy denies `vuln.go.dev`) and `make licenses` (licence URLs not resolvable
offline; with an auto-downloaded toolchain `go-licenses` also needs `GOROOT` set to it) do not run
in the environment that implemented the project; both run in CI on every push.
