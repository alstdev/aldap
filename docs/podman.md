# Rootless Podman

ALDAP runs well as a rootless Podman container under a systemd user unit (Quadlet). The
important part is the **network mode**: ALDAP must see the real client IP address.

## TL;DR

```sh
./build.sh --podman                      # image localhost/aldap/aldap (docker format, HEALTHCHECK kept)
mkdir -p ~/.config/aldap ~/.config/containers/systemd
cp aldap.toml.example ~/.config/aldap/aldap.toml   # edit: listen ports, upstream, secrets as /run/secrets/<name>
podman secret create ad_pass ./ad_pass
podman secret create virola_bind ./virola_bind
cp deploy/podman/aldap.container ~/.config/containers/systemd/
systemctl --user daemon-reload
systemctl --user start aldap.service
loginctl enable-linger "$USER"           # keep running after logout and start at boot
```

Reload after editing the configuration on the host: `systemctl --user reload aldap.service`
(sends `SIGHUP`; hot reload without dropping connections, `docs/service.md`).

## Build: `./build.sh --podman`

- `./build.sh --podman` builds the DHI image (`--dhi`) with podman; `./build.sh --podman --plain`
  builds the public `golang` + `scratch` image. Images land in the user's storage as
  `localhost/aldap/aldap:<version>` (and `:latest` for DHI).
- DHI needs a login first: `podman login dhi.io` (credentials go to
  `${XDG_RUNTIME_DIR}/containers/auth.json`, podman-login(1)).
- The script passes `--format docker`. `podman build` writes OCI images by default
  ([options/format.md][format]), and the OCI image format has no `HEALTHCHECK`: buildah drops it
  with *"HEALTHCHECK is not supported for OCI image format and will be ignored. Must use `docker`
  format"*. The docker format keeps the image health check `aldap check --quick`, which the Quadlet
  unit relies on: the static image has no shell, so a `HealthCmd=` string (run through
  `/bin/sh -c`) would not work.
- `ATTEST=1` (BuildKit attestations) is docker-only and ignored with podman; `syft` reads the image
  as `podman:<image>`.

## Network: keep the client IP

Per-IP rate limits (`[ratelimit.ip]`), `ratelimit.lockdown.allow_cidrs`, IP locks, the IDS
(spray, stuffing, slow brute force, anomaly baselines) and every event's `client_ip` depend on the
real source address. Which rootless network modes keep it (table "Listening TCP/UDP sockets" of
[eriksjolund/podman-networking-docs][erik]; Podman docs [options/network.md][network],
[options/publish.md][publish]):

| Network mode | Source IP preserved | Notes |
|---|---|---|
| `pasta` (default since Podman 5.0), **no custom network** | yes | *"Port forwarding preserves the original source IP address."* — **use this** (`Network=pasta`). |
| `host` | yes | The container shares the host network namespace; less isolation. |
| `slirp4netns` + `port_handler=slirp4netns` | yes | Podman **< 6.0** only: *"Support for the slirp4netns rootless network stack has been removed. Please use Pasta instead."* ([v6.0.0 release notes][rn6]). |
| `slirp4netns` + default `port_handler=rootlesskit` | **no** | *"Rootlesskit changes the source IP address of incoming packets to … usually `10.0.2.100`"*. |
| custom network (`podman network create`, `Network=<name>.network`, **podman-compose**) | **no** | Published ports go through `rootlessport`, *"a userspace proxy that does not preserve client source IPs"*. |

**Do not use `podman-compose` or a custom network with pasta.** Every client then arrives from one
private address of the container network; ALDAP cannot tell clients apart: one attacker locks the
address of everybody, `allow_cidrs` either admits everyone or nobody, and spray/stuffing detection
sees a single source. Podman 6.0 adds an experimental `rootless_port_forwarder="pasta"` in
`containers.conf` that keeps the source IP on bridge networks; the default stays `rootlessport`
([v6.0.0 release notes][rn6]). Until that is the default, use `Network=pasta`.

Systemd socket activation also preserves the source address ([eriksjolund][erik]), but ALDAP does
not accept inherited sockets (`LISTEN_FDS`); it is not an option today.

### ALDAP warns about it

The detector `[ids.client_ip_masked]` (enabled by default) reports a masked setup: when, within
`window` (10m), at least `min_requests` (50) binds and searches were seen, at least
`min_share_percent` (90 %) of them came from **one private address** (RFC 1918, `fc00::/7`,
`100.64.0.0/10`, link-local; loopback excluded) and that address carried at least `min_accounts` (3)
distinct accounts, ALDAP logs a WARN and emits

```json
{"event":"insecure_config","level":"medium","client_ip":"10.89.0.2",
 "data":{"what":"client_ip_masked","share_percent":100,"requests":120,"requests_total":120,"accounts":7,"window":"10m0s"}}
```

once per window and address. A legitimate single client — e.g. one application server that binds
on behalf of its users — looks the same: put it in `ignore_cidrs` or raise the thresholds
(`docs/config.md`).

## Ports below 1024

Rootless Podman cannot publish host ports below `net.ipv4.ip_unprivileged_port_start` (default
1024, [ip-sysctl.rst][sysctl]). Either:

- publish high host ports — the Quadlet unit maps `PublishPort=6360:636` (ldaps), `13890:1389`
  (honeypot), and clients use 6360; or
- lower the limit on the host (affects every unprivileged process of the host):

  ```sh
  echo 'net.ipv4.ip_unprivileged_port_start=636' | sudo tee /etc/sysctl.d/90-aldap-ports.conf
  sudo sysctl --system
  ```

Inside the container ALDAP keeps the profile ports (`listen = [":636"]`); the unit sets
`Sysctl=net.ipv4.ip_unprivileged_port_start=0` for the container's own network namespace so the
unprivileged ALDAP user can bind them with every capability dropped.

## The Quadlet unit (`deploy/podman/aldap.container`)

Keys as listed in podman-container.unit(5) ([podman-systemd.unit][quadlet]); the unit goes into
`~/.config/containers/systemd/` and becomes `aldap.service` after `systemctl --user daemon-reload`.

| Key | Why |
|---|---|
| `Network=pasta` | Real client IP (above). No `.network` file. |
| `PublishPort=6360:636` | Host 6360 → ALDAP 636; more profiles → more lines. |
| `ReadOnly=true` | Read-only root file system (`ReadOnlyTmpfs` defaults to true: tmpfs on `/tmp`, `/run`, …). |
| `DropCapability=all`, `NoNewPrivileges=true` | No capabilities, no privilege gain. |
| `UserNS=keep-id:uid=65532,gid=65532` | The host user is the image user inside the container: host files (0600 configuration, CA keys) stay readable without making them world-readable. |
| `Tmpfs=/run/aldap…` | IPC socket of `aldapctl` (`[server] ipc_socket = "/run/aldap/aldap.sock"`). |
| `Volume=%h/.config/aldap:/etc/aldap:ro,Z` | Configuration **directory**, read-only (below). |
| `Volume=aldap-state:/var/lib/aldap:U,Z` | Built-in CA, certificates, event files; `U` gives the volume to the container user. |
| `Secret=<name>,type=mount,uid=65532,gid=65532,mode=0400` | Podman secrets at `/run/secrets/<name>`, readable by ALDAP only. |
| `StopTimeout=40`, `TimeoutStopSec=45` | `SIGTERM` starts the graceful drain (`server.shutdown_timeout`, default 30s); podman must not kill earlier. |
| `ExecReload=podman kill --signal HUP aldap` | `systemctl --user reload aldap` = hot reload. |

`aldapctl` inside the container: `podman exec -it aldap /usr/local/bin/aldapctl status` (IPC socket, no token).

## Secrets

```sh
podman secret create ad_pass ./ad_pass          # then shred/delete the source file
podman secret ls
```

In `aldap.toml` reference them as files: `bind_password_file = "/run/secrets/ad_pass"`. With the
default `file` driver podman keeps the secret data in a file readable only by the user
(mode 0600 in a 0700 directory) in its storage; it is not encrypted there by any documented
guarantee — protect the account and the host disk accordingly. Never put passwords into
`aldap.toml` or `Environment=`.

## Configuration: mount the directory, read-only

- **Mount the directory, not the file.** A bind mount of a single file is bound to the file's
  inode. Editors that save by writing a new file and renaming it over the old one (vim, many IDEs,
  `sed -i`) create a new inode; the container keeps seeing the old file and a reload reads stale
  configuration ([moby/moby#15793][moby]: *"This breaks the bind-mount, which is based on inode"*,
  *"Mount a dir instead of a file."* — kernel behaviour, the same for Podman). Mounting
  `~/.config/aldap` as `/etc/aldap` always shows the current files.
- **`:ro` means view-only from inside.** With the configuration mounted read-only,
  `GET /v1/config`, `aldapctl config get` and the TUI Config tab show it, `aldapctl config validate` works, but
  `PUT /v1/config` / `aldapctl config set` / TUI apply cannot write the file and answer `409 config_read_only`. Edit on
  the host and reload (`systemctl --user reload aldap`, `aldapctl reload`, `POST /v1/reload`).
  Making the mount writable to allow API edits weakens the container hardening; keep `:ro` unless
  you need remote edits.

## Checks after start

```sh
systemctl --user status aldap.service
podman healthcheck run aldap && echo healthy
podman logs --since 5m aldap | grep -E 'client_ip_masked|insecure_config' || echo "no masking warning"
podman exec aldap /usr/local/bin/aldapctl status
```

Connect once from another host and check that `bind_ok`/`search` events carry that host's address,
not a `10.x`/`fd00::` container address.

[erik]: https://github.com/eriksjolund/podman-networking-docs
[network]: https://github.com/containers/podman/blob/main/docs/source/markdown/options/network.md
[publish]: https://github.com/containers/podman/blob/main/docs/source/markdown/options/publish.md
[format]: https://github.com/containers/podman/blob/main/docs/source/markdown/options/format.md
[rn6]: https://github.com/containers/podman/blob/v6.0.0/RELEASE_NOTES.md
[sysctl]: https://github.com/torvalds/linux/blob/master/Documentation/networking/ip-sysctl.rst
[quadlet]: https://github.com/containers/podman/blob/main/docs/source/markdown/podman-systemd.unit.5.md
[moby]: https://github.com/moby/moby/issues/15793
