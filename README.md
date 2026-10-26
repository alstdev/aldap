# ALDAP

LDAP proxy with a virtual directory, brute-force protection and IDS telemetry. Sits between applications and Active Directory (or any LDAPv3 server). Applications see only the directory you describe in a profile and never touch AD directly; ALDAP never writes to the upstream.

**Status:** feature-complete against `SPEC.md` (Stages 0–13), tested against an in-memory directory and a Samba AD bench (`docs/samba.md`). Known limitations: `docs/limitations.md`.

## Quick start

Three ways to run it. Each needs: an AD (or the Samba test bench below), a read-only service account, and the CA certificate of your DCs. The image is `ghcr.io/alstdev/aldap` from the first release on; before that, build it yourself and pass it as `ALDAP_IMAGE`:

```sh
./build.sh --dhi                                   # Docker Hardened Images, needs: docker login dhi.io
#   → aldap/aldap:<version> and aldap/aldap:latest
IMAGE=aldap/aldap VERSION=local ./build.sh --plain # public golang + scratch → aldap/aldap:local-plain
```

### 1. Docker Compose (about 5 minutes)

```sh
git clone https://github.com/alstdev/aldap && cd aldap/deploy/quickstart
$EDITOR config/aldap.toml                 # the lines marked EDIT: DCs, service account, bases, UPN suffix
cp /path/to/your-ad-ca.pem config/ad-ca.pem
mkdir -p secrets
printf '%s' 'the AD service account password' > secrets/ad_pass
openssl rand -hex 24 | tr -d '\n' > secrets/virola_bind   # the password your application binds with
# Compose mounts secret files as they are on the host: make them readable by the image user only.
sudo chown 65532:65532 secrets/* && sudo chmod 0400 secrets/*
docker compose up -d --wait
docker compose exec aldap aldap check --online             # every DC, service bind, bases, audit
```

Point the application at `ldaps://<host>:636`, base `ou=users,ou=virola,dc=aldap`, bind DN `cn=virola,ou=services,dc=aldap` with the password from `secrets/virola_bind`, login attribute `userPrincipalName`. The application must trust ALDAP's built-in CA:

```sh
docker compose cp aldap:/var/lib/aldap/ca/ca.crt ./aldap-ca.crt
LDAPTLS_CACERT=./aldap-ca.crt ldapsearch -LLL -H ldaps://127.0.0.1:636 -x \
  -D cn=virola,ou=services,dc=aldap -y <(sudo cat secrets/virola_bind) \
  -b ou=users,ou=virola,dc=aldap '(uid=*)' uid mail memberOf
```

Add the names clients use to `tls.san` (the certificate already has `localhost` and `127.0.0.1`).

**No AD at hand?** Use the Samba AD test bench (two DCs, 20 users, nested groups; `docs/samba.md`) instead of editing the configuration:

```sh
deploy/samba-dc/init.sh                                    # from the repository root: passwords + CA, git-ignored
docker compose -f deploy/samba-dc/compose.yml up -d --wait
cd deploy/quickstart && mkdir -p secrets
sudo cp ../samba-dc/secrets/svc_pass secrets/ad_pass
openssl rand -hex 24 | tr -d '\n' > secrets/virola_bind
sudo chown 65532:65532 secrets/* && sudo chmod 0400 secrets/*
docker compose -f compose.yml -f compose.bench.yml up -d --wait
```

The test users' password is in `deploy/samba-dc/secrets/user_pass` (e.g. `alice.adams@test.aldap`).

### 2. Rootless Podman with Quadlet

Runs as your user under systemd, with the client source address preserved (`Network=pasta`, `docs/podman.md`). Needs a systemd user session and Podman with Quadlet (the units are checked with `quadlet -dryrun` of Podman 4.9.3; a run under systemd is not verified yet, `docs/limitations.md`).

```sh
./build.sh --podman                    # DHI image as localhost/aldap/aldap:latest (podman login dhi.io)
#   or: podman pull ghcr.io/alstdev/aldap:latest && podman tag ghcr.io/alstdev/aldap:latest localhost/aldap/aldap:latest
mkdir -p ~/.config/aldap ~/.config/containers/systemd
cp deploy/quickstart/config/aldap.toml ~/.config/aldap/ && $EDITOR ~/.config/aldap/aldap.toml
cp /path/to/your-ad-ca.pem ~/.config/aldap/ad-ca.pem
printf '%s' 'the AD service account password' | podman secret create ad_pass -
openssl rand -hex 24 | tr -d '\n' | podman secret create virola_bind -
cp deploy/podman/aldap.container ~/.config/containers/systemd/
systemctl --user daemon-reload && systemctl --user start aldap.service
loginctl enable-linger "$USER"         # keep running after logout
podman exec aldap aldap check --online
```

The unit publishes host port `6360` → container `636` (ports below 1024 rootless: `docs/podman.md`). `systemctl --user reload aldap` reloads without dropping connections. Socket activation (`aldap-virola.socket`) is in `docs/podman.md`.

### 3. Virola and ALDAP in one stack

Virola reaches `ldaps://aldap:636` over an internal network; the LDAP port is not published; Virola's fixed address is exempt from per-IP limits but not from account locks and detectors (`docs/virola.md`).

```sh
cd deploy/virola-stack
$EDITOR config/aldap.toml && cp /path/to/your-ad-ca.pem config/ad-ca.pem
#   with the Samba bench instead: skip this, use "-f compose.yml -f compose.bench.yml" below
#   and ../samba-dc/secrets/svc_pass as secrets/ad_pass
mkdir -p secrets trust
printf '%s' 'the AD service account password' > secrets/ad_pass
openssl rand -hex 24 | tr -d '\n' > secrets/virola_bind
sudo chown 65532:65532 secrets/* && sudo chmod 0400 secrets/*
docker compose up -d --wait aldap                               # first ALDAP alone: it creates its CA
docker compose cp aldap:/var/lib/aldap/ca/ca.crt trust/aldap-ca.crt   # before Virola starts (bind mount)
docker compose up -d                                             # Virola image: VIROLA_IMAGE, see compose.yml
```

In Virola: LDAP server `aldap`, port 636, LDAPS, base `ou=users,ou=virola,dc=aldap`, authentication attribute `userPrincipalName`, service account `cn=virola,ou=services,dc=aldap` with the password from `secrets/virola_bind`; then the checklist in `docs/virola.md`.

## Releases

Tags `v*` publish linux/amd64, linux/arm64 and windows/amd64 binaries of `aldap` and `aldapctl`, `SHA256SUMS`, a CycloneDX SBOM, keyless cosign signatures and the image `ghcr.io/alstdev/aldap`. Verification: `docs/release.md`.

## Documents
- `SPEC.md` — technical specification (normative); `TASKS.md` — implementation stages; `TESTING.md` — test strategy; `CLAUDE.md` — rules for the implementing agent
- `docs/config.md` — every configuration key; `aldap.toml.example` — a full example
- `docs/api.md` (+ `openapi.yaml`), `docs/events.md` (+ `events.schema.json`), `docs/aldapctl.md`
- `docs/security.md`, `docs/virola.md`, `docs/podman.md`, `docs/service.md`, `docs/windows.md`, `docs/proxy-protocol.md`
- `docs/samba.md` — Samba AD test bench; `docs/release.md` — releases; `docs/limitations.md` — known limitations; `docs/DECISIONS.md` — decisions log
- `THIRD_PARTY_LICENSES.md`

License: MIT.
