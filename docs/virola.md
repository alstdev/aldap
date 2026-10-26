# Virola Messenger and ALDAP

Virola reads its users from ALDAP's profile `virola` over LDAPS: a service bind (`client_bind`),
searches below the virtual base, and one bind per user login. This page covers the setup where
**Virola and ALDAP run in one container stack** (Stage 12b) and the client checklist of SPEC §12.

## Virola and ALDAP in one stack

Ready to use: `deploy/virola-stack/` (`compose.yml`, `config/aldap.toml`, and
`compose.bench.yml` for the Samba test bench), steps in README «Virola and ALDAP in one stack».
Checked in Stage 13 with a stand-in LDAP client at Virola's address `10.89.10.20` against the
Samba bench: service bind and search over `ldaps://aldap:636` with the ALDAP CA, user binds,
`bind_ok.client_ip = 10.89.10.20`, 25 failed binds from that address lock no IP, three wrong
passwords lock that one account, spray/enumeration are detected, the LDAP port is not
published. The Virola server itself (`providesupport/virola-server`, loaded from the tarball of
Virola's Docker guide) was not run: virola.io is not reachable from the build environment
(`docs/limitations.md`).

```
                    internal network "stack" (10.89.10.0/24), no published LDAP port
  ┌──────────────────────┐   ldaps://aldap:636   ┌──────────────────────┐   ldaps   ┌────┐
  │ virola  10.89.10.20  │ ────────────────────▶ │ aldap  10.89.10.10   │ ────────▶ │ AD │
  └──────────────────────┘                       └──────────────────────┘           └────┘
```

- Virola connects to `ldaps://aldap:636` — the service name on the internal network. The LDAP
  port of the profile is **not published** on the host: nothing outside the stack reaches it.
- Container-to-container traffic on one network is not translated: ALDAP sees Virola's own
  address. (The masking described in `docs/podman.md` concerns *published* ports of custom
  networks; it does not apply here.)
- Virola gets a **fixed address**, and that address is the profile's `ratelimit.allow_cidrs`.
- The ALDAP certificate carries `aldap` (`tls.san`), and Virola trusts the ALDAP CA.

### Why `allow_cidrs`, and what it does not lift

Every bind comes from Virola's one address: users log in to Virola, Virola binds to ALDAP on
their behalf. Per-IP limits would lock all users at once after a few typos of different people.
`allow_cidrs` lifts exactly the limits keyed by the address and nothing else (Stage 12b,
`docs/DECISIONS.md`):

| Mechanism | For the `allow_cidrs` address |
|---|---|
| IP lock (`ip.max_failures`, manual, honeytoken), `ip.*` token buckets, progressive delay, tarpit | **lifted** |
| account lock (`account.max_failures`), negative cache | **applies**: guessing one user's password through Virola locks that account; the next bind with the right password does not reach AD until `account.lock_duration` ends; other users keep working |
| detectors (spray, stuffing, slow brute force, enumeration, recon, anomaly), honeytoken events | **apply**: a spray through the Virola login page starts `attack_start{kind=spray}` |
| lockdown | **applies** unless the address is also in `ratelimit.lockdown.allow_cidrs` (see below) |
| `[ids.client_ip_masked]` | the address is **not counted**: one private address carrying many accounts is expected here |

Lockdown: with `lockdown.auto = true` a high-level attack switches lockdown on, and Virola's
address is refused like everyone else — all Virola logins stop until lockdown is switched off.
Put the address into `lockdown.allow_cidrs` only if Virola must keep working during lockdown;
account locks then remain the only brake on attacks through Virola.

### Compose

The relevant part (Docker Compose; with Podman use a `.network` Quadlet with `Subnet=` and
`IP=` in the `.container` files):

```yaml
services:
  aldap:
    image: localhost/aldap/aldap:latest
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    # no "ports:" for the virola profile: reachable only inside the stack
    networks:
      stack:
        ipv4_address: 10.89.10.10
    volumes:
      - ./config:/etc/aldap:ro          # the directory, not the file (docs/podman.md)
      - aldap-state:/var/lib/aldap      # tls.ca_dir = /var/lib/aldap/ca
    secrets: [ad_pass, virola_bind]

  virola:
    image: <the Virola server image you run>
    networks:
      stack:
        ipv4_address: 10.89.10.20       # = allow_cidrs below
    # + the ALDAP CA certificate in its trust store, see "Trust the ALDAP CA"

networks:
  stack:
    ipam:
      config:
        - subnet: 10.89.10.0/24
```

`aldap.toml`:

```toml
[tls]
mode = "builtin-ca"
auto_init = true
san = ["aldap"]                      # the name Virola connects to

[profile.virola]
listen = [":636"]
transport = "ldaps"
upstream = "ad-main"
virtual_base = "ou=virola,dc=aldap"
# … bases, filter, attrs as in aldap.toml.example …

[profile.virola.client_bind]
dn = "cn=virola,ou=services,dc=aldap"
password_file = "/run/secrets/virola_bind"

[profile.virola.ratelimit]
allow_cidrs = ["10.89.10.20/32"]     # Virola only, never the whole subnet
```

Use a single address (`/32`), not the stack subnet: every other container of the stack would
otherwise escape the IP limits too.

### Trust the ALDAP CA

With `tls.mode = "builtin-ca"` the CA certificate is `tls.ca_dir/ca.crt` (default
`/var/lib/aldap/ca/ca.crt`, the key stays `0600` next to it and must not leave ALDAP's volume).
Give Virola **only `ca.crt`**: copy it out once, or after a CA rotation, e.g.

```sh
docker compose cp aldap:/var/lib/aldap/ca/ca.crt ./virola-trust/aldap-ca.crt
```

and add it to the trust store Virola uses for LDAPS — its own CA setting if it has one,
otherwise the operating system trust store of the Virola container (for example
`/usr/local/share/ca-certificates/` + `update-ca-certificates` on Debian-based images).
⁉️ Whether Virola has its own CA setting is not verified (SPEC §14); see `docs/DECISIONS.md`.
Never disable certificate verification in Virola instead.

### Checks

```sh
aldapctl events --types bind_ok,bind_fail --limit 5   # client_ip = 10.89.10.20
aldapctl events --types insecure_config --limit 5     # no client_ip_masked for 10.89.10.20
```

A wrong password typed three times for one user locks that user (`lock{target=account}`) and
nobody else; `aldapctl unlock <name>` releases it early.

## Virola client checklist (SPEC §12)

Manual, on a real Virola installation:

- [ ] Server `aldap` (in the stack) or the ALDAP host name, port 636, LDAPS; the ALDAP CA trusted.
- [ ] Base DN `ou=users,<virtual_base>` (users only) or `<virtual_base>` (users and groups).
- [ ] Authentication attribute `userPrincipalName`.
- [ ] Service account = `client_bind.dn` with its password.
- [ ] A user login works; a wrong password is refused; three wrong passwords lock only that user.
- [ ] `memberOf` / the virtual groups appear as expected.
- ⁉️ Paged results: the cookie format Virola expects between pages is assumed to be the standard
  opaque cookie (SPEC §14).
