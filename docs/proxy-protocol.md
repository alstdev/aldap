# PROXY protocol (Stage 12b)

When a TCP proxy (Traefik, HAProxy, a cloud load balancer) sits in front of ALDAP, every
connection arrives from the proxy's address: per-IP rate limits, IP locks, `allow_cidrs`, the
IDS and every event's `client_ip` would see one client. The PROXY protocol
([haproxy proxy-protocol.txt][spec], versions 1 and 2) lets the proxy send the client's address
in a short header before the client's own bytes. ALDAP reads it per profile; it is **disabled by
default**.

```toml
[profile.virola]
listen = [":636"]
transport = "ldaps"
proxy_protocol = { enabled = true, trusted_cidrs = ["10.89.0.2/32"] }   # the proxy's address
```

`trusted_cidrs` is required when `enabled = true` (`aldap check` fails without it), and a prefix
of length 0 (`0.0.0.0/0`, `::/0`) is refused: whoever may send a header chooses the client
address ALDAP believes.

## What ALDAP does with a connection

| Peer (TCP source) | First bytes | Result |
|---|---|---|
| in `trusted_cidrs` | v1 `PROXY TCP4/TCP6 …` or v2 `PROXY` (TCP over IPv4/IPv6) | served; the client address and port are the header's source |
| in `trusted_cidrs` | v1 `PROXY UNKNOWN`, v2 `LOCAL` (health check) or v2 `AF_UNSPEC` | served under the proxy's own address |
| in `trusted_cidrs` | no header, a malformed header, UDP/unix families, nothing within 5 s | closed; WARN log (once a minute per proxy) |
| elsewhere | a PROXY header (v1 or v2 signature) | **closed**; WARN log and `insecure_config{what=proxy_protocol_untrusted, peer}` (once a minute per address) |
| elsewhere | LDAP or a TLS ClientHello | served under its own address, as without `proxy_protocol` |

- The header is read before TLS (`ldaps`: the proxy passes TLS through; ALDAP terminates it),
  within the first-packet deadline (5 s), off the accept loop. TLVs (v2) are skipped; the header
  block is limited to 4096 bytes.
- The per-IP connection limit (`limits.max_conns_per_ip`), the rate limiter, IP locks, the
  detectors and every event use the header's address. With log level `debug`, `connection
  accepted` carries `proxy_ip` and `direct_source=true`.
- Addresses taken from a trusted header are the clients' own, so the masked-address detector
  (`[ids.client_ip_masked]`) does not count them.
- An `insecure_config{what=proxy_protocol_untrusted}` means either a client tries to forge its
  address, or the proxy's address is missing from `trusted_cidrs` (its connections are then
  refused).

## Traefik ≥ 3.5.2

Traefik routes LDAP as TCP. With TLS passthrough Traefik does not decrypt: ALDAP keeps
terminating TLS with its own certificate (`tls.san` must contain the name clients connect to).
Since Traefik v3.5.2 the PROXY protocol for TCP services is set on a TCP `serversTransport`; the
`proxyProtocol` option of the TCP load balancer is deprecated ([migration notes][tmig],
[TCP serversTransport][tst]).

**One entrypoint per ALDAP port.** A passthrough router cannot tell LDAP profiles apart by
anything but SNI, and many LDAP clients send none (an IP address in the URL, older Java). Give
every profile its own Traefik entrypoint and a catch-all router ``HostSNI(`*`)``, which matches
every connection, with or without SNI.

Static configuration (`traefik.toml`):

```toml
[entryPoints.ldaps-virola]
  address = ":636"

[providers.file]
  directory = "/etc/traefik/dynamic"
  watch = true

[providers.docker]
  exposedByDefault = false
```

Dynamic configuration of the file provider (`/etc/traefik/dynamic/aldap.toml`): the transport
that sends PROXY protocol version 2.

```toml
[tcp.serversTransports.aldap-pp2.proxyProtocol]
  version = 2
```

The ALDAP service, here from Docker/Podman labels; the transport lives in the file provider, so
it is referenced with the `@file` suffix:

```yaml
services:
  aldap:
    image: localhost/aldap/aldap:latest
    networks:
      stack:
        ipv4_address: 10.89.0.10
    labels:
      - "traefik.enable=true"
      - "traefik.tcp.routers.aldap-virola.entryPoints=ldaps-virola"
      - "traefik.tcp.routers.aldap-virola.rule=HostSNI(`*`)"
      - "traefik.tcp.routers.aldap-virola.tls.passthrough=true"
      - "traefik.tcp.routers.aldap-virola.service=aldap-virola"
      - "traefik.tcp.services.aldap-virola.loadBalancer.server.port=636"
      - "traefik.tcp.services.aldap-virola.loadBalancer.serversTransport=aldap-pp2@file"
  traefik:
    networks:
      stack:
        ipv4_address: 10.89.0.2      # = proxy_protocol.trusted_cidrs of ALDAP
```

The same router and service entirely in the file provider:

```toml
[tcp.routers.aldap-virola]
  entryPoints = ["ldaps-virola"]
  rule = "HostSNI(`*`)"
  service = "aldap-virola"
  [tcp.routers.aldap-virola.tls]
    passthrough = true

[tcp.services.aldap-virola.loadBalancer]
  serversTransport = "aldap-pp2@file"
  [[tcp.services.aldap-virola.loadBalancer.servers]]
    address = "10.89.0.10:636"
```

ALDAP side:

```toml
[profile.virola]
listen = [":636"]
transport = "ldaps"
proxy_protocol = { enabled = true, trusted_cidrs = ["10.89.0.2/32"] }
[profile.virola.tls]
san = ["ldap.example.org"]      # the name clients use through Traefik
```

Give Traefik a fixed address on the container network (above) or a dedicated subnet, and do not
publish ALDAP's own port: clients reaching ALDAP directly bypass the proxy (they are then served
under their real address, which is safe, but not what the deployment intends).

Check after start: connect through Traefik, then

```sh
aldapctl events --types bind_ok --limit 5     # client_ip must be the client, not 10.89.0.2
```

[spec]: https://www.haproxy.org/download/2.0/doc/proxy-protocol.txt
[tst]: https://doc.traefik.io/traefik/v3.6/reference/routing-configuration/tcp/serverstransport/
[tmig]: https://doc.traefik.io/traefik/v3.6/migrate/v3/
