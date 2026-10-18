# ALDAP

LDAP proxy with a virtual directory, brute-force protection and IDS telemetry. Sits between applications and Active Directory (or any LDAPv3 server). Applications see only the directory you describe in a profile and never touch AD directly.

**Status:** specification stage. Implementation is driven by `SPEC.md`, `TASKS.md`, `TESTING.md` and `CLAUDE.md`.

## Quick start (compose, 5 minutes) — target behaviour after Stage 13
1. `cp aldap.toml.example aldap.toml` and edit `[upstream.ad-main]` and `[profile.virola]`.
2. `mkdir secrets && printf '%s' 'AD service password' > secrets/ad_pass` (and the other secrets referenced in compose).
3. `docker compose up -d`
4. `docker compose exec aldap aldap check --online`
5. Point the application at `ldaps://<host>:636`, base `ou=users,ou=virola,dc=aldap`, bind `cn=virola,ou=services,dc=aldap`.

## Documents
- `SPEC.md` — technical specification (normative)
- `TASKS.md` — implementation stages with acceptance criteria
- `TESTING.md` — test strategy and mandatory scenarios
- `CLAUDE.md` — rules for the implementing agent
- `docs/openapi.yaml`, `docs/events.schema.json` — API and event contracts

License: MIT.
