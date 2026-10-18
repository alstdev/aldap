# Decisions log

Format: `YYYY-MM-DD | STATUS (OPEN/DECIDED) | topic | decision | rationale`

| Date | Status | Topic | Decision | Rationale |
|---|---|---|---|---|
| 2026-10-18 | DECIDED | Config format | TOML only | Owner requirement; YAML forbidden |
| 2026-10-18 | DECIDED | Upstream writes | Never | Scope; safety |
| 2026-10-18 | DECIDED | Compare op | Denied (`compareFalse` + `op_denied`) | Compare allows attribute-value enumeration |
| 2026-10-18 | DECIDED | Denied filter terms | Replace with FALSE, no error | Do not leak schema/allowlist |
| 2026-10-18 | OPEN | Virola custom CA | Verify on real install whether CA can be added or verification disabled | Affects TLS deployment docs |
| 2026-10-18 | OPEN | DHI tags | Verify `dhi.io/golang` and `dhi.io/static` tags at build time | Catalog changes |
