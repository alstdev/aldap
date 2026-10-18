// Package upstream manages connections to the upstream directories of one
// [upstream.<name>] table (SPEC §5.2): URL parsing (ldap://, ldaps://,
// StartTLS, CA, SNI), a service-bound connection pool and a separate
// bind-only pool per server, health checks with up/down thresholds and
// failover (prefer_primary or roundrobin), paged searches (RFC 2696) with
// referrals ignored, the mapping of Active Directory bind diagnostics to
// bind_fail reasons, the service-account audit and the probes behind
// `aldap check --online`.
//
// The package never writes to the upstream: it offers Search, RootDSE and
// UserBind only.
package upstream
