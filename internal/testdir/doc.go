// Package testdir is an in-memory LDAP directory for tests (TESTING.md
// "In-memory тестовий каталог"). It is built on gldap and mimics the parts
// of Active Directory that ALDAP relies on: an AD-like schema loaded from
// LDIF (objectCategory, userAccountControl, sAMAccountName,
// userPrincipalName, memberOf/member, objectGUID, distinguishedName), the
// bit-match rules 1.2.840.113556.1.4.803/804, LDAP_MATCHING_RULE_IN_CHAIN
// (1.2.840.113556.1.4.1941) as a transitive closure over member/memberOf,
// the paged results control (RFC 2696), a RootDSE and the AD simple bind
// diagnostics (data 525/52e/533/775/701/773).
//
// Test hooks: call counters, an artificial delay and a forced death
// (Kill/Restart) that closes the listener and every client connection
// while keeping the directory data, so failover and recovery can be
// exercised without Docker.
package testdir
