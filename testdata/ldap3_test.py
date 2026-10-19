#!/usr/bin/env python3
"""ldap3 compatibility check for ALDAP (TESTING.md 48).

Usage: ldap3_test.py URL CA_FILE BIND_UPN PASSWORD USERS_BASE GROUP_DN [PAGE_SIZE] [VALID_NAME]

VALID_NAME is a certificate name accepted besides the host of URL (ldap3
matches DNS names only, so an IP listener needs its DNS SAN here).

Performs a simple bind with a UPN over ldaps, a paged search of USERS_BASE
and reads memberOf of the bound user. Prints one JSON line with the
findings and exits 0 on success, 1 on a failed check, 2 on usage errors.
"""
import json
import ssl
import sys

try:
    import ldap3
except ImportError:  # pragma: no cover - reported to the Go test
    print(json.dumps({"ok": False, "error": "ldap3 not installed"}))
    sys.exit(2)


def main(argv):
    if len(argv) < 7:
        print(json.dumps({"ok": False, "error": "usage"}))
        return 2
    url, ca_file, upn, password, users_base, group_dn = argv[1:7]
    page_size = int(argv[7]) if len(argv) > 7 else 5
    valid_names = [argv[8]] if len(argv) > 8 else None
    tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca_file, version=ssl.PROTOCOL_TLS_CLIENT, valid_names=valid_names)
    server = ldap3.Server(url, use_ssl=True, tls=tls, get_info=ldap3.DSA)
    conn = ldap3.Connection(server, user=upn, password=password, authentication=ldap3.SIMPLE, auto_bind=False, raise_exceptions=False)
    out = {"ok": False}
    conn.open()  # returns None; failures raise
    if not conn.bind():
        out["error"] = "bind failed: %s" % conn.result
        print(json.dumps(out))
        return 1
    out["naming_contexts"] = list(server.info.naming_contexts or [])
    out["supported_controls"] = [c[0] for c in (server.info.supported_controls or [])]
    entries = []
    pages = 0
    cookie = None
    while True:
        conn.search(users_base, "(objectClass=*)", search_scope=ldap3.SUBTREE,
                    attributes=["uid", "mail", "memberOf"], paged_size=page_size, paged_cookie=cookie)
        pages += 1
        entries.extend(conn.entries)
        ctl = conn.result.get("controls", {}).get("1.2.840.113556.1.4.319", {}).get("value", {})
        cookie = ctl.get("cookie")
        if not cookie:
            break
    out["entries"] = len(entries)
    out["pages"] = pages
    me = [e for e in entries if upn.lower().startswith(str(e.uid).lower() + "@")]
    out["member_of"] = [str(v) for v in me[0].memberOf] if me else []
    out["ok"] = bool(me) and group_dn.lower() in [m.lower() for m in out["member_of"]]
    if not out["ok"]:
        out["error"] = "bound user not found or memberOf lacks %s" % group_dn
    conn.unbind()
    print(json.dumps(out))
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
