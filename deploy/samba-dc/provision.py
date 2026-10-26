"""Loads provision.ldif into the freshly provisioned sam.ldb and sets passwords.

Accounts are created without a password (Samba makes them disabled); this
sets the bench passwords from the compose secrets (computers get a random
one) and enables every account except the ones whose description is
"bench:disabled", so computers are excluded by their object class only.
Test bench only.
"""
import secrets
import sys

import ldb
from samba.auth import system_session
from samba.param import LoadParm
from samba.samdb import SamDB


def secret(name):
    with open("/run/secrets/" + name, encoding="utf-8") as f:
        return f.read().strip()


def main(path):
    lp = LoadParm()
    lp.load_default()
    samdb = SamDB(url=lp.samdb_url(), session_info=system_session(), lp=lp)
    with open(path, encoding="utf-8") as f:
        samdb.add_ldif(f.read())

    user_pass, svc_pass = secret("user_pass"), secret("svc_pass")
    res = samdb.search(base=samdb.domain_dn(), scope=ldb.SCOPE_SUBTREE,
                       expression="(&(objectClass=user)(description=bench:*))",
                       attrs=["sAMAccountName", "description", "objectClass"])
    counts = {}
    for msg in res:
        name = str(msg["sAMAccountName"][0])
        kind = str(msg["description"][0])
        flt = "(sAMAccountName=%s)" % ldb.binary_encode(name)
        counts[kind] = counts.get(kind, 0) + 1
        password = {"bench:service": svc_pass,
                    "bench:computer": "Aa1-" + secrets.token_hex(16)}.get(kind, user_pass)
        samdb.setpassword(flt, password, force_change_at_next_login=False, username=name)
        if kind == "bench:disabled":
            samdb.disable_account(flt)
        else:
            samdb.enable_account(flt)
    print("provisioned:", ", ".join("%s=%d" % kv for kv in sorted(counts.items())))


if __name__ == "__main__":
    main(sys.argv[1])
