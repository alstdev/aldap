#!/bin/bash
# Provisions a fresh Samba AD DC (TEST.ALDAP) on every start of a new container
# and runs it in the foreground. Inputs (compose secrets, written by init.sh):
#   /run/secrets/admin_pass  Administrator password
#   /run/secrets/svc_pass    password of CN=svc-aldap (the ALDAP upstream account)
#   /run/secrets/user_pass   password of every test user
#   /run/secrets/tls_*       server certificate and key, CA certificate
set -euo pipefail

log() { printf '[bench %s] %s\n' "$(hostname)" "$*"; }

if [ ! -f /var/lib/samba/private/sam.ldb ]; then
  log "provisioning TEST.ALDAP"
  rm -f /etc/samba/smb.conf
  # NT ACLs of sysvol go to a tdb (xattr_tdb) instead of security.* xattrs,
  # which would need CAP_SYS_ADMIN.
  samba-tool domain provision --realm=TEST.ALDAP --domain=TEST --server-role=dc \
    --use-rfc2307 --dns-backend=SAMBA_INTERNAL \
    --host-name="$(hostname -s)" \
    --adminpass="$(cat /run/secrets/admin_pass)" \
    --option="dns forwarder = 127.0.0.1" \
    --option="vfs objects = dfs_samba4 acl_xattr xattr_tdb" \
    --option="xattr_tdb:file = /var/lib/samba/private/xattr.tdb" \
    --option="dns update command = /bin/true" \
    --option="disable netbios = yes" >/var/log/provision.log 2>&1 \
    || { cat /var/log/provision.log; exit 1; }

  install -d -m 0700 /var/lib/samba/private/bench-tls
  install -m 0600 /run/secrets/tls_key /var/lib/samba/private/bench-tls/key.pem
  install -m 0644 /run/secrets/tls_cert /var/lib/samba/private/bench-tls/cert.pem
  install -m 0644 /run/secrets/tls_ca /var/lib/samba/private/bench-tls/ca.pem
  sed -i '/^\[global\]/a \
	tls enabled = yes\
	tls keyfile = /var/lib/samba/private/bench-tls/key.pem\
	tls certfile = /var/lib/samba/private/bench-tls/cert.pem\
	tls cafile = /var/lib/samba/private/bench-tls/ca.pem' /etc/samba/smb.conf

  # AD lockout above ALDAP's limit (3): the test checks ALDAP locks first.
  samba-tool domain passwordsettings set --account-lockout-threshold=5 \
    --account-lockout-duration=30 --reset-account-lockout-after=30 >/dev/null
  log "loading provision.ldif"
  python3 /opt/bench/provision.py /opt/bench/provision.ldif
fi

touch /run/bench-ready
log "starting samba"
exec samba --foreground --no-process-group --debug-stdout --debuglevel=1
