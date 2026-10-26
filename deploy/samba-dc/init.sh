#!/usr/bin/env bash
# Generates the Samba test bench secrets into deploy/samba-dc/secrets/ (git-ignored):
# random passwords and a self-signed CA with one LDAPS certificate for dc1 and dc2.
# The CA certificate is exported to testdata/samba-ca.pem for the tests.
# Existing files are kept, so a second run reuses them; `init.sh --force` renews all.
# SAMBA_APT_CA=/path/to/bundle.crt gives apt a CA bundle for the image build.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
dir="${here}/secrets"
ca_out="${here}/../../testdata/samba-ca.pem"

if [ "${1:-}" = "--force" ]; then
  rm -f "${dir}"/*
fi
umask 077
mkdir -p "$dir"

# Samba's default complexity: upper, lower, digit; 4 + 32 characters.
password() { printf 'Aa1-%s' "$(openssl rand -hex 16)"; }
for name in admin_pass svc_pass user_pass; do
  [ -s "${dir}/${name}" ] || password > "${dir}/${name}"
done

if [ ! -s "${dir}/tls_ca" ]; then
  openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "${dir}/ca.key" -out "${dir}/tls_ca" -days 30 \
    -subj "/CN=ALDAP Samba bench CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "${dir}/tls_key" -out "${dir}/tls.csr" -subj "/CN=dc.test.aldap" 2>/dev/null
  printf '%s\n' \
    "subjectAltName=DNS:dc1,DNS:dc2,DNS:dc1.test.aldap,DNS:dc2.test.aldap,DNS:localhost,IP:127.0.0.1" \
    "extendedKeyUsage=serverAuth" "keyUsage=critical,digitalSignature" > "${dir}/tls.ext"
  openssl x509 -req -in "${dir}/tls.csr" -CA "${dir}/tls_ca" -CAkey "${dir}/ca.key" \
    -CAcreateserial -out "${dir}/tls_cert" -days 30 -extfile "${dir}/tls.ext" 2>/dev/null
  rm -f "${dir}/tls.csr" "${dir}/tls.ext" "${dir}/tls_ca.srl"
fi
# Build secret for apt behind a TLS-intercepting proxy (empty: image defaults).
if [ -n "${SAMBA_APT_CA:-}" ]; then
  cp "$SAMBA_APT_CA" "${dir}/apt_ca"
else
  : > "${dir}/apt_ca"
fi
# The containers read the secrets as root; the tests read them as the caller.
chmod 0600 "${dir}"/*
install -m 0644 "${dir}/tls_ca" "$ca_out"
echo "samba bench secrets in ${dir}, CA exported to testdata/samba-ca.pem"
