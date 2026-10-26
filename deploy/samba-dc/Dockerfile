# syntax=docker/dockerfile:1.7
# Samba AD DC for `make integration-samba` (test bench only, never production).
# Ubuntu's Samba 4.19 package; the base is an ARG so a registry mirror can be used.
ARG BASE=ubuntu:24.04
FROM ${BASE}

# An optional build secret `apt_ca` (a CA bundle) switches apt to HTTPS through a
# TLS-intercepting proxy; without it the image's default sources are used.
RUN --mount=type=secret,id=apt_ca,required=false \
    set -eu; \
    if [ -s /run/secrets/apt_ca ]; then \
      sed -i 's|http://|https://|g' /etc/apt/sources.list.d/ubuntu.sources; \
      install -m 0644 /run/secrets/apt_ca /tmp/apt_ca; \
      echo 'Acquire::https::CaInfo "/tmp/apt_ca";' > /etc/apt/apt.conf.d/99build-ca; \
    fi; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      samba-ad-dc samba-ad-provision samba-dsdb-modules samba-vfs-modules winbind \
      python3-samba ldb-tools openssl ca-certificates; \
    rm -f /etc/apt/apt.conf.d/99build-ca /tmp/apt_ca /etc/samba/smb.conf; \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh provision.py provision.ldif /opt/bench/
RUN chmod 0755 /opt/bench/entrypoint.sh

EXPOSE 636
HEALTHCHECK --interval=3s --timeout=3s --start-period=120s --retries=40 \
  CMD ["/bin/bash", "-c", "test -f /run/bench-ready && exec 3<>/dev/tcp/127.0.0.1/636"]
ENTRYPOINT ["/opt/bench/entrypoint.sh"]
