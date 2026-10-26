# syntax=docker/dockerfile:1.7
# ALDAP container. Two runtime targets:
#   dhi   — Docker Hardened Images (production):  docker build --target dhi .
#   plain — public golang + scratch (local tests): docker build --target plain .
# Verify DHI tags in https://hub.docker.com/hardened-images/catalog/ ; `docker login dhi.io` is required.

ARG GO_MINOR=1.26
# Pinned (docs/DECISIONS.md «DHI tags»), same defaults as build.sh (TestDHITagsPinned).
ARG DHI_GOLANG_TAG=1.26.10-debian13-dev
ARG DHI_STATIC_TAG=20250419-debian13

# ---------- build stage: DHI ----------
FROM dhi.io/golang:${DHI_GOLANG_TAG} AS build-dhi
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -buildvcs=false -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" -o /out/aldap ./cmd/aldap && \
    go build -buildvcs=false -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" -o /out/aldapctl ./cmd/aldapctl && \
    mkdir -p /out/empty

# ---------- build stage: plain ----------
FROM golang:${GO_MINOR}-alpine AS build-plain
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -buildvcs=false -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" -o /out/aldap ./cmd/aldap && \
    go build -buildvcs=false -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" -o /out/aldapctl ./cmd/aldapctl && \
    mkdir -p /out/empty

# ---------- runtime: DHI static ----------
FROM dhi.io/static:${DHI_STATIC_TAG} AS dhi
LABEL org.opencontainers.image.title="ALDAP" \
      org.opencontainers.image.description="LDAP proxy with virtual directory, brute-force protection and IDS telemetry" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/alstdev/aldap"
COPY --from=build-dhi --chown=65532:65532 /out/aldap /usr/local/bin/aldap
COPY --from=build-dhi --chown=65532:65532 /out/aldapctl /usr/local/bin/aldapctl
# State and socket directories owned by the image user: a new named volume
# takes them over (without this a scratch-like image gives root:root and
# the CA cannot be created). Parents stay root-owned.
COPY --from=build-dhi /out/empty /var/lib
COPY --from=build-dhi /out/empty /run
COPY --from=build-dhi --chown=65532:65532 --chmod=0700 /out/empty /var/lib/aldap
COPY --from=build-dhi --chown=65532:65532 --chmod=0700 /out/empty /run/aldap
USER 65532:65532
VOLUME ["/etc/aldap", "/var/lib/aldap", "/run/aldap"]
ENV ALDAP_CONFIG=/etc/aldap/aldap.toml
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/usr/local/bin/aldap", "check", "--quick"]
ENTRYPOINT ["/usr/local/bin/aldap"]
CMD ["run"]

# ---------- runtime: scratch ----------
FROM scratch AS plain
COPY --from=build-plain /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build-plain /out/aldap /usr/local/bin/aldap
COPY --from=build-plain /out/aldapctl /usr/local/bin/aldapctl
COPY --from=build-plain /out/empty /var/lib
COPY --from=build-plain /out/empty /run
COPY --from=build-plain --chown=65532:65532 --chmod=0700 /out/empty /var/lib/aldap
COPY --from=build-plain --chown=65532:65532 --chmod=0700 /out/empty /run/aldap
USER 65532:65532
VOLUME ["/etc/aldap", "/var/lib/aldap", "/run/aldap"]
ENV ALDAP_CONFIG=/etc/aldap/aldap.toml
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/usr/local/bin/aldap", "check", "--quick"]
ENTRYPOINT ["/usr/local/bin/aldap"]
CMD ["run"]
