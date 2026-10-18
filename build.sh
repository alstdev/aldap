#!/usr/bin/env bash
# ALDAP build script.
#   ./build.sh --dhi       build container from Docker Hardened Images (requires: docker login dhi.io)
#   ./build.sh --plain     build container from public golang/scratch (local testing only)
#   ./build.sh --linux     static linux binaries (amd64, arm64) into dist/
#   ./build.sh --windows   windows/amd64 binaries into dist/
#   ./build.sh --all       everything above
# Env overrides: DHI_GOLANG_TAG, DHI_STATIC_TAG, IMAGE, VERSION, NO_SIGN=1, PUSH=1,
#   ATTEST=1 (BuildKit provenance/SBOM attestations; needs a docker-container
#   builder or the containerd image store, so it is off by default)
set -euo pipefail

IMAGE="${IMAGE:-aldap/aldap}"
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo none)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GO_MINOR="$(sed -n 's/^go \([0-9]*\.[0-9]*\).*/\1/p' go.mod 2>/dev/null || echo 1.25)"

# DHI tags: verify current tags in https://hub.docker.com/hardened-images/catalog/ (golang, static)
DHI_GOLANG_TAG="${DHI_GOLANG_TAG:-${GO_MINOR}-debian13-dev}"
DHI_STATIC_TAG="${DHI_STATIC_TAG:-latest}"

usage() { sed -n '2,8p' "$0"; exit 1; }

log() { printf '\033[1;34m[build]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[build] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing tool: $1"; }

build_bins() {
  local os="$1"; shift
  need go
  mkdir -p dist
  for arch in "$@"; do
    local ext=""; [ "$os" = "windows" ] && ext=".exe"
    log "go build ${os}/${arch}"
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
      -o "dist/aldap_${os}_${arch}${ext}" ./cmd/aldap
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
      -o "dist/aldapctl_${os}_${arch}${ext}" ./cmd/aldapctl
  done
}

sbom_and_sign() {
  local target="$1"
  if command -v syft >/dev/null 2>&1; then
    log "SBOM (CycloneDX) for ${target}"
    syft "$target" -o cyclonedx-json > "dist/sbom-$(echo "$target" | tr '/:' '__').cdx.json"
  else
    log "syft not found, SBOM skipped"
  fi
  if [ "${NO_SIGN:-0}" != "1" ] && command -v cosign >/dev/null 2>&1 && [ -n "${COSIGN_KEY:-}" ]; then
    log "cosign sign ${target}"
    cosign sign --key "$COSIGN_KEY" --yes "$target"
  else
    log "signing skipped (NO_SIGN=1, no cosign, or no COSIGN_KEY)"
  fi
}

docker_build() {
  local target="$1"
  need docker
  local tag="${IMAGE}:${VERSION}"
  [ "$target" = "plain" ] && tag="${tag}-plain"
  log "docker build target=${target} tag=${tag}"
  if [ "$target" = "dhi" ]; then
    if ! docker pull "dhi.io/golang:${DHI_GOLANG_TAG}" >/dev/null 2>&1; then
      die "cannot pull dhi.io/golang:${DHI_GOLANG_TAG}. Run 'docker login dhi.io' and/or set DHI_GOLANG_TAG to a tag listed at https://hub.docker.com/hardened-images/catalog/"
    fi
    if ! docker pull "dhi.io/static:${DHI_STATIC_TAG}" >/dev/null 2>&1; then
      die "cannot pull dhi.io/static:${DHI_STATIC_TAG}. Set DHI_STATIC_TAG to a tag listed in the DHI catalog"
    fi
  fi
  local attest=()
  if [ "${ATTEST:-0}" = "1" ]; then
    attest=(--provenance=true --sbom=true)
  fi
  docker build \
    --target "$target" \
    --build-arg "DHI_GOLANG_TAG=${DHI_GOLANG_TAG}" \
    --build-arg "DHI_STATIC_TAG=${DHI_STATIC_TAG}" \
    --build-arg "GO_MINOR=${GO_MINOR}" \
    --build-arg "VERSION=${VERSION}" \
    --build-arg "COMMIT=${COMMIT}" \
    --build-arg "DATE=${DATE}" \
    "${attest[@]}" \
    -t "$tag" .
  [ "$target" = "dhi" ] && docker tag "$tag" "${IMAGE}:latest"
  sbom_and_sign "$tag"
  if [ "${PUSH:-0}" = "1" ]; then
    log "docker push ${tag}"
    docker push "$tag"
  fi
}

[ $# -eq 0 ] && usage
for arg in "$@"; do
  case "$arg" in
    --dhi)     docker_build dhi ;;
    --plain)   docker_build plain ;;
    --linux)   build_bins linux amd64 arm64 ;;
    --windows) build_bins windows amd64 ;;
    --all)     build_bins linux amd64 arm64; build_bins windows amd64; docker_build plain; docker_build dhi ;;
    -h|--help) usage ;;
    *) die "unknown option: $arg" ;;
  esac
done
log "done"
