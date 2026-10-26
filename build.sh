#!/usr/bin/env bash
# ALDAP build script.
#   ./build.sh --dhi       build container from Docker Hardened Images (requires: docker login dhi.io)
#   ./build.sh --plain     build container from public golang/scratch (local testing only)
#   ./build.sh --linux     static linux binaries (amd64, arm64) into dist/
#   ./build.sh --windows   windows/amd64 binaries into dist/
#   ./build.sh --all       everything above
#   ./build.sh --podman [--dhi|--plain]  build the image with (rootless) podman instead of docker;
#                          --dhi when no image target is given (requires: podman login dhi.io)
# Env overrides: DHI_GOLANG_TAG, DHI_STATIC_TAG, IMAGE, VERSION, NO_SIGN=1, PUSH=1,
#   ATTEST=1 (BuildKit provenance/SBOM attestations; needs a docker-container
#   builder or the containerd image store, so it is off by default; docker only)
set -euo pipefail

IMAGE="${IMAGE:-aldap/aldap}"
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo none)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GO_MINOR="$(sed -n 's/^go \([0-9]*\.[0-9]*\).*/\1/p' go.mod 2>/dev/null || echo 1.26)"

# DHI tags: verify current tags in https://hub.docker.com/hardened-images/catalog/ (golang, static)
DHI_GOLANG_TAG="${DHI_GOLANG_TAG:-${GO_MINOR}-debian13-dev}"
DHI_STATIC_TAG="${DHI_STATIC_TAG:-latest}"

usage() { sed -n '2,10p' "$0"; exit 1; }

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
    local src="$target"
    # syft reads the docker daemon by default; podman images need the source prefix.
    [ "$ENGINE" = "podman" ] && src="podman:${target}"
    mkdir -p dist
    syft "$src" -o cyclonedx-json > "dist/sbom-$(echo "$target" | tr '/:' '__').cdx.json"
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

# ENGINE builds the images: docker, or podman with --podman.
ENGINE=docker

docker_build() {
  local target="$1"
  need "$ENGINE"
  local tag="${IMAGE}:${VERSION}"
  [ "$target" = "plain" ] && tag="${tag}-plain"
  log "${ENGINE} build target=${target} tag=${tag}"
  if [ "$target" = "dhi" ]; then
    if ! "$ENGINE" pull "dhi.io/golang:${DHI_GOLANG_TAG}" >/dev/null 2>&1; then
      die "cannot pull dhi.io/golang:${DHI_GOLANG_TAG}. Run '${ENGINE} login dhi.io' and/or set DHI_GOLANG_TAG to a tag listed at https://hub.docker.com/hardened-images/catalog/"
    fi
    if ! "$ENGINE" pull "dhi.io/static:${DHI_STATIC_TAG}" >/dev/null 2>&1; then
      die "cannot pull dhi.io/static:${DHI_STATIC_TAG}. Set DHI_STATIC_TAG to a tag listed in the DHI catalog"
    fi
  fi
  local extra=()
  if [ "$ENGINE" = "podman" ]; then
    # podman builds OCI images by default, and the OCI format has no
    # HEALTHCHECK: buildah drops it with a warning. The docker format keeps it.
    extra=(--format docker)
    [ "${ATTEST:-0}" = "1" ] && log "ATTEST=1 ignored: BuildKit attestations are docker-only"
  elif [ "${ATTEST:-0}" = "1" ]; then
    extra=(--provenance=true --sbom=true)
  fi
  "$ENGINE" build \
    --target "$target" \
    --build-arg "DHI_GOLANG_TAG=${DHI_GOLANG_TAG}" \
    --build-arg "DHI_STATIC_TAG=${DHI_STATIC_TAG}" \
    --build-arg "GO_MINOR=${GO_MINOR}" \
    --build-arg "VERSION=${VERSION}" \
    --build-arg "COMMIT=${COMMIT}" \
    --build-arg "DATE=${DATE}" \
    "${extra[@]}" \
    -t "$tag" .
  if [ "$target" = "dhi" ]; then
    "$ENGINE" tag "$tag" "${IMAGE}:latest"
  fi
  sbom_and_sign "$tag"
  if [ "${PUSH:-0}" = "1" ]; then
    log "${ENGINE} push ${tag}"
    "$ENGINE" push "$tag"
  fi
}

[ $# -eq 0 ] && usage
# --podman switches the engine for every image target; given alone it builds --dhi.
images=0
for arg in "$@"; do
  case "$arg" in
    --podman) ENGINE=podman ;;
    --dhi|--plain|--all) images=1 ;;
  esac
done
if [ "$ENGINE" = "podman" ] && [ "$images" = "0" ] && [ "$#" -eq 1 ]; then
  set -- "$@" --dhi
fi
for arg in "$@"; do
  case "$arg" in
    --podman)  ;;
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
