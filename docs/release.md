# Releases

`.github/workflows/release.yml` builds and publishes a release when a tag `v*` is pushed. The
owner creates the tag; nothing in the repository creates one.

## What a release contains

| Artifact | How |
|---|---|
| `aldap_linux_amd64`, `aldap_linux_arm64`, `aldap_windows_amd64.exe`, `aldapctl_*` (same platforms) | `make build VERSION=<tag>`: static, `-trimpath`, version/commit/date in `aldap version` |
| `aldap_<tag>_sbom.cdx.json` | CycloneDX SBOM of the Go modules (syft via `anchore/sbom-action`) |
| `sbom-ghcr.io_alstdev_aldap_<tag>.cdx.json` | CycloneDX SBOM of the container image (syft in `build.sh`) |
| `SHA256SUMS` | SHA-256 of the binaries and the source SBOM |
| `SHA256SUMS.sigstore.json` | keyless cosign signature bundle of `SHA256SUMS` (GitHub OIDC, Rekor) |
| `ghcr.io/alstdev/aldap:<tag>`, `:latest` | `build.sh --dhi` (Docker Hardened Images), pushed, signed keyless by digest |
| Release notes | the `## [<version>]` section of `CHANGELOG.md` (`scripts/release-notes.sh`) |

Before anything is published the workflow re-runs `go vet`, `make test` and the Samba bench
(`samba.yml`) on the tagged commit. The GitHub Release is created only when the binaries, the
image, the tests and the Samba bench all succeeded.

## Cutting a release (owner)

1. Rename `## [Unreleased]` in `CHANGELOG.md` to `## [X.Y.Z] - YYYY-MM-DD` (and start a new
   empty `[Unreleased]`); merge to `main` with green CI. A tag without its section fails the
   workflow (`no CHANGELOG section for X.Y.Z`).
2. Make sure the repository secrets `DHI_USERNAME` and `DHI_TOKEN` exist (a Docker account with
   access to `dhi.io`): on a tag the image job **fails** without them — no release without the
   image.
3. `git tag -s vX.Y.Z && git push origin vX.Y.Z`.

The workflow needs `packages: write` (GHCR) and `id-token: write` (keyless signing) only in the
image and release jobs; everything else runs with `contents: read`.

## Dry run

`workflow_dispatch` (Actions → release → Run workflow) and pull requests that change
`release.yml`, `scripts/release-notes.sh`, `build.sh` or `Dockerfile` run the same jobs as a dry
run: version `v0.0.0-dryrun.<sha>`, notes from `[Unreleased]`, binaries, SBOM and checksums built
and verified, the DHI image built but not pushed. Nothing is signed (a keyless signature is
itself a public Rekor entry), pushed or released; the job summary lists the files. Without DHI
secrets the dry run skips the image with a warning. `workflow_dispatch` needs the workflow on the
default branch, so before the first merge the pull-request trigger is the dry run.

## Verifying a release

```sh
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/alstdev/aldap/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS --ignore-missing

cosign verify ghcr.io/alstdev/aldap:vX.Y.Z \
  --certificate-identity-regexp '^https://github.com/alstdev/aldap/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## DHI base images

`Dockerfile` and `build.sh` pin `dhi.io/golang:1.26.10-debian13-dev` (the patch release equals
the `go.mod` toolchain) and `dhi.io/static:20250419-debian13`; `TestDHITagsPinned` keeps the two
files and `go.mod` in step. When the toolchain moves, move the golang tag with it (the catalog:
<https://hub.docker.com/hardened-images/catalog/dhi/golang>). Pull requires `docker login dhi.io`.
