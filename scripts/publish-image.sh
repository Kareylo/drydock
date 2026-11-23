#!/usr/bin/env bash
# Builds the production image for amd64 and arm64 on this machine and pushes it
# to Docker Hub as vX.Y.Z, vX.Y, vX and latest. A dev build (dev-vX.Y.Z) gets
# the same tags with the dev- prefix, down to dev-latest. Run it from a clean
# checkout of the commit to release, after `podman login docker.io`:
#   scripts/publish-image.sh v1.2.0
#   scripts/publish-image.sh dev-v1.2.0
# The first build compiles the Rust binary for arm64 under QEMU: count up to
# an hour. Later builds reuse the local cache.
# Trivy scans the image of this machine first: a fixable critical or high
# vulnerability stops the script before anything is pushed. The image is built
# FROM scratch: Trivy reads the dependency list cargo-auditable embeds in the binary.
# The commit must carry the git tag being published, pushed to origin
# (`git tag -a v1.2.0 -m v1.2.0 && git push origin v1.2.0`).
# The pushed image is signed with cosign and gets an SPDX SBOM attestation
# (syft). Signing is keyless by default (a browser opens for the Sigstore
# login); set COSIGN_KEY to sign with a key instead (cosign.key, kms://…).
set -euo pipefail

readonly REPOSITORY=docker.io/kareylo/drydock

version="${1:-}"
if [[ ! "$version" =~ ^(dev-)?v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
    echo "Usage: $0 vX.Y.Z | dev-vX.Y.Z (for example v1.2.0 or dev-v1.2.0)" >&2
    exit 2
fi
prefix="${BASH_REMATCH[1]}"
major="${BASH_REMATCH[2]}"
minor="${BASH_REMATCH[3]}"
tags=("$version" "${prefix}v${major}.${minor}" "${prefix}v${major}" "${prefix}latest")

for tool in trivy cosign syft; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "${tool} is needed (scan, signature, SBOM): install it first." >&2
        exit 1
    fi
done

cd "$(dirname "$0")/.."

if [ -n "$(git status --porcelain)" ]; then
    echo "There are uncommitted changes: commit or stash them, the image must match a commit." >&2
    exit 1
fi

# The image must match a release anyone can find: HEAD carries the tag, and
# origin has the same tag on the same commit.
if ! git tag --points-at HEAD | grep -qxF "$version"; then
    echo "HEAD is not tagged ${version}: run git tag -a ${version} -m ${version} first." >&2
    exit 1
fi
head_commit="$(git rev-parse HEAD)"
remote_commit="$(git ls-remote --tags origin "refs/tags/${version}^{}" "refs/tags/${version}" | awk 'END { print $1 }')"
if [ "$remote_commit" != "$head_commit" ]; then
    echo "Tag ${version} is not on origin, or points elsewhere: run git push origin ${version} first." >&2
    exit 1
fi

# From an archive: the same for both engines, with no socket to set up. What
# follows the engine goes to its build.
scan_image() {
    local engine="$1"
    shift
    local image="localhost/drydock:${version}-scan"

    scan_dir="$(mktemp -d)"
    trap 'rm -rf "$scan_dir"' EXIT

    "$engine" build "$@" --file Dockerfile --tag "$image" .
    "$engine" save --output "${scan_dir}/image.tar" "$image"
    trivy image --input "${scan_dir}/image.tar" --scanners vuln \
        --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1
    # SBOM of the scanned build: same commit and Cargo.lock as the pushed
    # images (the dependency list is the same for amd64 and arm64).
    syft "docker-archive:${scan_dir}/image.tar" --output "spdx-json=${scan_dir}/sbom.spdx.json"
}

# Signs the pushed index (covers every tag and platform) and attaches the SBOM.
sign_image() {
    local ref="${REPOSITORY}@$1"
    local key_flags=()
    if [ -n "${COSIGN_KEY:-}" ]; then
        key_flags=(--key "$COSIGN_KEY")
    fi
    cosign sign --yes "${key_flags[@]}" "$ref"
    cosign attest --yes "${key_flags[@]}" --type spdxjson \
        --predicate "${scan_dir}/sbom.spdx.json" "$ref"
    echo "Signed ${ref}"
}

publish_with_podman() {
    if ! podman login --get-login docker.io >/dev/null 2>&1; then
        echo "Not logged in to Docker Hub: run podman login docker.io first." >&2
        exit 1
    fi

    scan_image podman --format docker

    local manifest="localhost/drydock:${version}"
    if podman manifest exists "$manifest"; then
        podman manifest rm "$manifest" >/dev/null
    fi

    # docker format: an OCI image drops HEALTHCHECK, which the stacks rely on.
    podman build \
        --platform linux/amd64,linux/arm64 \
        --format docker \
        --file Dockerfile \
        --manifest "$manifest" \
        .

    local tag
    for tag in "${tags[@]}"; do
        podman manifest push --all --format v2s2 --digestfile "${scan_dir}/digest" \
            "$manifest" "docker://${REPOSITORY}:${tag}"
    done
    # Every tag points to the same index: one signature covers them all.
    sign_image "$(cat "${scan_dir}/digest")"
}

publish_with_docker() {
    # docker login records the registry in the client config.
    if ! grep -qs 'index.docker.io' "${DOCKER_CONFIG:-$HOME/.docker}/config.json"; then
        echo "Not logged in to Docker Hub: run docker login first." >&2
        exit 1
    fi

    if ! docker buildx version >/dev/null 2>&1; then
        echo "docker buildx is needed to build for amd64 and arm64: install the buildx plugin." >&2
        exit 1
    fi

    scan_image docker

    local tag tag_flags=()
    for tag in "${tags[@]}"; do
        tag_flags+=(--tag "${REPOSITORY}:${tag}")
    done

    docker buildx build \
        --platform linux/amd64,linux/arm64 \
        --file Dockerfile \
        "${tag_flags[@]}" \
        --push \
        .

    sign_image "$(docker buildx imagetools inspect --format '{{.Manifest.Digest}}' "${REPOSITORY}:${version}")"
}

# podman first: on some machines, docker is only a podman shim.
if command -v podman >/dev/null 2>&1; then
    publish_with_podman
elif command -v docker >/dev/null 2>&1; then
    publish_with_docker
else
    echo "Neither podman nor docker is installed: install one of them." >&2
    exit 1
fi

echo "Published ${REPOSITORY}: ${tags[*]}"
