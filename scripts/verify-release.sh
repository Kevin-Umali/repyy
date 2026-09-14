#!/usr/bin/env bash
# Verify public or authenticated draft downloads, before executing a binary.
set -euo pipefail
release_tag="${1:?usage: verify-release.sh vX.Y.Z EMPTY-DIRECTORY}"
verify_dir="${2:?provide a fresh verification directory}"
[[ "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
mkdir "$verify_dir"
repo=Kevin-Umali/repyy
gh release download "$release_tag" --repo "$repo" --dir "$verify_dir"
cd "$verify_dir"
identity="https://github.com/$repo/.github/workflows/release.yml@refs/tags/$release_tag"
verify_attestation() {
  gh attestation verify "$@" --repo "$repo" \
    --signer-workflow "$repo/.github/workflows/release.yml" \
    --source-ref "refs/tags/$release_tag"
}
cosign verify-blob checksums.txt \
  --signature checksums.txt.sig --certificate checksums.txt.pem \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --check checksums.txt
artifacts=(
  *.tar.gz *.zip *.deb *.rpm *.apk *.sbom.json
  repyy-intelligence.json repyy-intelligence.json.sig
  repyy-sandbox-image.txt repyy-release.spdx.json
  repyy-container-linux-{amd64,arm64}.spdx.json
  repyy-container-linux-{amd64,arm64}.txt
  results.json results.md checksums.txt checksums.txt.sig checksums.txt.pem
)
for artifact in "${artifacts[@]}"; do
  test -f "$artifact"
  verify_attestation "$artifact"
done
for artifact in *.tar.gz *.zip *.deb *.rpm *.apk; do
  verify_attestation "$artifact" --predicate-type https://spdx.dev/Document
done
image="$(cat repyy-sandbox-image.txt)"
[[ "$image" =~ ^ghcr.io/kevin-umali/repyy-sandbox@sha256:[a-f0-9]{64}$ ]]
cosign verify "$image" --certificate-identity "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
verify_attestation "oci://$image"
for arch in amd64 arm64; do
  platform_image="$(cat "repyy-container-linux-$arch.txt")"
  [[ "$platform_image" =~ ^ghcr.io/kevin-umali/repyy-sandbox@sha256:[a-f0-9]{64}$ ]]
  verify_attestation "oci://$platform_image" --predicate-type https://spdx.dev/Document
done
printf 'Verified checksums, signatures, provenance, and SBOM attestations for %s.\n' "$release_tag"
printf 'This does not prove harmlessness.\n'
