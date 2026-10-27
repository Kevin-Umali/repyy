#!/usr/bin/env bash
# Verify public or authenticated draft downloads, before executing a binary.
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
release_tag="${1:?usage: verify-release.sh vX.Y.Z EMPTY-DIRECTORY}"
verify_dir="${2:?provide a fresh verification directory}"
[[ "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
mkdir "$verify_dir"
repo=Kevin-Umali/repyy
gh release download "$release_tag" --repo "$repo" --dir "$verify_dir"
cd "$verify_dir"
source_ref="refs/tags/$release_tag"
identity="https://github.com/$repo/.github/workflows/release.yml@$source_ref"
if [[ -f release.json ]]; then
  source_ref="refs/heads/main"
  identity="https://github.com/$repo/.github/workflows/release.yml@$source_ref"
  gh attestation verify release.json --repo "$repo" --signer-repo "$repo" \
    --signer-workflow "$repo/.github/workflows/release.yml" \
    --source-ref "$source_ref" --cert-identity "$identity"
  object="$(gh api "repos/$repo/git/ref/tags/$release_tag")"
  for ((depth = 0; depth < 10; depth++)); do
    read -r type sha < <(printf '%s' "$object" | python3 -c 'import json,sys; o=json.load(sys.stdin)["object"]; print(o["type"], o["sha"])')
    [[ "$sha" =~ ^[0-9a-f]{40}$ ]]
    if [[ "$type" == commit ]]; then break; fi
    [[ "$type" == tag ]]
    object="$(gh api "repos/$repo/git/tags/$sha")"
  done
  [[ "$type" == commit ]]
  python3 "$script_dir/release.py" validate "$release_tag" "$sha" "$PWD" >/dev/null
fi
verify_attestation() {
  local identity_args=()
  if [[ "$source_ref" == refs/heads/main ]]; then
    identity_args=(--cert-identity "$identity" --signer-repo "$repo")
  fi
  gh attestation verify "$@" --repo "$repo" \
    --signer-workflow "$repo/.github/workflows/release.yml" \
    --source-ref "$source_ref" ${identity_args[@]+"${identity_args[@]}"}
}
signature_artifacts=(checksums.txt.sigstore.json)
signature_args=(--bundle checksums.txt.sigstore.json)
if [[ ! -f checksums.txt.sigstore.json ]]; then
  signature_artifacts=(checksums.txt.sig checksums.txt.pem)
  signature_args=(--signature checksums.txt.sig --certificate checksums.txt.pem)
fi
cosign verify-blob checksums.txt "${signature_args[@]}" \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --check checksums.txt
artifacts=(
  *.tar.gz *.zip *.deb *.rpm *.apk *.sbom.json
  repyy-intelligence.json repyy-intelligence.json.sig
  repyy-sandbox-image.txt repyy-release.spdx.json
  repyy-container-linux-{amd64,arm64}.spdx.json
  repyy-container-linux-{amd64,arm64}.txt
  results.json results.md checksums.txt "${signature_artifacts[@]}"
)
if [[ -f release.json ]]; then
  shopt -s dotglob
  artifacts=(*)
fi
pids=()
wait_batch() {
  local failed=0 pid
  for pid in ${pids[@]+"${pids[@]}"}; do wait "$pid" || failed=1; done
  pids=()
  return "$failed"
}
queue_attestation() {
  verify_attestation "$@" &
  pids+=("$!")
  if ((${#pids[@]} == 4)); then wait_batch; fi
}
for artifact in "${artifacts[@]}"; do
  test -f "$artifact"
  [[ "$artifact" == release.json ]] && continue
  queue_attestation "$artifact"
done
wait_batch
for artifact in *.tar.gz *.zip *.deb *.rpm *.apk; do
  queue_attestation "$artifact" --predicate-type https://spdx.dev/Document
done
wait_batch
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
