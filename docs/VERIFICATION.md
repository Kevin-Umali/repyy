# Releases and Verification

Reviewed: 2026-09-15. Describes the trust-roadmap changes; unreleased features are identified
explicitly.

Download only from [official GitHub Releases](https://github.com/Kevin-Umali/repyy/releases). The
sandbox image is `ghcr.io/kevin-umali/repyy-sandbox`. Verify downloaded artifacts before executing
them.

Provenance identifies a build's source and workflow. It does not prove the code is harmless, that
the maintainer account was uncompromised, or that a scan will detect every risk.

## Current evidence status

v0.5.1 is prepared on the development branch; it is not yet a published, verified release.

Release v0.5.0 publishes checksums and signing certificates, a signed sandbox image digest and
per-archive SBOMs. The next release workflow adds GitHub attestations and a release-set SPDX SBOM.
Do not assume older releases have these new attestations. A configured workflow is not published
verification evidence.

The new workflow keeps the GitHub release draft until download verification succeeds. A failed gate
must remain visible and must not be described as a verified release. Homebrew and Scoop manifests
are generated without upload, then published in a separate step only after verification and GitHub
release publication. Container blobs are pushed earlier to obtain the digest; availability alone is
not verification.

## Version and commit identity

Run `repyy version` only after verifying the downloaded artifact. It reports version, full source
commit, builder label, fixed source repository, Go version, build date and rules version. Missing
values are `unknown`; local builds label their builder `development`. These strings are diagnostics,
not cryptographic identity. Official workflow builds inject metadata into binaries and the sandbox
image.

Local scan reports cannot claim an immutable checkout commit: local content may be uncommitted or
change during inspection. Remote reports include the fetched revision. Report conversion preserves
the original scanner identity rather than substituting the converter's version.

## Verify provenance

Use a recent GitHub CLI with the `gh attestation` command. For a downloaded archive or extracted
binary, replace the placeholders with the exact release and filename:

```sh
gh attestation verify ARTIFACT --repo Kevin-Umali/repyy --signer-workflow Kevin-Umali/repyy/.github/workflows/release.yml --source-ref refs/tags/vX.Y.Z
```

Require the expected repository, workflow and release ref. Check the source commit in the
verification output against the release notes. Attestations for extracted binaries let users verify
after unpacking; archives and Linux packages also receive provenance.
[GitHub's attestation guide](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
explains verification and available policy controls.

## Checksums and existing signatures

A checksum detects changed bytes only after the checksum list itself is authenticated. Existing
releases use Cosign keyless signatures; this work retains that existing path rather than adding a
second signing system.

```sh
cosign verify-blob checksums.txt --signature checksums.txt.sig --certificate checksums.txt.pem --certificate-identity https://github.com/Kevin-Umali/repyy/.github/workflows/release.yml@refs/tags/vX.Y.Z --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --check checksums.txt
```

On macOS, use `shasum -a 256 --check checksums.txt`. Windows users can verify individual hashes with
`Get-FileHash`, after authenticating the checksum list. Do not treat a filename or download location
alone as verification.

## SBOM access and scope

Container inventories are published separately as `repyy-container-linux-amd64.spdx.json` and
`repyy-container-linux-arm64.spdx.json`. Each is attested against its platform image digest,
recorded in the corresponding `.txt` asset. These platform digests are selected from the signed
multi-platform image index; an inventory for one architecture does not claim coverage of the other.
Per-archive `*.sbom.json` assets identify archive contents. `repyy-release.spdx.json` describes the
release build directory as a set, including platform binaries and packages. It is not a separate
per-platform dependency assertion. The workflow binds that set inventory to each
binary/archive/package digest using an SPDX attestation. Read its package inventory and
relationships rather than interpreting an SBOM as a vulnerability scan.

```sh
gh attestation verify ARTIFACT --repo Kevin-Umali/repyy --signer-workflow Kevin-Umali/repyy/.github/workflows/release.yml --source-ref refs/tags/vX.Y.Z --predicate-type https://spdx.dev/Document
```

## Container verification

Read the exact image digest from the verified `repyy-sandbox-image.txt` asset. Replace `DIGEST` and
the version below:

```sh
gh attestation verify oci://ghcr.io/kevin-umali/repyy-sandbox@sha256:DIGEST --repo Kevin-Umali/repyy --signer-workflow Kevin-Umali/repyy/.github/workflows/release.yml --source-ref refs/tags/vX.Y.Z
cosign verify ghcr.io/kevin-umali/repyy-sandbox@sha256:DIGEST --certificate-identity https://github.com/Kevin-Umali/repyy/.github/workflows/release.yml@refs/tags/vX.Y.Z --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Pull that digest explicitly after verification. A digest pins bytes; signing/provenance identifies
who built them. Neither supplies VM isolation.

## Fresh-download release gate

Maintainers can run the same Linux gate used by the workflow, with a directory that does not yet
exist:

```sh
bash scripts/verify-release.sh vX.Y.Z /tmp/repyy-verification-vX.Y.Z
```

This needs GitHub CLI with attestation support, Cosign and SHA-256 tooling; GitHub Actions supplies
the tools for maintainers who do not want local installations. It downloads release assets into the
fresh directory and checks checksum signatures, hashes, artifact provenance, SBOM attestations and
container signatures/provenance. A nonzero result blocks publication. Public verification of the
next release remains a launch gate until that workflow actually runs successfully.

## Repository security signals

CodeQL is configured for Go and [GitHub Actions workflow security analysis](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-queries/actions-built-in-queries).
The added workflow analysis still needs its first CI run.

Inspect [CodeQL runs](https://github.com/Kevin-Umali/repyy/actions/workflows/codeql.yml),
[Scorecard workflow](https://github.com/Kevin-Umali/repyy/actions/workflows/scorecard.yml), the
[Scorecard breakdown](https://scorecard.dev/viewer/?uri=github.com/Kevin-Umali/repyy), and
[artifact attestations](https://github.com/Kevin-Umali/repyy/attestations). Scorecard results may be
unavailable before its first default-branch run. A passing check is limited evidence, not
certification.

Review high-risk Scorecard checks individually. Protected tags, branch protection, review
requirements and repository security settings need verification in GitHub; a workflow file alone
cannot enforce them. No extra paid service or separate badging account is required for this
pipeline.
