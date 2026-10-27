"""Offline behavioral checks for the release gate and manifest identity."""

import hashlib
import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "publish", SCRIPTS / "publish-packages.py"
)
publish = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publish)


class ReleaseGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.download_index = 0
        self.assets = self.root / "assets"
        self.assets.mkdir()
        names = [
            "repyy.tar.gz",
            "repyy.zip",
            "repyy.deb",
            "repyy.rpm",
            "repyy.apk",
            "repyy.sbom.json",
            "repyy-intelligence.json",
            "repyy-intelligence.json.sig",
            "repyy-release.spdx.json",
            "results.json",
            "results.md",
            "checksums.txt.sigstore.json",
            "checksums.txt.sig",
            "checksums.txt.pem",
        ]
        for arch in ("amd64", "arm64"):
            names.append(f"repyy-container-linux-{arch}.spdx.json")
        for name in names:
            (self.assets / name).write_text("inert verification fixture\n")
        for name, digest in [
            ("repyy-sandbox-image.txt", "c" * 64),
            ("repyy-container-linux-amd64.txt", "a" * 64),
            ("repyy-container-linux-arm64.txt", "b" * 64),
        ]:
            (self.assets / name).write_text(
                f"ghcr.io/kevin-umali/repyy-sandbox@sha256:{digest}\n"
            )
        checksum = hashlib.sha256(
            (self.assets / "repyy.tar.gz").read_bytes()
        ).hexdigest()
        (self.assets / "checksums.txt").write_text(f"{checksum}  repyy.tar.gz\n")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.fake(
            "gh",
            """#!/usr/bin/env python3
import json, os, pathlib, shutil, sys
args = sys.argv[1:]
with open(os.environ["CALL_LOG"], "a") as log:
    log.write("gh " + " ".join(args) + "\\n")
if args[:2] == ["release", "download"]:
    shutil.copytree(os.environ["ASSETS"], args[args.index("--dir") + 1], dirs_exist_ok=True)
elif args[:2] == ["attestation", "verify"]:
    if args[2] == "release.json":
        required = ("--source-ref", "refs/heads/main", "--cert-identity", "https://github.com/Kevin-Umali/repyy/.github/workflows/release.yml@refs/heads/main", "--signer-repo", "Kevin-Umali/repyy")
        if not all(value in args for value in required):
            sys.exit(1)
    sys.exit(int(os.environ.get("ATTEST_FAIL", "0")))
elif args[:2] == ["api", "repos/Kevin-Umali/repyy/git/ref/tags/v1.2.3"]:
    if os.environ.get("ANNOTATED"):
        print(json.dumps({"object": {"type": "tag", "sha": "d" * 40}}))
    else:
        print(json.dumps({"object": {"type": "commit", "sha": os.environ.get("TAG_SHA", "a" * 40)}}))
elif args[:2] == ["api", "repos/Kevin-Umali/repyy/git/tags/" + "d" * 40]:
    print(json.dumps({"object": {"type": "commit", "sha": "a" * 40}}))
else:
    sys.exit(99)
""",
        )
        self.fake(
            "cosign",
            """#!/usr/bin/env bash
printf 'cosign %s\\n' "$*" >> "$CALL_LOG"
exit "${COSIGN_FAIL:-0}"
""",
        )
        self.env = dict(
            os.environ,
            PATH=f"{self.bin}:{os.environ['PATH']}",
            ASSETS=str(self.assets),
            CALL_LOG=str(self.root / "calls"),
        )

    def fake(self, name, content):
        path = self.bin / name
        path.write_text(content)
        path.chmod(0o755)

    def gate(self, **env):
        self.download_index += 1
        (self.root / "calls").unlink(missing_ok=True)
        result = subprocess.run(
            [
                "bash",
                str(SCRIPTS / "verify-release.sh"),
                "v1.2.3",
                str(self.root / f"download-{self.download_index}"),
            ],
            env=dict(self.env, **env),
            capture_output=True,
            text=True,
            check=False,
        )
        return result, (self.root / "calls").read_text()

    def test_success_checks_both_container_platforms(self):
        for bundle in (True, False):
            with self.subTest(bundle=bundle):
                result, calls = self.gate()
                self.assertEqual(result.returncode, 0, result.stderr)
                for digest in ("a" * 64, "b" * 64):
                    self.assertIn(
                        f"gh attestation verify oci://ghcr.io/kevin-umali/repyy-sandbox@sha256:{digest} "
                        "--predicate-type https://spdx.dev/Document",
                        calls,
                    )
                if bundle:
                    self.assertIn(
                        "cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json",
                        calls,
                    )
                    self.assertIn(
                        "gh attestation verify checksums.txt.sigstore.json ", calls
                    )
                    self.assertNotIn("--signature checksums.txt.sig", calls)
                else:
                    self.assertIn(
                        "--signature checksums.txt.sig --certificate checksums.txt.pem",
                        calls,
                    )
                    self.assertIn("gh attestation verify checksums.txt.pem ", calls)
                self.assertIn("Verified checksums", result.stdout)
                if bundle:
                    (self.assets / "checksums.txt.sigstore.json").unlink()

    def test_signature_failure_stops_before_attestations(self):
        result, calls = self.gate(COSIGN_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("attestation verify", calls)
        self.assertNotIn("--signature checksums.txt.sig", calls)

    def test_checksum_mismatch_stops_before_attestations(self):
        (self.assets / "repyy.tar.gz").write_text("tampered")
        result, calls = self.gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("attestation verify", calls)

    def test_attestation_failure_does_not_claim_success(self):
        result, _ = self.gate(ATTEST_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Verified checksums", result.stdout)

    def make_release_record(self):
        for filename in ("repyy-homebrew.rb", "repyy-scoop.json"):
            (self.assets / filename).write_text("package manifest\n")
        subprocess.run(
            [
                "python3",
                str(SCRIPTS / "release.py"),
                "create",
                "v1.2.3",
                "a" * 40,
                "b" * 40,
                str(self.assets),
            ],
            check=True,
        )

    def test_new_release_record_is_attested_and_matches_tag_and_assets(self):
        self.make_release_record()
        result, calls = self.gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("gh attestation verify release.json", calls)
        self.assertIn("gh attestation verify repyy-homebrew.rb", calls)
        self.assertIn("gh attestation verify repyy-scoop.json", calls)
        self.assertLess(
            calls.index("gh attestation verify release.json"),
            calls.index("cosign verify-blob"),
        )
        result, calls = self.gate(ANNOTATED="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("git/tags/" + "d" * 40, calls)
        self.assertIn(
            "--certificate-identity https://github.com/Kevin-Umali/repyy/.github/workflows/release.yml@refs/heads/main",
            calls,
        )
        for env, tamper in (
            ({"TAG_SHA": "c" * 40}, False),
            ({}, True),
            ({"ATTEST_FAIL": "1"}, False),
        ):
            with self.subTest(env=env, tamper=tamper):
                if tamper:
                    (self.assets / "repyy-homebrew.rb").write_text("tampered")
                result, calls = self.gate(**env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("gh attestation verify release.json", calls)
                self.assertNotIn("gh attestation verify repyy-homebrew.rb", calls)
                if tamper:
                    (self.assets / "repyy-homebrew.rb").write_text("package manifest\n")

    def test_manifest_version_must_match_exactly(self):
        for filename, content in [
            ("repyy.json", '{"version":"11.2.3"}'),
            ("repyy.rb", '  version "11.2.3"\n'),
        ]:
            with self.subTest(filename=filename):
                source = self.root / filename
                source.write_text(content)
                with self.assertRaises(ValueError):
                    publish.validate_manifest(source, "1.2.3")
                self.assertEqual(
                    publish.validate_manifest(source, "11.2.3"), source.read_bytes()
                )


if __name__ == "__main__":
    unittest.main()
