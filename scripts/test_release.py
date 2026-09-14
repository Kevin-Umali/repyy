"""Offline regression checks for release verification ordering and manifest identity."""

import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

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
            "checksums.txt.sig",
            "checksums.txt.pem",
        ]
        for arch in ("amd64", "arm64"):
            names.append(f"repyy-container-linux-{arch}.spdx.json")
        for name in names:
            (self.assets / name).write_text("inert verification fixture\n")
        image = "ghcr.io/kevin-umali/repyy-sandbox@sha256:" + "a" * 64 + "\n"
        for name in [
            "repyy-sandbox-image.txt",
            "repyy-container-linux-amd64.txt",
            "repyy-container-linux-arm64.txt",
        ]:
            (self.assets / name).write_text(image)
        checksum = hashlib.sha256(
            (self.assets / "repyy.tar.gz").read_bytes()
        ).hexdigest()
        (self.assets / "checksums.txt").write_text(f"{checksum}  repyy.tar.gz\n")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.fake(
            "gh",
            """#!/usr/bin/env python3
import os, pathlib, shutil, sys
args = sys.argv[1:]
with open(os.environ["CALL_LOG"], "a") as log:
    log.write("gh " + " ".join(args) + "\\n")
if args[:2] == ["release", "download"]:
    shutil.copytree(os.environ["ASSETS"], args[args.index("--dir") + 1], dirs_exist_ok=True)
elif args[:2] == ["attestation", "verify"]:
    sys.exit(int(os.environ.get("ATTEST_FAIL", "0")))
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
        result = subprocess.run(
            [
                "bash",
                str(SCRIPTS / "verify-release.sh"),
                "v1.2.3",
                str(self.root / "download"),
            ],
            env=dict(self.env, **env),
            capture_output=True,
            text=True,
        )
        return result, (self.root / "calls").read_text()

    def test_success_checks_both_container_platforms(self):
        result, calls = self.gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls.count("--predicate-type https://spdx.dev/Document"), 7)
        self.assertIn("Verified checksums", result.stdout)

    def test_signature_failure_stops_before_attestations(self):
        result, calls = self.gate(COSIGN_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("attestation verify", calls)

    def test_checksum_mismatch_stops_before_attestations(self):
        (self.assets / "repyy.tar.gz").write_text("tampered")
        result, calls = self.gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("attestation verify", calls)

    def test_attestation_failure_does_not_claim_success(self):
        result, _ = self.gate(ATTEST_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Verified checksums", result.stdout)

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
