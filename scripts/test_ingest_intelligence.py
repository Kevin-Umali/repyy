import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("ingest", Path(__file__).with_name("ingest_intelligence.py"))
ingest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ingest)


class IngestionTests(unittest.TestCase):
    def test_aliases_merge_exact_versions_and_withdrawals_are_audited(self):
        github = {"type": "malware", "ghsa_id": "GHSA-aaaa-bbbb-cccc", "identifiers": [{"value": "MAL-1"}], "html_url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc", "published_at": "2026-01-01", "updated_at": "2026-01-02", "summary": "malware", "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "example-bad"}, "vulnerable_version_range": "= 1.2.3"}]}
        osv = {"id": "MAL-1", "aliases": ["GHSA-aaaa-bbbb-cccc"], "published": "2026-01-01", "modified": "2026-01-03", "summary": "duplicate", "affected": [{"package": {"ecosystem": "npm", "name": "example-bad"}, "versions": ["1.2.3"]}]}
        withdrawn = {"id": "MAL-2", "withdrawn": "2026-01-04", "affected": [{"package": {"ecosystem": "npm", "name": "safe-after-review"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}
        records = ingest.normalize_github(github) + ingest.normalize_osv(osv, "https://example.test/MAL-1") + ingest.normalize_osv(withdrawn, "https://example.test/MAL-2")
        packages, corrections = ingest.merge(records, "2026-09-26.1")
        self.assertEqual(len(packages), 1)
        self.assertEqual(packages[0]["affected_versions"], ["= 1.2.3"])
        self.assertEqual(packages[0]["advisory_id"], "GHSA-aaaa-bbbb-cccc")
        self.assertEqual(corrections[0]["reason"], "withdrawn-or-false-positive")

        correction = {"id": "MAL-1", "aliases": ["GHSA-aaaa-bbbb-cccc"], "withdrawn": "2026-01-04", "affected": [{"package": {"ecosystem": "npm", "name": "example-bad"}}]}
        corrected, ledger = ingest.merge(records + ingest.normalize_osv(correction, "https://example.test/correction"), "2026-09-26.1")
        self.assertEqual(corrected, [])
        self.assertEqual(len(ledger), 2)

    def test_osv_all_versions_and_benign_non_ecosystem_range(self):
        report = {"id": "MAL-3", "affected": [{"package": {"ecosystem": "PyPI", "name": "bad"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}, {"type": "GIT", "events": [{"introduced": "deadbeef"}]}]}]}
        record = ingest.normalize_osv(report, "https://example.test/MAL-3")[0]
        self.assertEqual(record["ecosystem"], "pip")
        self.assertEqual(record["affected"], [">= 0"])

    def test_bounded_osv_interval_does_not_claim_fixed_versions(self):
        report = {"id": "MAL-4", "affected": [{"package": {"ecosystem": "npm", "name": "bad"}, "versions": ["1.2.3"], "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}]}]}
        record = ingest.normalize_osv(report, "https://example.test/MAL-4")[0]
        self.assertEqual(record["affected"], ["= 1.2.3"])

        report["affected"][0]["versions"] = []
        record = ingest.normalize_osv(report, "https://example.test/MAL-4")[0]
        self.assertEqual(record["affected"], [])

    def test_transitive_aliases_form_one_advisory_group(self):
        records = [
            {"id": "A", "aliases": ["A", "B"], "ecosystem": "npm", "name": "bad", "affected": ["= 1"], "source_url": "https://a.test", "source": "osv", "published": "2026-01-01", "modified": "", "description": "bad", "withdrawn": False},
            {"id": "C", "aliases": ["C", "D"], "ecosystem": "npm", "name": "bad", "affected": ["= 2"], "source_url": "https://c.test", "source": "osv", "published": "2026-01-01", "modified": "", "description": "bad", "withdrawn": False},
            {"id": "B", "aliases": ["B", "C"], "ecosystem": "npm", "name": "bad", "affected": ["= 3"], "source_url": "https://b.test", "source": "osv", "published": "2026-01-01", "modified": "", "description": "bad", "withdrawn": False},
        ]
        packages, _ = ingest.merge(records, "2026-09-26.1")
        self.assertEqual(len(packages), 1)
        self.assertEqual(packages[0]["affected_versions"], ["= 1", "= 2", "= 3"])

    def test_pagination_rejects_non_github_destination(self):
        self.assertEqual(ingest.next_link('<https://api.github.com/advisories?type=malware&after=x>; rel="next"'), "https://api.github.com/advisories?type=malware&after=x")
        with self.assertRaisesRegex(ValueError, "left api.github.com"):
            ingest.next_link('<https://attacker.invalid/page>; rel="next"')

    def test_github_token_is_not_sent_to_an_untrusted_url(self):
        with patch.object(ingest.urllib.request, "build_opener") as build_opener:
            with self.assertRaisesRegex(ValueError, "api.github.com"):
                ingest.fetch_github("https://attacker.invalid/advisories", "example-token")
            build_opener.return_value.open.assert_not_called()

            with self.assertRaisesRegex(ValueError, "type=malware"):
                ingest.fetch_github("https://api.github.com/advisories", "example-token")
            build_opener.return_value.open.assert_not_called()

    def test_regular_vulnerability_is_not_labeled_malware(self):
        report = {"type": "reviewed", "ghsa_id": "GHSA-aaaa-bbbb-cccc", "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "safe"}}]}
        with self.assertRaisesRegex(ValueError, "malware"):
            ingest.normalize_github(report)

    def test_candidate_preserves_curated_base_and_bounds_local_pages(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary)
            (root / "osv").mkdir()
            (root / "osv" / "MAL-1.json").write_text('{"id":"MAL-1","affected":[{"package":{"ecosystem":"npm","name":"bad-example"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}')
            subprocess.run(["git", "-C", str(root), "init", "-q", "--template=/dev/null"], check=True)
            subprocess.run(["git", "-C", str(root), "add", "osv/MAL-1.json"], check=True)
            subprocess.run(["git", "-C", str(root), "-c", "user.name=Repyy Test", "-c", "user.email=test@example.invalid", "-c", "core.hooksPath=/dev/null", "commit", "-qm", "inert OSV fixture"], check=True)
            commit = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
            (root / "page-1.json").write_text("[]")
            (root / "page-2.json").write_text("[]")
            base = {"packages": [{"ecosystem": "npm", "name": "axios", "advisory_id": "MSFT-2026-04-01-AXIOS", "affected_versions": ["= 1.14.1", "= 0.30.4"], "snapshot_version": "old"}], "file_hashes": [{"sha256": "a" * 64, "snapshot_version": "old"}]}
            (root / "base.json").write_text(json.dumps(base))
            args = ["ingest_intelligence.py", "--github-page", str(root / "page-1.json"), "--github-page", str(root / "page-2.json"), "--openssf-dir", str(root / "osv"), "--openssf-commit", commit, "--snapshot-version", "2026-09-26.2", "--base-snapshot", str(root / "base.json"), "--output", str(root / "candidate.json"), "--corrections", str(root / "corrections.json")]
            with patch.object(sys, "argv", args), patch.object(ingest, "MAX_DOWNLOAD_BYTES", 3):
                with self.assertRaisesRegex(ValueError, "GitHub page inputs exceed byte limit"):
                    ingest.main()

            wrong_pin = args.copy()
            wrong_pin[wrong_pin.index("--openssf-commit") + 1] = "a" * 40 if commit != "a" * 40 else "b" * 40
            with patch.object(sys, "argv", wrong_pin):
                with self.assertRaisesRegex(ValueError, "OpenSSF source commit"):
                    ingest.main()

            with patch.object(sys, "argv", args):
                ingest.main()
            candidate = json.loads((root / "candidate.json").read_text())
            self.assertEqual(candidate["packages"][0]["affected_versions"], ["= 1.14.1", "= 0.30.4"])
            self.assertEqual(candidate["packages"][0]["snapshot_version"], "2026-09-26.2")
            self.assertEqual(candidate["packages"][1]["source_url"], f"https://github.com/ossf/malicious-packages/blob/{commit}/osv/MAL-1.json")


if __name__ == "__main__":
    unittest.main()
