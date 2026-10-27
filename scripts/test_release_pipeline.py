import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("release.py")
SHA = "a" * 40


class CheckReleaseCITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        gh = self.directory / "gh"
        gh.write_text("""#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
if os.environ.get("FAKE_ERROR"):
    sys.exit(1)
if "--paginate" not in args or "--slurp" not in args:
    sys.exit(2)
if "repos/example/project/actions/workflows/ci.yml/runs" in args:
    if not all(x in args for x in ("head_sha=" + "a" * 40, "branch=main", "event=push", "per_page=100")):
        sys.exit(2)
    key = "runs"
elif "repos/example/project/actions/runs/123/attempts/2/jobs" in args:
    key = "jobs"
else:
    sys.exit(2)
print(os.environ["FAKE_" + key.upper()])
""")
        gh.chmod(0o755)

    def cli(self, runs, jobs, sha=SHA, **extra):
        env = dict(
            os.environ,
            PATH=str(self.directory) + os.pathsep + os.environ["PATH"],
            GITHUB_REPOSITORY=extra.pop("repository", "example/project"),
            FAKE_RUNS=json.dumps([{"workflow_runs": runs}]),
            FAKE_JOBS=json.dumps([{"jobs": jobs}]),
            **extra,
        )
        return subprocess.run(
            [sys.executable, str(SCRIPT), "ci", sha],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_success_requires_passing_gate_on_latest_attempt(self):
        run = {
            "id": 123,
            "run_attempt": 2,
            "head_sha": SHA,
            "status": "completed",
            "conclusion": "success",
            "created_at": "2026-01-01T00:00:00Z",
        }
        result = self.cli([run], [{"name": "CI passed", "conclusion": "success"}])
        self.assertEqual(
            (result.returncode, result.stdout.strip()), (0, "true"), result.stderr
        )

    def test_nonpassing_runs_and_gates_cannot_be_reused(self):
        run = {
            "id": 123,
            "run_attempt": 2,
            "head_sha": SHA,
            "status": "completed",
            "conclusion": "success",
            "created_at": "2026-01-01T00:00:00Z",
        }
        older = dict(run, id=122, created_at="2025-01-01T00:00:00Z")
        gate = [{"name": "CI passed", "conclusion": "success"}]
        cases = [
            ([], gate),
            ([run], []),
            ([run], [{"name": "CI passed", "conclusion": "failure"}]),
            ([dict(run, conclusion="cancelled")], gate),
            ([dict(run, status="in_progress", conclusion=None)], gate),
            ([older, dict(run, conclusion="failure")], gate),
            ([older, dict(run, status="in_progress", conclusion=None)], gate),
            ([dict(run, head_sha="b" * 40)], gate),
        ]
        for runs, jobs in cases:
            with self.subTest(runs=runs, jobs=jobs):
                result = self.cli(runs, jobs)
                self.assertEqual(
                    (result.returncode, result.stdout.strip()),
                    (0, "false"),
                    result.stderr,
                )

    def test_invalid_inputs_fail_before_querying(self):
        for kwargs in ({"sha": "A" * 40}, {"sha": "a" * 39}, {"repository": "../.."}):
            with self.subTest(kwargs=kwargs):
                result = self.cli([], [], **kwargs)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "Invalid" if "repository" in kwargs else "Expected", result.stderr
                )

    def test_api_error_is_not_treated_as_absent_ci(self):
        result = self.cli([], [], FAKE_ERROR="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(result.stdout.strip(), "false")


SOURCE = "a" * 40
HELLO_SHA = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


class UploadReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.public = self.root / "public"
        self.public.mkdir()
        (self.public / "checksums.txt").write_text("hello")
        self.state = self.root / "state.json"
        self.log = self.root / "calls.jsonl"
        gh = self.root / "gh"
        gh.write_text("""#!/usr/bin/env python3
import json, os, sys
with open(os.environ["FAKE_GH_LOG"], "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\\n")
state = json.load(open(os.environ["FAKE_GH_STATE"]))
if sys.argv[1] == "api":
    if len(sys.argv) != 3:
        print("unsupported api flag", file=sys.stderr)
        sys.exit(1)
    if "error" in state:
        print(state["error"], file=sys.stderr)
        sys.exit(1)
    print(json.dumps(state))
elif sys.argv[1:3] == ["release", "download"]:
    from pathlib import Path
    destination = Path(sys.argv[sys.argv.index("--dir") + 1])
    name = sys.argv[sys.argv.index("--pattern") + 1]
    (destination / name).write_text(state["download"])
""")
        gh.chmod(0o755)

    def run_cli(self, state):
        self.state.write_text(json.dumps(state))
        env = dict(
            os.environ,
            PATH=str(self.root) + os.pathsep + os.environ["PATH"],
            FAKE_GH_LOG=str(self.log),
            FAKE_GH_STATE=str(self.state),
        )
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "upload", "v1.2.3", SOURCE, str(self.public)],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        calls = (
            [json.loads(line) for line in self.log.read_text().splitlines()]
            if self.log.exists()
            else []
        )
        return result, calls

    def test_matching_existing_asset_is_not_uploaded(self):
        state = {
            "draft": True,
            "assets": [{"name": "checksums.txt", "digest": "sha256:" + HELLO_SHA}],
        }
        result, calls = self.run_cli(state)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(call[:2] == ["release", "upload"] for call in calls))

    def test_missing_release_creates_draft_and_uploads_assets(self):
        result, calls = self.run_cli({"error": "gh: Not Found (HTTP 404)"})
        self.assertEqual(result.returncode, 0, result.stderr)
        created = next(call for call in calls if call[:2] == ["release", "create"])
        self.assertIn("--verify-tag", created)
        self.assertIn("--draft", created)
        self.assertIn(SOURCE, " ".join(created))
        self.assertTrue(any(call[:2] == ["release", "upload"] for call in calls))

    def test_permission_failure_never_creates_release(self):
        result, calls = self.run_cli({"error": "gh: Forbidden (HTTP 403)"})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(
            any(
                call[:2] in (["release", "create"], ["release", "upload"])
                for call in calls
            )
        )

    def test_existing_conflict_or_unexpected_remote_asset_is_rejected(self):
        for assets in (
            [{"name": "checksums.txt", "digest": "sha256:" + "0" * 64}],
            [{"name": "other.txt", "digest": "sha256:" + HELLO_SHA}],
        ):
            with self.subTest(assets=assets):
                self.log.unlink(missing_ok=True)
                result, calls = self.run_cli({"draft": True, "assets": assets})
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(
                    any(call[:2] == ["release", "upload"] for call in calls)
                )

    def test_published_release_missing_asset_is_rejected(self):
        result, calls = self.run_cli({"draft": False, "assets": []})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(
            any(
                call[:2] in (["release", "create"], ["release", "upload"])
                for call in calls
            )
        )

    def test_downloads_existing_asset_without_digest_to_compare(self):
        result, calls = self.run_cli(
            {
                "draft": True,
                "assets": [{"name": "checksums.txt", "digest": None}],
                "download": "hello",
            }
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([c[:2] for c in calls][1:], [["release", "download"]])

    def test_draft_uploads_only_missing_asset(self):
        (self.public / "release.json").write_text("record")
        state = {
            "draft": True,
            "assets": [{"name": "checksums.txt", "digest": "sha256:" + HELLO_SHA}],
        }
        result, calls = self.run_cli(state)
        self.assertEqual(result.returncode, 0, result.stderr)
        uploaded = next(call for call in calls if call[:2] == ["release", "upload"])
        self.assertIn(str(self.public / "release.json"), uploaded)
        self.assertNotIn(str(self.public / "checksums.txt"), uploaded)
        self.assertNotIn("--clobber", uploaded)

    def test_unsafe_local_files_are_rejected_before_api_call(self):
        (self.public / "wild*.txt").write_text("bad")
        result, calls = self.run_cli({"error": "gh: Not Found (HTTP 404)"})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
