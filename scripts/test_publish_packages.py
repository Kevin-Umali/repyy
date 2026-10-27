import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("publish-packages.py")
BREW = 'cask "repyy" do\n  version "1.2.3"\nend\n'
SCOOP = '{"version": "1.2.3"}\n'


class PublishPackagesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = self.root / "dist"
        for name, content in (
            ("homebrew/Casks/repyy.rb", BREW),
            ("scoop/repyy.json", SCOOP),
        ):
            path = self.directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        self.state = self.root / "state.json"
        self.writes = self.root / "writes.jsonl"
        gh = self.root / "gh"
        gh.write_text("""#!/usr/bin/env python3
import base64, json, os, sys
args = sys.argv[1:]
state = json.load(open(os.environ["FAKE_GH_STATE"]))
if args[:2] == ["release", "view"]:
    print(json.dumps({"isDraft": False, "isPrerelease": False}))
elif args[:3] == ["api", "--method", "PUT"]:
    payload = json.load(sys.stdin)
    with open(os.environ["FAKE_GH_WRITES"], "a") as f:
        f.write(json.dumps({"endpoint": args[3], "payload": payload}) + "\\n")
    if state.get("fail_write"):
        print("conflicting SHA", file=sys.stderr)
        sys.exit(1)
elif args[0] == "api":
    if state.get("fail_read"):
        print("remote read failed", file=sys.stderr)
        sys.exit(1)
    target = "homebrew" if "homebrew-tap" in args[1] else "scoop"
    print(json.dumps({"sha": "remote-sha", "content": base64.b64encode(state[target].encode()).decode()}))
else:
    sys.exit(1)
""")
        gh.chmod(0o755)

    def run_cli(self, state, target=None):
        self.state.write_text(json.dumps(state))
        self.writes.unlink(missing_ok=True)
        env = dict(
            os.environ,
            PATH=str(self.root) + os.pathsep + os.environ["PATH"],
            FAKE_GH_STATE=str(self.state),
            FAKE_GH_WRITES=str(self.writes),
        )
        args = [
            sys.executable,
            str(SCRIPT),
            "v1.2.3",
            "--directory",
            str(self.directory),
        ]
        if target:
            args.extend(["--target", target])
        result = subprocess.run(
            args, env=env, capture_output=True, text=True, check=False
        )
        writes = []
        if self.writes.exists():
            writes = [json.loads(line) for line in self.writes.read_text().splitlines()]
        return result, writes

    def test_retries_skip_identical_and_refuse_newer_or_conflicting_manifests(self):
        result, writes = self.run_cli({"homebrew": BREW, "scoop": SCOOP})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(writes, [])
        for remote in ('{"version":"2.0.0"}', '{"version":"1.2.3","changed":true}'):
            with self.subTest(remote=remote):
                result, writes = self.run_cli({"scoop": remote}, "scoop")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(writes, [])

    def test_independent_targets_write_only_selected_manifest_with_remote_sha(self):
        for target, old, expected in (
            ("homebrew", 'version "1.2.2"\n', BREW),
            ("scoop", '{"version":"1.2.2"}', SCOOP),
        ):
            with self.subTest(target=target):
                result, writes = self.run_cli({target: old}, target)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(writes), 1)
                repository = "homebrew-tap" if target == "homebrew" else "scoop-bucket"
                self.assertIn(repository, writes[0]["endpoint"])
                self.assertEqual(writes[0]["payload"]["sha"], "remote-sha")
                content = base64.b64decode(writes[0]["payload"]["content"]).decode()
                self.assertEqual(content, expected)

    def test_remote_failures_and_invalid_local_manifests_stop_publication(self):
        old = '{"version":"1.2.2"}'
        result, writes = self.run_cli({"scoop": old, "fail_read": True}, "scoop")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(writes, [])
        result, writes = self.run_cli({"scoop": old, "fail_write": True}, "scoop")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("conflicting SHA", result.stderr)
        (self.directory / "scoop/repyy.json").write_text('{"version":"1.0.0"}')
        result, writes = self.run_cli({"homebrew": 'version "1.2.2"\n', "scoop": old})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(writes, [])


if __name__ == "__main__":
    unittest.main()
