#!/usr/bin/env python3
"""Check release validation, record asset hashes, and upload missing draft files."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = "Kevin-Umali/repyy"


def api(endpoint, *fields):
    result = subprocess.run(
        [
            "gh",
            "api",
            "--method",
            "GET",
            "--paginate",
            "--slurp",
            endpoint,
            *[item for field in fields for item in ("-f", field)],
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def check_ci(args):
    sha = args.source_sha
    repo = os.environ.get("GITHUB_REPOSITORY", "Kevin-Umali/repyy")
    if not re.fullmatch(
        r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]+", repo
    ) or repo.split("/")[1] in (".", ".."):
        raise ValueError("Invalid GITHUB_REPOSITORY")
    pages = api(
        f"repos/{repo}/actions/workflows/ci.yml/runs",
        f"head_sha={sha}",
        "branch=main",
        "event=push",
        "per_page=100",
    )
    runs = [
        run for page in pages for run in page["workflow_runs"] if run["head_sha"] == sha
    ]
    if not runs:
        print("false")
        return
    run = max(runs, key=lambda item: (item["created_at"], item["id"]))
    if run["status"] != "completed" or run["conclusion"] != "success":
        print("false")
        return
    pages = api(
        f"repos/{repo}/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs",
        "per_page=100",
    )
    passed = any(
        job["name"] == "CI passed" and job["conclusion"] == "success"
        for page in pages
        for job in page["jobs"]
    )
    print(str(passed).lower())


def file_hashes(directory):
    files = {}
    for path in directory.iterdir():
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Release assets must be regular files: {path}")
        if path.name != "release.json":
            files[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    required = {
        "checksums.txt",
        "repyy-sandbox-image.txt",
        "repyy-homebrew.rb",
        "repyy-scoop.json",
    }
    if not required <= files.keys():
        raise ValueError("Release assets are incomplete")
    return files


def release_record(args):
    if args.command == "create":
        if not re.fullmatch(r"[0-9a-f]{40}", args.controller_sha):
            raise ValueError("Invalid controller SHA")
        record = {
            "schema": 1,
            "tag": args.tag,
            "source_sha": args.source_sha,
            "controller_sha": args.controller_sha,
            "files": file_hashes(args.directory),
        }
        output = args.directory / "release.json"
        output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    else:
        record = json.loads((args.directory / "release.json").read_text())
        if (
            type(record.get("schema")) is not int
            or record["schema"] != 1
            or record["tag"] != args.tag
            or record["source_sha"] != args.source_sha
            or record["files"] != file_hashes(args.directory)
        ):
            raise ValueError("Release record does not match")
        if not isinstance(record.get("controller_sha"), str) or not re.fullmatch(
            r"[0-9a-f]{40}", record["controller_sha"]
        ):
            raise ValueError("Invalid controller SHA")
        print(record["controller_sha"])


def upload_assets(args):
    paths = sorted(args.directory.iterdir())
    if not paths:
        raise ValueError("Release assets are empty")
    for path in paths:
        if (
            path.is_symlink()
            or not path.is_file()
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", path.name)
        ):
            raise ValueError(f"Unsafe release asset: {path}")
    response = subprocess.run(
        ["gh", "api", f"repos/{REPO}/releases/tags/{args.tag}"],
        text=True,
        capture_output=True,
        check=False,
    )
    if response.returncode:
        if not re.search(r"\(HTTP 404\)\s*$", response.stderr):
            raise RuntimeError(f"Could not read release: {response.stderr.strip()}")
        subprocess.run(
            [
                "gh",
                "release",
                "create",
                args.tag,
                "--repo",
                REPO,
                "--verify-tag",
                "--draft",
                "--title",
                args.tag,
                "--notes",
                f"Source commit: {args.source_sha}",
            ],
            check=True,
        )
        release = {"draft": True, "assets": []}
    else:
        release = json.loads(response.stdout)
    assets = {asset["name"]: asset for asset in release["assets"]}
    if len(assets) != len(release["assets"]) or assets.keys() - {
        path.name for path in paths
    }:
        raise ValueError("Release contains unexpected or duplicate assets")
    missing = []
    for path in paths:
        digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        if path.name in assets:
            remote_digest = assets[path.name].get("digest")
            if not isinstance(remote_digest, str) or not re.fullmatch(
                r"sha256:[0-9a-f]{64}", remote_digest
            ):
                with tempfile.TemporaryDirectory() as directory:
                    subprocess.run(
                        [
                            "gh",
                            "release",
                            "download",
                            args.tag,
                            "--repo",
                            REPO,
                            "--pattern",
                            path.name,
                            "--dir",
                            directory,
                        ],
                        check=True,
                    )
                    remote_digest = (
                        "sha256:"
                        + hashlib.sha256(
                            (Path(directory) / path.name).read_bytes()
                        ).hexdigest()
                    )
            if remote_digest != digest:
                raise ValueError(f"Asset differs: {path.name}")
            print(f"Already uploaded {path.name}")
        elif release["draft"]:
            missing.append(path)
        else:
            raise ValueError(f"Published release is missing {path.name}")
    if missing:
        subprocess.run(
            ["gh", "release", "upload", args.tag, *map(str, missing), "--repo", REPO],
            check=True,
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    ci = commands.add_parser("ci", help="Check the latest main validation for a commit")
    ci.add_argument("source_sha")
    for command in ("create", "validate", "upload"):
        sub = commands.add_parser(command)
        sub.add_argument("tag")
        sub.add_argument("source_sha")
        if command == "create":
            sub.add_argument("controller_sha")
        sub.add_argument("directory", type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_sha):
        parser.error("Expected a lowercase 40-character commit SHA")
    if args.command != "ci" and not re.fullmatch(
        r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", args.tag
    ):
        parser.error("Invalid release tag")
    if args.command == "ci":
        check_ci(args)
    elif args.command == "upload":
        upload_assets(args)
    else:
        release_record(args)


if __name__ == "__main__":
    try:
        main()
    except (
        ValueError,
        KeyError,
        TypeError,
        OSError,
        RuntimeError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"Release operation failed: {error}", file=sys.stderr)
        sys.exit(1)
