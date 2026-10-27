#!/usr/bin/env python3
"""Publish GoReleaser's generated manifests only after the release gate passes."""

import argparse
import base64
import json
import re
import subprocess
from pathlib import Path


def manifest_version(content, suffix):
    if suffix == ".json":
        actual = json.loads(content).get("version")
    else:
        match = re.search(rb'^\s*version "([^"\n]+)"\s*$', content, re.MULTILINE)
        actual = match.group(1).decode("utf-8") if match else None
    return actual


def validate_manifest(source, version):
    content = source.read_bytes()
    if manifest_version(content, source.suffix) != version or b"SNAPSHOT" in content:
        raise ValueError(f"Generated manifest does not describe {version}: {source}")
    return content


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--target", choices=("homebrew", "scoop"))
    parser.add_argument("--directory", type=Path, default=Path("dist"))
    args = parser.parse_args()
    if not re.fullmatch(r"v\d+\.\d+\.\d+", args.tag):
        parser.error("expected a stable release tag")
    targets = {
        "homebrew": (
            "Kevin-Umali/homebrew-tap",
            "Casks/repyy.rb",
            args.directory / "homebrew/Casks/repyy.rb",
        ),
        "scoop": (
            "Kevin-Umali/scoop-bucket",
            "repyy.json",
            args.directory / "scoop/repyy.json",
        ),
    }
    selected = [targets[args.target]] if args.target else targets.values()
    if not args.dry_run:
        release = json.loads(
            subprocess.check_output(
                [
                    "gh",
                    "release",
                    "view",
                    args.tag,
                    "--repo",
                    "Kevin-Umali/repyy",
                    "--json",
                    "isDraft,isPrerelease",
                ],
                text=True,
            )
        )
        if release["isDraft"] or release["isPrerelease"]:
            raise SystemExit("Package publication requires a published stable release")
    # Validate both manifests before updating either distribution repository.
    validated = [
        (repository, destination, source, validate_manifest(source, args.tag[1:]))
        for repository, destination, source in selected
    ]
    for repository, destination, source, content in validated:
        if args.dry_run:
            print(f"Would publish {source} to {repository}/{destination}")
            continue
        endpoint = f"repos/{repository}/contents/{destination}"
        # These are existing distribution repositories. A failed read is a hard
        # failure, not permission to overwrite/create an unexpected location.
        current = json.loads(
            subprocess.check_output(["gh", "api", endpoint], text=True)
        )
        remote = base64.b64decode(current["content"], validate=False)
        if remote == content:
            print(f"Already published {repository}/{destination}")
            continue
        remote_version = manifest_version(remote, source.suffix)
        if not isinstance(remote_version, str) or not re.fullmatch(
            r"\d+\.\d+\.\d+", remote_version
        ):
            raise ValueError(
                f"Cannot determine stable version of {repository}/{destination}"
            )
        old = tuple(map(int, remote_version.split(".")))
        new = tuple(map(int, args.tag[1:].split(".")))
        if old >= new:
            raise ValueError(
                f"Refusing to replace {repository}/{destination} at version {remote_version} with {args.tag[1:]}"
            )
        payload = {
            "message": f"Update repyy to {args.tag}",
            "sha": current["sha"],
            "content": base64.b64encode(content).decode("ascii"),
        }
        subprocess.run(
            ["gh", "api", "--method", "PUT", endpoint, "--input", "-"],
            input=json.dumps(payload),
            text=True,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        print(f"Published {repository}/{destination}")


if __name__ == "__main__":
    main()
