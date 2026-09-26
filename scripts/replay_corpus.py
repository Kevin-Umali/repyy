#!/usr/bin/env python3
"""Scan a pinned Git object store as data, without fetching or checking it out.

This maintainer-only tool never runs a command from the corpus. It accepts only
regular blobs, writes them without executable permissions under /private/tmp,
and removes the materialized files after the trusted Repyy binary exits.
"""

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import unicodedata
from pathlib import Path, PurePosixPath


CORPUS_COMMIT = "dc82f332dae0f4e9ea6bdc1d8341c7743c59913f"
MAX_FILES = 4_000
MAX_FILE_BYTES = 100_000_000
MAX_TOTAL_BYTES = 325_000_000
MAX_TREE_BYTES = 1_000_000
SCAN_TIMEOUT_SECONDS = 1_200


def git(git_dir: Path, *args: str, timeout: int = 60) -> bytes:
    return subprocess.run(
        ["git", f"--git-dir={git_dir}", *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    ).stdout


def inventory(git_dir: Path):
    if git(git_dir, "cat-file", "-t", CORPUS_COMMIT).strip() != b"commit":
        raise ValueError("pinned object is not a commit")
    tree = git(git_dir, "ls-tree", "-r", "-l", "-z", CORPUS_COMMIT)
    if len(tree) > MAX_TREE_BYTES:
        raise ValueError("tree inventory exceeds byte limit")
    rows = tree.rstrip(b"\0").split(b"\0")
    if len(rows) > MAX_FILES:
        raise ValueError("tree inventory exceeds file limit")
    seen = set()
    total = 0
    entries = []
    for row in rows:
        metadata, raw_path = row.split(b"\t", 1)
        mode, kind, object_id, raw_size = metadata.split()
        if (mode, kind) != (b"100644", b"blob"):
            raise ValueError("corpus contains a non-regular file")
        size = int(raw_size)
        total += size
        if size > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
            raise ValueError("corpus exceeds materialization byte limit")
        path = raw_path.decode("utf-8", "strict")
        parts = PurePosixPath(path).parts
        if (
            not parts
            or path.startswith("/")
            or PurePosixPath(path).as_posix() != path
            or "\\" in path
            or any(part in ("", ".", "..") for part in parts)
            or any(ord(char) < 32 for char in path)
        ):
            raise ValueError("corpus contains an unsafe path")
        portable = unicodedata.normalize("NFC", path).casefold()
        if portable in seen:
            raise ValueError("corpus contains colliding paths")
        seen.add(portable)
        entries.append((path, object_id.decode("ascii"), size))
    return entries


def materialize(git_dir: Path, root: Path, entries):
    for path, object_id, size in entries:
        destination = root.joinpath(*PurePosixPath(path).parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        data = git(git_dir, "cat-file", "blob", object_id)
        if len(data) != size:
            raise ValueError(f"invalid blob length: {path}")
        digest = hashlib.sha1()
        digest.update(f"blob {size}\0".encode("ascii"))
        digest.update(data)
        if digest.hexdigest() != object_id:
            raise ValueError(f"blob hash mismatch: {path}")
        with destination.open("xb") as output:
            os.chmod(destination, 0o600)
            output.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--git-dir", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    git_dir = args.git_dir.resolve(strict=True)
    binary = args.binary.resolve(strict=True)
    output = args.output.resolve()
    if not binary.is_file():
        raise ValueError("scanner binary is not a file")
    entries = inventory(git_dir)
    targets = sorted({path.split("/", 1)[0] for path, _, _ in entries if "/" in path})
    with tempfile.TemporaryDirectory(prefix="repyy-corpus-static-", dir="/private/tmp") as temporary:
        root = Path(temporary)
        if output.is_relative_to(root):
            raise ValueError("output cannot be inside temporary corpus directory")
        materialize(git_dir, root, entries)
        process = subprocess.run(
            [str(binary), "scan", *(str(root / target) for target in targets), "--format", "json", "--progress", "quiet"],
            check=False,
            capture_output=True,
            timeout=SCAN_TIMEOUT_SECONDS,
            env={**os.environ, "REPYY_CACHE_DIR": str(root / "empty-intelligence-cache")},
        )
        if process.returncode not in (0, 1, 2):
            raise RuntimeError(f"Repyy scan failed with code {process.returncode}: {process.stderr.decode('utf-8', 'replace')[:1000]}")
        report = json.loads(process.stdout)
        if len(report.get("results", [])) != len(targets):
            raise ValueError("scan did not report every corpus target")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(process.stdout)
        print(f"commit={CORPUS_COMMIT} targets={len(targets)} files={len(entries)} bytes={sum(size for _, _, size in entries)} exit={process.returncode}")


if __name__ == "__main__":
    main()
