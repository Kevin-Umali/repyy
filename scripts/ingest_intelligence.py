#!/usr/bin/env python3
"""Build a bounded, reviewable Repyy package-intelligence candidate.

The command consumes GitHub Advisory JSON pages and OpenSSF malicious-package
OSV JSON as data. Network acquisition is explicit; scans never invoke it. The
output is an unsigned candidate which must still be reviewed and signed by the
release workflow.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import urllib.parse
import urllib.request
from pathlib import Path

MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_PAGES = 1_000
MAX_RECORDS = 100_000
GIT_BATCH_SIZE = 100
VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]*$")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def github_advisory_url(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc != "api.github.com" or parsed.path != "/advisories" or parsed.fragment:
        raise ValueError("GitHub advisory URL must use https://api.github.com/advisories")
    if urllib.parse.parse_qs(parsed.query).get("type") != ["malware"]:
        raise ValueError("GitHub advisory URL must select type=malware")
    return url


def read_json(path: Path):
    with path.open("rb") as source:
        data = source.read(MAX_DOWNLOAD_BYTES + 1)
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise ValueError(f"input exceeds byte limit: {path}")
    return json.loads(data)


def git_output(directory: Path, *args):
    try:
        return subprocess.run(
            ["git", "-C", str(directory), *args],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
            env={**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull},
        ).stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise ValueError("OpenSSF source commit cannot be verified locally") from error


def verified_osv_documents(directory: Path, commit: str, paths):
    directory = directory.resolve(strict=True)
    root = Path(git_output(directory, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    if git_output(root, "rev-parse", "--show-object-format").strip() != b"sha1":
        raise ValueError("OpenSSF source commit requires a SHA-1 Git tree")
    if git_output(root, "cat-file", "-t", commit).strip() != b"commit":
        raise ValueError("OpenSSF source commit is not a commit object")
    documents = []
    for start in range(0, len(paths), GIT_BATCH_SIZE):
        batch = paths[start:start + GIT_BATCH_SIZE]
        relative = []
        for path in batch:
            if path.is_symlink() or not path.is_file():
                raise ValueError("OpenSSF input is not a regular file")
            relative.append(path.resolve().relative_to(root).as_posix())
        tree = git_output(root, "ls-tree", "-r", "-z", "--full-tree", commit, "--", *(f":(literal){path}" for path in relative))
        entries = {}
        for row in tree.rstrip(b"\0").split(b"\0"):
            if not row:
                continue
            metadata, raw_path = row.split(b"\t", 1)
            mode, kind, object_id = metadata.split()
            entries[raw_path.decode("utf-8", "strict")] = (mode, kind, object_id.decode("ascii"))
        if set(entries) != set(relative):
            raise ValueError("OpenSSF source commit does not contain every input file")
        for path, name in zip(batch, relative):
            mode, kind, object_id = entries[name]
            if mode != b"100644" or kind != b"blob":
                raise ValueError("OpenSSF input is not a regular Git blob")
            with path.open("rb") as source:
                data = source.read(MAX_DOWNLOAD_BYTES + 1)
            if len(data) > MAX_DOWNLOAD_BYTES:
                raise ValueError(f"input exceeds byte limit: {path}")
            actual = hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()
            if actual != object_id:
                raise ValueError("OpenSSF input does not match source commit: " + name)
            documents.append((name, json.loads(data)))
    return documents


def fetch_github(url: str, token: str | None):
    records, total = [], 0
    opener = urllib.request.build_opener(NoRedirect)
    for _ in range(MAX_PAGES):
        github_advisory_url(url)
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "repyy-intel-maintainer/0.6"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(url, headers=headers)
        with opener.open(request, timeout=60) as response:
            body = response.read(MAX_DOWNLOAD_BYTES - total + 1)
            total += len(body)
            if total > MAX_DOWNLOAD_BYTES:
                raise ValueError("GitHub advisory download exceeds byte limit")
            page = json.loads(body)
            if not isinstance(page, list):
                raise ValueError("GitHub advisory response is not a list")
            records.extend(page)
            if len(records) > MAX_RECORDS:
                raise ValueError("GitHub advisory count exceeds limit")
            url = next_link(response.headers.get("Link", ""))
        if not url:
            return records
    raise ValueError("GitHub advisory pagination exceeds page limit")


def next_link(header: str):
    for part in header.split(","):
        match = re.match(r'\s*<([^>]+)>;\s*rel="([^"]+)"', part)
        if match and match.group(2) == "next":
            try:
                return github_advisory_url(match.group(1))
            except ValueError:
                raise ValueError("GitHub pagination left api.github.com")
    return None


def ecosystem(value: str):
    return {"PyPI": "pip", "Go": "go", "Packagist": "composer", "RubyGems": "rubygems", "Maven": "maven", "NuGet": "nuget", "crates.io": "rust", "npm": "npm"}.get(value, value.lower())


def osv_ranges(affected):
    exact = {f"= {version}" for version in affected.get("versions", []) if VERSION.match(version)}
    ranges = set()
    for item in affected.get("ranges", []):
        if item.get("type") != "ECOSYSTEM":
            continue
        events = item.get("events", [])
        if len(events) == 1 and set(events[0]) == {"introduced"}:
            introduced = events[0]["introduced"]
            if isinstance(introduced, str) and VERSION.fullmatch(introduced):
                ranges.add(f">= {introduced}")
    return sorted(exact | ranges)


def normalize_github(document):
    if document.get("type") != "malware":
        raise ValueError("GitHub advisory input is not a malware advisory")
    identifier = document.get("ghsa_id")
    aliases = {entry.get("value") for entry in document.get("identifiers", []) if entry.get("value")}
    aliases.add(identifier)
    withdrawn = bool(document.get("withdrawn_at"))
    output = []
    for vulnerability in document.get("vulnerabilities", []):
        package = vulnerability.get("package", {})
        affected = vulnerability.get("vulnerable_version_range", "").strip()
        output.append(candidate(identifier, aliases, package.get("ecosystem"), package.get("name"), [affected] if affected else [], document.get("html_url"), "github-advisory-database", document.get("published_at"), document.get("updated_at"), document.get("summary"), withdrawn))
    return output


def normalize_osv(document, source_url):
    identifier = document.get("id")
    aliases = set(document.get("aliases", [])) | {identifier}
    review = str(document.get("database_specific", {}).get("review_status", "")).lower()
    withdrawn = bool(document.get("withdrawn")) or review in {"false_positive", "not_affected", "rejected"}
    return [candidate(identifier, aliases, item.get("package", {}).get("ecosystem"), item.get("package", {}).get("name"), osv_ranges(item), source_url, "openssf-malicious-packages", document.get("published"), document.get("modified"), document.get("summary"), withdrawn) for item in document.get("affected", [])]


def candidate(identifier, aliases, eco, name, affected, source_url, source, published, modified, description, withdrawn):
    return {"id": identifier, "aliases": sorted(value for value in aliases if value), "ecosystem": ecosystem(eco or ""), "name": name, "affected": sorted(set(affected)), "source_url": source_url, "source": source, "published": (published or "")[:10], "modified": (modified or "")[:10], "description": description or "Malicious package advisory", "withdrawn": withdrawn}


def merge(records, snapshot_version):
    alias_owner, parent = {}, list(range(len(records)))

    def find(index):
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left, right):
        left, right = find(left), find(right)
        if left != right:
            parent[max(left, right)] = min(left, right)

    for index, record in enumerate(records):
        if not record.get("id") or not record.get("ecosystem") or not record.get("name"):
            continue
        for value in record["aliases"]:
            if value in alias_owner:
                union(index, alias_owner[value])
            alias_owner[value] = index

    grouped = {}
    for index, record in enumerate(records):
        if record.get("id") and record.get("ecosystem") and record.get("name"):
            grouped.setdefault(find(index), []).append(record)
    packages, corrections = [], []
    for _, group in sorted(grouped.items()):
        if any(item["withdrawn"] for item in group):
            corrections.append({"aliases": sorted({alias for item in group for alias in item["aliases"]}), "reason": "withdrawn-or-false-positive"})
            continue
        active = group
        for key in sorted({(item["ecosystem"], item["name"].lower()) for item in active}):
            entries = [item for item in active if (item["ecosystem"], item["name"].lower()) == key]
            primary = sorted(entries, key=lambda item: (item["source"] != "github-advisory-database", item["id"]))[0]
            packages.append({
                "ecosystem": key[0], "name": primary["name"], "severity": "high",
                "source": primary["source"], "source_url": primary["source_url"],
                "advisory_id": primary["id"], "aliases": sorted({alias for item in entries for alias in item["aliases"] if alias != primary["id"]}),
                "description": primary["description"], "added": min(filter(None, (item["published"] for item in entries)), default=snapshot_version[:10]),
                "modified": max(filter(None, (item["modified"] for item in entries)), default=""),
                "affected_versions": sorted({value for item in entries for value in item["affected"]}),
                "references": sorted({item["source_url"] for item in entries if item["source_url"]}), "snapshot_version": snapshot_version,
            })
    return sorted(packages, key=lambda item: (item["ecosystem"], item["name"].lower(), item["advisory_id"])), corrections


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--github-page", action="append", default=[], type=Path, help="reviewed GitHub advisory JSON array; repeatable")
    parser.add_argument("--github-api", help="explicit GitHub advisories API URL (network)")
    parser.add_argument("--github-token")
    parser.add_argument("--openssf-dir", type=Path, required=True, help="directory of OSV JSON from a pinned OpenSSF source tree")
    parser.add_argument("--openssf-commit", required=True, help="40-hex commit for source provenance")
    parser.add_argument("--snapshot-version", required=True)
    parser.add_argument("--base-snapshot", required=True, type=Path, help="exported signed-schema snapshot whose file hashes are retained")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--corrections", required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.openssf_commit):
        raise ValueError("OpenSSF source commit must be 40 lowercase hex characters")
    if len(args.github_page) > MAX_PAGES or sum(path.stat().st_size for path in args.github_page) > MAX_DOWNLOAD_BYTES:
        raise ValueError("GitHub page inputs exceed byte limit or page limit")
    github = fetch_github(args.github_api, args.github_token) if args.github_api else [item for path in args.github_page for item in read_json(path)]
    osv_paths = sorted(args.openssf_dir.rglob("*.json"))
    if sum(path.stat().st_size for path in osv_paths) > MAX_DOWNLOAD_BYTES:
        raise ValueError("OpenSSF report inputs exceed byte limit")
    if len(github) + len(osv_paths) > MAX_RECORDS:
        raise ValueError("advisory count exceeds limit")
    records = [entry for document in github for entry in normalize_github(document)]
    for relative, document in verified_osv_documents(args.openssf_dir, args.openssf_commit, osv_paths):
        records.extend(normalize_osv(document, f"https://github.com/ossf/malicious-packages/blob/{args.openssf_commit}/{relative}"))
    packages, corrections = merge(records, args.snapshot_version)
    base = read_json(args.base_snapshot)
    base_packages = base.get("packages")
    if not isinstance(base_packages, list):
        raise ValueError("base snapshot has no package records")
    corrected_aliases = {alias for item in corrections for alias in item["aliases"]}
    preserved = {}
    for item in base_packages:
        if not isinstance(item, dict) or not all(isinstance(item.get(key), str) for key in ("ecosystem", "name", "advisory_id")):
            raise ValueError("base snapshot has an invalid package record")
        if item["advisory_id"] in corrected_aliases or corrected_aliases.intersection(item.get("aliases", [])):
            continue
        entry = {**item, "snapshot_version": args.snapshot_version}
        preserved[(entry["ecosystem"], entry["name"].lower(), entry["advisory_id"])] = entry
    for item in packages:
        preserved.setdefault((item["ecosystem"], item["name"].lower(), item["advisory_id"]), item)
    packages = [preserved[key] for key in sorted(preserved)]
    hashes = base.get("file_hashes")
    if not isinstance(hashes, list) or not hashes:
        raise ValueError("base snapshot has no file-hash indicators")
    for item in hashes:
        item["snapshot_version"] = args.snapshot_version
    output = json.dumps({"snapshot_version": args.snapshot_version, "snapshot_date": args.snapshot_version[:10], "packages": packages, "file_hashes": hashes}, indent=2, sort_keys=True).encode() + b"\n"
    if len(output) > MAX_OUTPUT_BYTES:
        raise ValueError(f"candidate is {len(output)} bytes and exceeds updater limit {MAX_OUTPUT_BYTES}")
    args.output.write_bytes(output)
    args.corrections.write_text(json.dumps(corrections, indent=2, sort_keys=True) + "\n")
    print(f"github={len(github)} openssf={len(osv_paths)} packages={len(packages)} bytes={len(output)} updater_limit={MAX_OUTPUT_BYTES}")


if __name__ == "__main__":
    main()
