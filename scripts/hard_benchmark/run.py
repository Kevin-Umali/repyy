#!/usr/bin/env python3
"""Hard benchmark: evasion fixtures, benign controls, and timing/noise on real repositories.

Fixtures are inert text written to a temporary directory. `real` reads repositories from
WORK/corpus/<name> (clones you make yourself). `noise` fetches the commits pinned in
corpus.json into WORK/pinned/<name> and counts high and critical findings on them; with
--check it fails when the total exceeds the manifest's max_high. --malware DIR adds
per-sample recall over a local directory of samples, which is never fetched for you.
Nothing is executed except git and repyy.

  run.py --binary BIN --work DIR fixtures
  run.py --binary BIN --work DIR real --repos express django --runs 3
  run.py --binary BIN --work DIR fixtures noise --check --min-detected 50
  run.py --binary BIN --work DIR noise --malware ~/samples/malicious-repositories
"""

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cases import CASES, CONTROLS  # noqa: E402

HIGH = ("high", "critical")
MANIFEST = Path(__file__).resolve().parent / "corpus.json"


def scan(binary, env, path, extra=()):
    start = time.perf_counter()
    proc = subprocess.run(
        [binary, "scan", str(path), "--format", "json", "--progress", "quiet", "--detail", "all", *extra],
        capture_output=True,
        text=True,
        env=env,
        timeout=3600,
    )
    wall = time.perf_counter() - start
    if proc.returncode not in (0, 1, 2):
        raise RuntimeError(proc.stderr)
    result = json.loads(proc.stdout)["results"][0]
    result["findings"] = result.get("findings") or []
    return result, wall


def materialize(root, files):
    for name, body in {"README.md": "# x\n", "LICENSE": "MIT\n", **files}.items():
        if Path(name).is_absolute() or ".." in Path(name).parts:
            raise ValueError(f"fixture path escapes root: {name}")
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")


def fixtures(binary, env):
    rows, controls = [], []
    with tempfile.TemporaryDirectory(prefix="repyy-hard-") as temp:
        for cid, title, files, expect in CASES:
            directory = Path(temp) / cid
            materialize(directory, files)
            result, _ = scan(binary, env, directory)
            found = sorted({f["rule_id"] for f in result["findings"]})
            high = sorted({f["rule_id"] for f in result["findings"] if f["severity"] in HIGH})
            hits = [rule for rule in found if any(rule.startswith(e) for e in expect)]
            rows.append({
                "id": cid, "title": title, "expect": expect, "found": found, "high": high,
                "detected": bool(hits), "detected_high": any(h in high for h in hits),
            })
        for cid, files in CONTROLS:
            directory = Path(temp) / cid
            materialize(directory, files)
            result, _ = scan(binary, env, directory)
            controls.append({
                "id": cid,
                "found": sorted({f["rule_id"] for f in result["findings"]}),
                "high": sorted({f["rule_id"] for f in result["findings"] if f["severity"] in HIGH}),
            })
    return rows, controls


def real(binary, env, work, repos, runs):
    out = []
    for name in repos:
        path = work / "corpus" / name
        walls = []
        for _ in range(runs):
            result, wall = scan(binary, env, path, ("--fail-on", "critical", "--timeout", "60m"))
            walls.append(wall)
        coverage = result["coverage"]
        megabytes = (coverage.get("bytes_scanned") or 0) / 1e6
        high = [f for f in result["findings"] if f["severity"] in HIGH]
        median = statistics.median(walls)
        row = {
            "repo": name,
            "files": coverage.get("files_scanned"),
            "mb": round(megabytes, 1),
            "wall_s_median": round(median, 2),
            "walls": [round(w, 2) for w in walls],
            "mb_per_s": round(megabytes / median, 2) if median else None,
            "complete": coverage.get("complete"),
            "findings": len(result["findings"]),
            "high": len(high),
            "high_per_mb": round(len(high) / megabytes, 2) if megabytes else None,
            "by_severity": dict(Counter(f["severity"] for f in result["findings"])),
            "top_high_rules": Counter(f["rule_id"] for f in high).most_common(12),
        }
        out.append(row)
        print(f"{name}: {row['files']} files {row['mb']} MB {median:.2f}s high={row['high']}", file=sys.stderr)
    return out


def fetch_pinned(work, repo):
    """Check out repo["commit"] at depth 1 into WORK/pinned/<name>, reusing a matching checkout."""
    dest = work / "pinned" / repo["name"]
    git = ["git", "-C", str(dest), "-c", "core.hooksPath=/dev/null"]
    if (dest / ".git").is_dir():
        head = subprocess.run([*git, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        if head == repo["commit"]:
            return dest
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    env = {**os.environ, "GIT_LFS_SKIP_SMUDGE": "1", "GIT_TERMINAL_PROMPT": "0"}
    subprocess.run([*git, "init", "-q"], check=True, env=env)
    subprocess.run([*git, "fetch", "-q", "--depth", "1", "--no-tags", repo["url"], repo["commit"]], check=True, env=env)
    subprocess.run([*git, "checkout", "-q", "--detach", "FETCH_HEAD"], check=True, env=env)
    return dest


def noise(binary, env, work, malware):
    manifest = json.loads(MANIFEST.read_text())
    repos, rules = [], Counter()
    for repo in manifest["repositories"]:
        result, wall = scan(binary, env, fetch_pinned(work, repo), ("--fail-on", "critical", "--timeout", "60m"))
        high = Counter(f["rule_id"] for f in result["findings"] if f["severity"] in HIGH)
        rules.update(high)
        count = sum(high.values())
        repos.append({"repo": repo["name"], "commit": repo["commit"], "high": count, "baseline": repo["high"],
                      "complete": result["coverage"].get("complete"), "seconds": round(wall, 2), "rules": dict(high.most_common())})
        print(f"noise {repo['name']:10} high={count:4} (baseline {repo['high']:3}) {wall:6.2f}s")
    total = sum(r["high"] for r in repos)
    out = {"total_high": total, "max_high": manifest["max_high"], "repos": repos, "top_rules": rules.most_common(15)}
    print(f"noise TOTAL high={total} (max {manifest['max_high']}); top rules {rules.most_common(8)}")
    if malware:
        samples = sorted(p for p in Path(malware).expanduser().iterdir() if p.is_dir() and p.name != ".git")
        recall = {}
        for sample in samples:
            result, _ = scan(binary, env, sample, ("--fail-on", "critical"))
            recall[sample.name] = sorted({f["rule_id"] for f in result["findings"] if f["severity"] in HIGH})
            if not recall[sample.name]:
                print(f"  MISS {sample.name}")
        out["malware_recall"] = {"detected": sum(bool(v) for v in recall.values()), "samples": len(samples), "high_rules": recall}
        print(f"malware recall {out['malware_recall']['detected']}/{len(samples)} samples with a high finding")
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--repos", nargs="*", default=["express", "django"])
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--check", action="store_true", help="fail when controls get high findings, detections fall below --min-detected, or noise exceeds max_high")
    parser.add_argument("--min-detected", type=int, default=0)
    parser.add_argument("--malware", help="local directory of malicious-repository samples for noise recall")
    parser.add_argument("which", nargs="*", default=["fixtures"])
    args = parser.parse_args()
    work = Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    binary = str(Path(args.binary).resolve())
    env = {**os.environ, "REPYY_CACHE_DIR": str(work / "intel-cache")}

    results_path = work / "results.json"
    results = json.loads(results_path.read_text()) if results_path.exists() else {}
    results["build"] = subprocess.check_output([binary, "version"], text=True).splitlines()[0]
    if "fixtures" in args.which:
        results["fixtures"], results["controls"] = fixtures(binary, env)
        detected = sum(r["detected"] for r in results["fixtures"])
        flagged = [c["id"] for c in results["controls"] if c["high"]]
        print(f"detected {detected}/{len(results['fixtures'])}; controls with high findings {len(flagged)}/{len(results['controls'])}")
        for row in results["fixtures"]:
            if not row["detected"]:
                print(f"  MISS {row['id']}: found {row['found']}")
        for control in results["controls"]:
            if control["high"]:
                print(f"  FP   {control['id']}: {control['high']}")
    if "real" in args.which:
        results["real"] = real(binary, env, work, args.repos, args.runs)
    if "noise" in args.which:
        results["noise"] = noise(binary, env, work, args.malware)
    results_path.write_text(json.dumps(results, indent=1) + "\n")

    failed = False
    if args.check and "fixtures" in args.which:
        failed |= bool(flagged) or detected < args.min_detected
    if args.check and "noise" in args.which:
        failed |= results["noise"]["total_high"] > results["noise"]["max_high"]
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
