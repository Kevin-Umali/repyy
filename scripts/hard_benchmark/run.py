#!/usr/bin/env python3
"""Hard benchmark: evasion fixtures, benign controls, and timing/noise on real repositories.

Fixtures are inert text written to a temporary directory. Real repositories are read from
WORK/corpus/<name> (shallow clones you make yourself). Nothing is executed except repyy.

  run.py --binary BIN --work DIR fixtures
  run.py --binary BIN --work DIR real --repos express django --runs 3
  run.py --binary BIN --work DIR fixtures --check --min-detected 50
"""

import argparse
import json
import os
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


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--repos", nargs="*", default=["express", "django"])
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--check", action="store_true", help="fail when controls get high findings or detections fall below --min-detected")
    parser.add_argument("--min-detected", type=int, default=0)
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
    results_path.write_text(json.dumps(results, indent=1) + "\n")

    if args.check and "fixtures" in args.which:
        if flagged or detected < args.min_detected:
            sys.exit(1)


if __name__ == "__main__":
    main()
