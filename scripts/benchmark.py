#!/usr/bin/env python3
"""Materialize inert data in temporary directories and invoke only the Repyy CLI."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def materialize(root, files):
    for name, body in {
        "README.md": "# Inert Repyy demonstration\n",
        "LICENSE": "MIT demonstration fixture\n",
        **files,
    }.items():
        path = root / name
        if Path(name).is_absolute() or ".." in Path(name).parts:
            raise ValueError(f"fixture path escapes root: {name}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        path.chmod(0o600)


def run(binary, root):
    result = subprocess.run(
        [binary, "scan", str(root), "--format", "json", "--progress", "quiet"],
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, "REPYY_CACHE_DIR": str(root.parent / "intelligence-cache")},
    )
    if result.returncode not in (0, 1, 2):
        raise RuntimeError(result.stderr)
    report = json.loads(result.stdout)
    return report, result.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail on new misses, high-severity control findings or incomplete scans",
    )
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    destination = Path(args.output)
    destination.mkdir(parents=True, exist_ok=True)
    corpus = json.loads((ROOT / "demo/cases.json").read_text())
    rows = []
    sample = None
    with tempfile.TemporaryDirectory(prefix="repyy-benchmark-") as temp:
        for case in corpus["cases"]:
            row = {
                "id": case["id"],
                "expected_rules": case["expected_rules"],
                "known_missing": case["known_missing"],
            }
            for kind in ("risky", "control"):
                directory = Path(temp) / case["id"] / kind
                materialize(directory, case[kind])
                report, code = run(binary, directory)
                result = report["results"][0]
                result["findings"] = result["findings"] or []
                # Local temporary paths are not useful in the public artifact.
                result["target"] = f"demo/{case['id']}/{kind}"
                result.pop("resolved", None)
                result["duration_ns"] = 0
                found = sorted({f["rule_id"] for f in result["findings"]})
                row[kind] = {
                    "rules": found,
                    "complete": result["coverage"]["complete"],
                    "exit_code": code,
                    "high_findings": sorted(
                        {
                            f["rule_id"]
                            for f in result["findings"]
                            if f["severity"] in ("high", "critical")
                        }
                    ),
                    "skipped": result["coverage"].get("skipped", []),
                    "warnings": result["coverage"].get("warnings", []),
                }
                if sample is None:
                    sample = report
                    sample["results"] = []
                sample["results"].append(result)
            row["missing"] = sorted(
                set(case["expected_rules"]) - set(row["risky"]["rules"])
            )
            rows.append(row)
    summary = {
        "benchmark_version": corpus["benchmark_version"],
        "tool_version": sample["tool_version"],
        "build_identity": subprocess.check_output(
            [binary, "version"], text=True
        ).strip(),
        "risky_detected": sum(not r["missing"] for r in rows),
        "risky_total": len(rows),
        "controls_high_flagged": sum(bool(r["control"]["high_findings"]) for r in rows),
        "controls_total": len(rows),
        "incomplete_scans": sum(
            not r[k]["complete"] for r in rows for k in ("risky", "control")
        ),
        "unsupported_fixtures": sum(
            bool(r[k]["skipped"]) for r in rows for k in ("risky", "control")
        ),
        "cases": rows,
    }
    (destination / "results.json").write_text(json.dumps(summary, indent=2) + "\n")
    lines = [
        f"# Repyy benchmark {corpus['benchmark_version']}",
        "",
        f"Repyy: {sample['tool_version']}",
        f"Expected risky fixtures detected: {summary['risky_detected']}/{len(rows)}",
        f"Clean controls incorrectly flagged at high/critical: {summary['controls_high_flagged']}/{len(rows)}",
        f"Unsupported/skipped fixture scans: {summary['unsupported_fixtures']}",
        f"Incomplete fixture scans: {summary['incomplete_scans']}",
        "",
        "This measures this inert corpus only, not general accuracy or proof of safety. Every observed rule is recorded in results.json.",
        "",
        "| Case | Expected rules | Missing | Control high/critical |",
        "| --- | --- | --- | --- |",
    ]
    lines += [
        f"| {r['id']} | {', '.join(r['expected_rules'])} | {', '.join(r['missing']) or 'none'} | {', '.join(r['control']['high_findings']) or 'none'} |"
        for r in rows
    ]
    (destination / "results.md").write_text("\n".join(lines) + "\n")
    sample_file = destination / "sample.json"
    sample_file.write_text(json.dumps(sample, indent=2) + "\n")
    for fmt, suffix in (("terminal", "txt"), ("html", "html")):
        rendered = subprocess.run(
            [
                binary,
                "report",
                str(sample_file),
                "--format",
                fmt,
                "--output",
                str(destination / f"sample.{suffix}"),
                "--color",
                "never",
            ],
            check=False,
        )
        if rendered.returncode not in (0, 1, 2):
            raise RuntimeError("sample rendering failed")
    print("\n".join(lines[:9]))
    if args.check and any(
        r["missing"] != r["known_missing"]
        or r["control"]["high_findings"]
        or not all(r[k]["complete"] for k in ("risky", "control"))
        for r in rows
    ):
        raise SystemExit(
            "Benchmark regression: inspect results.json (known misses remain visible)."
        )


if __name__ == "__main__":
    main()
