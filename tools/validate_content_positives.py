"""Tier-2.2: filter content training positives to Kingfisher-validated.

The 2026-05-31 v0.5 audit (Tier 1.D + Tier 2.3 / CredData) found that
~96% of content classifier training positives are LLM-rule-labeled
(regex matches on ``password=``, ``apikey=``, etc.), not validated
against live APIs. The CredData benchmark confirmed the impact:
F1=0.564 on externally-curated negatives vs F1=0.971 on Truffler's
own distribution.

This tool runs Kingfisher's live-validation pipeline over the training
positives and emits two artifacts:

1. ``data/content/verified_positives.jsonl`` — only the positives
   where Kingfisher's pattern scan + live API validation both
   succeeded (status = ``Active``).
2. ``data/content/positive_validation_audit.jsonl`` — full per-record
   audit: original snippet + Kingfisher's findings + validation status
   (Active / Inactive / Unknown / NotMatched). Negative reasoning lets
   us understand what the rule-only positives actually look like.

Workflow:
* Materialize each positive snippet to a temp file under
  ``data/external/kingfisher_input/`` (gitignored).
* Invoke ``kingfisher scan`` on the directory with JSONL output.
* Parse findings, group by source file, classify each record.

Live validation hits real provider APIs (GitHub, AWS, GCP, Slack, etc.)
with the credential string. The credentials in Truffler's training set
are scraped from public repos — they may be already-revoked,
honeypotted, or never-real-in-the-first-place. Active validation
proves the credential was both real-format AND live at scan time.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_TRAINING = REPO_ROOT / "data" / "content" / "training_dataset.jsonl"
DEFAULT_WORKDIR = REPO_ROOT / "data" / "external" / "kingfisher_input"
DEFAULT_VERIFIED_OUT = REPO_ROOT / "data" / "content" / "verified_positives.jsonl"
DEFAULT_AUDIT_OUT = REPO_ROOT / "data" / "content" / "positive_validation_audit.jsonl"
DEFAULT_KINGFISHER_RAW = REPO_ROOT / "reports" / "kingfisher_validation_raw.jsonl"


def _extract_extension(snippet: str) -> str:
    """Try to guess a file extension from the snippet so Kingfisher
    activates the right language rules. Fall back to .txt for unknown.
    """
    s = snippet.lower()
    if "<?php" in s or "$_get" in s or "$_post" in s:
        return ".php"
    if "package " in s and ("import (" in s or "func " in s):
        return ".go"
    if "import " in s and ("def " in s or "class " in s) and (":" in s):
        return ".py"
    if "function " in s and "var " in s:
        return ".js"
    if "<script" in s or "<html" in s:
        return ".html"
    if "<configuration" in s or "<appsettings" in s.lower() or "</xml" in s:
        return ".xml"
    if "{" in s and "}" in s and ('"' in s or ":" in s):
        return ".json"
    if "yaml" in s or s.lstrip().startswith("apiVersion:"):
        return ".yaml"
    return ".txt"


def materialize(
    training_path: Path, workdir: Path
) -> dict[str, dict]:
    """Write each positive snippet to a uniquely-named file under
    ``workdir``. Return a mapping of file basename → record metadata."""
    if workdir.exists():
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True)

    mapping: dict[str, dict] = {}
    n_total = 0
    n_pos = 0
    for line in training_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        n_total += 1
        rec = json.loads(line)
        if rec["messages"][-1]["content"] != "yes":
            continue
        idx = n_pos
        n_pos += 1
        snippet = rec["messages"][1]["content"]
        ext = _extract_extension(snippet)
        # 6-digit zero-padded id keeps file ordering stable across
        # filesystem and kingfisher output.
        name = f"pos_{idx:06d}{ext}"
        (workdir / name).write_text(snippet, encoding="utf-8")
        mapping[name] = {
            "training_index": idx,
            "snippet": snippet,
            "label": "yes",
        }

    print(
        f"Materialized {n_pos}/{n_total} positives to "
        f"{workdir.relative_to(REPO_ROOT)} ({ext} hint)",
        file=sys.stderr,
    )
    return mapping


def run_kingfisher(
    workdir: Path, raw_out: Path, kingfisher_bin: str
) -> None:
    raw_out.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        kingfisher_bin,
        "scan",
        str(workdir),
        "--format",
        "jsonl",
        "-o",
        str(raw_out),
        "--no-update-check",
        "--no-binary",
        "--validation-timeout",
        "10",
        "--validation-retries",
        "1",
    ]
    print(f"Running: {' '.join(cmd)}", file=sys.stderr)
    result = subprocess.run(cmd, capture_output=True, text=True)
    # Kingfisher convention: exit 0 = no findings, exit 200 = findings
    # present (this is the expected case for a known-positive corpus),
    # other non-zero codes are real failures.
    if result.returncode not in (0, 200):
        print(f"  stderr: {result.stderr[-2000:]}", file=sys.stderr)
        raise RuntimeError(
            f"kingfisher scan returned {result.returncode}"
        )
    if result.returncode == 200:
        print(
            f"  (kingfisher exit 200 = findings present, expected)",
            file=sys.stderr,
        )
    print(f"  raw output: {raw_out.relative_to(REPO_ROOT)}", file=sys.stderr)


def parse_findings(
    raw_path: Path, mapping: dict[str, dict]
) -> dict[str, list[dict]]:
    """Group findings by source basename. Each basename maps to a list
    of findings (a single file may match multiple rules)."""
    by_file: dict[str, list[dict]] = {name: [] for name in mapping}
    n_findings = 0
    if not raw_path.exists():
        return by_file
    for line in raw_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        # Kingfisher JSONL emits one record per finding. Path is at
        # ``finding.path`` in current schema; older versions used
        # ``finding.origin.path``. Check both.
        f = rec.get("finding", {})
        path_str = (
            f.get("path")
            or (f.get("origin") or {}).get("path")
            or rec.get("path")
            or ""
        )
        basename = Path(path_str).name
        if basename in by_file:
            by_file[basename].append(rec)
            n_findings += 1
    print(
        f"Parsed {n_findings} findings across {sum(1 for v in by_file.values() if v)} "
        f"source files (of {len(by_file)} positives)",
        file=sys.stderr,
    )
    return by_file


def _is_active(finding: dict) -> bool:
    """A finding is 'active' when Kingfisher's live-validation succeeded
    against the provider's API. The exact field varies by rule shape;
    check the common locations.
    """
    f = finding.get("finding", finding)
    # Kingfisher's "validation" or "validation_result" block.
    val = f.get("validation") or f.get("validation_result") or {}
    status = (val.get("status") or "").lower()
    if status in {"active", "valid", "verified"}:
        return True
    # Some rule families just emit ``is_active: True`` directly.
    if f.get("is_active") is True:
        return True
    return False


def classify(by_file: dict, mapping: dict) -> tuple[list[dict], dict]:
    """For each positive, decide its classification status."""
    audit_records: list[dict] = []
    summary = {
        "active": 0,
        "matched_but_inactive": 0,
        "matched_but_unknown": 0,
        "not_matched": 0,
        "total": len(mapping),
    }
    for name, meta in mapping.items():
        findings = by_file.get(name, [])
        if not findings:
            status = "not_matched"
            summary["not_matched"] += 1
        else:
            actives = [f for f in findings if _is_active(f)]
            if actives:
                status = "active"
                summary["active"] += 1
            else:
                statuses = [
                    (f.get("finding", f).get("validation") or {}).get("status")
                    for f in findings
                ]
                # Kingfisher emits values like "Inactive Credential",
                # "Not Attempted", "Active Credential" — match by
                # substring not equality.
                if any(s and "inactive" in s.lower() for s in statuses):
                    status = "matched_but_inactive"
                    summary["matched_but_inactive"] += 1
                else:
                    status = "matched_but_unknown"
                    summary["matched_but_unknown"] += 1
        audit_records.append(
            {
                "training_index": meta["training_index"],
                "source_file": name,
                "status": status,
                "n_findings": len(findings),
                "snippet": meta["snippet"],
                "findings": findings,
            }
        )
    return audit_records, summary


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--training", type=Path, default=DEFAULT_TRAINING)
    p.add_argument("--workdir", type=Path, default=DEFAULT_WORKDIR)
    p.add_argument("--verified-out", type=Path, default=DEFAULT_VERIFIED_OUT)
    p.add_argument("--audit-out", type=Path, default=DEFAULT_AUDIT_OUT)
    p.add_argument("--raw-out", type=Path, default=DEFAULT_KINGFISHER_RAW)
    p.add_argument(
        "--kingfisher-bin",
        default=str(REPO_ROOT / ".venv" / "bin" / "kingfisher"),
    )
    p.add_argument(
        "--skip-scan",
        action="store_true",
        help="Skip the kingfisher invocation; re-classify from an "
        "existing raw output (debugging).",
    )
    args = p.parse_args(argv)

    mapping = materialize(args.training, args.workdir)

    if not args.skip_scan:
        run_kingfisher(args.workdir, args.raw_out, args.kingfisher_bin)
    elif not args.raw_out.exists():
        print(
            f"--skip-scan requested but raw output {args.raw_out} missing",
            file=sys.stderr,
        )
        return 1

    by_file = parse_findings(args.raw_out, mapping)
    audit, summary = classify(by_file, mapping)

    args.audit_out.parent.mkdir(parents=True, exist_ok=True)
    with args.audit_out.open("w", encoding="utf-8") as f:
        for rec in audit:
            f.write(json.dumps(rec) + "\n")

    # Emit verified-only as training-shape records (chat template).
    verified = [
        {
            "messages": [
                {
                    "role": "system",
                    "content": "Does this snippet contain a hardcoded secret?",
                },
                {"role": "user", "content": rec["snippet"]},
                {"role": "assistant", "content": "yes"},
            ],
            "training_index": rec["training_index"],
            "source_file": rec["source_file"],
        }
        for rec in audit
        if rec["status"] == "active"
    ]
    args.verified_out.parent.mkdir(parents=True, exist_ok=True)
    with args.verified_out.open("w", encoding="utf-8") as f:
        for rec in verified:
            f.write(json.dumps(rec) + "\n")

    print("\n=== Validation summary ===", file=sys.stderr)
    for k in ("active", "matched_but_inactive", "matched_but_unknown", "not_matched"):
        n = summary[k]
        pct = 100.0 * n / summary["total"]
        print(f"  {k:24s}: {n:4d} ({pct:5.1f}%)", file=sys.stderr)
    print(
        f"\nVerified positives: {len(verified)} → {args.verified_out.relative_to(REPO_ROOT)}",
        file=sys.stderr,
    )
    print(
        f"Audit JSONL:        {args.audit_out.relative_to(REPO_ROOT)}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
