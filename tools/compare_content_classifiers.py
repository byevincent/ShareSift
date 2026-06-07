"""Print v0p3 vs v0p4 comparison table from reports/eval_content_classifier.json.

Reads the cumulative eval results JSON and emits a markdown-friendly
table for the audit doc + README. Picks the relevant labeled runs:

* v0p3 baselines: v0p3_7epochs_on_clean_test (own), v0p3_on_creddata_benchmark (v0.5 benchmark)
* v0p3 fresh: v0p3_on_creddata_v06 (new held-out benchmark)
* v0p4 family: v0p4_on_creddata_v06, v0p4_on_v0p3_test_split, v0p4_on_v0p4_test_split

Missing entries print as "(not run)" so the doc-builder can see what's
still pending.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _fmt_metrics(entry: dict | None) -> str:
    if entry is None:
        return "(not run)"
    m = entry.get("metrics", {})
    if not m:
        return "(no metrics)"
    return (
        f"P={m.get('precision', 0):.3f} "
        f"R={m.get('recall', 0):.3f} "
        f"F1={m.get('f1', 0):.3f} "
        f"acc={m.get('accuracy', 0):.3f} "
        f"(n={entry.get('records', '?')})"
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "--results",
        type=Path,
        default=REPO_ROOT / "reports" / "eval_content_classifier.json",
    )
    args = p.parse_args(argv)

    if not args.results.exists():
        print(f"ERROR: {args.results} missing", file=sys.stderr)
        return 1
    r = json.loads(args.results.read_text())

    runs = {
        "v0p3 on own test split (Truffler v0.3 distribution)": "v0p3_7epochs_on_clean_test",
        "v0p3 on CredData v0.5 benchmark (1500 records, all repos)": "v0p3_on_creddata_benchmark",
        "v0p3 on CredData v0.6 benchmark (1195 records, 50 held-out repos)": "v0p3_on_creddata_v06",
        "v0p3 on docx_salted_10 benchmark (1772 records, business docs)": "v0p3_on_docx_salted_10",
        "v0p4 on CredData v0.6 benchmark (Kingfisher labels, 1195 records)": "v0p4_on_creddata_v06",
        "v0p4 on v0p3 test split (cross-distribution)": "v0p4_on_v0p3_test_split",
        "v0p4 on docx_salted_10 benchmark": "v0p4_on_docx_salted_10",
        "v0p5 on CredData v0.6 benchmark (hand-labels, 1195 records)": "v0p5_on_creddata_v06",
        "v0p5 on v0p3 test split (cross-distribution)": "v0p5_on_v0p3_test_split",
        "v0p5 on docx_salted_10 benchmark": "v0p5_on_docx_salted_10",
        "v0p6 on docx_salted_10 benchmark (target — own distribution)": "v0p6_on_docx_salted_10",
        "v0p6 on CredData v0.6 benchmark (cross-distribution)": "v0p6_on_creddata_v06",
        "v0p6 on v0p3 test split (cross-distribution)": "v0p6_on_v0p3_test_split",
    }

    print("\n=== Content classifier comparison ===\n")
    for desc, key in runs.items():
        print(f"  {desc}")
        print(f"    → {_fmt_metrics(r.get(key))}")
        print()

    # Headline delta tables.
    def _f1(label: str) -> float | None:
        e = r.get(label)
        return e["metrics"]["f1"] if e else None

    print("\nF1 on CredData v0.6 (source-code distribution):")
    for v in ("v0p3", "v0p4", "v0p5", "v0p6"):
        f1 = _f1(f"{v}_on_creddata_v06")
        if f1 is not None:
            print(f"  {v}: {f1:.3f}")
    print("  Biringa & Kul 2025 reference (Mistral-7B): 0.985")

    print("\nF1 on docx_salted_10 (business-doc distribution):")
    for v in ("v0p3", "v0p4", "v0p5", "v0p6"):
        f1 = _f1(f"{v}_on_docx_salted_10")
        if f1 is not None:
            print(f"  {v}: {f1:.3f}")

    print("\nF1 on Truffler v0.3 test split (LLM-rule-labeled):")
    for v in ("v0p3", "v0p4", "v0p5", "v0p6"):
        key = "v0p3_7epochs_on_clean_test" if v == "v0p3" else f"{v}_on_v0p3_test_split"
        f1 = _f1(key)
        if f1 is not None:
            print(f"  {v}: {f1:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
