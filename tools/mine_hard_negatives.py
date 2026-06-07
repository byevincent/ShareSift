"""Hard-negative + uncertainty mining for the v0 path classifier.

Per ``docs/build_plan.md`` Phase 2: surface the records most likely to
yield rule fixes or label corrections when re-audited. Two categories:

1. **Confident disagreements** — model predicts probability ≥ 0.9 or
   ≤ 0.1 with the OPPOSITE of the labeler's verdict. These are
   high-leverage to review: either the labeler's rule has a gap and
   the model spotted it, or the model has a systematic blind spot
   worth understanding. Either way, both directions inform Phase-2
   refinement.
2. **Uncertain predictions** — model probability in the [0.4, 0.6]
   band. Decision-boundary cases where the model is genuinely
   ambivalent; manual review often clarifies whether the path has a
   feature the labeler missed.

This tool produces a human-reviewable report (paths grouped by
disagreement type, sorted by confidence) plus the underlying data as
JSON for follow-on programmatic analysis. Vincent reviews, decides
whether to update the labeler rules or accept the labels as-is, and
the cycle closes when re-running the labeler + this tool produces no
new actionable findings.

Scope: runs against the in-distribution test split by default. Use
``--input data/eval/eval_set_claude.jsonl`` to mine the whole labeled
queue (slower; more findings).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import joblib

from sharesift.features import featurize, is_juicy
from src.eval.model.train import load_records

DEFAULT_MODEL_DIR = REPO_ROOT / "models" / "path_classifier_v0"
DEFAULT_INPUT = REPO_ROOT / "data" / "eval" / "test_split.jsonl"


def mine(
    records: list[dict],
    model,
    uncertain_band: tuple[float, float] = (0.4, 0.6),
    confidence_threshold: float = 0.9,
) -> dict:
    """Score records and bucket into uncertain / model-says-juicy-but-labeled-no
    / model-says-not_juicy-but-labeled-juicy. Returns a dict suitable
    for JSON serialization."""
    paths = [r["path"] for r in records]
    X = featurize(paths)
    probs = model.predict_proba(X)[:, 1]

    fp_candidates: list[dict] = []  # model high, label not_juicy
    fn_candidates: list[dict] = []  # model low,  label juicy
    uncertain: list[dict] = []      # model in [0.4, 0.6]

    for rec, prob in zip(records, probs):
        labeled_juicy = is_juicy(rec)
        prob = float(prob)
        entry = {
            "path": rec["path"],
            "model_prob": round(prob, 4),
            "labeled": "juicy" if labeled_juicy else "not_juicy",
            "tier": rec.get("tier"),
            "category": rec.get("category"),
            "notes": (rec.get("notes") or "")[:140],
        }
        if uncertain_band[0] <= prob <= uncertain_band[1]:
            uncertain.append(entry)
        if prob >= confidence_threshold and not labeled_juicy:
            fp_candidates.append(entry)
        if prob <= (1 - confidence_threshold) and labeled_juicy:
            fn_candidates.append(entry)

    fp_candidates.sort(key=lambda e: -e["model_prob"])
    fn_candidates.sort(key=lambda e: e["model_prob"])
    uncertain.sort(key=lambda e: abs(e["model_prob"] - 0.5))

    return {
        "n_records": len(records),
        "thresholds": {
            "uncertain_band": list(uncertain_band),
            "confidence_threshold": confidence_threshold,
        },
        "false_positive_candidates": fp_candidates,
        "false_negative_candidates": fn_candidates,
        "uncertain": uncertain,
    }


def _print_section(title: str, entries: list[dict], limit: int) -> None:
    print(f"\n=== {title} ({len(entries)} total, showing first {min(limit, len(entries))}) ===")
    for entry in entries[:limit]:
        print(
            f"  p={entry['model_prob']:.3f}  "
            f"labeled={entry['labeled']:9s}  "
            f"tier={str(entry['tier'] or '-'):6s}  "
            f"category={entry['category']:30s}"
        )
        print(f"           {entry['path']}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    p.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    p.add_argument("--limit", type=int, default=10, help="Show N entries per section.")
    p.add_argument("--output", type=Path, default=None, help="JSON output for full result.")
    p.add_argument("--uncertain-low", type=float, default=0.4)
    p.add_argument("--uncertain-high", type=float, default=0.6)
    p.add_argument("--confidence-threshold", type=float, default=0.9)
    args = p.parse_args(argv)

    print(f"Loading model from {args.model_dir.relative_to(REPO_ROOT)}", file=sys.stderr)
    model = joblib.load(args.model_dir / "model.joblib")

    print(f"Loading records from {args.input.relative_to(REPO_ROOT)}", file=sys.stderr)
    records = load_records(args.input)
    print(f"  {len(records)} records", file=sys.stderr)

    result = mine(
        records,
        model,
        uncertain_band=(args.uncertain_low, args.uncertain_high),
        confidence_threshold=args.confidence_threshold,
    )

    _print_section(
        f"Model says juicy (p>={args.confidence_threshold}) but labeled not_juicy",
        result["false_positive_candidates"],
        args.limit,
    )
    _print_section(
        f"Model says not_juicy (p<={1 - args.confidence_threshold}) but labeled juicy",
        result["false_negative_candidates"],
        args.limit,
    )
    _print_section(
        f"Uncertain band ({args.uncertain_low}-{args.uncertain_high})",
        result["uncertain"],
        args.limit,
    )

    print(
        f"\nTotals: "
        f"{len(result['false_positive_candidates'])} model-says-juicy / labeled-not_juicy, "
        f"{len(result['false_negative_candidates'])} model-says-not_juicy / labeled-juicy, "
        f"{len(result['uncertain'])} uncertain"
    )

    if args.output:
        args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"Full result written to {args.output}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
