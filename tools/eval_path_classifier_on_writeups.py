"""v0.9.3: filter writeup-labeled paths to Snaffler-blind + eval classifiers.

Reads ``data/eval/writeups/labeled_paths.jsonl`` (v0.9.2 paste-workflow
output), classifies each path via the Snaffler rule pack (reuses
``tools/build_snaffler_blind_benchmark.py`` machinery), filters to the
Snaffler-blind subset (paths where no Snaffler rule fires), then
evaluates Truffler's existing per-shape path classifiers
(``models/path_classifier_v0_{windows,linux}/calibrated.joblib``)
against the labels.

Reports:

* Snaffler verdict breakdown over the writeup corpus (Discard /
  Snaffle / Silent) — apples-to-apples with the v0.5 numbers.
* Confusion + P/R/F1 at threshold 0.5 for each classifier × shape.
* PR-AUC and ECE compared to the existing Snaffler-blind benchmark
  numbers (PR-AUC 0.985 Windows / 0.99 Linux from v0.5).
* Per-tier-band precision against the writeup labels.

Output: ``reports/writeup_benchmark_eval.json``.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sharesift.features import featurize
from sharesift.path import PathClassifier, is_unc_path
from sharesift.tier import (
    DEFAULT_LINUX_THRESHOLDS,
    DEFAULT_WINDOWS_THRESHOLDS,
    probability_to_tier,
)

DEFAULT_INPUT = REPO_ROOT / "data" / "eval" / "writeups" / "labeled_paths.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "reports" / "writeup_benchmark_eval.json"
DEFAULT_SNAFFLER_BLIND_BENCH_REF = REPO_ROOT / "reports" / "snaffler_comparison_ci.json"


def _load_records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _classify_via_snaffler(records: list[dict]) -> tuple[list[str], dict]:
    """Tag each record with the Snaffler verdict via the existing
    classify_path() machinery. Returns (verdicts list, breakdown dict).
    """
    import importlib.util
    snaffler_tool = REPO_ROOT / "tools" / "build_snaffler_blind_benchmark.py"
    spec = importlib.util.spec_from_file_location("ssbb", snaffler_tool)
    if spec is None or spec.loader is None:
        print(f"ERROR: cannot import {snaffler_tool}", file=sys.stderr)
        sys.exit(2)
    mod = importlib.util.module_from_spec(spec)
    # Register before exec — dataclass introspection needs sys.modules lookup.
    sys.modules["ssbb"] = mod
    spec.loader.exec_module(mod)

    rules = mod.load_snaffler_rules(mod.SNAFFLER_RULES_ROOT)
    print(f"Loaded {len(rules)} Snaffler rules", file=sys.stderr)

    verdicts: list[str] = []
    breakdown: Counter[str] = Counter()
    for r in records:
        v, _ = mod.classify_path(r["path"], rules)
        verdicts.append(v)
        breakdown[v] += 1
    return verdicts, dict(breakdown)


def _precision_recall_f1(y_true: list[int], y_pred: list[int]) -> dict:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    prec = tp / max(1, tp + fp)
    rec = tp / max(1, tp + fn)
    f1 = 2 * prec * rec / max(1e-9, prec + rec)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": prec, "recall": rec, "f1": f1}


def _pr_auc(y_true: list[int], probs: list[float]) -> float:
    """Average precision = area under the precision-recall curve."""
    if not y_true:
        return 0.0
    order = sorted(range(len(probs)), key=lambda i: -probs[i])
    n_pos = sum(y_true)
    if n_pos == 0:
        return 0.0
    tp = 0
    fp = 0
    cum_precision_at_recall: list[float] = []
    last_recall = 0.0
    ap = 0.0
    for rank, idx in enumerate(order, start=1):
        if y_true[idx] == 1:
            tp += 1
        else:
            fp += 1
        precision = tp / (tp + fp)
        recall = tp / n_pos
        ap += (recall - last_recall) * precision
        last_recall = recall
    return ap


def _ece(y_true: list[int], probs: list[float], n_bins: int = 10) -> float:
    """Expected calibration error with equal-width bins."""
    bins = [(i / n_bins, (i + 1) / n_bins) for i in range(n_bins)]
    total = len(probs)
    if total == 0:
        return 0.0
    ece = 0.0
    for lo, hi in bins:
        bucket = [(t, p) for t, p in zip(y_true, probs) if lo <= p < hi or (hi == 1.0 and p == 1.0)]
        if not bucket:
            continue
        mean_pred = sum(p for _, p in bucket) / len(bucket)
        frac_pos = sum(t for t, _ in bucket) / len(bucket)
        ece += (len(bucket) / total) * abs(mean_pred - frac_pos)
    return ece


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    p.add_argument(
        "--snaffler-blind-only",
        action="store_true",
        default=True,
        help="Restrict eval to the Silent (Snaffler-blind) subset.",
    )
    args = p.parse_args(argv)

    records = _load_records(args.input)
    # Drop records with no label (failed labeling).
    records = [r for r in records if r.get("is_juicy") is not None]
    print(f"Loaded {len(records)} labeled records", file=sys.stderr)

    verdicts, breakdown = _classify_via_snaffler(records)
    print(f"Snaffler verdicts: {breakdown}", file=sys.stderr)

    if args.snaffler_blind_only:
        kept_indices = [i for i, v in enumerate(verdicts) if v == "Silent"]
        records = [records[i] for i in kept_indices]
        verdicts = [verdicts[i] for i in kept_indices]
        print(f"  Snaffler-blind subset: {len(records)} records", file=sys.stderr)

    # Split by path shape for the per-classifier eval.
    win_records = [r for r in records if is_unc_path(r["path"])]
    lin_records = [r for r in records if not is_unc_path(r["path"])]
    print(
        f"  by shape: windows (UNC)={len(win_records)}, linux={len(lin_records)}",
        file=sys.stderr,
    )

    classifier = PathClassifier()

    out: dict = {
        "label": "writeup_realistic_share_benchmark",
        "n_records": len(records),
        "snaffler_verdict_breakdown": breakdown,
        "n_windows_records": len(win_records),
        "n_linux_records": len(lin_records),
    }

    for shape, subset in (("windows", win_records), ("linux", lin_records)):
        if not subset:
            out[f"{shape}_metrics"] = {"n": 0, "skipped": "no records"}
            continue
        paths = [r["path"] for r in subset]
        y_true = [1 if r["is_juicy"] else 0 for r in subset]

        results = classifier.score_batch(paths)
        probs = [r.probability for r in results]

        # Threshold 0.5 metrics + per-tier-band.
        y_pred_05 = [1 if p >= 0.5 else 0 for p in probs]
        m = _precision_recall_f1(y_true, y_pred_05)
        m["pr_auc"] = _pr_auc(y_true, probs)
        m["ece"] = _ece(y_true, probs)
        m["n"] = len(subset)
        m["n_positive"] = sum(y_true)

        # Per-tier precision.
        thresholds = DEFAULT_WINDOWS_THRESHOLDS if shape == "windows" else DEFAULT_LINUX_THRESHOLDS
        tier_breakdown: dict = {}
        for tier_name in ("Black", "Red", "Yellow", None):
            tier_recs = [
                (r, t) for r, t, p in zip(subset, y_true, probs)
                if probability_to_tier(p, thresholds) == tier_name
            ]
            if not tier_recs:
                tier_breakdown[str(tier_name)] = {"n": 0}
                continue
            n_in_tier = len(tier_recs)
            n_juicy_in_tier = sum(1 for _, t in tier_recs if t == 1)
            tier_breakdown[str(tier_name)] = {
                "n": n_in_tier,
                "n_juicy": n_juicy_in_tier,
                "tier_precision": n_juicy_in_tier / n_in_tier,
            }
        m["per_tier"] = tier_breakdown

        out[f"{shape}_metrics"] = m

        print(
            f"\n[{shape}] n={m['n']} (positives={m['n_positive']}):\n"
            f"  P@0.5={m['precision']:.3f} R@0.5={m['recall']:.3f} F1@0.5={m['f1']:.3f}\n"
            f"  PR-AUC={m['pr_auc']:.3f} ECE={m['ece']:.3f}",
            file=sys.stderr,
        )
        for tier_name, td in tier_breakdown.items():
            if td.get("n", 0) > 0:
                print(
                    f"  tier {tier_name}: n={td['n']}, juicy={td['n_juicy']}, "
                    f"precision={td.get('tier_precision', 0):.3f}",
                    file=sys.stderr,
                )

    # Compare to existing v0.5 Snaffler-blind benchmark numbers.
    ref_path = DEFAULT_SNAFFLER_BLIND_BENCH_REF
    if ref_path.exists():
        try:
            ref = json.loads(ref_path.read_text())
            out["v0p5_snaffler_blind_reference"] = {
                "source": str(ref_path.relative_to(REPO_ROOT)),
                "windows_recall_at_0p5": ref.get("truffler_benchmark", {}).get("recall", {}).get("point"),
                "windows_delta_vs_snaffler": ref.get("delta_vs_snaffler", {}).get("point"),
            }
        except (json.JSONDecodeError, KeyError):
            pass

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(out, indent=2))
    print(f"\nWrote {args.output.relative_to(REPO_ROOT)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
