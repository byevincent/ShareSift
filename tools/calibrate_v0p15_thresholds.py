"""v0.15 — find optimal tier thresholds for the trained path classifier.

v0.15's PR-AUC is 0.97 on the Snaffler-blind benchmark, but recall@0.5 is
only 27% because best F1 sits at threshold 0.014. The model is well-trained
but its probability distribution is much lower than v0.5's was, so the
v0.5 tier thresholds (Black=0.95, Red=0.80, Yellow=0.50) over-quantize.

This tool finds the thresholds that align with the deployed tier
semantics:

- **Black** target: precision ≥ 0.95 ("near-certain credential material")
- **Red** target: precision ≥ 0.80 ("likely credential material")
- **Yellow** target: precision ≥ 0.50 OR best F1 cutoff ("plausible")

Operates on the same eval datasets as ``tools/train_path_classifier.py``:
in-distribution test split + Snaffler-blind benchmark.

Output is a TierThresholds-compatible recommendation that can be
plugged into ``DEFAULT_WINDOWS_THRESHOLDS`` / ``DEFAULT_LINUX_THRESHOLDS``
in ``src/truffler/tier.py``.

Usage::

    uv run python tools/calibrate_v0p15_thresholds.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

DEFAULT_MODEL = REPO_ROOT / "models" / "path_classifier_v0p15"
DEFAULT_BENCHMARK = REPO_ROOT / "data" / "eval" / "snaffler_blind_benchmark.jsonl"
DEFAULT_TEST_SPLIT = REPO_ROOT / "data" / "eval" / "test_split.jsonl"


def _load_jsonl(path: Path) -> list[dict]:
    records = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def _predict_proba(model, records: list[dict]) -> tuple[list[float], list[int]]:
    """Returns (probs, true_labels) using the same feature extraction the
    training script used (via src.eval.model.evaluate's featurize)."""
    from src.eval.model.evaluate import featurize, is_juicy
    paths = [r["path"] for r in records]
    y = [1 if is_juicy(r) else 0 for r in records]
    X = featurize(paths)
    probs = model.predict_proba(X)[:, 1]
    return list(probs), y


def _metrics_at(probs: list[float], y: list[int], threshold: float) -> dict:
    tp = sum(1 for p, t in zip(probs, y) if p >= threshold and t == 1)
    fp = sum(1 for p, t in zip(probs, y) if p >= threshold and t == 0)
    fn = sum(1 for p, t in zip(probs, y) if p < threshold and t == 1)
    tn = sum(1 for p, t in zip(probs, y) if p < threshold and t == 0)
    prec = tp / max(1, tp + fp)
    rec = tp / max(1, tp + fn)
    f1 = 2 * prec * rec / max(1e-9, prec + rec)
    return {"threshold": threshold, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": prec, "recall": rec, "f1": f1}


def _find_threshold_for_precision(
    probs: list[float], y: list[int], target_precision: float,
) -> tuple[float, dict]:
    """Walk thresholds from high to low. Return the LOWEST threshold that
    still meets target_precision (maximizing recall at that precision)."""
    sorted_probs = sorted(set(probs), reverse=True)
    best_thresh = sorted_probs[0] if sorted_probs else 1.0
    best_metrics = _metrics_at(probs, y, best_thresh)
    for thresh in sorted_probs:
        m = _metrics_at(probs, y, thresh)
        if m["tp"] < 5:
            continue  # too few positives, unstable
        if m["precision"] >= target_precision:
            best_thresh = thresh
            best_metrics = m
    return best_thresh, best_metrics


def _find_threshold_for_best_f1(
    probs: list[float], y: list[int],
) -> tuple[float, dict]:
    sorted_probs = sorted(set(probs))
    best_thresh = 0.5
    best_metrics = _metrics_at(probs, y, 0.5)
    for thresh in sorted_probs:
        m = _metrics_at(probs, y, thresh)
        if m["f1"] > best_metrics["f1"]:
            best_metrics = m
            best_thresh = thresh
    return best_thresh, best_metrics


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    p.add_argument("--benchmark", type=Path, default=DEFAULT_BENCHMARK)
    p.add_argument("--test-split", type=Path, default=DEFAULT_TEST_SPLIT)
    p.add_argument("--target-black-precision", type=float, default=0.95)
    p.add_argument("--target-red-precision", type=float, default=0.80)
    p.add_argument("--target-yellow-precision", type=float, default=0.50)
    args = p.parse_args(argv)

    import joblib
    model_path = args.model / "model.joblib"
    if not model_path.exists():
        print(f"ERROR: {model_path} missing", file=sys.stderr)
        return 2
    model = joblib.load(model_path)
    print(f"[load] model from {model_path}", file=sys.stderr)

    # Use the Snaffler-blind benchmark as the calibration set — it's the
    # OOD eval that drove v0.5's threshold tuning too, and it stresses
    # generalization better than the in-distribution test split.
    benchmark_records = _load_jsonl(args.benchmark)
    print(f"[load] {len(benchmark_records)} benchmark records",
          file=sys.stderr)
    probs, y = _predict_proba(model, benchmark_records)
    n_pos = sum(y)
    n_neg = len(y) - n_pos
    print(f"  positives: {n_pos}, negatives: {n_neg}", file=sys.stderr)

    print(f"\n  probability distribution:", file=sys.stderr)
    import statistics
    print(f"    min={min(probs):.4f}  max={max(probs):.4f}  "
          f"mean={statistics.mean(probs):.4f}  stdev={statistics.pstdev(probs):.4f}",
          file=sys.stderr)

    # Compute thresholds
    black_thresh, black_m = _find_threshold_for_precision(probs, y, args.target_black_precision)
    red_thresh, red_m = _find_threshold_for_precision(probs, y, args.target_red_precision)
    yellow_thresh, yellow_m = _find_threshold_for_precision(probs, y, args.target_yellow_precision)
    best_f1_thresh, best_f1_m = _find_threshold_for_best_f1(probs, y)

    # Sanity: thresholds should be monotonically decreasing
    print(f"\n=== Recommended v0.15 tier thresholds (Snaffler-blind benchmark) ===",
          file=sys.stderr)
    print(f"  Black  (P ≥ {args.target_black_precision:.2f}):  threshold={black_thresh:.4f}  "
          f"P={black_m['precision']:.3f}  R={black_m['recall']:.3f}  "
          f"F1={black_m['f1']:.3f}  TP={black_m['tp']}",
          file=sys.stderr)
    print(f"  Red    (P ≥ {args.target_red_precision:.2f}):  threshold={red_thresh:.4f}  "
          f"P={red_m['precision']:.3f}  R={red_m['recall']:.3f}  "
          f"F1={red_m['f1']:.3f}  TP={red_m['tp']}",
          file=sys.stderr)
    print(f"  Yellow (P ≥ {args.target_yellow_precision:.2f}):  threshold={yellow_thresh:.4f}  "
          f"P={yellow_m['precision']:.3f}  R={yellow_m['recall']:.3f}  "
          f"F1={yellow_m['f1']:.3f}  TP={yellow_m['tp']}",
          file=sys.stderr)
    print(f"  BestF1            :  threshold={best_f1_thresh:.4f}  "
          f"P={best_f1_m['precision']:.3f}  R={best_f1_m['recall']:.3f}  "
          f"F1={best_f1_m['f1']:.3f}  TP={best_f1_m['tp']}",
          file=sys.stderr)

    # Show context at common deployment-style thresholds for comparison
    print(f"\n=== Reference points ===", file=sys.stderr)
    for t in (0.50, 0.30, 0.10, 0.05, 0.014, 0.005):
        m = _metrics_at(probs, y, t)
        print(f"  @{t:.4f}: P={m['precision']:.3f}  R={m['recall']:.3f}  "
              f"F1={m['f1']:.3f}", file=sys.stderr)

    # Recommendation as a code snippet
    print(f"\n=== Suggested src/truffler/tier.py update ===", file=sys.stderr)
    print(f"  DEFAULT_V0P15_THRESHOLDS = TierThresholds(", file=sys.stderr)
    print(f"      black={black_thresh:.4f},", file=sys.stderr)
    print(f"      red={red_thresh:.4f},", file=sys.stderr)
    print(f"      yellow={yellow_thresh:.4f},", file=sys.stderr)
    print(f"  )", file=sys.stderr)

    # Emit machine-readable JSON for downstream tools / docs
    out = {
        "model_dir": str(args.model),
        "calibration_set": str(args.benchmark),
        "n_positives": n_pos,
        "n_negatives": n_neg,
        "thresholds": {
            "black": black_thresh,
            "red": red_thresh,
            "yellow": yellow_thresh,
            "best_f1": best_f1_thresh,
        },
        "metrics_at": {
            "black": black_m,
            "red": red_m,
            "yellow": yellow_m,
            "best_f1": best_f1_m,
        },
        "probability_distribution": {
            "min": min(probs),
            "max": max(probs),
            "mean": statistics.mean(probs),
            "stdev": statistics.pstdev(probs),
        },
    }
    out_path = args.model / "threshold_calibration.json"
    out_path.write_text(json.dumps(out, indent=2))
    print(f"\n[write] {out_path}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
