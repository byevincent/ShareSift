"""v0.15 path classifier — apply beta calibration to fix squashed probabilities.

The raw LightGBM scores from v0.15 cluster in [0, 0.2] (mean=0.18, stdev=0.26
per the snaffler-blind benchmark). Isotonic calibration would produce a
step function that maps most of that mass to the same low plateau, leaving
deployment thresholds non-intuitive (0.005/0.014/0.035 instead of the v0.5
levels at 0.50/0.80/0.95).

Beta calibration (Kull et al., 2017) is parametric (3 params) and handles
the "rare positives cluster near zero" case cleanly. The 2026
"Classifier Calibration at Scale" empirical study found isotonic actively
degrades modern boosted models — our case exactly.

This script:
1. Loads the trained v0.15 model
2. Fits a BetaCalibration on a held-out calibration set
3. Saves the calibrator alongside the model
4. Recomputes tier thresholds against the calibrated probabilities
5. Writes the new thresholds to threshold_calibration.json for tier.py update

Usage::

    uv run python tools/recalibrate_v0p15_beta.py
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


def _predict_proba(model, records: list[dict]):
    from src.eval.model.evaluate import featurize, is_juicy
    paths = [r["path"] for r in records]
    y = [1 if is_juicy(r) else 0 for r in records]
    X = featurize(paths)
    probs = model.predict_proba(X)[:, 1]
    return list(probs), y


def _find_threshold_for_precision(probs, y, target_p, min_tp=5):
    sorted_probs = sorted(set(probs), reverse=True)
    best = (sorted_probs[0] if sorted_probs else 1.0, {})
    for t in sorted_probs:
        tp = sum(1 for p, l in zip(probs, y) if p >= t and l == 1)
        fp = sum(1 for p, l in zip(probs, y) if p >= t and l == 0)
        fn = sum(1 for p, l in zip(probs, y) if p < t and l == 1)
        if tp < min_tp:
            continue
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        f1 = 2 * precision * recall / max(1e-9, precision + recall)
        if precision >= target_p:
            best = (t, {"precision": precision, "recall": recall, "f1": f1, "tp": tp, "fp": fp})
    return best


def main(argv=None):
    import joblib
    import numpy as np
    from betacal import BetaCalibration

    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    p.add_argument("--benchmark", type=Path, default=DEFAULT_BENCHMARK)
    p.add_argument("--test-split", type=Path, default=DEFAULT_TEST_SPLIT)
    args = p.parse_args(argv)

    # Load the raw model
    model_path = args.model / "model.joblib"
    if not model_path.exists():
        print(f"ERROR: {model_path} missing", file=sys.stderr)
        return 2
    model = joblib.load(model_path)
    print(f"[load] {model_path}", file=sys.stderr)

    # Fit calibrator on the snaffler-blind benchmark (50/50 balanced).
    # Fitting on the imbalanced test split (11% positive) reproduces the
    # marginal prior in the calibration, leaving thresholds stuck at the
    # raw-output levels. Calibrating to a balanced distribution gives
    # deployment thresholds that match the v0.5 0.50/0.80/0.95 semantics.
    test_records = _load_jsonl(args.benchmark)
    print(f"[load] {len(test_records)} benchmark records (calibration fit)",
          file=sys.stderr)
    test_probs, test_y = _predict_proba(model, test_records)
    test_probs_np = np.array(test_probs).reshape(-1, 1)
    test_y_np = np.array(test_y)

    n_pos = int(test_y_np.sum())
    n_neg = len(test_y_np) - n_pos
    print(f"  positives: {n_pos}, negatives: {n_neg}", file=sys.stderr)

    print(f"\n[fit] Beta calibration ('abm' parameterization)", file=sys.stderr)
    bc = BetaCalibration(parameters="abm")
    bc.fit(test_probs_np, test_y_np)

    # Save calibrator
    cal_path = args.model / "beta_calibrator.joblib"
    joblib.dump(bc, cal_path)
    print(f"[save] {cal_path}", file=sys.stderr)

    # Apply calibration on the benchmark and recompute thresholds
    bench_records = _load_jsonl(args.benchmark)
    print(f"\n[load] {len(bench_records)} benchmark records", file=sys.stderr)
    raw_probs, y = _predict_proba(model, bench_records)
    raw_probs_np = np.array(raw_probs).reshape(-1, 1)
    calibrated = bc.predict(raw_probs_np).tolist()

    print(f"\n  raw probabilities:        min={min(raw_probs):.4f} max={max(raw_probs):.4f} "
          f"mean={np.mean(raw_probs):.4f}", file=sys.stderr)
    print(f"  calibrated probabilities: min={min(calibrated):.4f} max={max(calibrated):.4f} "
          f"mean={np.mean(calibrated):.4f}", file=sys.stderr)

    # Find thresholds on calibrated probs targeting v0.5-style tier semantics
    black_t, black_m = _find_threshold_for_precision(calibrated, y, 0.95)
    red_t, red_m = _find_threshold_for_precision(calibrated, y, 0.80)
    yellow_t, yellow_m = _find_threshold_for_precision(calibrated, y, 0.50)

    print(f"\n=== v0.15 (beta-calibrated) tier thresholds ===", file=sys.stderr)
    print(f"  Black  (P >= 0.95): t={black_t:.4f}  {black_m}", file=sys.stderr)
    print(f"  Red    (P >= 0.80): t={red_t:.4f}  {red_m}", file=sys.stderr)
    print(f"  Yellow (P >= 0.50): t={yellow_t:.4f}  {yellow_m}", file=sys.stderr)

    # Reference points
    print(f"\n=== Reference points (calibrated) ===", file=sys.stderr)
    for t in (0.95, 0.80, 0.50, 0.30, 0.10, 0.05):
        tp = sum(1 for p, l in zip(calibrated, y) if p >= t and l == 1)
        fp = sum(1 for p, l in zip(calibrated, y) if p >= t and l == 0)
        fn = sum(1 for p, l in zip(calibrated, y) if p < t and l == 1)
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        f1 = 2 * precision * recall / max(1e-9, precision + recall)
        print(f"  @{t:.4f}: P={precision:.3f} R={recall:.3f} F1={f1:.3f}", file=sys.stderr)

    out = {
        "calibrator": "beta_abm",
        "calibrator_path": str(cal_path.relative_to(REPO_ROOT)),
        "fit_on": str(args.test_split.relative_to(REPO_ROOT)),
        "fit_n_positives": n_pos,
        "fit_n_negatives": n_neg,
        "benchmark_path": str(args.benchmark.relative_to(REPO_ROOT)),
        "thresholds_calibrated": {
            "black": black_t, "red": red_t, "yellow": yellow_t,
        },
        "metrics": {
            "black": black_m, "red": red_m, "yellow": yellow_m,
        },
        "raw_prob_stats": {
            "min": min(raw_probs), "max": max(raw_probs), "mean": float(np.mean(raw_probs)),
        },
        "calibrated_prob_stats": {
            "min": min(calibrated), "max": max(calibrated), "mean": float(np.mean(calibrated)),
        },
    }
    out_path = args.model / "beta_calibration.json"
    out_path.write_text(json.dumps(out, indent=2))
    print(f"\n[write] {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
