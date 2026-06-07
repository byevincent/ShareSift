"""Fit and save the calibrated v0 path classifier; report tier-band
precision/recall for Phase-2 closeout.

Per ``docs/build_plan.md`` Phase 2:
* Fit isotonic calibration via 5-fold CV on the labeled train split
  (``CalibratedClassifierCV(method='isotonic', cv=5)``).
* Save as ``models/path_classifier_v0/calibrated.joblib``.
* Evaluate the calibrated model on the Snaffler-blind benchmark and
  the in-distribution test split.
* Report precision/recall at each Snaffler tier band (Black ≥ 0.95,
  Red ≥ 0.80, Yellow ≥ 0.50) so we can verify the bands behave
  sensibly before Phase-4 pysnaffler integration.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import joblib
import numpy as np

from src.eval.model.calibrate import fit_calibrator, predict_calibrated_proba
from sharesift.features import is_juicy
from sharesift.tier import DEFAULT_THRESHOLDS, probability_to_tier
from src.eval.model.train import TrainConfig, load_records

DEFAULT_TRAIN = REPO_ROOT / "data" / "eval" / "train_split.jsonl"
DEFAULT_BENCHMARK = REPO_ROOT / "data" / "eval" / "snaffler_blind_benchmark.jsonl"
DEFAULT_TEST = REPO_ROOT / "data" / "eval" / "test_split.jsonl"
DEFAULT_MODEL_DIR = REPO_ROOT / "models" / "path_classifier_v0"


def _tier_precision_recall(
    probs: np.ndarray, y: np.ndarray
) -> dict[str, dict[str, float]]:
    """Per-tier precision/recall: at each threshold, what fraction of
    predictions are actually juicy, and what fraction of all juicy are
    captured? Plus the cumulative ``flagged`` rate (anything tier-tagged)."""
    results: dict[str, dict[str, float]] = {}
    n_juicy = int(y.sum())
    n_total = len(y)
    for tier_name, threshold in [
        ("Black (≥ 0.95)", DEFAULT_THRESHOLDS.black),
        ("Red   (≥ 0.80)", DEFAULT_THRESHOLDS.red),
        ("Yellow(≥ 0.50)", DEFAULT_THRESHOLDS.yellow),
    ]:
        pred = (probs >= threshold)
        n_pred = int(pred.sum())
        tp = int((pred & (y == 1)).sum())
        prec = tp / n_pred if n_pred else 0.0
        rec = tp / n_juicy if n_juicy else 0.0
        results[tier_name] = {
            "threshold": threshold,
            "n_flagged": n_pred,
            "flagged_rate": n_pred / n_total,
            "precision": prec,
            "recall": rec,
        }
    return results


def _print_tier_table(name: str, n_records: int, n_juicy: int, table: dict) -> None:
    print(f"\n=== Tier band performance — {name} ===")
    print(f"  population: {n_records} records ({n_juicy} juicy)")
    print(
        f"  {'tier':<20} {'n_flagged':>10} {'flag-rate':>10} "
        f"{'precision':>10} {'recall':>10}"
    )
    for tier_name, m in table.items():
        print(
            f"  {tier_name:<20} {m['n_flagged']:>10} "
            f"{m['flagged_rate']:>9.2%} "
            f"{m['precision']:>9.2%} "
            f"{m['recall']:>9.2%}"
        )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--train-data", type=Path, default=DEFAULT_TRAIN)
    p.add_argument("--benchmark", type=Path, default=DEFAULT_BENCHMARK)
    p.add_argument("--test-split", type=Path, default=DEFAULT_TEST)
    p.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    p.add_argument("--cv", type=int, default=5)
    p.add_argument("--no-save", action="store_true")
    args = p.parse_args(argv)

    print(f"Loading training data from {args.train_data.relative_to(REPO_ROOT)}")
    train_records = load_records(args.train_data)
    print(f"  {len(train_records)} records")

    print(
        f"Fitting calibrator (CalibratedClassifierCV, method=isotonic, cv={args.cv})..."
    )
    calibrated = fit_calibrator(train_records, TrainConfig(), cv=args.cv)

    if not args.no_save:
        artifact = args.model_dir / "calibrated.joblib"
        joblib.dump(calibrated, artifact)
        print(f"Saved calibrated model to {artifact.relative_to(REPO_ROOT)}")

        # Calibration metadata supplements the base model's metadata.json.
        calib_meta = {
            "calibrated_at_utc": datetime.now(timezone.utc).isoformat(),
            "method": "isotonic",
            "cv": args.cv,
            "tier_thresholds": {
                "black": DEFAULT_THRESHOLDS.black,
                "red": DEFAULT_THRESHOLDS.red,
                "yellow": DEFAULT_THRESHOLDS.yellow,
            },
            "train_record_count": len(train_records),
        }
        (args.model_dir / "calibration_metadata.json").write_text(
            json.dumps(calib_meta, indent=2), encoding="utf-8"
        )

    for split_name, split_path in [
        ("Snaffler-blind benchmark", args.benchmark),
        ("In-distribution test split", args.test_split),
    ]:
        if not split_path.exists():
            continue
        records = load_records(split_path)
        paths = [r["path"] for r in records]
        y = np.array(
            [1 if is_juicy(r) else 0 for r in records], dtype=np.int32
        )
        probs = predict_calibrated_proba(calibrated, paths)
        table = _tier_precision_recall(probs, y)
        _print_tier_table(split_name, len(records), int(y.sum()), table)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
