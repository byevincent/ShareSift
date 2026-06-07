"""Install the recalibrated Windows calibrator (isotonic_mixed variant).

Companion to ``tools/recalibrate_windows_ood.py`` which audits the
options. This tool actually swaps in the new calibrator.

Procedure:
1. Load raw LightGBM model and existing calibrated wrapper.
2. Fit IsotonicRegression on raw scores from (Windows train ∪ first
   30% of Snaffler-blind benchmark records). The benchmark-record
   inclusion is what gives the calibrator OOD signal.
3. Wrap into ``_OODCalibratedModel`` (raw model + isotonic) with the
   same ``predict_proba`` interface the runtime expects.
4. Back up the previous ``calibrated.joblib`` to ``calibrated_v0p3.joblib``.
5. Write new calibrator to ``calibrated.joblib``.
6. Verify both in-distribution and OOD scoring still works.

Reversible: restore ``calibrated_v0p3.joblib`` to undo.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import warnings
from pathlib import Path

import joblib
import numpy as np

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sharesift.features import featurize
from sharesift.path import _OODCalibratedModel


def _load_records(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--raw-model",
        type=Path,
        default=REPO_ROOT / "models" / "path_classifier_v0_windows" / "model.joblib",
    )
    parser.add_argument(
        "--current-calibrated",
        type=Path,
        default=REPO_ROOT
        / "models"
        / "path_classifier_v0_windows"
        / "calibrated.joblib",
    )
    parser.add_argument(
        "--train-split",
        type=Path,
        default=REPO_ROOT / "data" / "eval" / "train_split.jsonl",
    )
    parser.add_argument(
        "--benchmark",
        type=Path,
        default=REPO_ROOT / "data" / "eval" / "snaffler_blind_benchmark.jsonl",
    )
    parser.add_argument("--benchmark-calib-fraction", type=float, default=0.30)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    # Load + filter Windows-only training records (the split file has both shapes).
    all_train = _load_records(args.train_split)
    windows_train = [r for r in all_train if r["path"].startswith("\\\\")]
    benchmark = _load_records(args.benchmark)
    print(
        f"Loaded {len(windows_train)} Windows train records, "
        f"{len(benchmark)} benchmark records",
        file=sys.stderr,
    )

    raw_model = joblib.load(args.raw_model)
    print(
        f"Loaded raw LightGBM model from {args.raw_model.name}",
        file=sys.stderr,
    )

    # Score everything with the raw model.
    train_paths = [r["path"] for r in windows_train]
    bench_paths = [r["path"] for r in benchmark]
    train_X = featurize(train_paths)
    bench_X = featurize(bench_paths)
    train_raw = raw_model.predict_proba(train_X)[:, 1]
    bench_raw = raw_model.predict_proba(bench_X)[:, 1]
    train_labels = np.array(
        [1 if r["label"] == "juicy" else 0 for r in windows_train]
    )
    bench_labels = np.array(
        [1 if r["label"] == "juicy" else 0 for r in benchmark]
    )

    # Reserve the same 30/70 benchmark split as the audit.
    rng = np.random.default_rng(args.seed)
    idx = np.arange(len(benchmark))
    rng.shuffle(idx)
    n_calib = int(len(idx) * args.benchmark_calib_fraction)
    calib_idx = idx[:n_calib]
    print(
        f"Using {n_calib} benchmark records for calibrator OOD signal "
        f"(seed={args.seed} matches audit script)",
        file=sys.stderr,
    )

    # Combined fit set.
    fit_scores = np.concatenate([train_raw, bench_raw[calib_idx]])
    fit_labels = np.concatenate([train_labels, bench_labels[calib_idx]])

    # Fit isotonic.
    from sklearn.isotonic import IsotonicRegression

    iso = IsotonicRegression(out_of_bounds="clip")
    iso.fit(fit_scores, fit_labels)
    print(
        f"Fit IsotonicRegression on {len(fit_scores)} records "
        f"({int(fit_labels.sum())} positive)",
        file=sys.stderr,
    )

    # Build the new calibrated model.
    new_model = _OODCalibratedModel(raw_model, iso)

    # Smoke test
    sample_paths = [
        "\\\\fs01\\share\\backups\\sql_backup.bak",
        "\\\\fs01\\share\\public\\readme.txt",
        "\\\\dc01\\SYSVOL\\corp\\Policies\\GPP.xml",
    ]
    print("\nSmoke test on representative paths:", file=sys.stderr)
    smoke_X = featurize(sample_paths)
    smoke_probs = new_model.predict_proba(smoke_X)[:, 1]
    for p, prob in zip(sample_paths, smoke_probs):
        print(f"  {p}: prob={prob:.4f}", file=sys.stderr)

    if args.dry_run:
        print("\nDRY RUN: not writing.", file=sys.stderr)
        return 0

    # Back up existing calibrated.
    backup_path = args.current_calibrated.parent / "calibrated_v0p3.joblib"
    if args.current_calibrated.exists() and not backup_path.exists():
        shutil.copy2(args.current_calibrated, backup_path)
        print(
            f"\nBacked up current calibrator to {backup_path.name}",
            file=sys.stderr,
        )

    joblib.dump(new_model, args.current_calibrated)
    print(
        f"Wrote new OOD-recalibrated model to "
        f"{args.current_calibrated.relative_to(REPO_ROOT)}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
