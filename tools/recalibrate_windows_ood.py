"""Re-fit the Windows path-classifier calibrator with OOD samples included.

Tier-2 fix to the v0.5 audit finding that the Windows isotonic
calibrator drifts catastrophically OOD (ECE 0.30 on Snaffler-blind
benchmark vs 0.007 on in-distribution test).

Method: split the 500-record Snaffler-blind benchmark into a
calibration set (30%) and a held-out test set (70%). Fit each of
{isotonic, sigmoid (Platt), temperature scaling} on the training data
combined with the calibration-set OOD records, then evaluate on:

* In-distribution test split (should not regress).
* Held-out OOD benchmark (should improve from ECE 0.30).

The best variant is saved as the new ``calibrated.joblib`` if it
strictly improves OOD ECE without regressing in-distribution ECE by
more than 0.01.

The underlying LightGBM model is unchanged — this is a calibration-only
refit. Ranking metrics (PR-AUC, ROC-AUC) are calibration-invariant and
won't change.
"""

from __future__ import annotations

import argparse
import json
import sys
import warnings
from pathlib import Path

import joblib
import numpy as np

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sharesift.features import featurize


def _load_records(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _reliability_table(probs: np.ndarray, labels: np.ndarray, n_bins: int = 10):
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    rows = []
    for i in range(n_bins):
        lo, hi = edges[i], edges[i + 1]
        if i == n_bins - 1:
            mask = (probs >= lo) & (probs <= hi)
        else:
            mask = (probs >= lo) & (probs < hi)
        n = int(mask.sum())
        if n == 0:
            continue
        rows.append(
            {
                "n": n,
                "mean_pred": float(probs[mask].mean()),
                "frac_pos": float(labels[mask].mean()),
                "abs_error": float(abs(probs[mask].mean() - labels[mask].mean())),
            }
        )
    return rows


def _ece(rel: list[dict], n_total: int) -> float:
    if n_total == 0:
        return 0.0
    return sum((r["n"] / n_total) * r["abs_error"] for r in rel)


def _metrics(probs: np.ndarray, labels: np.ndarray) -> dict:
    rel = _reliability_table(probs, labels)
    return {
        "n": int(len(labels)),
        "n_positive": int(labels.sum()),
        "ece": _ece(rel, len(labels)),
        "brier": float(((probs - labels) ** 2).mean()),
        "mean_pred": float(probs.mean()),
        "frac_pos": float(labels.mean()),
    }


def _fit_temperature(scores: np.ndarray, labels: np.ndarray) -> float:
    """Single-scalar temperature scaling. We treat ``scores`` as
    pre-sigmoid logit-like values and fit T to minimize NLL.

    Inputs here are probabilities in (0, 1), so we convert via logit
    first. Clamps probabilities away from {0, 1} to keep gradients
    finite.
    """
    from scipy.optimize import minimize_scalar

    eps = 1e-6
    p = np.clip(scores, eps, 1 - eps)
    z = np.log(p / (1 - p))  # logit

    def nll(T):
        if T <= 0:
            return np.inf
        z_T = z / T
        # softmax-ish: p(class=1) = sigmoid(z/T)
        p_pos = 1.0 / (1.0 + np.exp(-z_T))
        p_pos = np.clip(p_pos, eps, 1 - eps)
        return -float((labels * np.log(p_pos) + (1 - labels) * np.log(1 - p_pos)).mean())

    res = minimize_scalar(nll, bounds=(0.05, 20.0), method="bounded")
    return float(res.x)


def _apply_temperature(scores: np.ndarray, T: float) -> np.ndarray:
    eps = 1e-6
    p = np.clip(scores, eps, 1 - eps)
    z = np.log(p / (1 - p))
    return 1.0 / (1.0 + np.exp(-z / T))


def _fit_isotonic(scores: np.ndarray, labels: np.ndarray):
    from sklearn.isotonic import IsotonicRegression

    iso = IsotonicRegression(out_of_bounds="clip")
    iso.fit(scores, labels)
    return iso


def _fit_platt(scores: np.ndarray, labels: np.ndarray):
    from sklearn.linear_model import LogisticRegression

    # Platt scaling: fit logistic on the scores.
    X = scores.reshape(-1, 1)
    lr = LogisticRegression()
    lr.fit(X, labels)
    return lr


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--raw-model",
        type=Path,
        default=REPO_ROOT / "models" / "path_classifier_v0_windows" / "model.joblib",
        help="The uncalibrated LightGBM model (not the calibrated one).",
    )
    parser.add_argument(
        "--current-calibrated",
        type=Path,
        default=REPO_ROOT
        / "models"
        / "path_classifier_v0_windows"
        / "calibrated.joblib",
        help="Existing calibrated wrapper, kept for baseline comparison.",
    )
    parser.add_argument(
        "--train-split",
        type=Path,
        default=REPO_ROOT / "data" / "eval" / "train_split_windows.jsonl",
    )
    parser.add_argument(
        "--test-split",
        type=Path,
        default=REPO_ROOT / "data" / "eval" / "test_split_windows.jsonl",
    )
    parser.add_argument(
        "--benchmark",
        type=Path,
        default=REPO_ROOT / "data" / "eval" / "snaffler_blind_benchmark.jsonl",
    )
    parser.add_argument("--benchmark-calib-fraction", type=float, default=0.30)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument(
        "--output-report",
        type=Path,
        default=REPO_ROOT / "reports" / "recalibration_audit.json",
    )
    parser.add_argument(
        "--save-as",
        type=Path,
        default=None,
        help=(
            "If set and the new calibrator strictly improves on the OOD "
            "ECE without regressing the in-distribution ECE, save it here."
        ),
    )
    args = parser.parse_args()

    if not args.train_split.exists():
        # Fall back to filtering the combined train split.
        windows_train = []
        for line in (REPO_ROOT / "data" / "eval" / "train_split.jsonl").read_text().splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            if r["path"].startswith("\\\\"):
                windows_train.append(r)
        train_records = windows_train
        print(
            f"Note: --train-split {args.train_split} not found; using filtered "
            f"Windows subset of train_split.jsonl ({len(windows_train)} records)",
            file=sys.stderr,
        )
    else:
        train_records = _load_records(args.train_split)
    test_records = _load_records(args.test_split)
    benchmark_records = _load_records(args.benchmark)

    print(
        f"Records: train={len(train_records)}, test={len(test_records)}, "
        f"benchmark={len(benchmark_records)}",
        file=sys.stderr,
    )

    # Featurize + score everything with the raw model.
    print("Loading raw LightGBM model...", file=sys.stderr)
    raw_model = joblib.load(args.raw_model)
    print("Loading current calibrated model (for baseline)...", file=sys.stderr)
    current_calibrated = joblib.load(args.current_calibrated)

    def _score(records, model):
        X = featurize([r["path"] for r in records])
        return model.predict_proba(X)[:, 1]

    train_raw = _score(train_records, raw_model)
    test_raw = _score(test_records, raw_model)
    bench_raw = _score(benchmark_records, raw_model)

    test_cal_current = _score(test_records, current_calibrated)
    bench_cal_current = _score(benchmark_records, current_calibrated)

    train_labels = np.array(
        [1 if r["label"] == "juicy" else 0 for r in train_records]
    )
    test_labels = np.array(
        [1 if r["label"] == "juicy" else 0 for r in test_records]
    )
    bench_labels = np.array(
        [1 if r["label"] == "juicy" else 0 for r in benchmark_records]
    )

    # Split benchmark into calibration + held-out test.
    rng = np.random.default_rng(args.seed)
    bench_idx = np.arange(len(benchmark_records))
    rng.shuffle(bench_idx)
    n_calib = int(len(bench_idx) * args.benchmark_calib_fraction)
    calib_idx = bench_idx[:n_calib]
    held_out_idx = bench_idx[n_calib:]
    print(
        f"Benchmark split: {n_calib} for calibration, "
        f"{len(held_out_idx)} held-out",
        file=sys.stderr,
    )

    bench_calib_raw = bench_raw[calib_idx]
    bench_calib_labels = bench_labels[calib_idx]
    bench_heldout_raw = bench_raw[held_out_idx]
    bench_heldout_labels = bench_labels[held_out_idx]
    bench_heldout_cal_current = bench_cal_current[held_out_idx]

    # Build training scores + labels for calibrator fitting:
    # combine raw train + the benchmark calibration subset.
    fit_scores = np.concatenate([train_raw, bench_calib_raw])
    fit_labels = np.concatenate([train_labels, bench_calib_labels])
    print(
        f"Calibrator fit set: {len(fit_scores)} records "
        f"(train + {n_calib} OOD)",
        file=sys.stderr,
    )

    # Baselines: current calibrator (no retrain).
    results: dict = {
        "version": "v0.5_recalibration",
        "generated": "2026-05-31",
        "config": {
            "train_records": len(train_records),
            "test_records": len(test_records),
            "benchmark_records": len(benchmark_records),
            "benchmark_calib_fraction": args.benchmark_calib_fraction,
            "n_benchmark_calib": int(n_calib),
            "n_benchmark_heldout": int(len(held_out_idx)),
            "seed": args.seed,
        },
        "baselines": {
            "current_calibrated_test": _metrics(test_cal_current, test_labels),
            "current_calibrated_heldout_benchmark": _metrics(
                bench_heldout_cal_current, bench_heldout_labels
            ),
            "raw_uncalibrated_test": _metrics(test_raw, test_labels),
            "raw_uncalibrated_heldout_benchmark": _metrics(
                bench_heldout_raw, bench_heldout_labels
            ),
        },
        "variants": {},
    }

    # Variant A: isotonic on (train + OOD calib).
    print("\nFitting isotonic on (train + OOD calib)...", file=sys.stderr)
    iso = _fit_isotonic(fit_scores, fit_labels)
    iso_test = iso.predict(test_raw)
    iso_heldout = iso.predict(bench_heldout_raw)
    results["variants"]["isotonic_mixed"] = {
        "test": _metrics(iso_test, test_labels),
        "heldout_benchmark": _metrics(iso_heldout, bench_heldout_labels),
    }

    # Variant B: Platt scaling on (train + OOD calib).
    print("Fitting Platt scaling on (train + OOD calib)...", file=sys.stderr)
    platt = _fit_platt(fit_scores, fit_labels)
    platt_test = platt.predict_proba(test_raw.reshape(-1, 1))[:, 1]
    platt_heldout = platt.predict_proba(bench_heldout_raw.reshape(-1, 1))[:, 1]
    results["variants"]["platt_mixed"] = {
        "test": _metrics(platt_test, test_labels),
        "heldout_benchmark": _metrics(platt_heldout, bench_heldout_labels),
    }

    # Variant C: temperature scaling on raw scores via OOD calib only.
    print("Fitting temperature scaling on OOD calib only...", file=sys.stderr)
    T = _fit_temperature(bench_calib_raw, bench_calib_labels)
    print(f"  T = {T:.4f}", file=sys.stderr)
    temp_test = _apply_temperature(test_raw, T)
    temp_heldout = _apply_temperature(bench_heldout_raw, T)
    results["variants"]["temperature_ood_only"] = {
        "T": T,
        "test": _metrics(temp_test, test_labels),
        "heldout_benchmark": _metrics(temp_heldout, bench_heldout_labels),
    }

    # Variant D: temperature scaling on (train + OOD calib) mix.
    print("Fitting temperature scaling on (train + OOD calib)...", file=sys.stderr)
    T_mix = _fit_temperature(fit_scores, fit_labels)
    print(f"  T_mix = {T_mix:.4f}", file=sys.stderr)
    temp_mix_test = _apply_temperature(test_raw, T_mix)
    temp_mix_heldout = _apply_temperature(bench_heldout_raw, T_mix)
    results["variants"]["temperature_mixed"] = {
        "T": T_mix,
        "test": _metrics(temp_mix_test, test_labels),
        "heldout_benchmark": _metrics(temp_mix_heldout, bench_heldout_labels),
    }

    args.output_report.parent.mkdir(parents=True, exist_ok=True)
    args.output_report.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(
        f"\nWrote {args.output_report.relative_to(REPO_ROOT)}", file=sys.stderr
    )

    # Summary
    print("\n=== ECE COMPARISON ===", file=sys.stderr)
    print(
        f"{'variant':30s}  {'test ECE':>10s}  {'OOD ECE':>10s}  "
        f"{'test Brier':>11s}  {'OOD Brier':>10s}",
        file=sys.stderr,
    )

    def _row(label, m_test, m_heldout):
        print(
            f"{label:30s}  {m_test['ece']:10.4f}  {m_heldout['ece']:10.4f}  "
            f"{m_test['brier']:11.5f}  {m_heldout['brier']:10.5f}",
            file=sys.stderr,
        )

    _row(
        "[BASELINE] current calibrated",
        results["baselines"]["current_calibrated_test"],
        results["baselines"]["current_calibrated_heldout_benchmark"],
    )
    _row(
        "[BASELINE] raw uncalibrated",
        results["baselines"]["raw_uncalibrated_test"],
        results["baselines"]["raw_uncalibrated_heldout_benchmark"],
    )
    for name, v in results["variants"].items():
        _row(name, v["test"], v["heldout_benchmark"])

    # If save target is given and a variant is strictly better, write it.
    if args.save_as is not None:
        baseline_test_ece = results["baselines"]["current_calibrated_test"]["ece"]
        baseline_ood_ece = results["baselines"][
            "current_calibrated_heldout_benchmark"
        ]["ece"]
        best_variant = None
        best_ood_ece = baseline_ood_ece
        for name, v in results["variants"].items():
            test_ece = v["test"]["ece"]
            ood_ece = v["heldout_benchmark"]["ece"]
            # Accept if OOD ECE strictly improves AND in-distribution ECE
            # doesn't regress by more than 0.01.
            if ood_ece < best_ood_ece and test_ece <= baseline_test_ece + 0.01:
                best_variant = name
                best_ood_ece = ood_ece
        if best_variant is None:
            print(
                "\nNo variant strictly improved; not saving.", file=sys.stderr
            )
        else:
            print(
                f"\nBest variant: {best_variant} "
                f"(OOD ECE {best_ood_ece:.4f} vs baseline {baseline_ood_ece:.4f}). "
                f"NOT auto-saving since the sklearn calibrator wrapper has a "
                f"specific shape; refit via tools/calibrate_path_classifier.py "
                f"with the recommended approach.",
                file=sys.stderr,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
