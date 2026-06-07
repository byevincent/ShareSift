"""ECE + reliability table + Brier + MCC for the v0.5 path classifiers.

Tier-1 audit item from the 2026-05-31 v0.5 research pass: confirm or
refute the suspected calibration gap between the in-distribution test
split (Brier ~0.01 per the ablation report) and the Snaffler-blind
benchmark (Brier ~0.23 per the same source). A 23x Brier gap signals
the isotonic calibrator is significantly mis-fit to the OOD-ish
benchmark; if true, every tier-band precision contract advertised in
the README needs a footnote.

Per model × eval-set, this tool reports:

* Probability range, mean, std
* **Expected Calibration Error (ECE)** computed with 10 equal-width
  bins on the [0, 1] interval. Standard formula:
  ``ECE = Σ_b (n_b / N) * |frac_pos_b - mean_pred_b|``.
* **Reliability table** — 10 rows: bin range, n records, mean predicted
  probability, fraction actually positive, calibration error per bin.
* **Brier score** — mean squared probability error (raw calibration).
* **Matthews Correlation Coefficient (MCC) at threshold 0.5** —
  imbalance-robust point metric.
* **Per-tier-band precision/recall** at each model's deployment
  thresholds (the tier bands are the product, so they need their own
  numbers).

Output: JSON to ``reports/calibration_audit.json``. No matplotlib
dependency — the JSON tables drive any downstream plotting.
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
from sharesift.tier import DEFAULT_LINUX_THRESHOLDS, DEFAULT_WINDOWS_THRESHOLDS

DEFAULT_OUTPUT = REPO_ROOT / "reports" / "calibration_audit.json"


def _load_records(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _reliability_table(
    probs: np.ndarray, labels: np.ndarray, n_bins: int = 10
) -> list[dict]:
    """Equal-width bin reliability table. Empty bins are still emitted
    so the table is always 10 rows (predictable for diff vs other runs)."""
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    rows = []
    for i in range(n_bins):
        lo, hi = edges[i], edges[i + 1]
        # Right edge inclusive on the last bin so prob==1.0 is captured.
        if i == n_bins - 1:
            mask = (probs >= lo) & (probs <= hi)
        else:
            mask = (probs >= lo) & (probs < hi)
        n = int(mask.sum())
        if n == 0:
            rows.append(
                {
                    "bin_lo": float(lo),
                    "bin_hi": float(hi),
                    "n": 0,
                    "mean_predicted": None,
                    "frac_positive": None,
                    "abs_error": None,
                }
            )
            continue
        mean_pred = float(probs[mask].mean())
        frac_pos = float(labels[mask].mean())
        rows.append(
            {
                "bin_lo": float(lo),
                "bin_hi": float(hi),
                "n": n,
                "mean_predicted": mean_pred,
                "frac_positive": frac_pos,
                "abs_error": abs(mean_pred - frac_pos),
            }
        )
    return rows


def _ece(reliability_table: list[dict], n_total: int) -> float:
    """Standard 10-bin ECE. Skips empty bins."""
    if n_total == 0:
        return 0.0
    return sum(
        (row["n"] / n_total) * row["abs_error"]
        for row in reliability_table
        if row["n"] > 0
    )


def _brier(probs: np.ndarray, labels: np.ndarray) -> float:
    return float(((probs - labels) ** 2).mean())


def _mcc(probs: np.ndarray, labels: np.ndarray, threshold: float = 0.5) -> float:
    """Matthews Correlation Coefficient at threshold. Robust to label
    imbalance — the path test split is 60/2138 positive (~2.8%) so MCC
    is the honest single-number metric."""
    pred = (probs >= threshold).astype(int)
    tp = int(((pred == 1) & (labels == 1)).sum())
    tn = int(((pred == 0) & (labels == 0)).sum())
    fp = int(((pred == 1) & (labels == 0)).sum())
    fn = int(((pred == 0) & (labels == 1)).sum())
    denom = np.sqrt(float((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)))
    if denom == 0:
        return 0.0
    return float((tp * tn - fp * fn) / denom)


def _tier_band_stats(probs: np.ndarray, labels: np.ndarray, thresholds) -> dict:
    """Per-band precision/recall at each tier cutoff."""
    bands = {
        "Black": thresholds.black,
        "Red": thresholds.red,
        "Yellow": thresholds.yellow,
    }
    n_pos = int(labels.sum())
    out = {}
    for name, th in bands.items():
        flagged = probs >= th
        n_flagged = int(flagged.sum())
        n_tp = int((flagged & (labels == 1)).sum())
        precision = (n_tp / n_flagged) if n_flagged else None
        recall = (n_tp / n_pos) if n_pos else None
        out[name] = {
            "threshold": float(th),
            "n_flagged": n_flagged,
            "n_true_positive": n_tp,
            "precision": precision,
            "recall": recall,
        }
    return out


def _audit_one(
    model_path: Path,
    eval_path: Path,
    eval_name: str,
    thresholds,
) -> dict:
    print(
        f"  scoring {eval_name} ({eval_path.name})...", file=sys.stderr
    )
    model = joblib.load(model_path)
    records = _load_records(eval_path)
    paths = [r["path"] for r in records]
    labels = np.array([1 if r["label"] == "juicy" else 0 for r in records])
    X = featurize(paths)
    probs = model.predict_proba(X)[:, 1]

    rel = _reliability_table(probs, labels)
    return {
        "eval_set": eval_name,
        "n_records": int(len(records)),
        "n_positive": int(labels.sum()),
        "n_negative": int((labels == 0).sum()),
        "positive_rate": float(labels.mean()),
        "prob_distribution": {
            "min": float(probs.min()),
            "max": float(probs.max()),
            "mean": float(probs.mean()),
            "std": float(probs.std()),
            "p50": float(np.median(probs)),
            "p95": float(np.percentile(probs, 95)),
            "p99": float(np.percentile(probs, 99)),
        },
        "ece": _ece(rel, len(records)),
        "brier": _brier(probs, labels),
        "mcc_at_0.5": _mcc(probs, labels, threshold=0.5),
        "reliability_table": rel,
        "tier_bands": _tier_band_stats(probs, labels, thresholds),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--windows-model",
        type=Path,
        default=REPO_ROOT / "models" / "path_classifier_v0_windows" / "calibrated.joblib",
    )
    parser.add_argument(
        "--linux-model",
        type=Path,
        default=REPO_ROOT / "models" / "path_classifier_v0_linux" / "calibrated.joblib",
    )
    parser.add_argument(
        "--windows-test",
        type=Path,
        default=REPO_ROOT / "data" / "eval" / "test_split_windows.jsonl",
    )
    parser.add_argument(
        "--linux-test",
        type=Path,
        default=REPO_ROOT / "data" / "eval" / "test_split_linux.jsonl",
    )
    parser.add_argument(
        "--snaffler-benchmark",
        type=Path,
        default=REPO_ROOT / "data" / "eval" / "snaffler_blind_benchmark.jsonl",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    audits: list[dict] = []

    # Windows model × Windows test split
    print("Auditing Windows model...", file=sys.stderr)
    audits.append(
        {
            "model": "windows",
            "model_path": str(args.windows_model.relative_to(REPO_ROOT)),
            "thresholds": {
                "black": DEFAULT_WINDOWS_THRESHOLDS.black,
                "red": DEFAULT_WINDOWS_THRESHOLDS.red,
                "yellow": DEFAULT_WINDOWS_THRESHOLDS.yellow,
            },
            **_audit_one(
                args.windows_model,
                args.windows_test,
                "test_split_windows",
                DEFAULT_WINDOWS_THRESHOLDS,
            ),
        }
    )
    # Windows model × Snaffler-blind benchmark
    audits.append(
        {
            "model": "windows",
            "model_path": str(args.windows_model.relative_to(REPO_ROOT)),
            "thresholds": {
                "black": DEFAULT_WINDOWS_THRESHOLDS.black,
                "red": DEFAULT_WINDOWS_THRESHOLDS.red,
                "yellow": DEFAULT_WINDOWS_THRESHOLDS.yellow,
            },
            **_audit_one(
                args.windows_model,
                args.snaffler_benchmark,
                "snaffler_blind_benchmark",
                DEFAULT_WINDOWS_THRESHOLDS,
            ),
        }
    )

    # Linux model × Linux test split
    print("Auditing Linux model...", file=sys.stderr)
    audits.append(
        {
            "model": "linux",
            "model_path": str(args.linux_model.relative_to(REPO_ROOT)),
            "thresholds": {
                "black": DEFAULT_LINUX_THRESHOLDS.black,
                "red": DEFAULT_LINUX_THRESHOLDS.red,
                "yellow": DEFAULT_LINUX_THRESHOLDS.yellow,
            },
            **_audit_one(
                args.linux_model,
                args.linux_test,
                "test_split_linux",
                DEFAULT_LINUX_THRESHOLDS,
            ),
        }
    )

    report = {
        "version": "v0.5",
        "generated": "2026-05-31",
        "audits": audits,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"\nWrote {args.output.relative_to(REPO_ROOT)}", file=sys.stderr)

    # Headline summary.
    print("\n=== HEADLINE CALIBRATION TABLE ===", file=sys.stderr)
    print(
        f"{'model':10s}  {'eval_set':30s}  {'n':>5s}  {'ECE':>6s}  {'Brier':>7s}  {'MCC@0.5':>8s}",
        file=sys.stderr,
    )
    for a in audits:
        print(
            f"{a['model']:10s}  {a['eval_set']:30s}  {a['n_records']:5d}  "
            f"{a['ece']:.4f}  {a['brier']:.5f}  {a['mcc_at_0.5']:.4f}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
