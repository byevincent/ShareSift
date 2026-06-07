"""Paired bootstrap CI on the Truffler-vs-Snaffler headline delta.

The README claims "Path-classifier recall vs Snaffler at fixed precision:
**+13.7 pt**" — a point estimate that has never had a confidence
interval attached. Tier-1 audit item from the 2026-05-31 v0.5 research
pass.

Structure of the comparison:

* **Snaffler's baseline:** 41.5% recall on the 11,190-record labeled
  queue (228/550 Truffler-juicy paths matched by Snaffler's default
  rule pack). Precomputed in
  ``tools/train_path_classifier.py:SNAFFLER_RECALL_BASELINE``.
* **Truffler's headline:** recall@0.5 on the 500-record Snaffler-blind
  benchmark (250 juicy / 250 not_juicy, stratified by label, all
  Snaffler-silent by construction).

The two are computed on disjoint subsets so a paired-on-same-records
bootstrap isn't possible. The honest framing is:

  Bootstrap Truffler's benchmark recall@0.5 → 95% CI
  Subtract from fixed Snaffler 41.5% baseline → delta with CI

Bootstrap procedure: 10,000 resamples of the 500 benchmark records
with replacement, recomputing recall@0.5 each time. 95% CI from the
2.5th and 97.5th percentiles.

We also bootstrap precision@0.5 since the original claim is at "fixed
precision" — readers should see whether the precision contract holds
under resampling.
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

SNAFFLER_RECALL_BASELINE = 0.415  # 228/550 on the 11,190-record queue
DEFAULT_BOOTSTRAP_ITERS = 10_000
DEFAULT_THRESHOLD = 0.5
DEFAULT_SEED = 2026


def _load_records(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _metrics_at_threshold(
    probs: np.ndarray, labels: np.ndarray, threshold: float
) -> tuple[float, float]:
    """Returns (precision, recall) at the given threshold. Precision
    is undefined when n_flagged==0; we return 0.0 in that case for
    bootstrap aggregation."""
    pred = probs >= threshold
    n_flagged = int(pred.sum())
    n_pos = int(labels.sum())
    n_tp = int((pred & (labels == 1)).sum())
    precision = (n_tp / n_flagged) if n_flagged else 0.0
    recall = (n_tp / n_pos) if n_pos else 0.0
    return precision, recall


def _bootstrap(
    probs: np.ndarray,
    labels: np.ndarray,
    threshold: float,
    n_iters: int,
    seed: int,
) -> dict:
    rng = np.random.default_rng(seed)
    n = len(probs)
    precisions = np.empty(n_iters)
    recalls = np.empty(n_iters)
    for i in range(n_iters):
        idx = rng.integers(0, n, size=n)
        p, r = _metrics_at_threshold(probs[idx], labels[idx], threshold)
        precisions[i] = p
        recalls[i] = r
    return {
        "precision": {
            "point": float(_metrics_at_threshold(probs, labels, threshold)[0]),
            "mean": float(precisions.mean()),
            "std": float(precisions.std()),
            "ci_95_lo": float(np.percentile(precisions, 2.5)),
            "ci_95_hi": float(np.percentile(precisions, 97.5)),
        },
        "recall": {
            "point": float(_metrics_at_threshold(probs, labels, threshold)[1]),
            "mean": float(recalls.mean()),
            "std": float(recalls.std()),
            "ci_95_lo": float(np.percentile(recalls, 2.5)),
            "ci_95_hi": float(np.percentile(recalls, 97.5)),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--model",
        type=Path,
        default=REPO_ROOT
        / "models"
        / "path_classifier_v0_windows"
        / "calibrated.joblib",
    )
    parser.add_argument(
        "--benchmark",
        type=Path,
        default=REPO_ROOT / "data" / "eval" / "snaffler_blind_benchmark.jsonl",
    )
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    parser.add_argument("--iters", type=int, default=DEFAULT_BOOTSTRAP_ITERS)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "reports" / "snaffler_comparison_ci.json",
    )
    args = parser.parse_args()

    print(f"Loading model from {args.model.name}", file=sys.stderr)
    model = joblib.load(args.model)

    records = _load_records(args.benchmark)
    print(f"Benchmark: {len(records)} records", file=sys.stderr)
    paths = [r["path"] for r in records]
    labels = np.array([1 if r["label"] == "juicy" else 0 for r in records])
    X = featurize(paths)
    probs = model.predict_proba(X)[:, 1]

    print(
        f"Bootstrapping {args.iters} resamples at threshold={args.threshold}...",
        file=sys.stderr,
    )
    boot = _bootstrap(probs, labels, args.threshold, args.iters, args.seed)

    truffler_recall = boot["recall"]
    delta_ci = {
        "point": truffler_recall["point"] - SNAFFLER_RECALL_BASELINE,
        "ci_95_lo": truffler_recall["ci_95_lo"] - SNAFFLER_RECALL_BASELINE,
        "ci_95_hi": truffler_recall["ci_95_hi"] - SNAFFLER_RECALL_BASELINE,
        "note": (
            "Snaffler baseline is a fixed precomputed point estimate "
            "(228/550 = 41.5% on the full 11,190-record labeled queue). "
            "Delta CI = Truffler CI − fixed Snaffler value. The bootstrap "
            "captures only Truffler's sampling variance on the 500-record "
            "benchmark; Snaffler's variance is not modeled."
        ),
    }

    report = {
        "version": "v0.5",
        "generated": "2026-05-31",
        "config": {
            "model": str(args.model.relative_to(REPO_ROOT)),
            "benchmark": str(args.benchmark.relative_to(REPO_ROOT)),
            "n_records": int(len(records)),
            "n_positive": int(labels.sum()),
            "threshold": args.threshold,
            "bootstrap_iters": args.iters,
            "seed": args.seed,
        },
        "snaffler_baseline": {
            "recall": SNAFFLER_RECALL_BASELINE,
            "source": "tools/train_path_classifier.py:SNAFFLER_RECALL_BASELINE — 228/550 on the 11,190-record queue",
            "note": "Point estimate, not bootstrapped; computed from rule-pack-vs-labeled-queue.",
        },
        "truffler_benchmark": boot,
        "delta_vs_snaffler": delta_ci,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(f"\nWrote {args.output.relative_to(REPO_ROOT)}", file=sys.stderr)
    print(file=sys.stderr)
    print("=== HEADLINE TABLE ===", file=sys.stderr)
    print(
        f"Snaffler baseline recall (fixed): {SNAFFLER_RECALL_BASELINE:.3f}",
        file=sys.stderr,
    )
    print(
        f"Truffler benchmark precision @{args.threshold:.2f}: "
        f"{boot['precision']['point']:.3f} "
        f"[95% CI {boot['precision']['ci_95_lo']:.3f} – "
        f"{boot['precision']['ci_95_hi']:.3f}]",
        file=sys.stderr,
    )
    print(
        f"Truffler benchmark recall    @{args.threshold:.2f}: "
        f"{boot['recall']['point']:.3f} "
        f"[95% CI {boot['recall']['ci_95_lo']:.3f} – "
        f"{boot['recall']['ci_95_hi']:.3f}]",
        file=sys.stderr,
    )
    print(
        f"Delta (Truffler − Snaffler):           "
        f"{delta_ci['point']:+.3f} "
        f"[95% CI {delta_ci['ci_95_lo']:+.3f} – "
        f"{delta_ci['ci_95_hi']:+.3f}]",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
