"""Compute precision-at-base-rate from any existing confusion matrix.

The TP-rate (recall) and FP-rate (1-specificity) from a single eval
are base-rate-independent: they characterize the model's classification
behavior, not the dataset's positive frequency. For any target
base rate p ∈ (0, 1), we can recompute precision analytically:

    precision(p) = (p × TPR) / (p × TPR + (1 - p) × FPR)

This lets us report "precision at 1:1000 share-realistic positive
rate" without needing a 1-million-record benchmark to actually measure
it. The recall + accuracy at the eval base rate stay as the empirical
characterization.

Reads ``reports/eval_content_classifier.json`` and emits a markdown-
friendly table of precision at base rates {1:10, 1:100, 1:1000} for
the v0.8 docx-corpus runs.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _rates(entry: dict) -> tuple[float, float, int, int]:
    """Return (TPR, FPR, P_count, N_count) from an eval JSON entry."""
    c = entry["confusion"]
    tp, fp, fn, tn = c["tp"], c["fp"], c["fn"], c["tn"]
    p_count = tp + fn
    n_count = fp + tn
    tpr = tp / max(1, p_count)
    fpr = fp / max(1, n_count)
    return tpr, fpr, p_count, n_count


def _precision_at(tpr: float, fpr: float, base_rate: float) -> float:
    num = base_rate * tpr
    den = base_rate * tpr + (1.0 - base_rate) * fpr
    if den <= 0:
        return 0.0
    return num / den


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "--results",
        type=Path,
        default=REPO_ROOT / "reports" / "eval_content_classifier.json",
    )
    p.add_argument(
        "--labels",
        nargs="+",
        default=[
            "v0p3_on_docx_salted_10",
            "v0p4_on_docx_salted_10",
            "v0p5_on_docx_salted_10",
        ],
    )
    args = p.parse_args(argv)

    r = json.loads(args.results.read_text())

    base_rates = [(0.1, "1:10"), (0.01, "1:100"), (0.001, "1:1000")]
    print(
        "\n| Model | TPR (recall) | FPR | F1@1:10 | Prec @1:100 | Prec @1:1000 |"
    )
    print(
        "|---|---|---|---|---|---|"
    )
    for label in args.labels:
        entry = r.get(label)
        if entry is None:
            print(f"| {label} | (not run) | | | | |")
            continue
        tpr, fpr, npos, nneg = _rates(entry)
        m = entry["metrics"]
        precs = [_precision_at(tpr, fpr, br) for br, _ in base_rates]
        print(
            f"| {label} | "
            f"{tpr:.3f} | {fpr:.3f} | {m['f1']:.3f} | "
            f"{precs[1]:.3f} | {precs[2]:.4f} |"
        )

    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
