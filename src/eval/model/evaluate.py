"""Evaluation metrics for the path classifier.

Computes PR-AUC (the primary phase-2 success metric), F1-optimal threshold,
and precision/recall at that threshold. Also breaks down performance by
the ShareSift category so rare-category gaps surface explicitly.

Per ``docs/build_plan.md`` Phase 2, the v0 success criterion is
**PR-AUC ≥ 0.90 on the Snaffler-blind benchmark**. Hitting that means we
ship the LightGBM baseline; missing means we escalate to MiniLM/DistilBERT.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    precision_recall_curve,
    roc_auc_score,
)

from sharesift.features import featurize, is_juicy


@dataclass(frozen=True)
class EvalReport:
    n_records: int
    n_juicy: int
    n_not_juicy: int
    pr_auc: float
    roc_auc: float
    best_f1: float
    best_threshold: float
    best_precision: float
    best_recall: float
    # threshold=0.5 fixed baseline
    fixed_precision: float
    fixed_recall: float
    fixed_f1: float
    # Per-category recall on juicy records (catches "model is blind to
    # category X" failures that overall metrics hide).
    per_category_recall: dict[str, tuple[int, int]]  # cat -> (correct, total)


def evaluate(
    model,
    records: list[dict],
    fixed_threshold: float = 0.5,
) -> EvalReport:
    paths = [r["path"] for r in records]
    y = np.array([1 if is_juicy(r) else 0 for r in records], dtype=np.int32)
    X = featurize(paths)
    probs = model.predict_proba(X)[:, 1]

    pr_auc = float(average_precision_score(y, probs))
    roc_auc = float(roc_auc_score(y, probs))

    precision, recall, thresholds = precision_recall_curve(y, probs)
    # F1 at every threshold; best-F1 wins.
    f1 = 2 * precision * recall / (precision + recall + 1e-9)
    best_idx = int(np.argmax(f1))
    best_threshold = (
        float(thresholds[best_idx]) if best_idx < len(thresholds) else 1.0
    )

    fixed_preds = (probs >= fixed_threshold).astype(np.int32)
    tp = int(((fixed_preds == 1) & (y == 1)).sum())
    fp = int(((fixed_preds == 1) & (y == 0)).sum())
    fn = int(((fixed_preds == 0) & (y == 1)).sum())
    fixed_precision = tp / max(tp + fp, 1)
    fixed_recall = tp / max(tp + fn, 1)
    fixed_f1 = (
        2 * fixed_precision * fixed_recall / max(fixed_precision + fixed_recall, 1e-9)
    )

    per_cat: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for rec, prob in zip(records, probs):
        if not is_juicy(rec):
            continue
        cat = rec.get("category") or rec.get("category_hint") or "uncategorized"
        per_cat[cat][1] += 1
        if prob >= fixed_threshold:
            per_cat[cat][0] += 1

    return EvalReport(
        n_records=len(records),
        n_juicy=int(y.sum()),
        n_not_juicy=int((y == 0).sum()),
        pr_auc=pr_auc,
        roc_auc=roc_auc,
        best_f1=float(f1[best_idx]),
        best_threshold=best_threshold,
        best_precision=float(precision[best_idx]),
        best_recall=float(recall[best_idx]),
        fixed_precision=fixed_precision,
        fixed_recall=fixed_recall,
        fixed_f1=fixed_f1,
        per_category_recall={k: (v[0], v[1]) for k, v in per_cat.items()},
    )


def format_report(name: str, report: EvalReport) -> str:
    lines = [
        f"\n=== {name} ===",
        f"  records: {report.n_records} "
        f"({report.n_juicy} juicy / {report.n_not_juicy} not_juicy)",
        f"  PR-AUC:  {report.pr_auc:.4f}    ROC-AUC: {report.roc_auc:.4f}",
        f"  best F1: {report.best_f1:.4f} "
        f"at threshold={report.best_threshold:.3f}",
        f"           precision={report.best_precision:.4f}  "
        f"recall={report.best_recall:.4f}",
        f"  @0.5  :  precision={report.fixed_precision:.4f}  "
        f"recall={report.fixed_recall:.4f}  F1={report.fixed_f1:.4f}",
    ]
    if report.per_category_recall:
        lines.append("  per-category recall on juicy (@0.5):")
        for cat in sorted(report.per_category_recall, key=lambda c: -report.per_category_recall[c][1]):
            correct, total = report.per_category_recall[cat]
            pct = 100 * correct / total if total else 0
            lines.append(f"    {cat:32s} {correct:4d}/{total:<4d} ({pct:5.1f}%)")
    return "\n".join(lines)
