"""Held-out-by-source eval: train on one source, test on another.

Tier-1 audit item from the 2026-05-31 v0.5 research pass. The labeled
corpus is overwhelmingly Stack Exchange (Windows: 94% SE / 6% GH;
Linux: 89% GH / 11% seed). The standard random train/test split mixes
sources within each fold, so in-distribution metrics don't tell you
how the model generalizes from one corpus shape to another. This tool
trains on one source and evaluates on the other (both directions where
data volume permits), surfacing the cross-distribution generalization
gap.

Directions evaluated:
* Windows: SE-only train → GH eval (and GH → SE)
* Linux: GH-only train → seed eval (and seed → GH where viable)

Compares per-direction metrics to the existing in-distribution
baseline (path classifier headline numbers).
"""

from __future__ import annotations

import argparse
import json
import sys
import warnings
from pathlib import Path

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


def _train_lgbm(paths_train: list[str], labels_train: np.ndarray, seed: int):
    import lightgbm as lgb

    X = featurize(paths_train)
    clf = lgb.LGBMClassifier(
        n_estimators=300,
        learning_rate=0.05,
        num_leaves=31,
        class_weight="balanced",
        verbose=-1,
        random_state=seed,
    )
    clf.fit(X, labels_train)
    return clf


def _eval(model, paths: list[str], labels: np.ndarray) -> dict:
    from sklearn.metrics import precision_recall_curve, roc_auc_score, average_precision_score

    X = featurize(paths)
    probs = model.predict_proba(X)[:, 1]

    if labels.sum() == 0 or (labels == 0).sum() == 0:
        return {"error": "single-class eval set", "n": int(len(labels))}

    pr_auc = float(average_precision_score(labels, probs))
    roc_auc = float(roc_auc_score(labels, probs))

    p, r, t = precision_recall_curve(labels, probs)
    # best F1 (excluding the trailing point with no threshold)
    f1 = 2 * p[:-1] * r[:-1] / (p[:-1] + r[:-1] + 1e-12)
    best_idx = int(f1.argmax())

    # @0.5 standard threshold
    pred_at_05 = probs >= 0.5
    n_flagged = int(pred_at_05.sum())
    n_tp = int(((pred_at_05) & (labels == 1)).sum())
    p_at_05 = (n_tp / n_flagged) if n_flagged else 0.0
    r_at_05 = n_tp / int(labels.sum())
    f1_at_05 = 2 * p_at_05 * r_at_05 / (p_at_05 + r_at_05 + 1e-12)

    return {
        "n": int(len(labels)),
        "n_positive": int(labels.sum()),
        "pr_auc": pr_auc,
        "roc_auc": roc_auc,
        "best_f1": float(f1[best_idx]),
        "best_f1_threshold": float(t[best_idx]),
        "best_f1_precision": float(p[best_idx]),
        "best_f1_recall": float(r[best_idx]),
        "at_0.5_precision": p_at_05,
        "at_0.5_recall": r_at_05,
        "at_0.5_f1": f1_at_05,
    }


def _filter_by_source(records: list[dict], sources: set[str]) -> list[dict]:
    return [r for r in records if r.get("source") in sources]


def _run_direction(
    train_records: list[dict],
    test_records: list[dict],
    direction_label: str,
    seed: int,
) -> dict:
    train_paths = [r["path"] for r in train_records]
    train_labels = np.array([1 if r["label"] == "juicy" else 0 for r in train_records])
    test_paths = [r["path"] for r in test_records]
    test_labels = np.array([1 if r["label"] == "juicy" else 0 for r in test_records])

    print(
        f"  {direction_label}: train n={len(train_records)} "
        f"({int(train_labels.sum())} juicy), "
        f"test n={len(test_records)} ({int(test_labels.sum())} juicy)",
        file=sys.stderr,
    )
    if train_labels.sum() == 0 or (train_labels == 0).sum() == 0:
        return {"error": "single-class train set", "direction": direction_label}
    model = _train_lgbm(train_paths, train_labels, seed)
    metrics = _eval(model, test_paths, test_labels)
    return {
        "direction": direction_label,
        "train_n": int(len(train_records)),
        "train_n_positive": int(train_labels.sum()),
        "test_n": int(len(test_records)),
        "test_n_positive": int(test_labels.sum()),
        **metrics,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--windows-labeled",
        type=Path,
        default=REPO_ROOT / "data" / "eval" / "eval_set_claude.jsonl",
    )
    parser.add_argument(
        "--linux-labeled",
        type=Path,
        default=REPO_ROOT / "data" / "eval" / "eval_set_claude_linux_with_seed.jsonl",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "reports" / "cross_source_eval.json",
    )
    parser.add_argument("--seed", type=int, default=2026)
    args = parser.parse_args()

    windows = _load_records(args.windows_labeled)
    linux = _load_records(args.linux_labeled)
    print(f"Windows corpus: {len(windows)} records", file=sys.stderr)
    print(f"Linux corpus:   {len(linux)} records", file=sys.stderr)

    results: dict = {
        "version": "v0.5",
        "generated": "2026-05-31",
        "windows": [],
        "linux": [],
    }

    print("\n=== Windows cross-source ===", file=sys.stderr)
    win_se = _filter_by_source(windows, {"stackexchange"})
    win_gh = _filter_by_source(windows, {"github_search"})
    results["windows"].append(
        _run_direction(win_se, win_gh, "train=SE_test=GH", args.seed)
    )
    results["windows"].append(
        _run_direction(win_gh, win_se, "train=GH_test=SE", args.seed)
    )

    print("\n=== Linux cross-source ===", file=sys.stderr)
    lnx_gh = _filter_by_source(linux, {"github_search"})
    lnx_seed = _filter_by_source(linux, {"seed"})
    results["linux"].append(
        _run_direction(lnx_gh, lnx_seed, "train=GH_test=seed", args.seed)
    )
    results["linux"].append(
        _run_direction(lnx_seed, lnx_gh, "train=seed_test=GH", args.seed)
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    print(f"\nWrote {args.output.relative_to(REPO_ROOT)}", file=sys.stderr)
    print("\n=== HEADLINE TABLE ===", file=sys.stderr)
    print(
        f"{'corpus':10s}  {'direction':25s}  {'train_n':>7s}  {'test_n':>6s}  "
        f"{'PR-AUC':>7s}  {'F1@0.5':>7s}  {'P@0.5':>6s}  {'R@0.5':>6s}",
        file=sys.stderr,
    )
    for corpus in ("windows", "linux"):
        for r in results[corpus]:
            if "error" in r:
                print(f"  {r['direction']}: {r['error']}", file=sys.stderr)
                continue
            print(
                f"{corpus:10s}  {r['direction']:25s}  {r['train_n']:7d}  "
                f"{r['test_n']:6d}  {r['pr_auc']:.4f}  "
                f"{r['at_0.5_f1']:.4f}  {r['at_0.5_precision']:.4f}  "
                f"{r['at_0.5_recall']:.4f}",
                file=sys.stderr,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
