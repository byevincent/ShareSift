"""Estimate label noise rate on path-classifier training data via cleanlab.

Tier-1 audit item from the 2026-05-31 v0.5 research pass. The README
calls out that Truffler's labels are LLM-rule-based, not engagement-
grade, so a noise-rate estimate is the central epistemological number
the project has been missing.

Method: cross-validated out-of-fold predictions on the FULL labeled
corpus (train + test, since cleanlab estimates noise on whatever
labels you give it, not just train), then ``cleanlab.dataset.
health_summary`` for per-class label-issue estimates and the
``cleanlab.count.estimate_joint`` confidence-weighted joint
distribution.

Output for each model (Windows + Linux):

* Estimated noise rate per class (label_noise_estimate)
* Top-N records cleanlab thinks are mislabeled (high-suspicion list)
* Per-class confident joint distribution
* Overall data-quality score

Content classifier deferred to a separate run — each CV fold would
require retraining the LoRA (~10-15 min × 5 folds), which is too slow
for a sprint.
"""

from __future__ import annotations

import argparse
import json
import sys
import warnings
from pathlib import Path

import numpy as np

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning, module="cleanlab")

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sharesift.features import featurize  # noqa: E402


def _load_records(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _cv_predictions(
    paths: list[str],
    labels: np.ndarray,
    n_folds: int = 5,
    seed: int = 2026,
) -> np.ndarray:
    """Out-of-fold predictions via 5-fold CV with LightGBM. Returns
    (N, 2) probability matrix aligned with input order."""
    from sklearn.model_selection import StratifiedKFold

    import lightgbm as lgb

    X = featurize(paths)
    pred_probs = np.zeros((len(labels), 2))
    skf = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=seed)
    for fold_idx, (train_idx, val_idx) in enumerate(skf.split(np.zeros(len(labels)), labels), start=1):
        print(f"  fold {fold_idx}/{n_folds}", file=sys.stderr)
        clf = lgb.LGBMClassifier(
            n_estimators=300,
            learning_rate=0.05,
            num_leaves=31,
            class_weight="balanced",
            verbose=-1,
            random_state=seed,
        )
        clf.fit(X[train_idx], labels[train_idx])
        pred_probs[val_idx] = clf.predict_proba(X[val_idx])
    return pred_probs


def _audit_model(
    labeled_path: Path, model_name: str, n_folds: int, seed: int, top_n: int
) -> dict:
    print(f"\n=== {model_name} ===", file=sys.stderr)
    records = _load_records(labeled_path)
    print(f"  records: {len(records)}", file=sys.stderr)
    paths = [r["path"] for r in records]
    labels = np.array([1 if r["label"] == "juicy" else 0 for r in records])

    print("  computing cross-validated predictions...", file=sys.stderr)
    pred_probs = _cv_predictions(paths, labels, n_folds=n_folds, seed=seed)

    print("  estimating noise via cleanlab...", file=sys.stderr)
    from cleanlab.filter import find_label_issues
    from cleanlab.count import (
        estimate_joint,
        estimate_latent,
        compute_confident_joint,
    )

    confident_joint = compute_confident_joint(labels=labels, pred_probs=pred_probs)
    joint = estimate_joint(
        labels=labels, pred_probs=pred_probs, confident_joint=confident_joint
    )
    # cleanlab.count.estimate_latent returns (py, noise_matrix, inv_noise_matrix)
    py, noise_matrix, inv_noise_matrix = estimate_latent(
        confident_joint=confident_joint, labels=labels
    )

    # Per-class noise: noise_matrix[i, j] = P(noisy label = i | true label = j).
    # Off-diagonal entries are the noise rate per direction.
    label_issues = find_label_issues(
        labels=labels,
        pred_probs=pred_probs,
        return_indices_ranked_by="self_confidence",
    )
    issue_count = int(len(label_issues))

    # Top-N records cleanlab thinks are mislabeled (lowest self-confidence first).
    suspicions = []
    for rank, idx in enumerate(label_issues[:top_n], start=1):
        suspicions.append(
            {
                "rank": rank,
                "path": records[idx]["path"],
                "current_label": records[idx]["label"],
                "current_tier": records[idx].get("tier"),
                "current_category": records[idx].get("category"),
                "p_juicy_cv": float(pred_probs[idx, 1]),
            }
        )

    return {
        "model": model_name,
        "labeled_path": str(labeled_path.relative_to(REPO_ROOT)),
        "n_records": int(len(records)),
        "n_juicy": int(labels.sum()),
        "n_not_juicy": int((labels == 0).sum()),
        "n_folds_cv": n_folds,
        "label_issues": {
            "n_flagged": issue_count,
            "fraction_of_corpus": float(issue_count / len(records)),
        },
        "noise_matrix_rows": [
            "[noisy=not_juicy | true=not_juicy, noisy=not_juicy | true=juicy]",
            "[noisy=juicy     | true=not_juicy, noisy=juicy     | true=juicy]",
        ],
        "noise_matrix": noise_matrix.tolist(),
        "estimated_class_prior_py": py.tolist(),
        "joint_distribution_rows": [
            "[joint(noisy=not_juicy, true=not_juicy), joint(noisy=not_juicy, true=juicy)]",
            "[joint(noisy=juicy,     true=not_juicy), joint(noisy=juicy,     true=juicy)]",
        ],
        "joint_distribution": joint.tolist(),
        "top_suspect_mislabels": suspicions,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--windows-labeled",
        type=Path,
        default=REPO_ROOT / "data" / "eval" / "eval_set_claude.jsonl",
        help="Windows labeled corpus.",
    )
    parser.add_argument(
        "--linux-labeled",
        type=Path,
        default=REPO_ROOT / "data" / "eval" / "eval_set_claude_linux_with_seed.jsonl",
        help="Linux labeled corpus including seed + hardneg.",
    )
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument(
        "--top-n",
        type=int,
        default=20,
        help="Number of top-suspect mislabels to surface per model.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "reports" / "label_noise_audit.json",
    )
    args = parser.parse_args()

    audits = []
    audits.append(_audit_model(args.windows_labeled, "windows", args.folds, args.seed, args.top_n))
    audits.append(_audit_model(args.linux_labeled, "linux", args.folds, args.seed, args.top_n))

    report = {
        "version": "v0.5",
        "generated": "2026-05-31",
        "method": (
            "5-fold stratified CV with LightGBM; cleanlab.filter."
            "find_label_issues + cleanlab.count.estimate_latent for "
            "per-class noise matrix."
        ),
        "audits": audits,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"\nWrote {args.output.relative_to(REPO_ROOT)}", file=sys.stderr)

    # Headline summary
    print("\n=== HEADLINE NOISE TABLE ===", file=sys.stderr)
    print(
        f"{'model':10s}  {'n':>5s}  {'%juicy':>7s}  {'issues':>7s}  {'%issues':>8s}  noise_matrix_diag",
        file=sys.stderr,
    )
    for a in audits:
        nm = a["noise_matrix"]
        diag = f"[{nm[0][0]:.3f}, {nm[1][1]:.3f}]"
        print(
            f"{a['model']:10s}  {a['n_records']:5d}  "
            f"{100 * a['n_juicy'] / a['n_records']:6.1f}%  "
            f"{a['label_issues']['n_flagged']:7d}  "
            f"{100 * a['label_issues']['fraction_of_corpus']:7.1f}%  "
            f"{diag}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
