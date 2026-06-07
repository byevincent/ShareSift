"""Path-classifier ablation harness — P1 through P5 + bootstrap CIs.

Trains a family of model variants on the same train split, evaluates each
on the in-distribution test split and on the Snaffler-blind benchmark,
and reports a side-by-side comparison so the architecture/feature/calibration
choices are individually defensible (not just "the whole stack hit 0.97").

Variants
========

* P0_headline           — LightGBM on (n-grams + hand features) + isotonic CV
                          calibration. Matches the shipped model.
* P1_ngrams_only        — char n-grams only, LightGBM, isotonic. Tests whether
                          the 8 hand-engineered features pull weight.
* P2_hand_only          — 8 hand features only, LightGBM, isotonic. Tests
                          whether n-grams pull weight.
* P3_logreg             — logistic regression on the full feature set,
                          isotonic. Tests whether the GBM matters vs a linear
                          baseline.
* P4_uncalibrated       — LightGBM on full features, NO calibration. Tests
                          whether isotonic improves reliability (Brier score).
* P5_platt              — LightGBM on full features, Platt (sigmoid)
                          calibration via 5-fold CV. Tests isotonic vs Platt.

Bootstrap CIs (2.5–97.5 percentile, 1000 resamples) are computed on the
**headline variant only** for PR-AUC, ROC-AUC, and F1@0.5 — gives "Truffler
beats Snaffler by X ± Y" rather than just a point estimate.

Outputs
=======

* ``reports/ablate_path_classifier.json`` — per-variant metrics, headline
  CIs, full config snapshot.
* Console table sorted by benchmark PR-AUC (descending).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

import numpy as np
import scipy.sparse as sp
from lightgbm import LGBMClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sharesift.features import build_vectorizer, hand_features, is_juicy

DEFAULT_TRAIN = REPO_ROOT / "data" / "eval" / "train_split.jsonl"
DEFAULT_TEST = REPO_ROOT / "data" / "eval" / "test_split.jsonl"
DEFAULT_BENCH = REPO_ROOT / "data" / "eval" / "snaffler_blind_benchmark.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "reports" / "ablate_path_classifier.json"

LGBM_BASE_PARAMS = dict(
    n_estimators=300,
    learning_rate=0.05,
    num_leaves=31,
    class_weight="balanced",
    verbose=-1,
)


# --- Data structures -----------------------------------------------------


@dataclass(frozen=True)
class VariantConfig:
    name: str
    description: str
    use_ngrams: bool
    use_hand: bool
    classifier: str  # "lgbm" | "logreg"
    calibration: str  # "none" | "isotonic" | "platt"


VARIANTS: list[VariantConfig] = [
    VariantConfig(
        "P0_headline",
        "LightGBM, n-grams + hand features, isotonic CV calibration (shipped config)",
        use_ngrams=True, use_hand=True, classifier="lgbm", calibration="isotonic",
    ),
    VariantConfig(
        "P1_ngrams_only",
        "LightGBM, n-grams ONLY, isotonic — does the hand-feature block earn weight?",
        use_ngrams=True, use_hand=False, classifier="lgbm", calibration="isotonic",
    ),
    VariantConfig(
        "P2_hand_only",
        "LightGBM, hand features ONLY (8 dense floats), isotonic — do n-grams earn weight?",
        use_ngrams=False, use_hand=True, classifier="lgbm", calibration="isotonic",
    ),
    VariantConfig(
        "P3_logreg",
        "Logistic regression on full features, isotonic — does GBM beat a linear baseline?",
        use_ngrams=True, use_hand=True, classifier="logreg", calibration="isotonic",
    ),
    VariantConfig(
        "P4_uncalibrated",
        "LightGBM on full features, NO calibration — does isotonic improve reliability?",
        use_ngrams=True, use_hand=True, classifier="lgbm", calibration="none",
    ),
    VariantConfig(
        "P5_platt",
        "LightGBM on full features, Platt (sigmoid) calibration — isotonic vs Platt?",
        use_ngrams=True, use_hand=True, classifier="lgbm", calibration="platt",
    ),
]


@dataclass
class VariantResult:
    name: str
    description: str
    config: dict
    train_seconds: float
    test_metrics: dict
    bench_metrics: dict


# --- Featurization -------------------------------------------------------


def make_featurizer(use_ngrams: bool, use_hand: bool):
    """Return a callable ``paths -> sparse csr_matrix`` for this variant."""
    if not use_ngrams and not use_hand:
        raise ValueError("at least one feature family must be enabled")
    vec = build_vectorizer() if use_ngrams else None

    def featurize(paths: list[str]) -> sp.csr_matrix:
        parts: list[sp.spmatrix] = []
        if vec is not None:
            parts.append(vec.transform(paths))
        if use_hand:
            hand_X = np.vstack([hand_features(p) for p in paths])
            parts.append(sp.csr_matrix(hand_X))
        if len(parts) == 1:
            return parts[0].tocsr()
        return sp.hstack(parts).tocsr()

    return featurize


# --- Classifier construction ---------------------------------------------


def make_base_classifier(kind: str, seed: int):
    if kind == "lgbm":
        return LGBMClassifier(**LGBM_BASE_PARAMS, random_state=seed)
    if kind == "logreg":
        return LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            random_state=seed,
            n_jobs=-1,
            solver="liblinear",  # handles sparse + L2 fine, stable on small N
        )
    raise ValueError(f"unknown classifier kind: {kind}")


def train_variant(
    variant: VariantConfig,
    X_train: sp.csr_matrix,
    y_train: np.ndarray,
    seed: int,
):
    base = make_base_classifier(variant.classifier, seed)
    if variant.calibration == "none":
        base.fit(X_train, y_train)
        return base
    method = "isotonic" if variant.calibration == "isotonic" else "sigmoid"
    cal = CalibratedClassifierCV(base, method=method, cv=5)
    cal.fit(X_train, y_train)
    return cal


# --- Metrics + bootstrap -------------------------------------------------


def compute_metrics(
    y: np.ndarray, probs: np.ndarray, fixed_threshold: float = 0.5
) -> dict:
    pr_auc = float(average_precision_score(y, probs))
    roc_auc = float(roc_auc_score(y, probs))
    brier = float(brier_score_loss(y, probs))

    precision, recall, thresholds = precision_recall_curve(y, probs)
    f1 = 2 * precision * recall / (precision + recall + 1e-9)
    best_idx = int(np.argmax(f1))
    best_threshold = float(thresholds[best_idx]) if best_idx < len(thresholds) else 1.0

    fixed_preds = (probs >= fixed_threshold).astype(np.int32)
    fixed_p = float(precision_score(y, fixed_preds, zero_division=0))
    fixed_r = float(recall_score(y, fixed_preds, zero_division=0))
    fixed_f1 = float(f1_score(y, fixed_preds, zero_division=0))

    return {
        "n_records": int(len(y)),
        "n_positive": int(y.sum()),
        "pr_auc": pr_auc,
        "roc_auc": roc_auc,
        "brier_score": brier,
        "best_f1": float(f1[best_idx]),
        "best_threshold": best_threshold,
        "best_precision": float(precision[best_idx]),
        "best_recall": float(recall[best_idx]),
        "fixed_precision_at_0p5": fixed_p,
        "fixed_recall_at_0p5": fixed_r,
        "fixed_f1_at_0p5": fixed_f1,
    }


def bootstrap_ci(
    y: np.ndarray,
    probs: np.ndarray,
    metric_name: str,
    metric_fn,
    n_iter: int = 1000,
    seed: int = 2026,
) -> dict:
    rng = np.random.RandomState(seed)
    n = len(y)
    samples = np.empty(n_iter, dtype=np.float64)
    valid = 0
    for i in range(n_iter):
        idx = rng.choice(n, size=n, replace=True)
        try:
            samples[valid] = metric_fn(y[idx], probs[idx])
            valid += 1
        except (ValueError, ZeroDivisionError):
            continue
    samples = samples[:valid]
    return {
        "metric": metric_name,
        "n_resamples": valid,
        "point_estimate": float(metric_fn(y, probs)),
        "mean": float(samples.mean()),
        "std": float(samples.std()),
        "ci_low_2p5": float(np.percentile(samples, 2.5)),
        "ci_high_97p5": float(np.percentile(samples, 97.5)),
    }


def f1_at_0p5(y, probs) -> float:
    return float(f1_score(y, (probs >= 0.5).astype(np.int32), zero_division=0))


# --- I/O -----------------------------------------------------------------


def load_records(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# --- Main ----------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--train", type=Path, default=DEFAULT_TRAIN)
    p.add_argument("--test", type=Path, default=DEFAULT_TEST)
    p.add_argument("--bench", type=Path, default=DEFAULT_BENCH)
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    p.add_argument("--seed", type=int, default=2026)
    p.add_argument(
        "--bootstrap-iters",
        type=int,
        default=1000,
        help="Number of bootstrap resamples for headline-variant CIs.",
    )
    p.add_argument(
        "--variants",
        nargs="+",
        default=None,
        help="Variant names to run (default: all).",
    )
    args = p.parse_args(argv)

    print("Loading data...", file=sys.stderr)
    train_records = load_records(args.train)
    test_records = load_records(args.test)
    bench_records = load_records(args.bench)
    print(
        f"  train={len(train_records)}, test={len(test_records)}, "
        f"bench={len(bench_records)}",
        file=sys.stderr,
    )

    train_paths = [r["path"] for r in train_records]
    test_paths = [r["path"] for r in test_records]
    bench_paths = [r["path"] for r in bench_records]
    y_train = np.array([1 if is_juicy(r) else 0 for r in train_records], dtype=np.int32)
    y_test = np.array([1 if is_juicy(r) else 0 for r in test_records], dtype=np.int32)
    y_bench = np.array([1 if is_juicy(r) else 0 for r in bench_records], dtype=np.int32)

    requested = set(args.variants) if args.variants else None
    selected = [v for v in VARIANTS if requested is None or v.name in requested]
    if requested and not selected:
        print(f"ERROR: no variants matched {requested}", file=sys.stderr)
        return 2

    results: list[VariantResult] = []
    headline_result: dict | None = None

    for variant in selected:
        print(f"\n--- {variant.name} ---", file=sys.stderr)
        print(f"  {variant.description}", file=sys.stderr)

        featurize = make_featurizer(variant.use_ngrams, variant.use_hand)
        X_train = featurize(train_paths)
        X_test = featurize(test_paths)
        X_bench = featurize(bench_paths)
        print(
            f"  feature matrix: train shape={X_train.shape}, "
            f"nnz={X_train.nnz}",
            file=sys.stderr,
        )

        t0 = time.time()
        try:
            model = train_variant(variant, X_train, y_train, args.seed)
        except Exception as e:
            print(f"  TRAIN FAILED: {type(e).__name__}: {e}", file=sys.stderr)
            continue
        train_seconds = time.time() - t0
        print(f"  trained in {train_seconds:.1f}s", file=sys.stderr)

        probs_test = model.predict_proba(X_test)[:, 1]
        probs_bench = model.predict_proba(X_bench)[:, 1]
        test_metrics = compute_metrics(y_test, probs_test)
        bench_metrics = compute_metrics(y_bench, probs_bench)

        print(
            f"  test  PR-AUC={test_metrics['pr_auc']:.4f}  "
            f"F1@0.5={test_metrics['fixed_f1_at_0p5']:.4f}  "
            f"Brier={test_metrics['brier_score']:.4f}",
            file=sys.stderr,
        )
        print(
            f"  bench PR-AUC={bench_metrics['pr_auc']:.4f}  "
            f"F1@0.5={bench_metrics['fixed_f1_at_0p5']:.4f}  "
            f"Brier={bench_metrics['brier_score']:.4f}",
            file=sys.stderr,
        )

        results.append(
            VariantResult(
                name=variant.name,
                description=variant.description,
                config={
                    "use_ngrams": variant.use_ngrams,
                    "use_hand": variant.use_hand,
                    "classifier": variant.classifier,
                    "calibration": variant.calibration,
                },
                train_seconds=train_seconds,
                test_metrics=test_metrics,
                bench_metrics=bench_metrics,
            )
        )

        if variant.name == "P0_headline":
            print("  computing bootstrap CIs on headline...", file=sys.stderr)
            t0 = time.time()
            headline_result = {
                "test": {
                    "pr_auc": bootstrap_ci(
                        y_test, probs_test, "pr_auc",
                        average_precision_score,
                        n_iter=args.bootstrap_iters, seed=args.seed,
                    ),
                    "roc_auc": bootstrap_ci(
                        y_test, probs_test, "roc_auc",
                        roc_auc_score,
                        n_iter=args.bootstrap_iters, seed=args.seed,
                    ),
                    "f1_at_0p5": bootstrap_ci(
                        y_test, probs_test, "f1_at_0p5",
                        f1_at_0p5,
                        n_iter=args.bootstrap_iters, seed=args.seed,
                    ),
                },
                "bench": {
                    "pr_auc": bootstrap_ci(
                        y_bench, probs_bench, "pr_auc",
                        average_precision_score,
                        n_iter=args.bootstrap_iters, seed=args.seed,
                    ),
                    "roc_auc": bootstrap_ci(
                        y_bench, probs_bench, "roc_auc",
                        roc_auc_score,
                        n_iter=args.bootstrap_iters, seed=args.seed,
                    ),
                    "f1_at_0p5": bootstrap_ci(
                        y_bench, probs_bench, "f1_at_0p5",
                        f1_at_0p5,
                        n_iter=args.bootstrap_iters, seed=args.seed,
                    ),
                },
            }
            print(f"  bootstrap done in {time.time() - t0:.1f}s", file=sys.stderr)

    # --- Report ---
    print()
    print("=" * 100)
    print("PATH-CLASSIFIER ABLATION RESULTS  (sorted by bench PR-AUC desc)")
    print("=" * 100)
    print(
        f"{'variant':<22}  "
        f"{'bench_PR_AUC':>13}  {'bench_F1@.5':>12}  {'bench_Brier':>12}  "
        f"{'test_PR_AUC':>12}  {'test_F1@.5':>11}"
    )
    print("-" * 100)
    for r in sorted(results, key=lambda r: -r.bench_metrics["pr_auc"]):
        print(
            f"{r.name:<22}  "
            f"{r.bench_metrics['pr_auc']:>13.4f}  "
            f"{r.bench_metrics['fixed_f1_at_0p5']:>12.4f}  "
            f"{r.bench_metrics['brier_score']:>12.4f}  "
            f"{r.test_metrics['pr_auc']:>12.4f}  "
            f"{r.test_metrics['fixed_f1_at_0p5']:>11.4f}"
        )
    print("=" * 100)

    if headline_result:
        print("\nHeadline (P0) bootstrap 95% CIs:")
        for split_name, split_cis in headline_result.items():
            for metric, ci in split_cis.items():
                print(
                    f"  {split_name} {metric}: "
                    f"{ci['point_estimate']:.4f} "
                    f"[{ci['ci_low_2p5']:.4f}, {ci['ci_high_97p5']:.4f}]  "
                    f"(mean={ci['mean']:.4f}, std={ci['std']:.4f})"
                )

    payload = {
        "config": {
            "train": str(args.train.relative_to(REPO_ROOT)),
            "test": str(args.test.relative_to(REPO_ROOT)),
            "bench": str(args.bench.relative_to(REPO_ROOT)),
            "seed": args.seed,
            "bootstrap_iters": args.bootstrap_iters,
            "lgbm_params": LGBM_BASE_PARAMS,
        },
        "variants": [asdict(r) for r in results],
        "headline_bootstrap_ci": headline_result,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2))
    print(f"\nReport written to {args.output.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
