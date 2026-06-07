"""Path-classifier multi-seed variance characterization (P6).

Trains two configurations N times across different random seeds and
reports per-seed metrics + aggregate stats per config:

* ``deterministic`` — the shipped config. LightGBM with no row/feature
  subsampling (the defaults). Should produce identical numbers across
  seeds; non-zero variance here would indicate something is wrong.

* ``stochastic`` — same hyperparams BUT with ``bagging_fraction=0.8``,
  ``feature_fraction=0.8``, ``bagging_freq=1``. Injects stochasticity into
  the tree-building so seed actually matters. Tells us:
  (a) what fitting-variance looks like for a stochastic version of this
      model (model-uncertainty signal, complements the test-set bootstrap
      CIs from ``ablate_path_classifier.py``);
  (b) whether stochastic training would beat the deterministic shipped
      config on PR-AUC.

Notes
=====

CalibratedClassifierCV's internal StratifiedKFold split is deterministic
(no shuffle), so changing ``--seed`` only changes the LightGBM base model
sampling. This is intentional — the goal is to characterize variance from
model fitting, not from data partitioning.

Output
======

* ``reports/ablate_path_seeds.json`` — per-(config, seed) metrics, aggregates
* Console table — one row per (config, seed), plus aggregate block.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import scipy.sparse as sp
from lightgbm import LGBMClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    f1_score,
    precision_recall_curve,
    roc_auc_score,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sharesift.features import build_vectorizer, hand_features, is_juicy

DEFAULT_TRAIN = REPO_ROOT / "data" / "eval" / "train_split.jsonl"
DEFAULT_TEST = REPO_ROOT / "data" / "eval" / "test_split.jsonl"
DEFAULT_BENCH = REPO_ROOT / "data" / "eval" / "snaffler_blind_benchmark.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "reports" / "ablate_path_seeds.json"

LGBM_BASE_PARAMS = dict(
    n_estimators=300,
    learning_rate=0.05,
    num_leaves=31,
    class_weight="balanced",
    verbose=-1,
)

# Per-config LGBM overrides on top of LGBM_BASE_PARAMS. ``deterministic`` is
# empty — the defaults already disable bagging and feature subsampling, so
# seed has no effect. ``stochastic`` enables row + column sampling with the
# seed plumbed through bagging_seed / feature_fraction_seed so the seed
# actually matters.
CONFIGS: dict[str, dict] = {
    "deterministic": {},
    "stochastic": {
        "bagging_fraction": 0.8,
        "feature_fraction": 0.8,
        "bagging_freq": 1,
    },
}


# --- Helpers --------------------------------------------------------------


def load_records(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def featurize(paths: list[str], vec) -> sp.csr_matrix:
    char_X = vec.transform(paths)
    hand_X = np.vstack([hand_features(p) for p in paths])
    return sp.hstack([char_X, sp.csr_matrix(hand_X)]).tocsr()


def train_headline(X_train, y_train, seed: int, config_overrides: dict):
    # Plumb seed through every randomness knob LightGBM exposes so the
    # stochastic config actually varies per seed.
    params = {
        **LGBM_BASE_PARAMS,
        **config_overrides,
        "random_state": seed,
        "bagging_seed": seed,
        "feature_fraction_seed": seed,
    }
    base = LGBMClassifier(**params)
    cal = CalibratedClassifierCV(base, method="isotonic", cv=5)
    cal.fit(X_train, y_train)
    return cal


def compute_metrics(y, probs, fixed_threshold: float = 0.5) -> dict:
    pr_auc = float(average_precision_score(y, probs))
    roc_auc = float(roc_auc_score(y, probs))
    brier = float(brier_score_loss(y, probs))

    precision, recall, thresholds = precision_recall_curve(y, probs)
    f1 = 2 * precision * recall / (precision + recall + 1e-9)
    best_idx = int(np.argmax(f1))

    fixed_preds = (probs >= fixed_threshold).astype(np.int32)
    fixed_f1 = float(f1_score(y, fixed_preds, zero_division=0))

    return {
        "pr_auc": pr_auc,
        "roc_auc": roc_auc,
        "brier_score": brier,
        "best_f1": float(f1[best_idx]),
        "fixed_f1_at_0p5": fixed_f1,
    }


def aggregate(per_seed: list[dict], metric_keys: list[str]) -> dict:
    out: dict = {}
    for key in metric_keys:
        vals = np.array([s[key] for s in per_seed], dtype=np.float64)
        out[key] = {
            "mean": float(vals.mean()),
            "std": float(vals.std(ddof=1)) if len(vals) > 1 else 0.0,
            "min": float(vals.min()),
            "max": float(vals.max()),
            "n_seeds": int(len(vals)),
        }
    return out


# --- Main -----------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--train", type=Path, default=DEFAULT_TRAIN)
    p.add_argument("--test", type=Path, default=DEFAULT_TEST)
    p.add_argument("--bench", type=Path, default=DEFAULT_BENCH)
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    p.add_argument(
        "--seeds",
        type=int,
        nargs="+",
        default=[2026, 8472, 31337, 42, 1729],
        help="Random seeds to run. Default: 5 mixed-source seeds.",
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

    vec = build_vectorizer()
    X_train = featurize([r["path"] for r in train_records], vec)
    X_test = featurize([r["path"] for r in test_records], vec)
    X_bench = featurize([r["path"] for r in bench_records], vec)
    y_train = np.array([1 if is_juicy(r) else 0 for r in train_records], dtype=np.int32)
    y_test = np.array([1 if is_juicy(r) else 0 for r in test_records], dtype=np.int32)
    y_bench = np.array([1 if is_juicy(r) else 0 for r in bench_records], dtype=np.int32)
    print(f"  feature matrix: train shape={X_train.shape}", file=sys.stderr)

    metric_keys = ["pr_auc", "roc_auc", "brier_score", "best_f1", "fixed_f1_at_0p5"]
    per_config_results: dict[str, dict] = {}
    per_config_meta: dict[str, list[dict]] = {}

    for config_name, config_overrides in CONFIGS.items():
        print(f"\n=== config={config_name} ===", file=sys.stderr)
        if config_overrides:
            print(f"  overrides: {config_overrides}", file=sys.stderr)
        else:
            print("  overrides: none (default LGBM = deterministic)", file=sys.stderr)
        meta_for_config: list[dict] = []
        test_metrics_list: list[dict] = []
        bench_metrics_list: list[dict] = []
        for seed in args.seeds:
            print(f"  --- seed={seed} ---", file=sys.stderr)
            t0 = time.time()
            model = train_headline(X_train, y_train, seed, config_overrides)
            train_seconds = time.time() - t0
            probs_test = model.predict_proba(X_test)[:, 1]
            probs_bench = model.predict_proba(X_bench)[:, 1]
            tm = compute_metrics(y_test, probs_test)
            bm = compute_metrics(y_bench, probs_bench)
            test_metrics_list.append(tm)
            bench_metrics_list.append(bm)
            meta_for_config.append(
                {
                    "seed": seed,
                    "train_seconds": train_seconds,
                    "test": tm,
                    "bench": bm,
                }
            )
            print(
                f"    trained {train_seconds:.1f}s; "
                f"test PR-AUC={tm['pr_auc']:.4f}, "
                f"bench PR-AUC={bm['pr_auc']:.4f}, "
                f"bench F1@0.5={bm['fixed_f1_at_0p5']:.4f}",
                file=sys.stderr,
            )
        per_config_meta[config_name] = meta_for_config
        per_config_results[config_name] = {
            "test": aggregate(test_metrics_list, metric_keys),
            "bench": aggregate(bench_metrics_list, metric_keys),
        }

    # --- Console report ---
    print()
    print("=" * 110)
    print("PATH-CLASSIFIER SEED VARIANCE  (headline P0 config × seed × determinism)")
    print("=" * 110)
    print(
        f"{'config':<14}  {'seed':>8}  {'test_PR_AUC':>11}  {'test_F1@.5':>11}  "
        f"{'bench_PR_AUC':>12}  {'bench_F1@.5':>11}  {'bench_Brier':>11}"
    )
    print("-" * 110)
    for config_name, meta_list in per_config_meta.items():
        for m in meta_list:
            print(
                f"{config_name:<14}  {m['seed']:>8}  "
                f"{m['test']['pr_auc']:>11.4f}  "
                f"{m['test']['fixed_f1_at_0p5']:>11.4f}  "
                f"{m['bench']['pr_auc']:>12.4f}  "
                f"{m['bench']['fixed_f1_at_0p5']:>11.4f}  "
                f"{m['bench']['brier_score']:>11.4f}"
            )
        print("-" * 110)

    def fmt_agg(agg, key):
        v = agg[key]
        return f"{v['mean']:.4f} ± {v['std']:.4f}  [{v['min']:.4f}, {v['max']:.4f}]"

    print("\nAggregates per config (mean ± std, [min, max]):")
    for config_name, aggregates in per_config_results.items():
        print(f"\n  [{config_name}]")
        print(f"    test PR-AUC:    {fmt_agg(aggregates['test'], 'pr_auc')}")
        print(f"    test F1@0.5:    {fmt_agg(aggregates['test'], 'fixed_f1_at_0p5')}")
        print(f"    bench PR-AUC:   {fmt_agg(aggregates['bench'], 'pr_auc')}")
        print(f"    bench F1@0.5:   {fmt_agg(aggregates['bench'], 'fixed_f1_at_0p5')}")
        print(f"    bench Brier:    {fmt_agg(aggregates['bench'], 'brier_score')}")
    print("=" * 110)

    payload = {
        "config": {
            "train": str(args.train.relative_to(REPO_ROOT)),
            "test": str(args.test.relative_to(REPO_ROOT)),
            "bench": str(args.bench.relative_to(REPO_ROOT)),
            "seeds": args.seeds,
            "lgbm_base_params": LGBM_BASE_PARAMS,
            "config_overrides": CONFIGS,
            "calibration": "isotonic_cv5",
        },
        "per_seed_per_config": per_config_meta,
        "aggregates": per_config_results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2))
    print(f"\nReport written to {args.output.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
