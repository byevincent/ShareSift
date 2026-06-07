"""CLI: train the v0 path classifier and report metrics on held-out sets.

Per ``docs/build_plan.md`` Phase 2 success criterion: PR-AUC ≥ 0.90 on
the Snaffler-blind benchmark. If this hits, ship LightGBM and skip the
transformer escalation. If it misses, the build plan calls for
MiniLM-L6 / DistilBERT fine-tune as the next step.

Default run:

    uv run python tools/train_path_classifier.py

Trains on ``data/synthetic/training_v0.jsonl``, saves to
``models/path_classifier_v0/``, and evaluates on:

* ``data/eval/snaffler_blind_benchmark.jsonl`` (the phase-2 target)
* ``data/eval/eval_set_claude.jsonl`` (the broader-population view)

The Snaffler-recall baseline (41.5% on Truffler-juicy paths) is printed
for direct comparison.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from src.eval.model.evaluate import evaluate, format_report
from src.eval.model.train import (
    TrainConfig,
    load_records,
    save_model,
    train_model,
)


DEFAULT_TRAIN = REPO_ROOT / "data" / "eval" / "train_split.jsonl"
DEFAULT_SYNTHETIC = REPO_ROOT / "data" / "synthetic" / "training_v0.jsonl"
DEFAULT_BENCHMARK = REPO_ROOT / "data" / "eval" / "snaffler_blind_benchmark.jsonl"
DEFAULT_TEST_SPLIT = REPO_ROOT / "data" / "eval" / "test_split.jsonl"
DEFAULT_MODEL_DIR = REPO_ROOT / "models" / "path_classifier_v0"

# From tools/build_snaffler_blind_benchmark.py run on 2026-05-29.
SNAFFLER_RECALL_BASELINE = 0.415  # 228/550 on the 11,190-record queue


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument(
        "--train-data",
        type=Path,
        default=DEFAULT_TRAIN,
        help=(
            "Primary training JSONL. Defaults to the labeled 80%% split "
            "produced by tools/build_train_test_splits.py."
        ),
    )
    p.add_argument(
        "--include-synthetic",
        action="store_true",
        help=(
            "Also include data/synthetic/training_v0.jsonl in the training set. "
            "Useful for regex-tier coverage where the labeled split is thin."
        ),
    )
    p.add_argument("--benchmark", type=Path, default=DEFAULT_BENCHMARK)
    p.add_argument(
        "--test-split",
        type=Path,
        default=DEFAULT_TEST_SPLIT,
        help=(
            "In-distribution held-out test (20%% of non-benchmark labeled)."
        ),
    )
    p.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    p.add_argument(
        "--no-save", action="store_true", help="Skip writing the artifact."
    )
    args = p.parse_args(argv)

    print(f"Loading training data from {args.train_data.relative_to(REPO_ROOT)}")
    train_records = load_records(args.train_data)
    print(f"  {len(train_records)} records (labeled)")
    if args.include_synthetic and DEFAULT_SYNTHETIC.exists():
        synth = load_records(DEFAULT_SYNTHETIC)
        train_records = train_records + synth
        print(f"  + {len(synth)} synthetic records → {len(train_records)} total")

    config = TrainConfig()
    print(
        f"Training LightGBM (n_estimators={config.n_estimators}, "
        f"learning_rate={config.learning_rate}, num_leaves={config.num_leaves})..."
    )
    model = train_model(train_records, config)

    if not args.no_save:
        save_model(model, args.model_dir, train_records, config, args.train_data)
        print(f"Saved model to {args.model_dir.relative_to(REPO_ROOT)}")

    if args.test_split.exists():
        test_records = load_records(args.test_split)
        test_report = evaluate(model, test_records)
        print(format_report("In-distribution test split (20% held-out)", test_report))

    if args.benchmark.exists():
        bench_records = load_records(args.benchmark)
        bench_report = evaluate(model, bench_records)
        print(format_report("Snaffler-blind benchmark", bench_report))
        print(
            f"\n  Phase-2 success criterion (PR-AUC ≥ 0.90): "
            f"{'PASS' if bench_report.pr_auc >= 0.90 else 'MISS'}"
        )
        print(
            f"  Recall @0.5 vs Snaffler's {SNAFFLER_RECALL_BASELINE:.1%} baseline: "
            f"{bench_report.fixed_recall:.1%} "
            f"(delta {bench_report.fixed_recall - SNAFFLER_RECALL_BASELINE:+.1%})"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
