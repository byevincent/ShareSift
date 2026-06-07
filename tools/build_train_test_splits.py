"""Build train/test splits from the Claude-labeled eval set.

Per ``docs/build_plan.md`` Phase 2 (revised after the synthetic-only
training failed): the labeled set IS the ground truth (hand-labeling
dropped); the synthetic is supplementary bootstrap material. Standard
ML practice — hold out the Snaffler-blind benchmark, then split the
remainder 80/20 stratified by label.

Output:
* ``data/eval/train_split.jsonl``  — 80% of non-benchmark labeled records
* ``data/eval/test_split.jsonl``   — 20% held out for in-distribution eval

The benchmark (``data/eval/snaffler_blind_benchmark.jsonl``) stays as the
primary phase-2 measurement target. The test split is the secondary
in-distribution eval — it tells us whether the model is learning the
labeler's calibration in general, not just on Snaffler's blind spots.

Seed is fixed at 2026 for reproducibility. Re-running overwrites both
output files.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LABELED_PATH = REPO_ROOT / "data" / "eval" / "eval_set_claude.jsonl"
BENCHMARK_PATH = REPO_ROOT / "data" / "eval" / "snaffler_blind_benchmark.jsonl"
TRAIN_PATH = REPO_ROOT / "data" / "eval" / "train_split.jsonl"
TEST_PATH = REPO_ROOT / "data" / "eval" / "test_split.jsonl"


def load_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def stratified_split(
    records: list[dict], test_fraction: float, seed: int
) -> tuple[list[dict], list[dict]]:
    """Split records into (train, test) stratified by ``label``.

    Stratification keeps the juicy/not_juicy ratio identical between
    splits — important here because the population is ~5/95 imbalanced
    and a non-stratified split would risk a test set with very few
    juicy records.
    """
    rng = random.Random(seed)
    by_label: dict[str, list[dict]] = {"juicy": [], "not_juicy": []}
    for r in records:
        by_label.setdefault(r["label"], []).append(r)

    train: list[dict] = []
    test: list[dict] = []
    for label, group in by_label.items():
        rng.shuffle(group)
        n_test = int(round(len(group) * test_fraction))
        test.extend(group[:n_test])
        train.extend(group[n_test:])

    rng.shuffle(train)
    rng.shuffle(test)
    return train, test


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--labeled", type=Path, default=LABELED_PATH)
    p.add_argument("--benchmark", type=Path, default=BENCHMARK_PATH)
    p.add_argument("--train-out", type=Path, default=TRAIN_PATH)
    p.add_argument("--test-out", type=Path, default=TEST_PATH)
    p.add_argument("--test-fraction", type=float, default=0.20)
    p.add_argument("--seed", type=int, default=2026)
    args = p.parse_args(argv)

    labeled = load_jsonl(args.labeled)
    benchmark_paths = {r["path"] for r in load_jsonl(args.benchmark)}
    pool = [r for r in labeled if r["path"] not in benchmark_paths]
    print(
        f"Labeled: {len(labeled)} ; benchmark excluded: "
        f"{len(labeled) - len(pool)} ; eligible: {len(pool)}",
        file=sys.stderr,
    )

    train, test = stratified_split(pool, args.test_fraction, args.seed)
    args.train_out.parent.mkdir(parents=True, exist_ok=True)
    with args.train_out.open("w", encoding="utf-8") as f:
        for r in train:
            f.write(json.dumps(r) + "\n")
    with args.test_out.open("w", encoding="utf-8") as f:
        for r in test:
            f.write(json.dumps(r) + "\n")

    train_labels = Counter(r["label"] for r in train)
    test_labels = Counter(r["label"] for r in test)
    print(
        f"Train ({args.train_out.relative_to(REPO_ROOT)}): "
        f"{len(train)} records — "
        f"{train_labels['juicy']} juicy / {train_labels['not_juicy']} not_juicy"
    )
    print(
        f"Test  ({args.test_out.relative_to(REPO_ROOT)}): "
        f"{len(test)} records — "
        f"{test_labels['juicy']} juicy / {test_labels['not_juicy']} not_juicy"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
