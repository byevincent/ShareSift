"""v0.11.1: Build Linux path classifier training corpus from v0.9 writeup labels.

v0.10 closed the Stage 2 (content) bottleneck. v0.9 had documented
that Stage 1 (path classifier) overfits to its GitHub-mined training
distribution: Linux PR-AUC drops from 0.99 in-distribution to 0.27 on
writeup-mined paths. v0.11 retrains the Linux LightGBM on a combined
corpus (existing in-distribution training + 80% of v0.9 boxes) with a
by-box split to prevent leakage on the held-out writeup test.

Procedure
=========

1. Read v0.9 ``data/eval/writeups/labeled_paths.jsonl``, filter to
   Linux-shape records (kind == "linux_abs").
2. Group by ``source_box`` (230 boxes total in v0.9).
3. Deterministic shuffle (seed=2026), split 80/20 by box →
   ~184 train-boxes / ~46 test-boxes.
4. Convert v0.9 records to the training JSONL shape used by
   ``tools/train_path_classifier.py`` (label + tier + source +
   added_date + added_by).
5. Append the train-box subset to ``data/eval/train_split_linux.jsonl``
   contents → emit ``data/eval/train_split_linux_v0p11.jsonl``.
6. Test set: just the test-box subset →
   ``data/eval/test_split_linux_v0p11_writeup.jsonl``. The existing
   ``data/eval/test_split_linux.jsonl`` stays as the in-distribution
   regression check.

Stratification: NOT applied across kind because all v0.9 records here
are Linux. Existing Linux train + Linux v0.9 writeup → balanced enough.

Output stats: counts + by-box stats for the audit trail.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_V09_LABELS = REPO_ROOT / "data" / "eval" / "writeups" / "labeled_paths.jsonl"
DEFAULT_EXISTING_TRAIN = REPO_ROOT / "data" / "eval" / "train_split_linux.jsonl"
DEFAULT_NEW_TRAIN = REPO_ROOT / "data" / "eval" / "train_split_linux_v0p11.jsonl"
DEFAULT_WRITEUP_TEST = REPO_ROOT / "data" / "eval" / "test_split_linux_v0p11_writeup.jsonl"


def _convert_v09_to_training_shape(rec: dict) -> dict:
    """Map a v0.9-labeled record to the training-corpus JSONL shape
    train_path_classifier.py + the labelers expect."""
    return {
        "path": rec["path"],
        "label": "juicy" if rec.get("is_juicy") else "not_juicy",
        "tier": rec.get("tier"),
        "category": rec.get("category"),
        "sub_type": None,
        "source": f"writeup_0xdf_{rec.get('source_box', 'unknown')}",
        "notes": (rec.get("reason") or "")[:200],
        "added_date": "2026-06-01",
        "added_by": "claude_via_paste_workflow",
        "pre_category": None,
        "validator_warnings": [],
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--v09-labels", type=Path, default=DEFAULT_V09_LABELS)
    p.add_argument("--existing-train", type=Path, default=DEFAULT_EXISTING_TRAIN)
    p.add_argument("--new-train", type=Path, default=DEFAULT_NEW_TRAIN)
    p.add_argument("--writeup-test", type=Path, default=DEFAULT_WRITEUP_TEST)
    p.add_argument("--train-frac", type=float, default=0.80)
    p.add_argument("--seed", type=int, default=2026)
    args = p.parse_args(argv)

    # Step 1-2: load + filter to Linux + group by box.
    by_box: dict[str, list[dict]] = defaultdict(list)
    total = linux = 0
    for line in args.v09_labels.read_text().splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        total += 1
        if rec.get("kind") != "linux_abs":
            continue
        linux += 1
        if rec.get("is_juicy") is None:
            continue
        box = rec.get("source_box", "unknown")
        by_box[box].append(rec)
    print(
        f"v0.9 labels: {total} total, {linux} Linux, "
        f"{sum(len(v) for v in by_box.values())} usable across "
        f"{len(by_box)} boxes",
        file=sys.stderr,
    )

    # Step 3: deterministic shuffle + split by box.
    boxes = sorted(by_box.keys())
    rng = random.Random(args.seed)
    rng.shuffle(boxes)
    n_train_boxes = int(len(boxes) * args.train_frac)
    train_boxes = set(boxes[:n_train_boxes])
    test_boxes = set(boxes[n_train_boxes:])
    print(
        f"  by-box split: {len(train_boxes)} train / {len(test_boxes)} test boxes "
        f"(seed={args.seed})",
        file=sys.stderr,
    )

    train_recs_v09: list[dict] = []
    test_recs_v09: list[dict] = []
    for box, recs in by_box.items():
        target = train_recs_v09 if box in train_boxes else test_recs_v09
        target.extend(recs)
    print(
        f"  records: {len(train_recs_v09)} train / {len(test_recs_v09)} test",
        file=sys.stderr,
    )

    # Step 4: convert to training shape.
    train_recs_converted = [_convert_v09_to_training_shape(r) for r in train_recs_v09]
    test_recs_converted = [_convert_v09_to_training_shape(r) for r in test_recs_v09]

    # Step 5: append to existing Linux train.
    existing_train = []
    for line in args.existing_train.read_text().splitlines():
        if not line.strip():
            continue
        existing_train.append(json.loads(line))
    print(
        f"Existing train_split_linux: {len(existing_train)} records",
        file=sys.stderr,
    )

    combined_train = existing_train + train_recs_converted
    rng.shuffle(combined_train)
    print(
        f"Combined train: {len(combined_train)} records "
        f"({len(existing_train)} existing + {len(train_recs_converted)} v0.9 writeup)",
        file=sys.stderr,
    )

    # Step 6: emit train + test.
    args.new_train.parent.mkdir(parents=True, exist_ok=True)
    with args.new_train.open("w", encoding="utf-8") as f:
        for r in combined_train:
            f.write(json.dumps(r) + "\n")
    with args.writeup_test.open("w", encoding="utf-8") as f:
        for r in test_recs_converted:
            f.write(json.dumps(r) + "\n")

    # Stats.
    train_labels = Counter(r["label"] for r in combined_train)
    test_labels = Counter(r["label"] for r in test_recs_converted)
    print(f"\nWrote {args.new_train.relative_to(REPO_ROOT)}", file=sys.stderr)
    print(f"  train: {dict(train_labels)}", file=sys.stderr)
    print(f"Wrote {args.writeup_test.relative_to(REPO_ROOT)}", file=sys.stderr)
    print(f"  test (writeup held-out): {dict(test_labels)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
