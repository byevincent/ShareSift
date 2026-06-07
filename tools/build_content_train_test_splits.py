"""Build content-classifier train/test splits with cross-split dedup.

Replaces the unknown process that produced the original
``data/content/train_split.jsonl`` and ``test_split.jsonl`` (audit found
43/519 test records byte-identical to train, 55/519 near-duplicate at
Jaccard 0.8 — see ``reports/audit_eval_integrity.json``).

Method
======

1. Load the full dataset.
2. Compute a 5-char-shingle MinHash (num_perm=128) per record's user content.
3. Build a MinHashLSH at Jaccard threshold 0.8 (matches the
   ``build_content_dataset.py`` dedup threshold).
4. Compute near-duplicate connected components via union-find over LSH
   neighbors. Each component is a "cluster" — records that are
   near-duplicates directly or transitively.
5. Each cluster is assigned ENTIRELY to either train or test. This
   guarantees zero cross-split near-duplication including the byte-identical
   case (Jaccard 1.0 sits above 0.8).
6. Clusters stratify by their majority label. Unanimous "yes" or "no"
   clusters stratify on that label; mixed-label clusters route to train
   (preserves test purity at the cost of mild label noise in train).
7. Within each stratum, clusters are shuffled (seeded) and assigned to
   train or test by a streaming heuristic that tracks the running test
   record count against the target test fraction.

Outputs
=======

* ``train_split.jsonl`` / ``test_split.jsonl`` — same JSONL schema as input
  (the ``{"messages": [...]}`` chat-template shape).
* ``dataset_stats_split.json`` — per-split label counts, cluster size
  distribution, input-file SHA, run config.

Reproducibility: fixed seed (default 2026). Re-running overwrites the
output splits and stats file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

from datasketch import MinHash, MinHashLSH

REPO_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_DATASET = REPO_ROOT / "data" / "content" / "training_dataset.jsonl"
DEFAULT_TRAIN_OUT = REPO_ROOT / "data" / "content" / "train_split.jsonl"
DEFAULT_TEST_OUT = REPO_ROOT / "data" / "content" / "test_split.jsonl"
DEFAULT_STATS_OUT = REPO_ROOT / "data" / "content" / "dataset_stats_split.json"


# --- Helpers --------------------------------------------------------------


def load_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def content_user_text(record: dict) -> str:
    for m in record.get("messages", []):
        if m.get("role") == "user":
            return m.get("content", "")
    return ""


def content_label(record: dict) -> str:
    for m in record.get("messages", []):
        if m.get("role") == "assistant":
            return m.get("content", "").strip()
    return ""


def char_shingles(text: str, k: int = 5) -> set[str]:
    if len(text) < k:
        return {text} if text else set()
    return {text[i : i + k] for i in range(len(text) - k + 1)}


def build_minhash(text: str, num_perm: int = 128) -> "MinHash":
    m = MinHash(num_perm=num_perm)
    for sh in char_shingles(text, k=5):
        m.update(sh.encode("utf-8"))
    return m


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --- Clustering -----------------------------------------------------------


class UnionFind:
    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, x: int, y: int) -> None:
        px, py = self.find(x), self.find(y)
        if px != py:
            self.parent[px] = py


def build_clusters(
    records: list[dict],
    threshold: float = 0.8,
    num_perm: int = 128,
) -> list[list[int]]:
    """Connected-component clusters of near-duplicate records.

    Each cluster is a list of indices into ``records``. Records with no
    near-duplicate land in singleton clusters.
    """
    print(f"  computing MinHashes for {len(records)} records...", file=sys.stderr)
    t0 = time.time()
    mhs = [build_minhash(content_user_text(r), num_perm=num_perm) for r in records]
    print(f"  MinHash build: {time.time() - t0:.1f}s", file=sys.stderr)

    print(f"  building LSH at Jaccard >= {threshold}...", file=sys.stderr)
    t0 = time.time()
    lsh = MinHashLSH(threshold=threshold, num_perm=num_perm)
    for i, mh in enumerate(mhs):
        lsh.insert(str(i), mh)
    print(f"  LSH build: {time.time() - t0:.1f}s", file=sys.stderr)

    print("  union-find on LSH neighbors...", file=sys.stderr)
    t0 = time.time()
    uf = UnionFind(len(records))
    for i, mh in enumerate(mhs):
        for key in lsh.query(mh):
            j = int(key)
            if j != i:
                uf.union(i, j)
    print(f"  union-find: {time.time() - t0:.1f}s", file=sys.stderr)

    by_root: dict[int, list[int]] = defaultdict(list)
    for i in range(len(records)):
        by_root[uf.find(i)].append(i)
    return list(by_root.values())


# --- Stratified assignment ------------------------------------------------


def cluster_stratum(cluster: list[int], records: list[dict]) -> str:
    labels = Counter(content_label(records[i]) for i in cluster)
    if len(labels) == 1:
        return next(iter(labels))  # unanimous: "yes" or "no"
    return "mixed"


def assign_clusters_to_splits(
    clusters: list[list[int]],
    records: list[dict],
    test_fraction: float,
    seed: int,
) -> tuple[set[int], set[int], dict]:
    """Stratified streaming cluster assignment.

    Returns ``(train_indices, test_indices, stratum_stats)``.

    Mixed-label clusters are always routed to train so the test set is
    label-clean. Pure clusters are shuffled within each stratum and
    streamed into test until the per-stratum target count is reached;
    remainder go to train.
    """
    rng = random.Random(seed)
    by_stratum: dict[str, list[list[int]]] = defaultdict(list)
    for cluster in clusters:
        by_stratum[cluster_stratum(cluster, records)].append(cluster)

    train_idx: set[int] = set()
    test_idx: set[int] = set()
    stratum_stats: dict[str, dict] = {}

    for stratum, stratum_clusters in by_stratum.items():
        rng.shuffle(stratum_clusters)

        if stratum == "mixed":
            for cluster in stratum_clusters:
                train_idx.update(cluster)
            stratum_stats[stratum] = {
                "clusters": len(stratum_clusters),
                "records": sum(len(c) for c in stratum_clusters),
                "to_train": sum(len(c) for c in stratum_clusters),
                "to_test": 0,
                "note": "mixed-label clusters routed to train to keep test pure",
            }
            continue

        total = sum(len(c) for c in stratum_clusters)
        target_test_records = round(test_fraction * total)
        running_test = 0
        for cluster in stratum_clusters:
            if running_test + len(cluster) <= target_test_records:
                test_idx.update(cluster)
                running_test += len(cluster)
            else:
                train_idx.update(cluster)
        stratum_stats[stratum] = {
            "clusters": len(stratum_clusters),
            "records": total,
            "to_train": total - running_test,
            "to_test": running_test,
            "target_test": target_test_records,
            "test_fraction_actual": running_test / total if total else 0.0,
        }

    return train_idx, test_idx, stratum_stats


def write_jsonl(records: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


# --- Main -----------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    p.add_argument("--train-out", type=Path, default=DEFAULT_TRAIN_OUT)
    p.add_argument("--test-out", type=Path, default=DEFAULT_TEST_OUT)
    p.add_argument("--stats-out", type=Path, default=DEFAULT_STATS_OUT)
    p.add_argument("--test-fraction", type=float, default=0.20)
    p.add_argument("--seed", type=int, default=2026)
    p.add_argument(
        "--jaccard-threshold",
        type=float,
        default=0.8,
        help=(
            "MinHash LSH threshold for cross-split dedup "
            "(default matches build_content_dataset.py)."
        ),
    )
    p.add_argument(
        "--num-perm",
        type=int,
        default=128,
        help="MinHash permutations (higher = more accurate, slower).",
    )
    args = p.parse_args(argv)

    if not args.dataset.exists():
        print(f"ERROR: input dataset not found at {args.dataset}", file=sys.stderr)
        return 2

    for out in (args.train_out, args.test_out):
        if out.resolve() == args.dataset.resolve():
            print(
                f"ERROR: output path {out} matches input dataset; refusing.",
                file=sys.stderr,
            )
            return 2

    print(
        f"Loading dataset from {args.dataset.relative_to(REPO_ROOT)}...",
        file=sys.stderr,
    )
    raw_records = load_jsonl(args.dataset)
    print(f"  {len(raw_records)} records loaded", file=sys.stderr)

    # Exact-dedup pass. The upstream build_content_dataset.py has a bug
    # in its dedup filter (kept_set membership test fires for every record
    # that shares a kept text, not just one) so the input file is not
    # actually exact-deduped despite its dataset_stats.json claim. Collapse
    # by sha256 of user-content; keep the first occurrence.
    seen_fps: set[str] = set()
    records: list[dict] = []
    for r in raw_records:
        fp = hashlib.sha256(content_user_text(r).encode("utf-8")).hexdigest()
        if fp in seen_fps:
            continue
        seen_fps.add(fp)
        records.append(r)
    n_exact_dropped = len(raw_records) - len(records)
    print(
        f"  exact-dedup pass: dropped {n_exact_dropped} duplicate records, "
        f"{len(records)} unique remain",
        file=sys.stderr,
    )

    print("Clustering near-duplicates...", file=sys.stderr)
    clusters = build_clusters(
        records,
        threshold=args.jaccard_threshold,
        num_perm=args.num_perm,
    )
    cluster_sizes = Counter(len(c) for c in clusters)
    n_singletons = cluster_sizes.get(1, 0)
    n_clustered = len(clusters) - n_singletons
    print(
        f"  {len(clusters)} clusters: {n_singletons} singletons, "
        f"{n_clustered} multi-record",
        file=sys.stderr,
    )

    print("Assigning clusters to splits...", file=sys.stderr)
    train_idx, test_idx, stratum_stats = assign_clusters_to_splits(
        clusters, records, args.test_fraction, args.seed
    )

    train_records = [records[i] for i in sorted(train_idx)]
    test_records = [records[i] for i in sorted(test_idx)]
    rng = random.Random(args.seed + 1)
    rng.shuffle(train_records)
    rng.shuffle(test_records)

    print(
        f"Writing {len(train_records)} train -> "
        f"{args.train_out.relative_to(REPO_ROOT)}",
        file=sys.stderr,
    )
    write_jsonl(train_records, args.train_out)
    print(
        f"Writing {len(test_records)} test  -> "
        f"{args.test_out.relative_to(REPO_ROOT)}",
        file=sys.stderr,
    )
    write_jsonl(test_records, args.test_out)

    train_labels = Counter(content_label(r) for r in train_records)
    test_labels = Counter(content_label(r) for r in test_records)

    stats = {
        "input_dataset": str(args.dataset.relative_to(REPO_ROOT)),
        "input_dataset_sha256": file_sha256(args.dataset),
        "input_records_raw": len(raw_records),
        "input_records_after_exact_dedup": len(records),
        "exact_duplicates_dropped": n_exact_dropped,
        "clusters_total": len(clusters),
        "clusters_singleton": n_singletons,
        "clusters_multi": n_clustered,
        "largest_cluster_size": max(cluster_sizes.keys()) if cluster_sizes else 0,
        "cluster_size_distribution": {
            str(k): v for k, v in sorted(cluster_sizes.items())
        },
        "stratum_stats": stratum_stats,
        "train": {
            "records": len(train_records),
            "labels": dict(train_labels),
            "sha256": file_sha256(args.train_out),
        },
        "test": {
            "records": len(test_records),
            "labels": dict(test_labels),
            "fraction": len(test_records) / len(records) if records else 0.0,
            "sha256": file_sha256(args.test_out),
        },
        "config": {
            "test_fraction": args.test_fraction,
            "seed": args.seed,
            "jaccard_threshold": args.jaccard_threshold,
            "num_perm": args.num_perm,
        },
    }
    args.stats_out.parent.mkdir(parents=True, exist_ok=True)
    args.stats_out.write_text(json.dumps(stats, indent=2))
    print(
        f"Wrote stats to {args.stats_out.relative_to(REPO_ROOT)}",
        file=sys.stderr,
    )

    print()
    print(
        f"Train: {len(train_records)} records "
        f"({train_labels.get('yes', 0)} yes / {train_labels.get('no', 0)} no)"
    )
    test_frac = 100 * len(test_records) / len(records) if records else 0
    print(
        f"Test:  {len(test_records)} records "
        f"({test_labels.get('yes', 0)} yes / {test_labels.get('no', 0)} no) "
        f"-- {test_frac:.1f}% of input"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
