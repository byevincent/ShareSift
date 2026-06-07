#!/usr/bin/env python3
"""v0.13 Phase 3 — by-repo train/val/test split with leakage controls.

Reads ``scraped.jsonl`` from Phase 2, applies the leakage banlist, splits
**by repo** (not by snippet) at 80/10/10, stratifies the split assignment
to keep the literal:referenced ratio roughly constant across train/val/test,
and writes one JSONL file per split.

By-repo splitting is the load-bearing decision here. The scraper allows
≤5 snippets per repo and globally dedupes identical snippet hashes, but
two snippets from the *same* repo are still correlated (same author, same
codebase conventions, often the same security mistakes). If we did a
naive snippet-level split, near-duplicates from one repo could land in
both train and test and inflate evaluation metrics. Splitting at the
repo level eliminates this leakage channel.

Banlist semantics: any repo listed in ``--banlist`` is dropped entirely
(its snippets are excluded from train, val, and test). Use this to
exclude repos that overlap with prior corpora (CredData training set is
the main concern; v0p6 docx-corpus is text-not-code so no overlap).

Usage:
    uv run python tools/split_literal_vs_referenced_corpus.py \\
        --input data/external/literal_vs_referenced/scraped.jsonl \\
        --output-dir data/external/literal_vs_referenced/splits/ \\
        --banlist data/external/literal_vs_referenced/banlist_repos.txt \\
        --val-frac 0.10 \\
        --test-frac 0.10 \\
        --seed 2026

Output files:
    splits/train.jsonl
    splits/val.jsonl
    splits/test.jsonl
    splits/split_report.json   # class balance + per-subtype + per-extension
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import defaultdict, Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = REPO_ROOT / "data" / "external" / "literal_vs_referenced" / "scraped.jsonl"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "data" / "external" / "literal_vs_referenced" / "splits"
DEFAULT_BANLIST = REPO_ROOT / "data" / "external" / "literal_vs_referenced" / "banlist_repos.txt"


def _load_jsonl(path: Path) -> list[dict]:
    records: list[dict] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def _load_banlist(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {
        line.strip().lower()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }


def _split_repos_stratified(
    repo_class_counts: dict[str, Counter],
    val_frac: float,
    test_frac: float,
    rng: random.Random,
) -> tuple[set[str], set[str], set[str]]:
    """Assign each repo to train/val/test, stratifying on dominant class.

    We bucket repos by their majority class (literal vs referenced), then
    independently shuffle and split each bucket by the requested fractions.
    Net effect: literal-heavy and referenced-heavy repos are both
    represented across all three splits, so neither split has 0% of a class.
    """
    by_dominant: dict[str, list[str]] = defaultdict(list)
    for repo, counts in repo_class_counts.items():
        dominant = counts.most_common(1)[0][0] if counts else "referenced"
        by_dominant[dominant].append(repo)

    train_repos: set[str] = set()
    val_repos: set[str] = set()
    test_repos: set[str] = set()
    for dominant, repos in by_dominant.items():
        rng.shuffle(repos)
        n = len(repos)
        n_test = max(1, int(round(n * test_frac))) if n >= 10 else 0
        n_val = max(1, int(round(n * val_frac))) if n >= 10 else 0
        n_train = n - n_test - n_val
        if n_train <= 0:
            # Tiny bucket — just keep everything in train rather than
            # forcing val/test with degenerate sizes.
            train_repos.update(repos)
            continue
        train_repos.update(repos[:n_train])
        val_repos.update(repos[n_train:n_train + n_val])
        test_repos.update(repos[n_train + n_val:])
    return train_repos, val_repos, test_repos


def _summarise(records: list[dict]) -> dict:
    by_label = Counter(r["label"] for r in records)
    by_subtype = Counter(r.get("subtype") for r in records if r["label"] == "referenced")
    by_ext = Counter(r.get("file_extension", "?") for r in records)
    by_pattern = Counter(r.get("matched_pattern", "?") for r in records)
    n_repos = len({r["source_repo"] for r in records})
    return {
        "n_records": len(records),
        "n_repos": n_repos,
        "by_label": dict(by_label),
        "by_subtype": dict(by_subtype),
        "by_extension": dict(by_ext.most_common(15)),
        "by_pattern": dict(by_pattern.most_common(15)),
        "literal_fraction": (
            by_label.get("literal", 0) / max(1, len(records))
        ),
    }


def split(
    input_path: Path,
    output_dir: Path,
    banlist: set[str],
    val_frac: float,
    test_frac: float,
    seed: int,
) -> None:
    records = _load_jsonl(input_path)
    print(f"[load] {len(records)} records from {input_path}", file=sys.stderr)

    n_banned = 0
    kept: list[dict] = []
    for r in records:
        if r["source_repo"].lower() in banlist:
            n_banned += 1
            continue
        kept.append(r)
    print(f"[banlist] dropped {n_banned} records from {len(banlist)} banned repos", file=sys.stderr)

    # Build per-repo class counts for stratified split
    repo_class_counts: dict[str, Counter] = defaultdict(Counter)
    for r in kept:
        repo_class_counts[r["source_repo"]][r["label"]] += 1

    n_repos = len(repo_class_counts)
    print(f"[repos] {n_repos} unique repos in corpus", file=sys.stderr)

    if n_repos < 30:
        print(
            f"[warn] only {n_repos} repos — by-repo split will produce very "
            f"thin val/test sets. Consider waiting for more scrape data "
            f"or accepting noisy held-out metrics.",
            file=sys.stderr,
        )

    rng = random.Random(seed)
    train_repos, val_repos, test_repos = _split_repos_stratified(
        repo_class_counts, val_frac=val_frac, test_frac=test_frac, rng=rng,
    )
    print(
        f"[split] train: {len(train_repos)} repos / "
        f"val: {len(val_repos)} repos / "
        f"test: {len(test_repos)} repos",
        file=sys.stderr,
    )

    # Assign records to splits by repo membership
    train_records = [r for r in kept if r["source_repo"] in train_repos]
    val_records = [r for r in kept if r["source_repo"] in val_repos]
    test_records = [r for r in kept if r["source_repo"] in test_repos]

    output_dir.mkdir(parents=True, exist_ok=True)
    train_path = output_dir / "train.jsonl"
    val_path = output_dir / "val.jsonl"
    test_path = output_dir / "test.jsonl"
    def _rel(p: Path) -> Path | str:
        try:
            return p.resolve().relative_to(REPO_ROOT)
        except ValueError:
            return p
    for path, recs in [
        (train_path, train_records),
        (val_path, val_records),
        (test_path, test_records),
    ]:
        with path.open("w", encoding="utf-8") as fh:
            for r in recs:
                fh.write(json.dumps(r) + "\n")
        print(f"[write] {len(recs):>6d} → {_rel(path)}", file=sys.stderr)

    try:
        input_rel = str(input_path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        input_rel = str(input_path)
    report = {
        "input": input_rel,
        "seed": seed,
        "val_frac": val_frac,
        "test_frac": test_frac,
        "n_banned_records": n_banned,
        "n_banlist_repos": len(banlist),
        "train": _summarise(train_records),
        "val": _summarise(val_records),
        "test": _summarise(test_records),
    }
    report_path = output_dir / "split_report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[report] {_rel(report_path)}", file=sys.stderr)

    # Console summary
    print("\n=== split summary ===", file=sys.stderr)
    for name, summary in [("train", report["train"]), ("val", report["val"]), ("test", report["test"])]:
        lf = summary["literal_fraction"]
        bl = summary["by_label"]
        print(
            f"  {name:5s}: {summary['n_records']:6d} records, "
            f"{summary['n_repos']:5d} repos, "
            f"literal={bl.get('literal', 0):5d} ({lf:.1%}) / "
            f"referenced={bl.get('referenced', 0):6d}",
            file=sys.stderr,
        )
    print("\n  subtype distribution (test set):", file=sys.stderr)
    for st, n in sorted(report["test"]["by_subtype"].items(), key=lambda x: -(x[1] or 0)):
        print(f"    {str(st):30s} {n}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    p.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    p.add_argument("--banlist", type=Path, default=DEFAULT_BANLIST)
    p.add_argument("--val-frac", type=float, default=0.10)
    p.add_argument("--test-frac", type=float, default=0.10)
    p.add_argument("--seed", type=int, default=2026)
    args = p.parse_args(argv)

    if not args.input.exists():
        print(f"ERROR: {args.input} missing — run build_literal_vs_referenced_corpus.py first", file=sys.stderr)
        return 1

    banlist = _load_banlist(args.banlist)
    if banlist:
        print(f"[init] banlist: {len(banlist)} repos", file=sys.stderr)

    split(
        input_path=args.input,
        output_dir=args.output_dir,
        banlist=banlist,
        val_frac=args.val_frac,
        test_frac=args.test_frac,
        seed=args.seed,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
