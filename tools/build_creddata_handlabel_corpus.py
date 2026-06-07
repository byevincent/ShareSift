"""Build v0.7 content classifier training corpus from CredData hand-labels.

v0.6 trained on CredData repos with Kingfisher's pattern detection as
the labeling oracle. Result: precision win, recall loss, F1 worse than
v0p3 because Kingfisher's positive labels are a strict subset of
CredData's hand-labels.

v0.7 closes that gap by using **CredData's own GroundTruth column
(Samsung's hand-labels)** as the training oracle — matches Biringa &
Kul 2025's exact methodology, just with a smaller base model. The same
50/283 by-repo split from v0.6 prevents leakage with the held-out
benchmark.

Procedure:

1. Read ``data/content_v0p4/repo_split.json`` for the 283 training
   repos. (Same seed/split as v0.6 — eval benchmark stays untouched.)
2. Read CredData metadata; filter rows to ``RepoName ∈ train_repos``.
3. Sample ``--max-positives`` GroundTruth=T rows + ``--neg-per-pos``
   times as many GroundTruth=F rows.
4. For each sampled row, fetch the source file from the local CredData
   clone, extract a snippet at LineStart..LineEnd ±context lines (same
   shape as ``tools/rebuild_creddata_eval_benchmark.py``).
5. Emit chat-template JSONL compatible with
   ``tools/train_content_classifier.py``.

Output: ``data/content_v0p5/{train_split,test_split}.jsonl``,
80/20 split, seed=2026.

Per-line granularity (one record per labeled line) matches Biringa &
Kul's training methodology and CredData's eval shape. Files may
appear multiple times with different label/snippet pairs — that's the
expected behavior.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CREDDATA_ROOT = REPO_ROOT / "data" / "external" / "creddata"
DEFAULT_REPO_SPLIT = REPO_ROOT / "data" / "content_v0p4" / "repo_split.json"
DEFAULT_OUT_DIR = REPO_ROOT / "data" / "content_v0p5"


def _fetch_file(file_path: str) -> str | None:
    full = CREDDATA_ROOT / file_path
    if not full.exists():
        return None
    try:
        return full.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        print(f"  ! {file_path}: {e}", file=sys.stderr)
        return None


def _extract_snippet(source: str, line_start: int, line_end: int, context: int = 5, max_chars: int = 4000) -> str:
    lines = source.splitlines()
    if not lines:
        return ""
    lo = max(0, line_start - 1 - context)
    hi = min(len(lines), line_end + context)
    snippet = "\n".join(lines[lo:hi])
    if len(snippet) <= max_chars:
        return snippet
    secret_line = lines[line_start - 1] if 0 < line_start <= len(lines) else lines[0]
    if len(secret_line) > max_chars:
        mid = len(secret_line) // 2
        half = max_chars // 2
        return secret_line[max(0, mid - half): mid + half]
    while len(snippet) > max_chars and (lo > 0 or hi < len(lines)):
        if lo > 0: lo += 1
        if hi < len(lines): hi -= 1
        snippet = "\n".join(lines[lo:hi])
    return snippet[:max_chars]


_SYSTEM_PROMPT = (
    "You are a security analyst. Examine the code snippet below and determine "
    "whether it contains a hardcoded secret — an API key, password, private "
    "key, database credential, token, or other credential material embedded "
    "as a literal value in the code. Answer with exactly one word: "
    '"yes" or "no".'
)


def _to_chat_template(snippet: str, label: str, meta: dict) -> dict:
    return {
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": snippet},
            {"role": "assistant", "content": label},
        ],
        **meta,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--repo-split", type=Path, default=DEFAULT_REPO_SPLIT)
    p.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    p.add_argument("--max-positives", type=int, default=1000)
    p.add_argument("--neg-per-pos", type=float, default=2.0)
    p.add_argument("--seed", type=int, default=2026)
    args = p.parse_args(argv)

    split = json.loads(args.repo_split.read_text())
    train_repos = set(split["train_repos"])
    print(f"Training repos: {len(train_repos)}", file=sys.stderr)

    all_rows: list[dict] = []
    for meta_csv in sorted((CREDDATA_ROOT / "meta").glob("*.csv")):
        for row in csv.DictReader(meta_csv.open(encoding="utf-8")):
            if row.get("RepoName") in train_repos:
                all_rows.append(row)

    positives = [r for r in all_rows if r.get("GroundTruth") == "T"]
    negatives = [r for r in all_rows if r.get("GroundTruth") == "F"]
    print(
        f"Metadata in training repos: {len(all_rows)} rows "
        f"({len(positives)} pos / {len(negatives)} neg, natural ratio "
        f"{len(negatives) / max(1, len(positives)):.1f}:1)",
        file=sys.stderr,
    )

    rng = random.Random(args.seed)
    rng.shuffle(positives)
    rng.shuffle(negatives)

    picks_pos = positives[: args.max_positives]
    n_neg = int(len(picks_pos) * args.neg_per_pos)
    picks_neg = negatives[:n_neg]
    print(
        f"Sampling: {len(picks_pos)} pos + {len(picks_neg)} neg = "
        f"{len(picks_pos) + len(picks_neg)} records target",
        file=sys.stderr,
    )

    records_out: list[dict] = []
    misses = {"not_found": 0, "bad_lines": 0, "empty_snippet": 0}
    for i, row in enumerate(picks_pos + picks_neg):
        if (i + 1) % 500 == 0:
            print(f"  [{i + 1}/{len(picks_pos) + len(picks_neg)}]", file=sys.stderr)
        try:
            ls = int(row["LineStart"])
            le = int(row["LineEnd"])
        except (ValueError, KeyError):
            misses["bad_lines"] += 1
            continue
        source = _fetch_file(row["FilePath"])
        if source is None:
            misses["not_found"] += 1
            continue
        snippet = _extract_snippet(source, ls, le)
        if not snippet.strip():
            misses["empty_snippet"] += 1
            continue
        label = "yes" if row["GroundTruth"] == "T" else "no"
        records_out.append(_to_chat_template(snippet, label, {
            "source_repo": row.get("RepoName"),
            "source_path": row.get("FilePath"),
            "line_start": ls,
            "line_end": le,
            "predefined_pattern": row.get("PredefinedPattern") or "",
            "category": row.get("Category") or "",
        }))

    rng.shuffle(records_out)
    n_test = int(len(records_out) * 0.2)
    test_set = records_out[:n_test]
    train_set = records_out[n_test:]

    args.out_dir.mkdir(parents=True, exist_ok=True)
    train_path = args.out_dir / "train_split.jsonl"
    test_path = args.out_dir / "test_split.jsonl"
    with train_path.open("w", encoding="utf-8") as f:
        for r in train_set:
            f.write(json.dumps(r) + "\n")
    with test_path.open("w", encoding="utf-8") as f:
        for r in test_set:
            f.write(json.dumps(r) + "\n")

    n_pos_out = sum(1 for r in records_out if r["messages"][-1]["content"] == "yes")
    n_neg_out = len(records_out) - n_pos_out
    stats = {
        "seed": args.seed,
        "n_train_repos": len(train_repos),
        "max_positives": args.max_positives,
        "neg_per_pos": args.neg_per_pos,
        "n_total": len(records_out),
        "n_positives": n_pos_out,
        "n_negatives": n_neg_out,
        "n_train": len(train_set),
        "n_test": len(test_set),
        "misses": misses,
    }
    (args.out_dir / "dataset_stats.json").write_text(json.dumps(stats, indent=2))

    print(
        f"\nWrote train  {train_path.relative_to(REPO_ROOT)}: {len(train_set)} records",
        file=sys.stderr,
    )
    print(
        f"Wrote test   {test_path.relative_to(REPO_ROOT)}: {len(test_set)} records",
        file=sys.stderr,
    )
    print(f"Stats: {json.dumps(stats, indent=2)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
