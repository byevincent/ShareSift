"""Rebuild the CredData eval benchmark from the 50 held-out repos.

Companion to ``tools/build_creddata_training_corpus.py``. The original
benchmark (built by ``tools/build_creddata_benchmark.py``) sampled from
all 333 CredData repos, which overlaps with what v0.6's training will
see. To keep v0.6 → CredData comparisons leak-free, this script
samples from ONLY the 50 repos reserved for evaluation in
``data/content_v0p4/repo_split.json``.

Sampling matches the original methodology: stratified by GroundTruth
{T, F}, snippet capped at 4000 chars around LineStart..LineEnd ±5
context. The output target size is calibrated so the resulting
benchmark roughly matches the v0.5 1500-record version while staying
strictly within the held-out repos.

Labels come from CredData's GroundTruth column (hand-labeled by
Samsung's team), not from Kingfisher — this is the *external*
benchmark, fully independent of v0.6's training labeling oracle.
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
DEFAULT_OUTPUT = REPO_ROOT / "data" / "eval" / "creddata_benchmark_v06.jsonl"


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


def _to_chat_template(snippet: str, label: str) -> dict:
    return {
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": snippet},
            {"role": "assistant", "content": label},
        ]
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--repo-split", type=Path, default=DEFAULT_REPO_SPLIT)
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    p.add_argument("--max-positives", type=int, default=400)
    p.add_argument("--negatives-per-positive", type=float, default=2.0)
    p.add_argument("--seed", type=int, default=2026)
    args = p.parse_args(argv)

    split = json.loads(args.repo_split.read_text())
    eval_repos = set(split["eval_repos"])
    print(f"Eval repos: {len(eval_repos)}", file=sys.stderr)

    # Read all metadata rows, filter to eval repos.
    all_rows: list[dict] = []
    for meta_csv in sorted((CREDDATA_ROOT / "meta").glob("*.csv")):
        for row in csv.DictReader(meta_csv.open(encoding="utf-8")):
            if row.get("RepoName") in eval_repos:
                all_rows.append(row)
    print(f"Metadata rows from eval repos: {len(all_rows)}", file=sys.stderr)

    positives = [r for r in all_rows if r.get("GroundTruth") == "T"]
    negatives = [r for r in all_rows if r.get("GroundTruth") == "F"]
    print(
        f"  positives: {len(positives)}, negatives: {len(negatives)} "
        f"(ratio {len(negatives) / max(1, len(positives)):.1f}:1)",
        file=sys.stderr,
    )

    rng = random.Random(args.seed)
    rng.shuffle(positives)
    rng.shuffle(negatives)

    picks_pos = positives[: args.max_positives]
    n_neg = int(len(picks_pos) * args.negatives_per_positive)
    picks_neg = negatives[:n_neg]
    picks = picks_pos + picks_neg
    rng.shuffle(picks)

    records_out = []
    misses = {"not_found": 0, "empty_snippet": 0, "bad_lines": 0}
    for i, row in enumerate(picks):
        if (i + 1) % 200 == 0:
            print(f"  [{i + 1}/{len(picks)}]", file=sys.stderr)
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
        records_out.append(_to_chat_template(snippet, label))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as f:
        for rec in records_out:
            f.write(json.dumps(rec) + "\n")

    n_pos = sum(1 for r in records_out if r["messages"][-1]["content"] == "yes")
    n_neg = sum(1 for r in records_out if r["messages"][-1]["content"] == "no")
    print(
        f"\nWrote {len(records_out)} records ({n_pos} pos / {n_neg} neg) "
        f"to {args.output.relative_to(REPO_ROOT)}",
        file=sys.stderr,
    )
    print(f"Misses: {misses}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
