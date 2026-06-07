"""Build a Truffler-evaluable benchmark from the CredData corpus.

Tier-2.3 audit item. CredData (Samsung) is a publicly-labeled
credential dataset with per-line labels (GroundTruth=T/F) across
~333 repos. The Biringa & Kul 2025 paper reports F1=0.985 on the full
set with a Mistral-7B-Instruct-v0.3 LoRA; we evaluate Truffler's
Qwen3-1.7B content classifier on a stratified sample for a directly
comparable directional number.

Procedure:
1. Read all metadata CSVs from ``data/external/creddata/meta/``.
2. Aggregate + stratified-sample N records balanced across
   GroundTruth=T/F.
3. Read each referenced source file from the local CredData clone at
   ``data/external/creddata/<FilePath>``.
4. Extract a snippet centered on LineStart..LineEnd with ±context lines.
5. Write a chat-template JSONL compatible with
   ``tools/eval_content_classifier.py``.

Requires the official downloader to have been run first:
    cd data/external/creddata && python download_data.py --jobs 4
which obfuscates real credentials and lands sources under
``data/external/creddata/data/<repo-hash>/...``.
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


def _list_meta_files() -> list[Path]:
    return sorted((CREDDATA_ROOT / "meta").glob("*.csv"))


def _fetch_meta(path: Path) -> list[dict]:
    return list(csv.DictReader(path.open(encoding="utf-8")))


def _fetch_file(file_path: str) -> str | None:
    """Read source from the local CredData clone. ``file_path`` is the
    relative path from the CSV's FilePath column, in the form
    ``data/<repo-hash>/<subdir>/<file>``."""
    full = CREDDATA_ROOT / file_path
    if not full.exists():
        return None
    try:
        return full.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        print(f"  ! read failed: {file_path} ({e})", file=sys.stderr)
        return None


def _extract_snippet(
    source: str, line_start: int, line_end: int, context: int = 5, max_chars: int = 4000
) -> str:
    lines = source.splitlines()
    if not lines:
        return ""
    lo = max(0, line_start - 1 - context)
    hi = min(len(lines), line_end + context)
    snippet = "\n".join(lines[lo:hi])
    if len(snippet) <= max_chars:
        return snippet
    # Single-line files (often minified JS/HTML) blow past max_chars
    # with one line. Anchor on the LineStart character offset if the
    # secret line is in-bounds, otherwise truncate from the start.
    secret_line = lines[line_start - 1] if 0 < line_start <= len(lines) else lines[0]
    if len(secret_line) > max_chars:
        # The secret-bearing line itself is huge — center on it.
        # No useful line breaks to preserve; just take a window.
        mid = len(secret_line) // 2
        half = max_chars // 2
        return secret_line[max(0, mid - half) : mid + half]
    # Otherwise, trim context lines symmetrically until fits.
    while len(snippet) > max_chars and (lo > 0 or hi < len(lines)):
        if lo > 0:
            lo += 1
        if hi < len(lines):
            hi -= 1
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "data" / "eval" / "creddata_benchmark.jsonl",
    )
    parser.add_argument(
        "--max-positives",
        type=int,
        default=500,
        help="Cap on positive records (GroundTruth=T). The full CredData "
        "corpus has ~7700 positives across categories; the eval cost on "
        "Qwen3-1.7B is the dominant constraint.",
    )
    parser.add_argument(
        "--negatives-per-positive",
        type=float,
        default=2.0,
        help="Ratio of negatives to positives. CredData's natural ratio "
        "is ~25:1 negatives:positives which is unrealistic for a "
        "secrets-detection eval. 2:1 keeps the negative class hard but "
        "doesn't drown the signal.",
    )
    parser.add_argument(
        "--context-lines",
        type=int,
        default=5,
    )
    parser.add_argument("--seed", type=int, default=2026)
    args = parser.parse_args()

    rng = random.Random(args.seed)

    print("Reading CredData meta/ files...", file=sys.stderr)
    all_meta = _list_meta_files()
    print(f"  found {len(all_meta)} meta files", file=sys.stderr)

    # Aggregate all rows; each row is one labeled line.
    all_rows: list[dict] = []
    for path in all_meta:
        try:
            all_rows.extend(_fetch_meta(path))
        except Exception as e:
            print(f"  ! {path.name}: {e}", file=sys.stderr)
    print(f"  loaded {len(all_rows)} labeled rows", file=sys.stderr)

    positives = [r for r in all_rows if r.get("GroundTruth") == "T"]
    negatives = [r for r in all_rows if r.get("GroundTruth") == "F"]
    print(
        f"  {len(positives)} positives, {len(negatives)} negatives "
        f"(natural ratio {len(negatives) / max(1, len(positives)):.1f}:1)",
        file=sys.stderr,
    )

    rng.shuffle(positives)
    rng.shuffle(negatives)
    picks = positives[: args.max_positives]
    n_neg = int(len(picks) * args.negatives_per_positive)
    picks.extend(negatives[:n_neg])
    rng.shuffle(picks)
    print(
        f"  sampled {len(picks)} records "
        f"({sum(1 for r in picks if r['GroundTruth'] == 'T')} pos, "
        f"{sum(1 for r in picks if r['GroundTruth'] == 'F')} neg)",
        file=sys.stderr,
    )

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
        snippet = _extract_snippet(source, ls, le, context=args.context_lines)
        if not snippet.strip():
            misses["empty_snippet"] += 1
            continue
        label = "yes" if row["GroundTruth"] == "T" else "no"
        records_out.append(_to_chat_template(snippet, label))

    print(
        f"\nCollected {len(records_out)} records "
        f"(misses: {misses})",
        file=sys.stderr,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as f:
        for rec in records_out:
            f.write(json.dumps(rec) + "\n")
    print(f"Wrote {args.output.relative_to(REPO_ROOT)}", file=sys.stderr)

    # Quick stats
    yes_n = sum(1 for r in records_out if r["messages"][-1]["content"] == "yes")
    no_n = sum(1 for r in records_out if r["messages"][-1]["content"] == "no")
    print(f"  yes: {yes_n}, no: {no_n}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
