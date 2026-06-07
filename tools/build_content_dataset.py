"""Build the Phase-3 content classifier training dataset.

Pipeline:

1. Walk the input corpus directory for code files.
2. Run kingfisher over the corpus (no validation — strict regex+entropy).
3. For each finding, extract a ±8-line context window around the match
   line as a POSITIVE training example. Label by kingfisher confidence:
   * high   → strong positive  (label "yes", weight 1.0)
   * medium → soft positive    (label "yes", weight 0.7)
   * low    → weak positive    (label "yes", weight 0.4)
4. Sample random non-matching snippets from the same corpus as
   NEGATIVE examples (label "no", weight 1.0). Files that have ANY
   finding are excluded from negative sampling so we don't accidentally
   sample a window that overlaps a real secret.
5. Dedup near-duplicates via MinHash/LSH (Jaccard >= 0.8).
6. Format as ``messages``-style SFT JSONL for Qwen3-1.7B-Instruct.

Output:

* ``data/content/training_dataset.jsonl`` — full dataset
* ``data/content/dataset_stats.json`` — counts, per-confidence breakdown,
  dedup stats, file-list summary

Per ``docs/build_plan.md`` Phase 3, this is the canonical training-data
artifact for the Qwen3-1.7B + Unsloth LoRA stage.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from src.eval.content.corpus import walk_code_files
from src.eval.content.dedup import dedup_snippets
from src.eval.content.kingfisher import scan
from sharesift.prompt import format_sft_example
from src.eval.content.snippet import extract_around_line, random_snippet

DEFAULT_OUTPUT_DIR = REPO_ROOT / "data" / "content"


def _sample_negatives(
    files: list[Path],
    n_target: int,
    *,
    rng: random.Random,
    window_lines: int,
) -> list[str]:
    """Sample ``n_target`` random snippets from files known to have no
    kingfisher findings. Returns the snippet text list; tries up to 3x
    the target count to handle files that fail extraction (too short,
    binary, etc.)."""
    out: list[str] = []
    attempts = 0
    max_attempts = max(3 * n_target, 20)
    while len(out) < n_target and attempts < max_attempts:
        attempts += 1
        if not files:
            break
        f = rng.choice(files)
        s = random_snippet(f, window_lines=window_lines, rng=rng)
        if s:
            out.append(s)
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument(
        "--corpus",
        type=Path,
        required=True,
        help="Directory to scan (code files walked recursively).",
    )
    p.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    p.add_argument(
        "--window-before",
        type=int,
        default=8,
        help="Context lines above the match line.",
    )
    p.add_argument(
        "--window-after",
        type=int,
        default=8,
        help="Context lines below the match line.",
    )
    p.add_argument(
        "--neg-window-lines",
        type=int,
        default=16,
        help="Window size for negative-sample random snippets.",
    )
    p.add_argument(
        "--neg-ratio",
        type=float,
        default=2.0,
        help="Negatives per positive (default 2.0).",
    )
    p.add_argument(
        "--dedup-threshold",
        type=float,
        default=0.8,
        help="Jaccard similarity threshold for MinHash dedup.",
    )
    p.add_argument(
        "--confidence",
        default="low",
        choices=["low", "medium", "high"],
        help="Minimum kingfisher confidence level to include.",
    )
    p.add_argument("--seed", type=int, default=2026)
    args = p.parse_args(argv)

    if not args.corpus.exists():
        print(f"error: corpus path {args.corpus} does not exist", file=sys.stderr)
        return 1

    print(f"Walking corpus at {args.corpus}", file=sys.stderr)
    files = list(walk_code_files(args.corpus))
    print(f"  {len(files)} code files identified", file=sys.stderr)

    # Pass the corpus root (single path) to kingfisher rather than the
    # full file list — passing thousands of paths as argv breaks on
    # ``ARG_MAX`` (typically 128KB). Kingfisher walks recursively
    # internally with its own (broader) file filter; we use ``files``
    # only for clean-file selection during negative sampling.
    print(
        f"Running kingfisher (--no-validate, --confidence {args.confidence})...",
        file=sys.stderr,
    )
    findings = scan([args.corpus], confidence=args.confidence)
    print(f"  {len(findings)} findings", file=sys.stderr)

    # Build positives: one snippet per finding.
    positives: list[tuple[str, str, str]] = []  # (snippet, label, confidence)
    files_with_findings: set[Path] = set()
    for f in findings:
        snippet = extract_around_line(
            f.path,
            f.line,
            before=args.window_before,
            after=args.window_after,
        )
        if snippet is None:
            continue
        positives.append((snippet, "yes", f.confidence))
        files_with_findings.add(f.path)
    print(
        f"  {len(positives)} positives extracted; "
        f"{len(files_with_findings)} files yielded ≥1 finding",
        file=sys.stderr,
    )

    # Negatives: random snippets from files with no findings.
    rng = random.Random(args.seed)
    clean_files = [f for f in files if f not in files_with_findings]
    n_negatives = int(len(positives) * args.neg_ratio)
    print(
        f"Sampling {n_negatives} negatives from {len(clean_files)} clean files",
        file=sys.stderr,
    )
    negatives = _sample_negatives(
        clean_files,
        n_negatives,
        rng=rng,
        window_lines=args.neg_window_lines,
    )
    print(f"  {len(negatives)} negatives sampled", file=sys.stderr)

    # Dedup — across the whole pool. Positives are inserted first so
    # they survive collisions with the more-numerous negatives.
    all_snippets = (
        [(t, l, c) for (t, l, c) in positives]
        + [(t, "no", "negative") for t in negatives]
    )
    snippet_texts = [s[0] for s in all_snippets]
    deduped_texts, n_dropped = dedup_snippets(
        snippet_texts, threshold=args.dedup_threshold
    )
    kept_set = set(deduped_texts)
    deduped = [s for s in all_snippets if s[0] in kept_set]
    print(
        f"Dedup: kept {len(deduped)}, dropped {n_dropped}", file=sys.stderr
    )

    # Write JSONL.
    args.output_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.output_dir / "training_dataset.jsonl"
    with out_path.open("w", encoding="utf-8") as f:
        for snippet, label, _conf in deduped:
            f.write(json.dumps(format_sft_example(snippet, label)) + "\n")

    # Stats.
    label_counts = Counter(l for _, l, _ in deduped)
    conf_counts = Counter(c for _, _, c in deduped)
    stats = {
        "corpus_root": str(args.corpus),
        "code_files_scanned": len(files),
        "files_with_findings": len(files_with_findings),
        "findings": len(findings),
        "positives_extracted": len(positives),
        "negatives_sampled": len(negatives),
        "dedup_dropped": n_dropped,
        "final_size": len(deduped),
        "label_counts": dict(label_counts),
        "confidence_counts": dict(conf_counts),
        "config": {
            "window_before": args.window_before,
            "window_after": args.window_after,
            "neg_window_lines": args.neg_window_lines,
            "neg_ratio": args.neg_ratio,
            "dedup_threshold": args.dedup_threshold,
            "confidence_floor": args.confidence,
            "seed": args.seed,
        },
    }
    (args.output_dir / "dataset_stats.json").write_text(
        json.dumps(stats, indent=2), encoding="utf-8"
    )
    print(
        f"\nWrote {len(deduped)} records to {out_path.relative_to(REPO_ROOT)}"
    )
    print(
        f"Stats: {label_counts} | confidence: {conf_counts}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
