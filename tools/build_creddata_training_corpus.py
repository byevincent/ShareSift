"""Build v0.6 content classifier training corpus from CredData.

v0.6 pivots from "live-Active harvest from GitHub" (Tier-2.2 found 0
actives in the existing corpus + the realistic base rate in fresh
public code is near zero due to provider auto-revocation) to **using
CredData's static obfuscated corpus as the training source with
Kingfisher's pattern detection as the labeling oracle**.

Why this works
==============
* Kingfisher's 925 rules use entropy + context + pattern matching,
  not just regex — much higher label quality than v0p3's LLM-rule
  regex labels (which the 2026-05-31 audit found were ~96% noise
  on externally-curated benchmarks).
* CredData's corpus is obfuscated (real credentials replaced with
  shape-preserving synthetic values), so live-validation isn't
  meaningful anyway. The *patterns* are real.
* No time-decay: corpus is static.

Avoiding contamination
======================
The existing eval benchmark (``data/eval/creddata_benchmark.jsonl``)
samples records from 233 of CredData's 333 repos. To avoid leakage,
this script:

1. Splits the 333 repos deterministically by hash-sorted order (seed
   2026): first 50 → eval, remaining 283 → training.
2. Builds the training corpus ONLY from the 283 training repos.
3. The companion script
   ``tools/rebuild_creddata_eval_benchmark.py`` rebuilds the eval
   benchmark using only the 50 held-out repos. Run that one before
   evaluating v0p4 to ensure the comparison is clean.

Labeling
========
Positive (``yes``): any Kingfisher finding in the file → that file is
labeled positive. The snippet shipped to the model is a ±5-line window
around the first finding (or the whole file if shorter than 12 lines).

Negative (``no``): files in training repos with **zero** Kingfisher
findings. Snippets are extracted from random offsets to match the
positive-class length distribution.

Per-file deduplication
======================
A file can have multiple findings (different rules firing on different
lines). We emit one record per file, anchored on the first finding,
to avoid the model seeing the same surrounding context multiple times.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CREDDATA_ROOT = REPO_ROOT / "data" / "external" / "creddata"
DEFAULT_OUT_DIR = REPO_ROOT / "data" / "content_v0p4"
DEFAULT_KINGFISHER_RAW = REPO_ROOT / "reports" / "creddata_training_kingfisher.jsonl"
DEFAULT_REPO_SPLIT = REPO_ROOT / "data" / "content_v0p4" / "repo_split.json"


def split_repos(seed: int, n_eval_repos: int) -> tuple[list[str], list[str]]:
    """Deterministic split of CredData repos by sorted hash. Same
    seeded ordering anywhere across machines.
    """
    data_dir = CREDDATA_ROOT / "data"
    all_repos = sorted(p.name for p in data_dir.iterdir() if p.is_dir())
    rng = random.Random(seed)
    shuffled = list(all_repos)
    rng.shuffle(shuffled)
    eval_repos = sorted(shuffled[:n_eval_repos])
    train_repos = sorted(shuffled[n_eval_repos:])
    return eval_repos, train_repos


def run_kingfisher(train_repos: list[str], raw_out: Path, kingfisher_bin: str) -> None:
    """Scan only the training-half repos. Excludes eval-half by limiting
    the input paths Kingfisher walks."""
    raw_out.parent.mkdir(parents=True, exist_ok=True)
    paths = [str(CREDDATA_ROOT / "data" / r) for r in train_repos]
    cmd = [
        kingfisher_bin, "scan", *paths,
        "--no-update-check", "--no-binary", "--no-validate",
        "--format", "jsonl", "-o", str(raw_out),
    ]
    print(
        f"Running kingfisher over {len(train_repos)} training repos...",
        file=sys.stderr,
    )
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode not in (0, 200):
        print(f"stderr: {result.stderr[-2000:]}", file=sys.stderr)
        raise RuntimeError(f"kingfisher returned {result.returncode}")
    print(f"  raw output: {raw_out.relative_to(REPO_ROOT)}", file=sys.stderr)


def parse_findings_by_file(raw_path: Path) -> dict[str, list[dict]]:
    """Group findings by absolute file path."""
    by_file: dict[str, list[dict]] = defaultdict(list)
    for line in raw_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        f = rec.get("finding", {})
        path = f.get("path") or (f.get("origin") or {}).get("path")
        if path:
            by_file[path].append(rec)
    return by_file


def _extract_snippet(file_path: Path, line_start: int, line_end: int, context: int = 5, max_chars: int = 4000) -> str:
    """±context lines around (line_start..line_end). Same cap-handling
    as build_creddata_benchmark.py for consistency."""
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return ""
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


def _extract_random_window(file_path: Path, rng: random.Random, target_lines: int = 12, max_chars: int = 4000) -> str:
    """For negative files: pick a random ``target_lines``-wide window."""
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return ""
    if not lines:
        return ""
    if len(lines) <= target_lines:
        snippet = "\n".join(lines)
    else:
        start = rng.randint(0, len(lines) - target_lines)
        snippet = "\n".join(lines[start: start + target_lines])
    if len(snippet) > max_chars:
        return snippet[:max_chars]
    return snippet


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
    p.add_argument("--n-eval-repos", type=int, default=50)
    p.add_argument("--neg-per-pos", type=float, default=2.0)
    p.add_argument("--seed", type=int, default=2026)
    p.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    p.add_argument("--raw-out", type=Path, default=DEFAULT_KINGFISHER_RAW)
    p.add_argument(
        "--kingfisher-bin",
        default=str(REPO_ROOT / ".venv" / "bin" / "kingfisher"),
    )
    p.add_argument("--skip-scan", action="store_true")
    args = p.parse_args(argv)

    rng = random.Random(args.seed)

    eval_repos, train_repos = split_repos(args.seed, args.n_eval_repos)
    print(
        f"Repo split: {len(eval_repos)} eval / {len(train_repos)} train "
        f"(seed={args.seed})",
        file=sys.stderr,
    )
    args.out_dir.mkdir(parents=True, exist_ok=True)
    split_out = args.out_dir / "repo_split.json"
    split_out.write_text(json.dumps({
        "seed": args.seed,
        "n_eval_repos": args.n_eval_repos,
        "eval_repos": eval_repos,
        "train_repos": train_repos,
    }, indent=2))
    print(f"  → {split_out.relative_to(REPO_ROOT)}", file=sys.stderr)

    if not args.skip_scan:
        run_kingfisher(train_repos, args.raw_out, args.kingfisher_bin)
    elif not args.raw_out.exists():
        print(f"--skip-scan but no raw at {args.raw_out}", file=sys.stderr)
        return 1

    by_file = parse_findings_by_file(args.raw_out)
    print(
        f"Kingfisher findings: {sum(len(v) for v in by_file.values())} "
        f"across {len(by_file)} files",
        file=sys.stderr,
    )

    # Build positive records: one per file, anchored on the first finding.
    train_repo_set = set(train_repos)
    train_data_dir = CREDDATA_ROOT / "data"
    positives: list[dict] = []
    for file_path_str, findings in by_file.items():
        file_path = Path(file_path_str)
        # Filter to training repos only (paranoid sanity check).
        # Path format: .../data/external/creddata/data/<repo>/...
        try:
            rel = file_path.relative_to(train_data_dir)
        except ValueError:
            continue
        repo = rel.parts[0]
        if repo not in train_repo_set:
            continue
        first = findings[0].get("finding", {})
        line_start = first.get("line") or 1
        line_end = line_start  # most kingfisher rules emit single-line
        snippet = _extract_snippet(file_path, line_start, line_end)
        if not snippet.strip():
            continue
        rule_names = sorted({fnd.get("rule", {}).get("name", "?") for fnd in findings})
        positives.append(_to_chat_template(snippet, "yes", {
            "source_repo": repo,
            "source_path": str(rel),
            "n_findings": len(findings),
            "rule_names": rule_names,
        }))
    print(f"Positives extracted: {len(positives)}", file=sys.stderr)

    # Build negative records from files in training repos with NO findings.
    matched_files = {Path(p) for p in by_file}
    n_neg_target = int(len(positives) * args.neg_per_pos)
    candidate_negatives: list[Path] = []
    for repo in train_repos:
        repo_root = train_data_dir / repo
        if not repo_root.is_dir():
            continue
        for f in repo_root.rglob("*"):
            if f.is_file() and f not in matched_files:
                # Cheap heuristics to skip binaries kingfisher would have
                # already excluded — and pure-empty files.
                if f.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".tar", ".gz", ".bz2", ".woff", ".woff2", ".ttf", ".eot", ".ico", ".bin", ".exe", ".dll", ".so", ".dylib"}:
                    continue
                try:
                    if f.stat().st_size == 0:
                        continue
                except OSError:
                    continue
                candidate_negatives.append(f)
    print(
        f"Candidate negative files: {len(candidate_negatives)} "
        f"(target: {n_neg_target})",
        file=sys.stderr,
    )
    rng.shuffle(candidate_negatives)

    negatives: list[dict] = []
    for f in candidate_negatives:
        if len(negatives) >= n_neg_target:
            break
        snippet = _extract_random_window(f, rng)
        if not snippet.strip():
            continue
        try:
            rel = f.relative_to(train_data_dir)
        except ValueError:
            continue
        repo = rel.parts[0]
        negatives.append(_to_chat_template(snippet, "no", {
            "source_repo": repo,
            "source_path": str(rel),
            "n_findings": 0,
            "rule_names": [],
        }))
    print(f"Negatives extracted: {len(negatives)}", file=sys.stderr)

    # Shuffle + 80/20 train/test split.
    all_records = positives + negatives
    rng.shuffle(all_records)
    n_test = int(len(all_records) * 0.2)
    test_set = all_records[:n_test]
    train_set = all_records[n_test:]

    train_path = args.out_dir / "train_split.jsonl"
    test_path = args.out_dir / "test_split.jsonl"
    with train_path.open("w", encoding="utf-8") as f:
        for r in train_set:
            f.write(json.dumps(r) + "\n")
    with test_path.open("w", encoding="utf-8") as f:
        for r in test_set:
            f.write(json.dumps(r) + "\n")

    stats = {
        "seed": args.seed,
        "n_train_repos": len(train_repos),
        "n_eval_repos": len(eval_repos),
        "n_positives": len(positives),
        "n_negatives": len(negatives),
        "n_train": len(train_set),
        "n_test": len(test_set),
        "neg_per_pos_actual": len(negatives) / max(1, len(positives)),
    }
    (args.out_dir / "dataset_stats.json").write_text(json.dumps(stats, indent=2))

    print(f"\nWrote train  {train_path.relative_to(REPO_ROOT)}: {len(train_set)} records", file=sys.stderr)
    print(f"Wrote test   {test_path.relative_to(REPO_ROOT)}: {len(test_set)} records", file=sys.stderr)
    print(f"Stats: {json.dumps(stats, indent=2)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
