"""v0.10.1: Build content classifier training corpus from docx-corpus.

v0.8 found that v0p5's CredData F1=0.853 is a misleading proxy for
real-share quality — the model trained on source-code snippets fails
on business-document content (recall collapses 0.820 → 0.254). v0.10
trains v0p6 directly on the docx-corpus distribution v0p5 fails on,
salted with the same Kingfisher-derived credential strings.

Leak prevention vs v0.8 eval benchmark
======================================

The v0.8 benchmark (``data/eval/docx_salted_benchmark_10.jsonl``)
uses 1772 docs sampled from docx-corpus. This script reads the
benchmark's ``doc_id`` field, excludes those IDs from the training
sample, and pulls additional fresh docs. The v0.8 benchmark remains
strictly held-out — we never see those docs in training.

Procedure
=========

1. Load docx-corpus metadata from HuggingFace.
2. Filter to enterprise-shaped doc types (legal/reports/forms/manuals/
   specifications), English, confidence ≥0.7.
3. Drop the v0.8-benchmark IDs.
4. Sample ``--n-target`` records (default 5000).
5. Download .docx files in parallel, extract text via python-docx.
6. Salt a fraction (rate=positive-rate) with credentials from the
   v0.6 Kingfisher findings — same source as v0.8 to keep salt
   distribution consistent (the bias of v0p4 winning v0.8 partly
   because of Kingfisher labels reverses here: v0p6 trains on
   Kingfisher-derived strings, removing v0p5's source-code-context
   dependence by construction).
7. Emit chat-template JSONL at ``data/content_v0p6/`` with 80/20
   train/test split.

This is symmetric to v0.7's CredData hand-label corpus (which fixed
v0p4's Kingfisher-only-pattern coverage gap on the source-code
distribution). v0.10 fixes the business-document distribution v0p5
fails on.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import random
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_V08_BENCH = REPO_ROOT / "data" / "eval" / "docx_salted_benchmark_10.jsonl"
DEFAULT_KINGFISHER_RAW = REPO_ROOT / "reports" / "creddata_training_kingfisher.jsonl"
DEFAULT_OUT_DIR = REPO_ROOT / "data" / "content_v0p6"
DEFAULT_DOWNLOAD_DIR = REPO_ROOT / "data" / "external" / "docx_corpus_cache"


_SYSTEM_PROMPT = (
    "You are a security analyst. Examine the code snippet below and determine "
    "whether it contains a hardcoded secret — an API key, password, private "
    "key, database credential, token, or other credential material embedded "
    "as a literal value in the code. Answer with exactly one word: "
    '"yes" or "no".'
)


_INJECTION_PREFIXES = (
    "The password is: ",
    "API key: ",
    "Connection string: ",
    "Auth token: ",
    "Database URL: ",
    "Private key (do not share): ",
    "Admin credentials: ",
    "Bearer token: ",
    "Access key: ",
    "Login: admin / Password: ",
)


def _load_kingfisher_creds(path: Path, min_chars: int = 12, max_chars: int = 200) -> list[str]:
    creds: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        snippet = rec.get("finding", {}).get("snippet", "")
        if min_chars <= len(snippet) <= max_chars:
            creds.append(snippet)
    return creds


def _salt_text(text: str, cred: str, rng: random.Random) -> str:
    lines = text.splitlines() or [""]
    insert_at = rng.randint(0, len(lines))
    if rng.random() < 0.8:
        line = rng.choice(_INJECTION_PREFIXES) + cred
    else:
        line = cred
    return "\n".join(lines[:insert_at] + [line] + lines[insert_at:])


def _to_chat_template(snippet: str, label: str, meta: dict) -> dict:
    return {
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": snippet},
            {"role": "assistant", "content": label},
        ],
        **meta,
    }


def _download_docx(url: str, dest: Path, timeout: float = 20.0) -> bool:
    if dest.exists() and dest.stat().st_size > 0:
        return True
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "truffler-research-bench/0.10"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
        if not data:
            return False
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        return True
    except Exception:
        return False


def _extract_docx_text(path: Path) -> str:
    try:
        from docx import Document  # type: ignore[import-not-found]
    except ImportError:
        print("ERROR: python-docx not installed", file=sys.stderr)
        sys.exit(2)
    try:
        doc = Document(str(path))
        return "\n".join(p.text for p in doc.paragraphs if p.text)
    except Exception:
        return ""


def _truncate(text: str, max_chars: int = 4000) -> str:
    return text[:max_chars] if len(text) > max_chars else text


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "--n-target",
        type=int,
        default=5000,
        help="How many fresh docx-corpus docs to sample (excluding v0.8 benchmark IDs).",
    )
    p.add_argument(
        "--positive-rate",
        type=float,
        default=0.33,
        help="Fraction of usable docs to salt with credentials.",
    )
    p.add_argument(
        "--types",
        nargs="+",
        default=["legal", "reports", "forms", "manuals", "specifications"],
    )
    p.add_argument("--min-confidence", type=float, default=0.7)
    p.add_argument("--language", default="en")
    p.add_argument("--v08-bench", type=Path, default=DEFAULT_V08_BENCH)
    p.add_argument("--kingfisher-raw", type=Path, default=DEFAULT_KINGFISHER_RAW)
    p.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    p.add_argument("--download-dir", type=Path, default=DEFAULT_DOWNLOAD_DIR)
    p.add_argument("--parallel", type=int, default=16)
    p.add_argument("--seed", type=int, default=2027)  # different from v0.8's 2026
    p.add_argument("--skip-download", action="store_true")
    args = p.parse_args(argv)

    rng = random.Random(args.seed)

    # Step 1: identify excluded IDs.
    excluded_ids: set[str] = set()
    if args.v08_bench.exists():
        for line in args.v08_bench.read_text().splitlines():
            if not line.strip():
                continue
            try:
                excluded_ids.add(json.loads(line)["doc_id"])
            except (json.JSONDecodeError, KeyError):
                continue
    print(f"Excluding {len(excluded_ids)} v0.8 benchmark doc IDs", file=sys.stderr)

    # Step 2: load metadata.
    try:
        from datasets import load_dataset  # type: ignore[import-not-found]
    except ImportError:
        print("ERROR: datasets not installed", file=sys.stderr)
        return 2

    print("Loading docx-corpus metadata from HuggingFace...", file=sys.stderr)
    ds = load_dataset("superdoc-dev/docx-corpus", split="train")
    target_types = set(args.types)
    filtered = ds.filter(
        lambda r: (
            r["language"] == args.language
            and r["type"] in target_types
            and r["confidence"] >= args.min_confidence
            and r["id"] not in excluded_ids
        ),
        load_from_cache_file=False,
    )
    print(
        f"  filtered (lang/type/conf/not-in-v0.8): {len(filtered)} rows",
        file=sys.stderr,
    )

    # Step 3: sample.
    indices = list(range(len(filtered)))
    rng.shuffle(indices)
    sampled = [filtered[i] for i in indices[: args.n_target]]
    print(f"  sampling {len(sampled)} fresh docs", file=sys.stderr)

    # Step 4: download.
    args.download_dir.mkdir(parents=True, exist_ok=True)
    if not args.skip_download:
        print(
            f"Downloading {len(sampled)} .docx via {args.parallel} parallel workers...",
            file=sys.stderr,
        )
        ok = fail = 0

        def fetch(rec):
            dest = args.download_dir / f"{rec['id']}.docx"
            return _download_docx(rec["url"], dest), dest

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as pool:
            for i, (status, _) in enumerate(pool.map(fetch, sampled)):
                if status:
                    ok += 1
                else:
                    fail += 1
                if (i + 1) % 200 == 0:
                    print(f"  [{i + 1}/{len(sampled)}] ok={ok} fail={fail}", file=sys.stderr)
        print(f"Download: ok={ok}, fail={fail}", file=sys.stderr)

    # Step 5: extract text.
    print("Extracting text...", file=sys.stderr)
    extracted: list[dict] = []
    for rec in sampled:
        dest = args.download_dir / f"{rec['id']}.docx"
        if not dest.exists():
            continue
        text = _extract_docx_text(dest)
        if not text.strip() or len(text) < 200:
            continue
        extracted.append({
            "id": rec["id"],
            "type": rec["type"],
            "topic": rec["topic"],
            "text": text,
        })
    print(f"Usable: {len(extracted)} docs", file=sys.stderr)
    if len(extracted) < 500:
        print(f"ERROR: only {len(extracted)} usable docs", file=sys.stderr)
        return 1

    # Step 6: salt + label.
    creds = _load_kingfisher_creds(args.kingfisher_raw)
    if not creds:
        print(f"ERROR: no usable credentials in {args.kingfisher_raw}", file=sys.stderr)
        return 1
    print(f"Loaded {len(creds)} candidate credentials", file=sys.stderr)
    rng.shuffle(creds)

    n_positive = int(len(extracted) * args.positive_rate)
    positive_indices = set(rng.sample(range(len(extracted)), n_positive))
    print(
        f"Salting {n_positive} of {len(extracted)} docs as positives "
        f"(rate {args.positive_rate})",
        file=sys.stderr,
    )

    records_out: list[dict] = []
    for i, doc in enumerate(extracted):
        if i in positive_indices:
            cred = creds[i % len(creds)]
            salted_text = _salt_text(doc["text"], cred, rng)
            snippet = _truncate(salted_text)
            records_out.append(_to_chat_template(snippet, "yes", {
                "doc_id": doc["id"],
                "doc_type": doc["type"],
                "doc_topic": doc["topic"],
                "salted": True,
            }))
        else:
            snippet = _truncate(doc["text"])
            records_out.append(_to_chat_template(snippet, "no", {
                "doc_id": doc["id"],
                "doc_type": doc["type"],
                "doc_topic": doc["topic"],
                "salted": False,
            }))

    rng.shuffle(records_out)

    # Step 7: 80/20 split.
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

    n_pos = sum(1 for r in records_out if r["messages"][-1]["content"] == "yes")
    stats = {
        "seed": args.seed,
        "n_target": args.n_target,
        "n_excluded_v08_ids": len(excluded_ids),
        "n_usable": len(extracted),
        "positive_rate": args.positive_rate,
        "n_total": len(records_out),
        "n_positives": n_pos,
        "n_negatives": len(records_out) - n_pos,
        "n_train": len(train_set),
        "n_test": len(test_set),
    }
    (args.out_dir / "dataset_stats.json").write_text(json.dumps(stats, indent=2))

    print(f"\nWrote train {train_path.relative_to(REPO_ROOT)}: {len(train_set)} records", file=sys.stderr)
    print(f"Wrote test  {test_path.relative_to(REPO_ROOT)}: {len(test_set)} records", file=sys.stderr)
    print(json.dumps(stats, indent=2), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
