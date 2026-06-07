"""Build a salted-document benchmark from docx-corpus.

v0.8. CredData (the v0.6/v0.7 eval source) is source-code-with-credentials
in source-code-without-credentials. Real Truffler deployment targets
SMB shares full of .docx legal documents, .xlsx spreadsheets, .pdf
reports — business prose with credentials embedded rarely. The
negative-class distribution between training (CredData) and deployment
(real shares) is wildly different, so v0p5's CredData F1=0.853 may not
transfer.

This script builds an evaluation benchmark from docx-corpus (737K
classified .docx files from Common Crawl, ODC-BY licensed) salted with
real-shape credentials extracted from Kingfisher's CredData scan. The
result is a benchmark that exercises the business-document negative
class CredData can't.

Procedure:

1. Load docx-corpus metadata from HuggingFace (small parquet, ~63MB).
2. Filter to English, ``min_confidence`` (default 0.7), enterprise-ish
   types (legal, reports, forms, manuals — closest to share content).
3. Sample N documents, download each from the docxcorp CDN.
4. Extract text via ``python-docx``.
5. Salt a fraction K with credentials extracted from Kingfisher's
   CredData scan output (``reports/creddata_training_kingfisher.jsonl``
   or a fallback /tmp file). Inject mid-document with realistic
   prefix patterns ("the password is: <cred>", etc.) 80% of the time;
   raw insertion 20%.
6. Emit chat-template JSONL compatible with
   ``tools/eval_content_classifier.py``.

The salting source matters: if we synthesize fake-shape credentials
they may not pass kingfisher's entropy thresholds AND may not look like
real positives the classifier saw at training time. Reusing real
strings from the same kingfisher-CredData scan gives us
distribution-matched positives.

Output: ``data/eval/docx_salted_benchmark_{rate}.jsonl`` where rate ∈
{10, 100, 1000} → 1 positive per N records.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import io
import json
import random
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_KINGFISHER_RAW = REPO_ROOT / "reports" / "creddata_training_kingfisher.jsonl"
DEFAULT_OUT_DIR = REPO_ROOT / "data" / "eval"
DEFAULT_DOWNLOAD_DIR = REPO_ROOT / "data" / "external" / "docx_corpus_cache"


_SYSTEM_PROMPT = (
    "You are a security analyst. Examine the code snippet below and determine "
    "whether it contains a hardcoded secret — an API key, password, private "
    "key, database credential, token, or other credential material embedded "
    "as a literal value in the code. Answer with exactly one word: "
    '"yes" or "no".'
)


def _load_kingfisher_creds(path: Path, min_chars: int = 12, max_chars: int = 200) -> list[dict]:
    """Pull credential strings from a kingfisher --format jsonl output.

    Filter by length to drop trivially-short matches (which probably
    won't survive snippet truncation/context noise) and absurdly-long
    matches (which would dominate the prose context).
    """
    creds: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        f = rec.get("finding", {})
        snippet = f.get("snippet", "")
        if min_chars <= len(snippet) <= max_chars:
            creds.append({
                "snippet": snippet,
                "rule": rec.get("rule", {}).get("name", "unknown"),
            })
    return creds


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


def _salt_document(text: str, cred: str, rng: random.Random) -> tuple[str, int]:
    """Inject ``cred`` into ``text`` at a random line position. Return
    (new_text, injection_line_offset).

    80% of the time use a realistic prose prefix; 20% raw injection.
    """
    lines = text.splitlines()
    if not lines:
        lines = [""]
    insert_at = rng.randint(0, len(lines))
    if rng.random() < 0.8:
        prefix = rng.choice(_INJECTION_PREFIXES)
        line = prefix + cred
    else:
        line = cred
    new_lines = lines[:insert_at] + [line] + lines[insert_at:]
    return "\n".join(new_lines), insert_at


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
        req = urllib.request.Request(url, headers={"User-Agent": "truffler-bench/0.8"})
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
    """Extract paragraph text from a .docx. Returns "" on parse failure."""
    try:
        from docx import Document  # type: ignore[import-not-found]
    except ImportError:
        print(
            "ERROR: python-docx not installed. Run: uv add python-docx",
            file=sys.stderr,
        )
        sys.exit(2)
    try:
        doc = Document(str(path))
        return "\n".join(p.text for p in doc.paragraphs if p.text)
    except Exception:
        return ""


def _truncate_snippet(text: str, max_chars: int = 4000) -> str:
    """Match the eval-pipeline length cap. Truncate at the end since
    docx text doesn't have line-shaped boundaries to anchor on."""
    if len(text) <= max_chars:
        return text
    return text[:max_chars]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "--n-target",
        type=int,
        default=2000,
        help="How many documents to download + include in the benchmark.",
    )
    p.add_argument(
        "--positive-rate",
        type=int,
        default=10,
        choices=[10, 100, 1000],
        help="1 positive per N records (10=balanced-ish, 100=realistic, 1000=share-realistic).",
    )
    p.add_argument(
        "--types",
        nargs="+",
        default=["legal", "reports", "forms", "manuals", "specifications"],
        help="docx-corpus document types to include.",
    )
    p.add_argument(
        "--min-confidence",
        type=float,
        default=0.7,
        help="docx-corpus classification confidence threshold.",
    )
    p.add_argument("--language", default="en")
    p.add_argument(
        "--kingfisher-raw",
        type=Path,
        default=DEFAULT_KINGFISHER_RAW,
        help="Kingfisher JSONL to source credential strings from.",
    )
    p.add_argument(
        "--out-dir", type=Path, default=DEFAULT_OUT_DIR,
    )
    p.add_argument(
        "--download-dir", type=Path, default=DEFAULT_DOWNLOAD_DIR,
    )
    p.add_argument("--parallel", type=int, default=16)
    p.add_argument("--seed", type=int, default=2026)
    p.add_argument(
        "--skip-download",
        action="store_true",
        help="Use existing cached .docx files instead of downloading.",
    )
    args = p.parse_args(argv)

    rng = random.Random(args.seed)

    # Step 1: load docx-corpus metadata.
    print("Loading docx-corpus metadata from HuggingFace...", file=sys.stderr)
    try:
        from datasets import load_dataset  # type: ignore[import-not-found]
    except ImportError:
        print(
            "ERROR: datasets not installed. Run: uv add datasets",
            file=sys.stderr,
        )
        return 2
    ds = load_dataset("superdoc-dev/docx-corpus", split="train")
    print(f"  total rows: {len(ds)}", file=sys.stderr)

    # Filter.
    target_types = set(args.types)
    filtered = ds.filter(
        lambda r: (
            r["language"] == args.language
            and r["type"] in target_types
            and r["confidence"] >= args.min_confidence
        ),
        load_from_cache_file=False,
    )
    print(
        f"  after filter (language={args.language}, types={sorted(target_types)}, "
        f"min_confidence={args.min_confidence}): {len(filtered)} rows",
        file=sys.stderr,
    )

    # Step 2: sample.
    indices = list(range(len(filtered)))
    rng.shuffle(indices)
    sampled_idx = indices[: args.n_target]
    sampled = [filtered[i] for i in sampled_idx]

    # Step 3: download in parallel.
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
                if (i + 1) % 100 == 0:
                    print(f"  [{i + 1}/{len(sampled)}] ok={ok} fail={fail}", file=sys.stderr)
        print(f"Download done: ok={ok}, fail={fail}", file=sys.stderr)

    # Step 4: extract text + filter to documents with usable content.
    print("Extracting text from .docx...", file=sys.stderr)
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
    print(f"Usable documents: {len(extracted)}", file=sys.stderr)
    min_usable = min(100, max(10, args.n_target // 4))
    if len(extracted) < min_usable:
        print(
            f"ERROR: only {len(extracted)} usable documents, need ≥ {min_usable} — aborting.",
            file=sys.stderr,
        )
        return 1

    # Step 5: salt.
    print(
        f"Loading credentials from {args.kingfisher_raw.relative_to(REPO_ROOT)}...",
        file=sys.stderr,
    )
    creds = _load_kingfisher_creds(args.kingfisher_raw)
    if not creds:
        print(f"ERROR: no usable credentials in {args.kingfisher_raw}", file=sys.stderr)
        return 1
    print(f"  loaded {len(creds)} credential strings", file=sys.stderr)
    rng.shuffle(creds)

    n_positive = max(1, len(extracted) // args.positive_rate)
    positive_indices = set(rng.sample(range(len(extracted)), n_positive))
    print(
        f"Salting {n_positive} of {len(extracted)} docs (rate 1:{args.positive_rate})",
        file=sys.stderr,
    )

    records_out: list[dict] = []
    for i, doc in enumerate(extracted):
        if i in positive_indices:
            cred = creds[i % len(creds)]
            salted_text, inject_line = _salt_document(doc["text"], cred["snippet"], rng)
            snippet = _truncate_snippet(salted_text)
            records_out.append(_to_chat_template(snippet, "yes", {
                "doc_id": doc["id"],
                "doc_type": doc["type"],
                "doc_topic": doc["topic"],
                "inject_line": inject_line,
                "cred_rule": cred["rule"],
            }))
        else:
            snippet = _truncate_snippet(doc["text"])
            records_out.append(_to_chat_template(snippet, "no", {
                "doc_id": doc["id"],
                "doc_type": doc["type"],
                "doc_topic": doc["topic"],
            }))

    rng.shuffle(records_out)

    out_path = args.out_dir / f"docx_salted_benchmark_{args.positive_rate}.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for rec in records_out:
            f.write(json.dumps(rec) + "\n")

    n_pos = sum(1 for r in records_out if r["messages"][-1]["content"] == "yes")
    n_neg = len(records_out) - n_pos
    print(
        f"\nWrote {len(records_out)} records ({n_pos} pos / {n_neg} neg) to "
        f"{out_path.relative_to(REPO_ROOT)}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
