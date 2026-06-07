"""Audit eval-set integrity across the path- and content-classifier datasets.

Runs every leakage / duplication / metadata check we know how to do, in one
pass, against the data on disk. Each check returns an ``AuditFinding`` with a
severity grade; the script prints a summary table and writes a structured
JSON report to ``reports/audit_eval_integrity.json``.

Checks performed
================

Path classifier (``data/eval/{train_split,test_split,snaffler_blind_benchmark}.jsonl``):

* exact-path leakage across the three splits
* near-duplicate paths via char-n-gram cosine similarity (>= 0.95)
* source-field distribution (collector-tag granularity only — see notes)
* synthetic-path overlap (``data/synthetic/training_v0.jsonl``)
* benchmark internal duplicates

Content classifier (``data/content/{train_split,test_split}.jsonl``):

* exact-snippet leakage train → test
* near-duplicate leakage via MinHash at Jaccard 0.6 / 0.7 / 0.8 / 0.9
* internal label noise (same snippet, different labels) per split
* internal duplicate snippets per split
* source-file leakage (``--source-attribution``; slow, opt-in)
* label distribution of any leaked records

Cross:

* path-model training-data SHA integrity (``models/path_classifier_v0/metadata.json``)

Severity grades
===============

* ``ok``    — check passed, no action needed
* ``info``  — descriptive statistic, no action implied
* ``warn``  — material issue, action worth considering
* ``error`` — integrity issue that invalidates reported numbers

Exit code is nonzero iff any error-level finding is produced.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer

try:
    from datasketch import MinHash, MinHashLSH
    HAVE_DATASKETCH = True
except ImportError:
    HAVE_DATASKETCH = False


REPO_ROOT = Path(__file__).resolve().parent.parent

PATH_EVAL_DIR = REPO_ROOT / "data" / "eval"
PATH_TRAIN = PATH_EVAL_DIR / "train_split.jsonl"
PATH_TEST = PATH_EVAL_DIR / "test_split.jsonl"
PATH_BENCH = PATH_EVAL_DIR / "snaffler_blind_benchmark.jsonl"

CONTENT_DIR = REPO_ROOT / "data" / "content"
CONTENT_TRAIN = CONTENT_DIR / "train_split.jsonl"
CONTENT_TEST = CONTENT_DIR / "test_split.jsonl"
CONTENT_CORPUS = CONTENT_DIR / "corpus"

SYNTHETIC_PATH = REPO_ROOT / "data" / "synthetic" / "training_v0.jsonl"

PATH_MODEL_METADATA = REPO_ROOT / "models" / "path_classifier_v0" / "metadata.json"

DEFAULT_REPORT_PATH = REPO_ROOT / "reports" / "audit_eval_integrity.json"


# --- Finding structure ----------------------------------------------------


@dataclass
class AuditFinding:
    name: str
    severity: str  # "ok" / "info" / "warn" / "error"
    summary: str
    details: dict = field(default_factory=dict)


SEVERITY_RANK = {"ok": 0, "info": 1, "warn": 2, "error": 3}
SEVERITY_GLYPH = {
    "ok": "[OK]   ",
    "info": "[INFO] ",
    "warn": "[WARN] ",
    "error": "[ERROR]",
}


# --- Loaders / helpers ----------------------------------------------------


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


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


# --- Content-side checks --------------------------------------------------


def check_content_exact_leakage(
    train: list[dict], test: list[dict]
) -> AuditFinding:
    train_fps = {sha256_text(content_user_text(r)) for r in train}
    test_fps = {sha256_text(content_user_text(r)) for r in test}
    overlap_fps = train_fps & test_fps
    n_test_records_leaked = sum(
        1 for r in test if sha256_text(content_user_text(r)) in overlap_fps
    )
    if not overlap_fps:
        return AuditFinding(
            name="content_exact_leakage",
            severity="ok",
            summary="No exact-snippet leakage between content train and test splits.",
            details={"train_size": len(train), "test_size": len(test)},
        )
    pct = 100 * n_test_records_leaked / max(1, len(test))
    severity = "error" if pct >= 5 else "warn"
    return AuditFinding(
        name="content_exact_leakage",
        severity=severity,
        summary=(
            f"{n_test_records_leaked} of {len(test)} test records "
            f"({pct:.1f}%) have a byte-identical snippet in the training set."
        ),
        details={
            "train_size": len(train),
            "test_size": len(test),
            "leaked_test_records": n_test_records_leaked,
            "leaked_unique_snippets": len(overlap_fps),
        },
    )


def check_content_near_leakage(
    train: list[dict],
    test: list[dict],
    thresholds: tuple[float, ...] = (0.6, 0.7, 0.8, 0.9),
) -> list[AuditFinding]:
    if not HAVE_DATASKETCH:
        return [
            AuditFinding(
                name="content_near_leakage",
                severity="info",
                summary=(
                    "Skipped: datasketch not installed "
                    "(install via `uv sync --group content-training`)."
                ),
            )
        ]
    print("  computing MinHashes for content train + test...", file=sys.stderr)
    t0 = time.time()
    train_mh = [build_minhash(content_user_text(r)) for r in train]
    test_mh = [build_minhash(content_user_text(r)) for r in test]
    print(f"  MinHash build: {time.time() - t0:.1f}s", file=sys.stderr)

    findings: list[AuditFinding] = []
    for threshold in thresholds:
        lsh = MinHashLSH(threshold=threshold, num_perm=128)
        for i, mh in enumerate(train_mh):
            lsh.insert(f"train_{i}", mh)
        n_with_near_dup = sum(1 for mh in test_mh if lsh.query(mh))
        pct = 100 * n_with_near_dup / max(1, len(test))

        if threshold >= 0.9:
            severity = "error" if pct >= 5 else "warn" if pct >= 1 else "info"
        elif threshold >= 0.7:
            severity = "warn" if pct >= 10 else "info"
        else:
            severity = "info"

        findings.append(
            AuditFinding(
                name=f"content_near_leakage_j{int(threshold * 100)}",
                severity=severity,
                summary=(
                    f"At Jaccard >= {threshold}: {n_with_near_dup} of {len(test)} "
                    f"test snippets ({pct:.1f}%) have a near-duplicate in train."
                ),
                details={
                    "threshold": threshold,
                    "test_with_near_duplicate": n_with_near_dup,
                    "test_size": len(test),
                },
            )
        )
    return findings


def check_content_internal_duplicates(
    records: list[dict], name: str
) -> AuditFinding:
    fps = [sha256_text(content_user_text(r)) for r in records]
    counts = Counter(fps)
    repeated_fps = sum(1 for c in counts.values() if c > 1)
    redundant_records = sum(c - 1 for c in counts.values() if c > 1)
    if not redundant_records:
        return AuditFinding(
            name=f"content_internal_duplicates_{name}",
            severity="ok",
            summary=f"No duplicate snippets within {name}.",
            details={"records": len(records)},
        )
    pct = 100 * redundant_records / max(1, len(records))
    severity = "warn" if pct >= 5 else "info"
    return AuditFinding(
        name=f"content_internal_duplicates_{name}",
        severity=severity,
        summary=(
            f"{redundant_records} duplicate records inside {name} "
            f"({repeated_fps} repeated fingerprints, {pct:.1f}% redundancy)."
        ),
        details={
            "records": len(records),
            "repeated_fingerprints": repeated_fps,
            "redundant_records": redundant_records,
        },
    )


def check_content_internal_label_noise(
    records: list[dict], name: str
) -> AuditFinding:
    by_fp: dict[str, set[str]] = defaultdict(set)
    for r in records:
        by_fp[sha256_text(content_user_text(r))].add(content_label(r))
    conflicting = {fp: labels for fp, labels in by_fp.items() if len(labels) > 1}
    if not conflicting:
        return AuditFinding(
            name=f"content_internal_label_noise_{name}",
            severity="ok",
            summary=f"No conflicting labels for identical snippets in {name}.",
            details={"records": len(records)},
        )
    return AuditFinding(
        name=f"content_internal_label_noise_{name}",
        severity="warn",
        summary=(
            f"{len(conflicting)} snippet fingerprints have conflicting labels "
            f"in {name} — caps achievable F1."
        ),
        details={
            "records": len(records),
            "conflicting_fingerprints": len(conflicting),
        },
    )


def check_leak_label_breakdown(
    train: list[dict], test: list[dict]
) -> AuditFinding:
    train_fps = {sha256_text(content_user_text(r)) for r in train}
    leaked = [r for r in test if sha256_text(content_user_text(r)) in train_fps]
    if not leaked:
        return AuditFinding(
            name="content_leak_label_breakdown",
            severity="ok",
            summary="No leaked content records — nothing to break down.",
        )
    label_dist = Counter(content_label(r) for r in leaked)
    yes = label_dist.get("yes", 0)
    return AuditFinding(
        name="content_leak_label_breakdown",
        severity="info",
        summary=(
            f"Leaked test records by label: {dict(label_dist)}. "
            f"Upper-bound recall correction: if all {yes} positive-leaked records "
            f"were correctly classified, real-recall denominator drops by {yes}."
        ),
        details={
            "leaked_records": len(leaked),
            "label_distribution": dict(label_dist),
        },
    )


def check_content_source_attribution(
    train: list[dict],
    test: list[dict],
    corpus_dir: Path,
    max_files: int | None = None,
) -> AuditFinding:
    """Source-file leakage: do train and test snippets come from the same files?

    Substring-matches each unique snippet against every corpus file. Slow on
    the full corpus (~10–25 min on 55k files); opt-in via ``--source-attribution``.
    """
    if not corpus_dir.exists():
        return AuditFinding(
            name="content_source_leakage",
            severity="info",
            summary=f"Skipped: corpus directory not found at {corpus_dir}.",
        )

    print(
        f"  loading corpus from {corpus_dir.relative_to(REPO_ROOT)}...",
        file=sys.stderr,
    )
    t0 = time.time()
    corpus_files: list[tuple[str, bytes]] = []
    for p in corpus_dir.rglob("*"):
        if not p.is_file():
            continue
        try:
            data = p.read_bytes()
        except OSError:
            continue
        corpus_files.append((str(p.relative_to(corpus_dir)), data))
        if max_files and len(corpus_files) >= max_files:
            break
    print(
        f"  loaded {len(corpus_files)} files in {time.time() - t0:.1f}s",
        file=sys.stderr,
    )

    def attribute_unique(records: list[dict], label: str) -> dict[str, set[str]]:
        unique_snippets: dict[str, str] = {}
        for r in records:
            text = content_user_text(r).strip()
            if text:
                unique_snippets.setdefault(sha256_text(text), text)
        print(
            f"  attributing {len(unique_snippets)} unique {label} snippets "
            f"vs {len(corpus_files)} corpus files...",
            file=sys.stderr,
        )
        t0 = time.time()
        result: dict[str, set[str]] = {}
        for i, (fp, snippet) in enumerate(unique_snippets.items()):
            if i and i % 100 == 0:
                print(f"    {i}/{len(unique_snippets)}", file=sys.stderr)
            snippet_b = snippet.encode("utf-8", errors="ignore")
            hits: set[str] = set()
            for rel_path, file_bytes in corpus_files:
                if snippet_b in file_bytes:
                    hits.add(rel_path)
            if hits:
                result[fp] = hits
        print(
            f"  {label} attribution done in {time.time() - t0:.1f}s "
            f"({len(result)}/{len(unique_snippets)} attributed)",
            file=sys.stderr,
        )
        return result

    train_attribution = attribute_unique(train, "train")
    test_attribution = attribute_unique(test, "test")

    train_source_files: set[str] = set()
    for files in train_attribution.values():
        train_source_files.update(files)

    n_test_attributed = len(test_attribution)
    n_test_with_shared_source = sum(
        1 for files in test_attribution.values() if files & train_source_files
    )

    if n_test_attributed == 0:
        return AuditFinding(
            name="content_source_leakage",
            severity="warn",
            summary=(
                "Source attribution failed: zero test snippets matched a corpus "
                "file. The corpus may have moved/changed, or snippets were "
                "post-processed in a way that breaks exact substring match."
            ),
            details={"test_unique_snippets": 0, "corpus_files_loaded": len(corpus_files)},
        )

    pct = 100 * n_test_with_shared_source / n_test_attributed
    severity = "error" if pct >= 50 else "warn" if pct >= 20 else "info"
    return AuditFinding(
        name="content_source_leakage",
        severity=severity,
        summary=(
            f"{n_test_with_shared_source} of {n_test_attributed} attributed test "
            f"snippets ({pct:.1f}%) come from a source file that also contributed "
            f"a train snippet."
        ),
        details={
            "test_unique_attributed": n_test_attributed,
            "test_with_shared_source_file": n_test_with_shared_source,
            "train_unique_attributed": len(train_attribution),
            "train_distinct_source_files": len(train_source_files),
            "corpus_files_loaded": len(corpus_files),
        },
    )


# --- Path-side checks -----------------------------------------------------


def check_path_exact_leakage(
    train: list[dict], test: list[dict], bench: list[dict]
) -> AuditFinding:
    train_paths = {r["path"] for r in train}
    test_paths = {r["path"] for r in test}
    bench_paths = {r["path"] for r in bench}
    tt = len(train_paths & test_paths)
    tb = len(train_paths & bench_paths)
    eb = len(test_paths & bench_paths)
    total = tt + tb + eb
    if total == 0:
        return AuditFinding(
            name="path_exact_leakage",
            severity="ok",
            summary="No exact-path leakage across train / test / benchmark.",
            details={
                "train_size": len(train),
                "test_size": len(test),
                "bench_size": len(bench),
            },
        )
    return AuditFinding(
        name="path_exact_leakage",
        severity="error",
        summary=(
            f"Path overlap detected — train∩test={tt}, "
            f"train∩bench={tb}, test∩bench={eb}."
        ),
        details={
            "train_intersect_test": tt,
            "train_intersect_bench": tb,
            "test_intersect_bench": eb,
        },
    )


def check_path_near_duplicates(
    train: list[dict],
    test: list[dict],
    similarity_threshold: float = 0.95,
) -> AuditFinding:
    if not train or not test:
        return AuditFinding(
            name="path_near_duplicates",
            severity="info",
            summary="Skipped: empty path train or test split.",
        )
    train_paths = [r["path"] for r in train]
    test_paths = [r["path"] for r in test]
    vec = HashingVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        n_features=2**14,
        norm="l2",
        alternate_sign=False,
    )
    X_train = vec.transform(train_paths)
    X_test = vec.transform(test_paths)

    n_test = X_test.shape[0]
    chunk = 256
    max_per_test = np.zeros(n_test)
    for start in range(0, n_test, chunk):
        end = min(start + chunk, n_test)
        sims = (X_test[start:end] @ X_train.T).toarray()
        max_per_test[start:end] = sims.max(axis=1)

    n_near = int((max_per_test >= similarity_threshold).sum())
    pct = 100 * n_near / n_test
    severity = "warn" if pct >= 5 else "info"
    return AuditFinding(
        name="path_near_duplicates",
        severity=severity,
        summary=(
            f"{n_near} of {n_test} test paths ({pct:.1f}%) have a train path "
            f"with cosine similarity >= {similarity_threshold} on char n-grams."
        ),
        details={
            "train_size": len(train_paths),
            "test_size": n_test,
            "similarity_threshold": similarity_threshold,
            "near_dup_test_count": n_near,
            "max_similarity_p50": float(np.percentile(max_per_test, 50)),
            "max_similarity_p90": float(np.percentile(max_per_test, 90)),
            "max_similarity_p99": float(np.percentile(max_per_test, 99)),
        },
    )


def check_path_source_distribution(
    train: list[dict], test: list[dict]
) -> AuditFinding:
    train_sources = Counter(r.get("source") for r in train)
    test_sources = Counter(r.get("source") for r in test)
    return AuditFinding(
        name="path_source_distribution",
        severity="info",
        summary=(
            "Source field is collector-tag granularity only; finer source-id "
            "leakage (same SE thread / same GH repo across train and test) is "
            "not detectable from per-record fields alone."
        ),
        details={
            "train_sources": dict(train_sources),
            "test_sources": dict(test_sources),
        },
    )


def check_benchmark_internal_duplicates(bench: list[dict]) -> AuditFinding:
    paths = [r["path"] for r in bench]
    counts = Counter(paths)
    redundant = sum(c - 1 for c in counts.values() if c > 1)
    if not redundant:
        return AuditFinding(
            name="benchmark_internal_duplicates",
            severity="ok",
            summary=(
                f"No duplicate paths inside the Snaffler-blind benchmark "
                f"({len(bench)} records)."
            ),
        )
    return AuditFinding(
        name="benchmark_internal_duplicates",
        severity="warn",
        summary=f"Benchmark has {redundant} duplicate path entries.",
        details={"bench_size": len(bench), "redundant_records": redundant},
    )


def check_synthetic_overlap(
    synthetic_path: Path, eval_splits: dict[str, list[dict]]
) -> AuditFinding:
    if not synthetic_path.exists():
        return AuditFinding(
            name="synthetic_overlap",
            severity="info",
            summary=f"Skipped: synthetic file not found at {synthetic_path}.",
        )
    synthetic = load_jsonl(synthetic_path)
    synthetic_paths = {r.get("path") for r in synthetic if r.get("path")}
    overlaps = {}
    total = 0
    for split_name, records in eval_splits.items():
        split_paths = {r["path"] for r in records}
        n = len(synthetic_paths & split_paths)
        overlaps[split_name] = n
        total += n
    if total == 0:
        return AuditFinding(
            name="synthetic_overlap",
            severity="ok",
            summary="No synthetic-path overlap with any eval split.",
            details={"synthetic_size": len(synthetic), **overlaps},
        )
    return AuditFinding(
        name="synthetic_overlap",
        severity="warn",
        summary=(
            f"Synthetic paths overlap eval splits: {overlaps} "
            f"(only matters if synthetic was actually used in training)."
        ),
        details={"synthetic_size": len(synthetic), **overlaps},
    )


# --- Cross checks ---------------------------------------------------------


def check_path_training_metadata_hash() -> AuditFinding:
    if not PATH_MODEL_METADATA.exists():
        return AuditFinding(
            name="path_training_metadata_hash",
            severity="info",
            summary="Skipped: no path model metadata.json on disk.",
        )
    meta = json.loads(PATH_MODEL_METADATA.read_text())
    if not PATH_TRAIN.exists():
        return AuditFinding(
            name="path_training_metadata_hash",
            severity="warn",
            summary="Cannot verify: path train_split.jsonl missing on disk.",
        )
    train_sha = hashlib.sha256(PATH_TRAIN.read_bytes()).hexdigest()
    recorded = None
    for key in ("training_data_sha", "train_data_sha", "training_sha", "data_sha"):
        if key in meta:
            recorded = meta[key]
            break
    if not recorded:
        return AuditFinding(
            name="path_training_metadata_hash",
            severity="info",
            summary=(
                "Path model metadata.json has no training-data SHA field "
                "(model not bound to its training set on disk)."
            ),
            details={
                "available_keys": sorted(meta.keys()),
                "current_train_sha_prefix": train_sha[:16],
            },
        )
    if recorded == train_sha:
        return AuditFinding(
            name="path_training_metadata_hash",
            severity="ok",
            summary="Path model training-data SHA matches current train_split.jsonl.",
            details={"sha_prefix": train_sha[:16]},
        )
    return AuditFinding(
        name="path_training_metadata_hash",
        severity="warn",
        summary=(
            "Path model training-data SHA does NOT match current "
            "train_split.jsonl — training data has changed since the shipped "
            "model was trained."
        ),
        details={
            "recorded_sha_prefix": recorded[:16],
            "current_sha_prefix": train_sha[:16],
        },
    )


# --- Orchestration --------------------------------------------------------


def format_finding(f: AuditFinding) -> str:
    return f"{SEVERITY_GLYPH.get(f.severity, '[?]')} {f.name:<42}  {f.summary}"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--source-attribution",
        action="store_true",
        help=(
            "Enable content source-file leakage check (slow — reads the whole "
            "corpus into memory and substring-matches every unique snippet; "
            "typically 10–25 min on the full corpus)."
        ),
    )
    p.add_argument(
        "--source-attribution-max-files",
        type=int,
        default=None,
        help="Cap on corpus files to load for attribution (smoke-test mode).",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_REPORT_PATH,
        help=(
            f"JSON report output path "
            f"(default: {DEFAULT_REPORT_PATH.relative_to(REPO_ROOT)})"
        ),
    )
    args = p.parse_args(argv)

    findings: list[AuditFinding] = []

    # --- Path side ---
    print("=== Path classifier integrity ===", file=sys.stderr)
    path_train = load_jsonl(PATH_TRAIN)
    path_test = load_jsonl(PATH_TEST)
    path_bench = load_jsonl(PATH_BENCH)

    if path_train and path_test and path_bench:
        findings.append(check_path_exact_leakage(path_train, path_test, path_bench))
        findings.append(check_path_near_duplicates(path_train, path_test))
        findings.append(check_path_source_distribution(path_train, path_test))
        findings.append(check_benchmark_internal_duplicates(path_bench))
        findings.append(
            check_synthetic_overlap(
                SYNTHETIC_PATH,
                {"train": path_train, "test": path_test, "bench": path_bench},
            )
        )
    else:
        findings.append(
            AuditFinding(
                name="path_checks",
                severity="warn",
                summary="One or more path data files missing; path checks skipped.",
            )
        )

    findings.append(check_path_training_metadata_hash())

    # --- Content side ---
    print("=== Content classifier integrity ===", file=sys.stderr)
    content_train = load_jsonl(CONTENT_TRAIN)
    content_test = load_jsonl(CONTENT_TEST)

    if content_train and content_test:
        findings.append(check_content_exact_leakage(content_train, content_test))
        findings.append(check_content_internal_duplicates(content_train, "train"))
        findings.append(check_content_internal_duplicates(content_test, "test"))
        findings.append(check_content_internal_label_noise(content_train, "train"))
        findings.append(check_content_internal_label_noise(content_test, "test"))
        findings.extend(check_content_near_leakage(content_train, content_test))
        findings.append(check_leak_label_breakdown(content_train, content_test))

        if args.source_attribution:
            print(
                "=== Content source-file attribution (slow) ===",
                file=sys.stderr,
            )
            findings.append(
                check_content_source_attribution(
                    content_train,
                    content_test,
                    CONTENT_CORPUS,
                    max_files=args.source_attribution_max_files,
                )
            )
    else:
        findings.append(
            AuditFinding(
                name="content_checks",
                severity="warn",
                summary="Content train and/or test split missing; content checks skipped.",
            )
        )

    # --- Report ---
    findings.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.name))

    print()
    print("=" * 90)
    print("AUDIT SUMMARY")
    print("=" * 90)
    for f in findings:
        print(format_finding(f))
    print("=" * 90)

    severity_counts = Counter(f.severity for f in findings)
    print(
        "Severity counts: "
        + ", ".join(
            f"{SEVERITY_GLYPH[s].strip()}={severity_counts.get(s, 0)}"
            for s in ("error", "warn", "info", "ok")
        )
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps([asdict(f) for f in findings], indent=2)
    )
    print(f"\nReport written to {args.output.relative_to(REPO_ROOT)}")

    return 1 if severity_counts.get("error", 0) > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
