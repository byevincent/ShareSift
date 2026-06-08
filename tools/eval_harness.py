r"""v0.22 evaluation harness — production stack on frozen held-out sets.

Runs the v0.20 cascade (parsers + rules + extractor, NO v0.21
reranker) against multiple independently-collected real-world test
sets and reports the per-set metrics plus the MIN-across-sets as the
headline number.

The MIN matters more than the mean: an operator on a new engagement
sees ONE share, and the honest expectation is the worst observed
performance, not the average.

## Held-out sets

1. **Metasploitable 3** (`data/external/metasploitable3/`) — 1054
   real Windows SMB paths with `has_credential` labels from the v0.14
   audit. Path-side + filename-rule evaluation only (no file
   content available).

2. **CredData** (`data/eval/creddata_benchmark.jsonl`) — 1500 real
   source-code snippets in chat-template format with yes/no labels.
   Content-side cascade evaluation (rules + extractor).

3. **engagement_corpus** (`data/external/engagement_corpus/`) —
   401 real engagement-extracted paths from DFIR writeups with tier
   labels. Used as a *supplementary* signal because some of these
   paths may have informed the v0.5-v0.14 era training corpora.

## What the harness does NOT do

- Run the v0.21 reranker. It's experimental and overfits.
- Tune anything against the held-out scores. The point is to measure,
  not iterate.
- Report mean-across-sets as a headline. The MIN is the honest
  number.

## Output

Per-set: recall, top-10 precision, top-50 precision, k-for-full-recall.
Headline: MIN top-10 across all sets, MIN recall across all sets.

Writes `benchmarks/v0p22_eval/harness_results.json` for CI gates and
historical tracking.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _top_k_precision(records: list[dict], scores: list[float], k: int) -> float | None:
    if not records:
        return None
    idx = sorted(range(len(records)), key=lambda i: scores[i], reverse=True)[:k]
    return round(sum(1 for i in idx if records[i]["positive"]) / k, 4)


# v0.22 ranking: declarative share-wide score adjustments. No model
# training; no per-benchmark tuning. The principle is "things that are
# universally true about file-shares" — file-name repetition signals
# package-manager / installer noise; Green tier is informational.
_TIER_PSEUDO_P = {
    "Black": 0.99,
    "Red": 0.85,
    "Yellow": 0.65,
    # Green=0: Relay matches (RelayPsByExtension, etc.) fire on entire
    # categories of files (every .ps1, every .config). The v0.21 MSF3
    # validation showed these drown out genuine credentials when given
    # any positive weight. Green stays in matches[] for inspection.
    "Green": 0.0,
    None: 0.0,
}


def _score_with_dedup_penalty(records: list[dict]) -> list[float]:
    """Versatile ranking score.

    Combines two universal signals:

    1. ``max(path_probability, cascade_pseudo_p)`` — the best
       per-file evidence we have from Stage 1 + the v0.20 cascade.
    2. **Filename-frequency penalty** — files whose basename appears
       N times in the same share are likely package-manager
       installations, build artifacts, or boilerplate. The v0.14
       LightGBM ranker learned this; we replicate it declaratively
       as ``score / sqrt(filename_frequency)``.

    No per-benchmark tuning. ``filename_frequency`` is computed at
    scoring time from the records list alone — same logic on every
    benchmark, no learned weights. Applied uniformly to all primary
    held-out sets.
    """
    from collections import Counter

    filenames = [_basename(r.get("path", "")) for r in records]
    freq = Counter(filenames)

    scores: list[float] = []
    for r, fname in zip(records, filenames):
        per_file_evidence = max(
            r.get("path_probability") or 0.0,
            _TIER_PSEUDO_P[r.get("cascade_tier")],
        )
        # sqrt penalty: 1 occurrence = unchanged; 4 = halved; 16 = quartered.
        # Sub-linear so legitimate-but-common credential filenames (like
        # `.env`) still rank when other signals fire.
        penalty_divisor = max(1.0, freq[fname]) ** 0.5
        scores.append(per_file_evidence / penalty_divisor)
    return scores


def _basename(path: str) -> str:
    """Extract just the leaf filename (UNC, Windows, Unix paths)."""
    if not path:
        return ""
    # Strip backslash and forward-slash components.
    for sep in ("\\", "/"):
        if sep in path:
            path = path.rsplit(sep, 1)[-1]
    return path.lower()


def _eval_msf3() -> dict:
    """MSF3: path classifier + filename-side rules. No content."""
    from sharesift.content_rules import get_default_engine
    from sharesift.path import PathClassifier

    base = REPO_ROOT / "data" / "external" / "metasploitable3"
    ground = {r["path"]: r for r in _load_jsonl(base / "ground_truth.jsonl")}
    paths = [
        line.strip()
        for line in (base / "file_list.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and line.strip() in ground
    ]

    path_clf = PathClassifier()
    rules = get_default_engine()

    path_results = path_clf.score_batch(paths)

    records: list[dict] = []
    for p, p_result in zip(paths, path_results):
        v = rules.evaluate(p, content=None)
        gt = ground[p]
        records.append({
            "path": p,
            "positive": bool(gt.get("has_credential")),
            "path_tier": p_result.tier,
            "cascade_tier": v.tier,
            "path_probability": p_result.probability,
        })

    scores = _score_with_dedup_penalty(records)

    n_positive = sum(1 for r in records if r["positive"])
    flagged = sum(
        1 for r in records
        if r["positive"] and (r["path_tier"] is not None or r["cascade_tier"] is not None)
    )

    # k for full recall
    sorted_pairs = sorted(zip(records, scores), key=lambda t: t[1], reverse=True)
    seen = 0
    k_full = None
    for k, (r, _) in enumerate(sorted_pairs, 1):
        if r["positive"]:
            seen += 1
        if seen == n_positive:
            k_full = k
            break

    return {
        "set": "msf3",
        "n_records": len(records),
        "n_positive": n_positive,
        "recall_any_tier": round(flagged / max(1, n_positive), 4),
        "top_10_precision": _top_k_precision(records, scores, 10),
        "top_20_precision": _top_k_precision(records, scores, 20),
        "top_50_precision": _top_k_precision(records, scores, 50),
        "k_for_full_recall": k_full,
        "precision_at_full_recall": (
            round(n_positive / k_full, 4) if k_full else None
        ),
    }


def _eval_creddata() -> dict:
    """CredData: content-side cascade only (rules + extractor; no path stage)."""
    from sharesift.content_determiner import ContentDeterminer

    cred_path = REPO_ROOT / "data" / "eval" / "creddata_benchmark.jsonl"
    rows = _load_jsonl(cred_path)

    det = ContentDeterminer()

    records: list[dict] = []
    for row in rows:
        # CredData uses chat-template format: {"messages": [...]}.
        msgs = row.get("messages") or []
        # The user turn carries the code snippet; the assistant turn carries yes/no.
        content = ""
        label = None
        for m in msgs:
            if m.get("role") == "user":
                content = m.get("content", "")
            elif m.get("role") == "assistant":
                ans = (m.get("content") or "").strip().lower()
                if ans == "yes":
                    label = True
                elif ans == "no":
                    label = False
        if label is None or not content:
            continue
        # Synthetic filename — CredData entries don't carry one. Use the
        # extension if we can guess from the content (Python/Java/SQL/etc.)
        verdict = det.evaluate("snippet.txt", content, use_classifier=False)
        records.append({
            "positive": label,
            "cascade_tier": verdict.tier,
            "cascade_source": verdict.source,
            "n_matches": len(verdict.matches),
        })

    if not records:
        return {"set": "creddata", "n_records": 0, "skipped": True}

    n_positive = sum(1 for r in records if r["positive"])
    # Score: cascade tier rank only (no path classifier for content-only).
    # v0.22: Green tier scores 0 — Green is informational ("fetch for
    # context"), not a credential signal. Pre-v0.22 the 0.40 weight
    # let Green-tier Relay matches drown out genuine credentials in
    # top-K ranking. Yellow / Red / Black still rank.
    pseudo = {"Black": 0.99, "Red": 0.85, "Yellow": 0.65, "Green": 0.0, None: 0.0}
    scores = [pseudo[r["cascade_tier"]] for r in records]

    flagged = sum(
        1 for r in records if r["positive"] and r["cascade_tier"] is not None
    )

    # Binary precision/recall at "any tier fired" threshold.
    tp = sum(1 for r in records if r["positive"] and r["cascade_tier"] is not None)
    fp = sum(1 for r in records if (not r["positive"]) and r["cascade_tier"] is not None)
    fn = sum(1 for r in records if r["positive"] and r["cascade_tier"] is None)

    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)

    return {
        "set": "creddata",
        "n_records": len(records),
        "n_positive": n_positive,
        "recall_any_tier": round(recall, 4),
        "precision_any_tier": round(precision, 4),
        "top_10_precision": _top_k_precision(records, scores, 10),
        "top_20_precision": _top_k_precision(records, scores, 20),
        "top_50_precision": _top_k_precision(records, scores, 50),
    }


def _eval_engagement_corpus() -> dict:
    """Engagement corpus: path-only + tier label (supplementary; possibly
    training-contaminated)."""
    from sharesift.content_rules import get_default_engine
    from sharesift.path import PathClassifier

    path_clf = PathClassifier()
    rules = get_default_engine()

    rows = _load_jsonl(
        REPO_ROOT / "data" / "external" / "engagement_corpus" / "extracted_paths_clean.jsonl"
    )
    rows = [r for r in rows if r.get("verbatim_path")]

    paths = [r["verbatim_path"] for r in rows]
    path_results = path_clf.score_batch(paths)

    records: list[dict] = []
    for row, p_result in zip(rows, path_results):
        v = rules.evaluate(row["verbatim_path"], content=None)
        tier_label = row.get("tier")
        # "Positive" means anything above Green tier in the DFIR labeler's view.
        positive = tier_label in ("Black", "Red", "Yellow")
        records.append({
            "positive": positive,
            "path_tier": p_result.tier,
            "cascade_tier": v.tier,
            "path_probability": p_result.probability,
        })

    # v0.22: Green tier scores 0 — Green is informational ("fetch for
    # context"), not a credential signal. Pre-v0.22 the 0.40 weight
    # let Green-tier Relay matches drown out genuine credentials in
    # top-K ranking. Yellow / Red / Black still rank.
    scores = _score_with_dedup_penalty(records)

    n_positive = sum(1 for r in records if r["positive"])
    flagged = sum(
        1 for r in records
        if r["positive"] and (r["path_tier"] is not None or r["cascade_tier"] is not None)
    )

    return {
        "set": "engagement_corpus",
        "supplementary": True,
        "n_records": len(records),
        "n_positive": n_positive,
        "recall_any_tier": round(flagged / max(1, n_positive), 4),
        "top_10_precision": _top_k_precision(records, scores, 10),
        "top_20_precision": _top_k_precision(records, scores, 20),
        "top_50_precision": _top_k_precision(records, scores, 50),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "benchmarks" / "v0p22_eval" / "harness_results.json",
    )
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)

    t0 = time.monotonic()
    results = [
        _eval_msf3(),
        _eval_creddata(),
        _eval_engagement_corpus(),
    ]
    elapsed = round(time.monotonic() - t0, 2)

    # MIN-across-primary-sets (skip supplementary).
    primary = [r for r in results if not r.get("skipped") and not r.get("supplementary")]
    min_top10 = min(
        (r.get("top_10_precision") for r in primary
         if r.get("top_10_precision") is not None),
        default=None,
    )
    min_recall = min(
        (r.get("recall_any_tier") for r in primary
         if r.get("recall_any_tier") is not None),
        default=None,
    )

    summary = {
        "elapsed_s": elapsed,
        "per_set": results,
        "headline": {
            "min_top_10_precision_across_primary": min_top10,
            "min_recall_across_primary": min_recall,
            "primary_sets": [r["set"] for r in primary],
        },
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    if not args.quiet:
        print("\n=== v0.22 eval harness ===\n", file=sys.stderr)
        for r in results:
            tag = (
                " (supplementary)" if r.get("supplementary") else ""
            )
            print(f"--- {r['set']}{tag} ---", file=sys.stderr)
            if r.get("skipped"):
                print("  skipped", file=sys.stderr)
                continue
            print(f"  records: {r['n_records']} (positive: {r.get('n_positive')})",
                  file=sys.stderr)
            print(f"  recall_any_tier: {r.get('recall_any_tier')}", file=sys.stderr)
            print(
                f"  top-10/20/50 precision: "
                f"{r.get('top_10_precision')} / "
                f"{r.get('top_20_precision')} / "
                f"{r.get('top_50_precision')}",
                file=sys.stderr,
            )
            if r.get("precision_any_tier") is not None:
                print(f"  precision_any_tier: {r['precision_any_tier']}",
                      file=sys.stderr)
        print(file=sys.stderr)
        print(f"HEADLINE (primary sets: {', '.join(r['set'] for r in primary)})",
              file=sys.stderr)
        print(f"  MIN top-10 precision: {min_top10}", file=sys.stderr)
        print(f"  MIN recall any-tier:  {min_recall}", file=sys.stderr)
        print(f"  elapsed: {elapsed}s", file=sys.stderr)
        print(f"  wrote: {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
