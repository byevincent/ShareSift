r"""v0.21 validation: re-run the cascade + reranker on the
Metasploitable 3 benchmark from v0.14.

Goal: find out whether the v0.21 numbers survive contact with real
data. v0.14 reported 100% recall and 1.000 top-10 precision on MSF3
using the Stage 1 + ranker stack. v0.21 ships the cascade + reranker;
does it hold?

Caveat: MSF3 ground truth has paths + labels but no file content.
So we can run Stage 1 path classifier + filename-side rules (the
FileExtension / FileName / FilePath classes in ContentRuleEngine),
NOT the FileContentAsString rules. The reranker's content-side
features (cascade_source/n_matches) are populated by filename-side
hits when they fire.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _run(args) -> dict:
    from sharesift.content_rules import get_default_engine
    from sharesift.path import PathClassifier
    from sharesift.reranker_v0p21 import CascadeReranker, extract_features

    ground = {r["path"]: r for r in _load_jsonl(args.ground_truth)}
    paths = [
        line.strip()
        for line in args.file_list.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    # Filter to paths that have ground truth labels (drops noise).
    paths = [p for p in paths if p in ground]

    print(f"benchmarking {len(paths)} paths against MSF3 ground truth",
          file=sys.stderr)

    path_clf = PathClassifier()
    rule_engine = get_default_engine()
    print(f"path classifier loaded; {len(rule_engine)} rules in engine",
          file=sys.stderr)

    path_results = path_clf.score_batch(paths)

    records: list[dict] = []
    for p, p_result in zip(paths, path_results):
        # Filename-side rules only (no content available).
        verdict = rule_engine.evaluate(p, content=None)
        cascade_tier = verdict.tier
        cascade_source = "rules" if verdict.has_any() else None
        n_matches = len(verdict.matches)

        gt = ground[p]
        records.append({
            "path": p,
            "path_probability": p_result.probability,
            "path_tier": p_result.tier,
            "cascade_tier": cascade_tier,
            "cascade_source": cascade_source,
            "n_matches": n_matches,
            "salted": bool(gt.get("has_credential")),
            "snaffler_tier": gt.get("snaffler_tier"),
        })

    # Reranker scoring.
    rerank_model_path = args.reranker_model
    if rerank_model_path.exists():
        reranker = CascadeReranker.load(rerank_model_path)
        rerank_scores = reranker.score(records)
        print(f"reranker loaded from {rerank_model_path}", file=sys.stderr)
    else:
        rerank_scores = None
        print(f"WARN: reranker missing at {rerank_model_path}", file=sys.stderr)

    # Baseline ranking (v0.20-style): max(path_prob, cascade_pseudo_p).
    cascade_pseudo_p = {"Black": 0.99, "Red": 0.85, "Yellow": 0.65, "Green": 0.40, None: 0.0}
    baseline_scores = [
        max(r["path_probability"], cascade_pseudo_p[r["cascade_tier"]])
        for r in records
    ]

    n_positive = sum(1 for r in records if r["salted"])

    def _top_k(scores, k):
        if not scores:
            return None
        idx = sorted(range(len(records)), key=lambda i: scores[i], reverse=True)[:k]
        return round(sum(1 for i in idx if records[i]["salted"]) / k, 4)

    def _recall_any_tier(records):
        if not n_positive:
            return None
        n_caught = sum(
            1 for r in records
            if r["salted"] and (
                r["path_tier"] is not None or r["cascade_tier"] is not None
            )
        )
        return round(n_caught / n_positive, 4)

    # Per-class precision/recall at different score thresholds.
    def _pr_at_threshold(scores, threshold):
        flagged = [records[i] for i, s in enumerate(scores) if s >= threshold]
        if not flagged:
            return None, None
        tp = sum(1 for r in flagged if r["salted"])
        fp = sum(1 for r in flagged if not r["salted"])
        precision = tp / max(1, len(flagged))
        recall = tp / max(1, n_positive)
        return round(precision, 4), round(recall, 4)

    card = {
        "benchmark": "Metasploitable 3 (real-world v0.14 baseline)",
        "pipeline": "v0.21 cascade (filename-only) + reranker",
        "n_paths": len(records),
        "n_positive": n_positive,
        "v0p14_baseline": {
            "recall": 1.000,
            "top_10_precision": 1.000,
            "top_20_precision": 1.000,
            "source": "docs/v0p14_results.md / README Performance table",
        },
        "v0p21_recall_any_tier": _recall_any_tier(records),
        "v0p21_baseline_top_k": {
            "top_10": _top_k(baseline_scores, 10),
            "top_20": _top_k(baseline_scores, 20),
            "top_50": _top_k(baseline_scores, 50),
            "top_100": _top_k(baseline_scores, 100),
        },
    }
    if rerank_scores is not None:
        card["v0p21_reranked_top_k"] = {
            "top_10": _top_k(rerank_scores, 10),
            "top_20": _top_k(rerank_scores, 20),
            "top_50": _top_k(rerank_scores, 50),
            "top_100": _top_k(rerank_scores, 100),
        }
        # Precision @ recall = 1.0 — the threshold at which we'd
        # need to flag to catch every positive. Tells us about FP rate.
        scored = sorted(zip(records, rerank_scores), key=lambda t: t[1], reverse=True)
        seen_positives = 0
        full_recall_k = None
        for k, (r, _s) in enumerate(scored, 1):
            if r["salted"]:
                seen_positives += 1
            if seen_positives == n_positive:
                full_recall_k = k
                break
        if full_recall_k:
            card["k_for_full_recall"] = full_recall_k
            card["precision_at_full_recall"] = round(n_positive / full_recall_k, 4)

    # Honest source distribution.
    flagged_positives = [r for r in records if r["salted"] and (
        r["path_tier"] or r["cascade_tier"]
    )]
    by_source = Counter(
        "cascade+path" if (r["path_tier"] and r["cascade_tier"])
        else ("path" if r["path_tier"] else "cascade")
        for r in flagged_positives
    )
    card["caught_positive_source_distribution"] = dict(by_source)

    return card


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "--file-list",
        type=Path,
        default=REPO_ROOT / "data" / "external" / "metasploitable3" / "file_list.txt",
    )
    p.add_argument(
        "--ground-truth",
        type=Path,
        default=REPO_ROOT / "data" / "external" / "metasploitable3" / "ground_truth.jsonl",
    )
    p.add_argument(
        "--reranker-model",
        type=Path,
        default=REPO_ROOT / "models" / "reranker_v0p21.joblib",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "benchmarks" / "v0p21_validation" / "msf3.json",
    )
    args = p.parse_args(argv)

    card = _run(args)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(card, indent=2) + "\n", encoding="utf-8")

    print(file=sys.stderr)
    print("=== MSF3 validation ===", file=sys.stderr)
    print(f"paths: {card['n_paths']}  positives: {card['n_positive']}", file=sys.stderr)
    print(f"v0.14 baseline recall: 1.000 / top-10: 1.000", file=sys.stderr)
    print(f"v0.21 recall (any tier): {card['v0p21_recall_any_tier']}", file=sys.stderr)
    base = card["v0p21_baseline_top_k"]
    print(
        f"v0.21 BASELINE top-10/20/50/100: "
        f"{base['top_10']} / {base['top_20']} / {base['top_50']} / {base['top_100']}",
        file=sys.stderr,
    )
    if "v0p21_reranked_top_k" in card:
        rer = card["v0p21_reranked_top_k"]
        print(
            f"v0.21 RERANKED top-10/20/50/100: "
            f"{rer['top_10']} / {rer['top_20']} / {rer['top_50']} / {rer['top_100']}",
            file=sys.stderr,
        )
    if "k_for_full_recall" in card:
        print(
            f"k for full recall: {card['k_for_full_recall']} / {card['n_paths']} "
            f"(precision at full recall: {card['precision_at_full_recall']})",
            file=sys.stderr,
        )
    print(
        f"caught-positive source dist: {card['caught_positive_source_distribution']}",
        file=sys.stderr,
    )
    print(f"Wrote {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
