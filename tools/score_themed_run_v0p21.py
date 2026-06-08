r"""v0.21: re-run themed benchmark with the cascade + reranker.

The v0.20 cascade lifts recall but doesn't improve top-K ranking
(legal regressed to 0.00 top-10 precision). The v0.21 reranker takes
the same cascade output as input and produces a calibrated score
that orders files by salted-likelihood.

Per-theme output: top-K precision before/after reranking, source
distribution of the top-K positions, and the per-theme delta vs.
v0.20.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sharesift.content_determiner import ContentDeterminer
from sharesift.extract import load_content
from sharesift.path import PathClassifier
from sharesift.reranker_v0p21 import CascadeReranker

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _build_records(theme_dir: Path) -> list[dict]:
    determiner = ContentDeterminer()
    path_clf = PathClassifier()

    manifest = _load_jsonl(theme_dir / "manifest.jsonl")
    paths = [m["local_path"] for m in manifest]
    path_results = path_clf.score_batch(paths)

    records: list[dict] = []
    for entry, p_result in zip(manifest, path_results):
        local_path = Path(entry["local_path"])
        content = load_content(local_path, max_bytes=65536)
        verdict = determiner.evaluate(
            str(local_path), content, use_classifier=False
        )
        records.append({
            "path": str(local_path),
            "path_probability": p_result.probability,
            "path_tier": p_result.tier,
            "cascade_tier": verdict.tier,
            "cascade_source": verdict.source if verdict.source != "none" else None,
            "n_matches": len(verdict.matches),
            "salted": entry.get("salted", False),
            "salted_credential_type": entry.get("salted_credential_type"),
            "tier_label": entry.get("tier_label"),
            "filename_token": entry.get("filename_token"),
        })
    return records


def _top_k(records: list[dict], scores: list[float], k: int) -> float | None:
    if not records:
        return None
    ranked = sorted(zip(records, scores), key=lambda t: t[1], reverse=True)[:k]
    if not ranked:
        return None
    return round(sum(1 for r, _ in ranked if r["salted"]) / len(ranked), 4)


def _baseline_score(records: list[dict]) -> list[float]:
    """v0.20-equivalent score: max(path_prob, cascade_pseudo_p)."""
    cascade_pseudo_p = {"Black": 0.99, "Red": 0.85, "Yellow": 0.65, "Green": 0.40}
    out: list[float] = []
    for r in records:
        out.append(max(
            r.get("path_probability") or 0.0,
            cascade_pseudo_p.get(r.get("cascade_tier"), 0.0),
        ))
    return out


def score(theme: str, theme_dir: Path, reranker: CascadeReranker | None) -> dict:
    records = _build_records(theme_dir)

    n_salted = sum(1 for r in records if r["salted"])
    n_flagged = sum(
        1 for r in records
        if r["cascade_tier"] is not None or r["path_tier"] is not None
    )

    baseline_scores = _baseline_score(records)
    baseline_top10 = _top_k(records, baseline_scores, 10)
    baseline_top20 = _top_k(records, baseline_scores, 20)
    baseline_top50 = _top_k(records, baseline_scores, 50)

    if reranker is not None:
        rerank_scores = reranker.score(records)
        reranked_top10 = _top_k(records, rerank_scores, 10)
        reranked_top20 = _top_k(records, rerank_scores, 20)
        reranked_top50 = _top_k(records, rerank_scores, 50)
    else:
        rerank_scores = baseline_scores
        reranked_top10 = baseline_top10
        reranked_top20 = baseline_top20
        reranked_top50 = baseline_top50

    # Recall (any tier flagged) — should match v0.20.
    recall = round(
        sum(1 for r in records if r["salted"] and (
            r["cascade_tier"] is not None or r["path_tier"] is not None
        )) / max(1, n_salted), 4
    )

    return {
        "theme": theme,
        "pipeline": "v0.21 cascade + reranker",
        "n_files": len(records),
        "n_salted": n_salted,
        "n_flagged_any_tier": n_flagged,
        "recall_on_salted": recall,
        "top_k_precision_baseline": {
            "top_10": baseline_top10,
            "top_20": baseline_top20,
            "top_50": baseline_top50,
        },
        "top_k_precision_reranked": {
            "top_10": reranked_top10,
            "top_20": reranked_top20,
            "top_50": reranked_top50,
        },
        "top_10_delta_pp": (
            round((reranked_top10 - baseline_top10) * 100, 1)
            if reranked_top10 is not None and baseline_top10 is not None
            else None
        ),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--theme", required=True)
    p.add_argument("--theme-dir", type=Path, default=None)
    p.add_argument(
        "--reranker-model",
        type=Path,
        default=REPO_ROOT / "models" / "reranker_v0p21.joblib",
    )
    p.add_argument("--output", type=Path, default=None)
    args = p.parse_args(argv)

    theme_dir = args.theme_dir or (REPO_ROOT / "benchmarks" / "v0p19" / args.theme)
    reranker = (
        CascadeReranker.load(args.reranker_model)
        if args.reranker_model.exists() else None
    )
    card = score(args.theme, theme_dir, reranker)

    out_path = args.output or (REPO_ROOT / "benchmarks" / "v0p21" / args.theme / "metrics.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(card, indent=2) + "\n", encoding="utf-8")

    print(f"=== {args.theme} ===", file=sys.stderr)
    print(f"recall: {card['recall_on_salted']}", file=sys.stderr)
    base = card["top_k_precision_baseline"]
    rer = card["top_k_precision_reranked"]
    print(
        f"baseline top-10/20/50: {base['top_10']} / {base['top_20']} / {base['top_50']}",
        file=sys.stderr,
    )
    print(
        f"reranked top-10/20/50: {rer['top_10']} / {rer['top_20']} / {rer['top_50']}",
        file=sys.stderr,
    )
    print(f"Δ top-10: {card['top_10_delta_pp']} pp", file=sys.stderr)
    print(f"Wrote {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
