r"""v0.19: per-theme metrics card.

Given a themed share's manifest + a sharesift ``score-paths`` output
JSONL, compute and emit:

* Overall recall on salted files (Stage 1 path classifier flagged
  the file at any tier).
* Per-tier recall (Black-tier recall / Red-tier recall / ...).
* Top-K precision at K = 10, 20, 50 (precision among the K paths
  with highest path_probability).
* Per-credential-type recall (which cred types are
  systematically missed).
* Tier band assignment vs. ground-truth tier_label (calibration
  drift indicator).
* Bottom-5 misses — salted files the classifier missed entirely
  (tier=None), with full path for human triage.

Schema of the metrics card is JSON for ingestion into the v0.19
combined results doc. The runner also prints a human-readable summary
to stderr so an operator can eyeball it.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_TIER_ORDER = ["Black", "Red", "Yellow", "Green", "Gray"]


def _load_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _build_path_to_record(scores: list[dict]) -> dict[str, dict]:
    """Index sharesift output by path. Score JSONL uses the local
    absolute path that we wrote into paths.txt."""
    return {r["path"]: r for r in scores}


def _top_k_precision(scores: list[dict], manifest_by_path: dict[str, dict], k: int) -> float | None:
    """Precision = (salted ∧ in top-K) / K.

    The score JSONL records are sorted by probability desc; we take
    the first K and check their salted flag in the manifest.
    """
    if not scores:
        return None
    sorted_scores = sorted(scores, key=lambda r: r.get("probability", 0.0), reverse=True)[:k]
    if not sorted_scores:
        return None
    salted_in_topk = sum(
        1 for r in sorted_scores
        if manifest_by_path.get(r["path"], {}).get("salted", False)
    )
    return round(salted_in_topk / len(sorted_scores), 4)


def _per_tier_recall(scored_salted: list[dict]) -> dict[str, float]:
    """Recall partitioned by the GROUND-TRUTH tier_label.

    For each ground-truth tier, what fraction of salted files in that
    tier did the path classifier flag at any tier (i.e. tier != None
    in the score record)?
    """
    by_gt: dict[str, list[bool]] = defaultdict(list)
    for r in scored_salted:
        gt = r["manifest"].get("tier_label")
        if gt is None:
            continue
        scored_tier = r["score"].get("tier")
        by_gt[gt].append(scored_tier is not None)
    return {
        tier: round(sum(flags) / len(flags), 4) if flags else None
        for tier, flags in by_gt.items()
    }


def _per_cred_type_recall(scored_salted: list[dict]) -> dict[str, float]:
    by_type: dict[str, list[bool]] = defaultdict(list)
    for r in scored_salted:
        ct = r["manifest"].get("salted_credential_type")
        if ct is None:
            continue
        scored_tier = r["score"].get("tier")
        by_type[ct].append(scored_tier is not None)
    return {
        ct: round(sum(flags) / len(flags), 4) if flags else None
        for ct, flags in by_type.items()
    }


def _bottom_misses(scored_salted: list[dict], n: int = 5) -> list[dict]:
    """Salted files the classifier missed entirely (tier=None), sorted
    by probability ascending."""
    misses = [
        r for r in scored_salted
        if r["score"].get("tier") is None
    ]
    misses.sort(key=lambda r: r["score"].get("probability", 0.0))
    return [
        {
            "path": r["score"]["path"],
            "probability": r["score"].get("probability"),
            "tier": r["score"].get("tier"),
            "salted_credential_type": r["manifest"].get("salted_credential_type"),
            "filename_token": r["manifest"].get("filename_token"),
        }
        for r in misses[:n]
    ]


def score(theme: str, manifest_path: Path, scores_path: Path) -> dict:
    manifest = _load_jsonl(manifest_path)
    scores = _load_jsonl(scores_path)

    manifest_by_path = {r["local_path"]: r for r in manifest}
    scores_by_path = _build_path_to_record(scores)

    # Joined view: for each manifest record, attach the matching score.
    joined: list[dict] = []
    for m in manifest:
        s = scores_by_path.get(m["local_path"])
        if s is None:
            continue
        joined.append({"manifest": m, "score": s})

    scored_salted = [r for r in joined if r["manifest"].get("salted")]

    n_files = len(manifest)
    n_salted = sum(1 for r in manifest if r.get("salted"))
    n_flagged_overall = sum(1 for r in scores if r.get("tier") is not None)

    # Stage 1 recall on salted files = % flagged-at-any-tier.
    if scored_salted:
        recall_overall = round(
            sum(1 for r in scored_salted if r["score"].get("tier") is not None)
            / len(scored_salted),
            4,
        )
    else:
        recall_overall = None

    # Distribution of assigned tiers across the full share.
    tier_dist = Counter(r.get("tier") for r in scores)

    card = {
        "theme": theme,
        "n_files": n_files,
        "n_salted": n_salted,
        "n_flagged_any_tier": n_flagged_overall,
        "recall_on_salted_overall": recall_overall,
        "recall_per_tier_label": _per_tier_recall(scored_salted),
        "recall_per_credential_type": _per_cred_type_recall(scored_salted),
        "top_k_precision": {
            "top_10": _top_k_precision(scores, manifest_by_path, 10),
            "top_20": _top_k_precision(scores, manifest_by_path, 20),
            "top_50": _top_k_precision(scores, manifest_by_path, 50),
        },
        "tier_distribution": {
            str(tier): tier_dist.get(tier, 0) for tier in (None, *_TIER_ORDER)
        },
        "bottom_misses": _bottom_misses(scored_salted, n=5),
    }
    return card


def _human_summary(card: dict, fh) -> None:
    print(f"=== Theme: {card['theme']} ===", file=fh)
    print(
        f"Files: {card['n_files']} | Salted: {card['n_salted']} | "
        f"Flagged any tier: {card['n_flagged_any_tier']}",
        file=fh,
    )
    print(f"Recall on salted (any tier flag): {card['recall_on_salted_overall']}", file=fh)
    tier_recall = card["recall_per_tier_label"]
    if tier_recall:
        print("Recall by ground-truth tier:", file=fh)
        for tier in _TIER_ORDER:
            if tier in tier_recall:
                print(f"  {tier:7s}: {tier_recall[tier]}", file=fh)
    ct_recall = card["recall_per_credential_type"]
    if ct_recall:
        print("Recall by credential type:", file=fh)
        for ct, r in sorted(ct_recall.items()):
            print(f"  {ct:25s}: {r}", file=fh)
    print(
        f"Top-K precision: 10={card['top_k_precision']['top_10']} "
        f"20={card['top_k_precision']['top_20']} "
        f"50={card['top_k_precision']['top_50']}",
        file=fh,
    )
    misses = card["bottom_misses"]
    if misses:
        print("Bottom-5 misses (no tier assigned):", file=fh)
        for m in misses:
            print(
                f"  {m['salted_credential_type']:25s} "
                f"p={m['probability']:.3f}  {m['path']}",
                file=fh,
            )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--theme", required=True)
    p.add_argument(
        "--theme-dir",
        type=Path,
        default=None,
        help="Base directory for the theme. Default: benchmarks/v0p19/<theme>/.",
    )
    p.add_argument(
        "--scores",
        type=Path,
        required=True,
        help="JSONL from `sharesift score-paths` against the theme's paths.txt.",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write the JSON metrics card here. Default: <theme-dir>/metrics.json.",
    )
    args = p.parse_args(argv)

    theme_dir = args.theme_dir or (REPO_ROOT / "benchmarks" / "v0p19" / args.theme)
    manifest_path = theme_dir / "manifest.jsonl"
    if not manifest_path.exists():
        raise SystemExit(f"manifest missing: {manifest_path}")

    card = score(args.theme, manifest_path, args.scores)

    out_path = args.output or (theme_dir / "metrics.json")
    out_path.write_text(json.dumps(card, indent=2) + "\n", encoding="utf-8")
    _human_summary(card, sys.stderr)
    print(f"Wrote {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
