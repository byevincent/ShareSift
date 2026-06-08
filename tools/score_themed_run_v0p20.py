r"""v0.20: run the ContentDeterminer cascade (parsers + rules + extractor,
no LoRA) against a v0.19 themed share and emit a delta vs. v0.19's
Stage-1-only metrics.

This is the Phase 1 measurement script. It reuses the v0.19 themed
shares verbatim — same files, same ground-truth labels — and asks
the question: "what fraction of v0.19's content-ood misses does the
wiring-alone (no model retrain) catch?"

Output schema mirrors the v0.19 metrics card but adds:
* ``cascade_source_distribution`` — how often each tier fired
* ``recall_delta_vs_v0p19`` — absolute pp improvement
"""

from __future__ import annotations

import argparse
import json
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


def _run_cascade(theme_dir: Path) -> list[dict]:
    """For every file in the theme's manifest, run BOTH the Stage 1
    path classifier AND the v0.20 cascade, then combine — a file is
    flagged if EITHER produces a tier.

    This matches what the v0.20 Scanner.scan_batch actually does in
    production. The previous attempt compared cascade-only vs.
    Stage-1-only and produced misleading regressions on themes where
    the path classifier's fuzzy match was catching what the strict
    rule engine missed.
    """
    from sharesift.content_determiner import ContentDeterminer
    from sharesift.extract import load_content
    from sharesift.path import PathClassifier

    manifest = _load_jsonl(theme_dir / "manifest.jsonl")
    determiner = ContentDeterminer()
    path_clf = PathClassifier()

    paths = [entry["local_path"] for entry in manifest]
    path_results = path_clf.score_batch(paths)

    records: list[dict] = []
    for entry, p_result in zip(manifest, path_results):
        local_path = Path(entry["local_path"])
        content = load_content(local_path, max_bytes=65536)
        verdict = determiner.evaluate(
            str(local_path), content, use_classifier=False
        )

        # Combined verdict: prefer the higher tier of (path_tier,
        # cascade_tier). Source is "cascade" if cascade fired,
        # "path" otherwise, or "none".
        path_tier = p_result.tier
        cascade_tier = verdict.tier
        if cascade_tier and path_tier:
            combined_source = f"cascade+path"
        elif cascade_tier:
            combined_source = verdict.source  # rules/extractor/etc.
        elif path_tier:
            combined_source = "path"
        else:
            combined_source = "none"

        records.append({
            "path": str(local_path),
            "salted": entry.get("salted", False),
            "salted_credential_type": entry.get("salted_credential_type"),
            "tier_label": entry.get("tier_label"),
            "filename_token": entry.get("filename_token"),
            "path_tier": path_tier,
            "path_probability": p_result.probability,
            "cascade_tier": cascade_tier,
            "cascade_source": verdict.source if verdict.source != "none" else None,
            "combined_flagged": (path_tier is not None) or (cascade_tier is not None),
            "combined_source": combined_source,
        })
    return records


def score(theme: str, theme_dir: Path, v0p19_metrics_path: Path | None) -> dict:
    records = _run_cascade(theme_dir)

    salted = [r for r in records if r["salted"]]
    n_salted = len(salted)
    n_flagged = sum(1 for r in salted if r["combined_flagged"])

    recall = round(n_flagged / n_salted, 4) if n_salted else None

    # Top-K precision: rank by best-of (path_probability, cascade_tier).
    # Cascade Black=0.99, Red=0.85, Yellow=0.65, Green=0.40 so a
    # high-tier cascade hit ranks above an uncertain path probability.
    cascade_pseudo_p = {"Black": 0.99, "Red": 0.85, "Yellow": 0.65, "Green": 0.40}
    def rank_score(r):
        return max(
            r.get("path_probability") or 0.0,
            cascade_pseudo_p.get(r["cascade_tier"], 0.0),
        )
    sorted_records = sorted(records, key=rank_score, reverse=True)
    def precision_at_k(k):
        top = sorted_records[:k]
        return round(
            sum(1 for r in top if r["salted"]) / len(top), 4
        ) if top else None

    source_dist = Counter(r["combined_source"] for r in records)
    # Salted-file source breakdown — what caught each salted file.
    salted_source_dist = Counter(
        r["combined_source"] for r in salted if r["combined_flagged"]
    )

    # Recall delta vs. v0.19 Stage 1-only.
    v0p19_recall = None
    if v0p19_metrics_path and v0p19_metrics_path.exists():
        v0p19 = json.loads(v0p19_metrics_path.read_text(encoding="utf-8"))
        v0p19_recall = v0p19.get("recall_on_salted_overall")

    delta_pp = None
    if v0p19_recall is not None and recall is not None:
        delta_pp = round((recall - v0p19_recall) * 100, 1)

    misses = [r for r in salted if not r["combined_flagged"]]
    bottom_misses = sorted(
        misses,
        key=lambda r: (r["filename_token"] or "", r["salted_credential_type"] or "")
    )[:5]

    return {
        "theme": theme,
        "pipeline": "v0.20 cascade (parsers + rules + extractor)",
        "n_files": len(records),
        "n_salted": n_salted,
        "recall_on_salted": recall,
        "v0p19_recall_on_salted": v0p19_recall,
        "recall_delta_pp": delta_pp,
        "top_k_precision": {
            "top_10": precision_at_k(10),
            "top_20": precision_at_k(20),
            "top_50": precision_at_k(50),
        },
        "cascade_source_distribution_all": dict(source_dist),
        "cascade_source_distribution_caught_salted": dict(salted_source_dist),
        "n_unmatched_salted": len(misses),
        "bottom_misses_examples": [
            {
                "path": r["path"],
                "filename_token": r["filename_token"],
                "salted_credential_type": r["salted_credential_type"],
            }
            for r in bottom_misses
        ],
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--theme", required=True)
    p.add_argument(
        "--theme-dir",
        type=Path,
        default=None,
    )
    p.add_argument(
        "--v0p19-metrics",
        type=Path,
        default=None,
        help="Path to v0.19 metrics.json for delta comparison.",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=None,
    )
    args = p.parse_args(argv)

    theme_dir = args.theme_dir or (REPO_ROOT / "benchmarks" / "v0p19" / args.theme)
    v0p19_metrics = args.v0p19_metrics or (theme_dir / "metrics.json")

    card = score(args.theme, theme_dir, v0p19_metrics)

    out_path = args.output or (REPO_ROOT / "benchmarks" / "v0p20" / args.theme / "metrics.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(card, indent=2) + "\n", encoding="utf-8")

    print(f"=== {args.theme} ===", file=sys.stderr)
    print(f"v0.19 recall: {card['v0p19_recall_on_salted']}", file=sys.stderr)
    print(f"v0.20 recall: {card['recall_on_salted']}", file=sys.stderr)
    print(f"Δ:            {card['recall_delta_pp']} pp", file=sys.stderr)
    print(
        f"top-10 precision: {card['top_k_precision']['top_10']}",
        file=sys.stderr,
    )
    print(
        f"caught-salted source distribution: "
        f"{card['cascade_source_distribution_caught_salted']}",
        file=sys.stderr,
    )
    print(f"unmatched salted: {card['n_unmatched_salted']}/{card['n_salted']}", file=sys.stderr)
    print(f"Wrote {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
