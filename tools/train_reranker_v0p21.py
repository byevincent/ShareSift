r"""v0.21: train the cascade-aware reranker on the v0.19 themed
manifests + v0.20 cascade output.

Each themed share gives us ~80 labeled rows: (features, salted).
We train a LightGBM binary classifier with class weights tuned for
the ~25% positive rate.

Cross-validation: leave-one-theme-out CV gives a per-theme held-out
score; the production model trains on all themes.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np

from sharesift.content_determiner import ContentDeterminer
from sharesift.extract import load_content
from sharesift.path import PathClassifier
from sharesift.reranker_v0p21 import RerankFeatures, extract_features

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _build_theme_records(theme_dir: Path) -> list[dict]:
    """Run cascade + path classifier on every file in a theme manifest.
    Returns one record per file with features + salted label.
    """
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
            "theme": entry.get("source_box"),
        })
    return records


def _build_xy(records: list[dict]) -> tuple[np.ndarray, np.ndarray]:
    X = np.array([extract_features(r).to_vector() for r in records], dtype=np.float32)
    y = np.array([1 if r["salted"] else 0 for r in records], dtype=np.int32)
    return X, y


def _train_model(X: np.ndarray, y: np.ndarray):
    import lightgbm as lgb

    pos_weight = float(np.sum(y == 0)) / max(1, float(np.sum(y == 1)))
    model = lgb.LGBMClassifier(
        n_estimators=200,
        max_depth=4,
        num_leaves=15,
        learning_rate=0.05,
        scale_pos_weight=pos_weight,
        random_state=2026,
        verbose=-1,
    )
    model.fit(X, y, feature_name=RerankFeatures.feature_names())
    return model


def _evaluate_top_k(records: list[dict], scores: list[float], k: int) -> float:
    """Top-K precision: sort by score desc; what fraction of the top K are salted?"""
    if not records or not scores:
        return 0.0
    indexed = sorted(
        zip(records, scores), key=lambda t: t[1], reverse=True
    )[:k]
    if not indexed:
        return 0.0
    return sum(1 for r, _s in indexed if r.get("salted")) / len(indexed)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "--themes-dir",
        type=Path,
        default=REPO_ROOT / "benchmarks" / "v0p19",
    )
    p.add_argument(
        "--themes",
        type=str,
        default="finance,healthcare,dev_eng,gov_contractor,legal",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "models" / "reranker_v0p21.joblib",
    )
    p.add_argument(
        "--cv",
        action="store_true",
        help="Run leave-one-theme-out cross-validation before training the final model.",
    )
    args = p.parse_args(argv)

    themes = [t.strip() for t in args.themes.split(",") if t.strip()]

    # Build feature records for each theme.
    print(f"building features for {len(themes)} themes...")
    per_theme: dict[str, list[dict]] = {}
    for theme in themes:
        theme_dir = args.themes_dir / theme
        per_theme[theme] = _build_theme_records(theme_dir)
        print(f"  {theme}: {len(per_theme[theme])} records "
              f"({sum(r['salted'] for r in per_theme[theme])} salted)")

    if args.cv:
        print()
        print("=== leave-one-theme-out CV ===")
        cv_results: list[tuple[str, float, float]] = []
        for held_out in themes:
            train_records: list[dict] = []
            for t, recs in per_theme.items():
                if t != held_out:
                    train_records.extend(recs)
            X_train, y_train = _build_xy(train_records)
            model = _train_model(X_train, y_train)
            held_records = per_theme[held_out]
            X_held, _ = _build_xy(held_records)
            held_scores = list(model.predict_proba(X_held)[:, 1])
            top10 = _evaluate_top_k(held_records, held_scores, 10)
            top20 = _evaluate_top_k(held_records, held_scores, 20)
            cv_results.append((held_out, top10, top20))
            print(f"  held-out {held_out:18s} top-10={top10:.3f}  top-20={top20:.3f}")

    print()
    print("=== training final model on all themes ===")
    all_records = [r for recs in per_theme.values() for r in recs]
    X, y = _build_xy(all_records)
    print(f"  total: {len(all_records)} records, {y.sum()} salted")
    final_model = _train_model(X, y)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(final_model, args.output)
    print(f"  saved → {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
