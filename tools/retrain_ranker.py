"""Retrain the LightGBM ranker on operator-labeled hits.

Joins a ``labels.jsonl`` exported from the v0.17 HTML report against a
``hits.jsonl`` from the corresponding scan, builds ranker features from
each labeled record, trains a new LightGBM ranker, and saves the
result alongside a small metrics report.

Usage::

    uv run python tools/retrain_ranker.py \\
        --hits hits.jsonl \\
        --labels labels.jsonl \\
        --base-ranker models/ranker_v0p14_msf3.joblib \\
        --output models/ranker_engagement.joblib

The ``--base-ranker`` is informational only in this version: we record
which production ranker the retrain is incremental to so the operator
can A/B them downstream. Future work (v0.18) will warm-start from the
base ranker's tree ensemble rather than training from scratch.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))


def _fingerprint(record: dict) -> str:
    h = hashlib.sha256()
    h.update((record.get("path") or "").encode("utf-8", errors="replace"))
    h.update(b"\x00")
    h.update((record.get("content_excerpt") or "").encode("utf-8", errors="replace"))
    return "sha256:" + h.hexdigest()[:32]


def _share_of(path: str) -> str:
    if not path:
        return "unknown"
    if path.startswith("\\\\"):
        parts = path.lstrip("\\").split("\\")
        return f"\\\\{parts[0]}\\{parts[1]}" if len(parts) >= 2 else path
    if path.startswith("/"):
        bits = [p for p in path.split("/") if p]
        return "/" + bits[0] if bits else "unknown"
    return "unknown"


def _synthetic_matched_rules(record: dict) -> list[dict]:
    """Build a matched_rules-shaped list from a Scanner-path record.

    The production ranker's extract_features() walks matched_rules to
    build the feature vector. Scanner-path records don't have rules
    directly, but they have signals we can fold in:

    - path_tier → a synthetic rule with that tier
    - content_check == "yes" → synthetic FileContentAsString hit
    - extracted_fields non-empty → ShareSiftStructuredParser hit with
      max-confidence metadata
    """
    rules = []
    tier = record.get("path_tier")
    if tier:
        rules.append(
            {
                "rule_name": "PathClassifier",
                "tier": tier,
                "match_location": "FilePath",
                "match_action": "Snaffle",
            }
        )
    if record.get("content_check") == "yes":
        rules.append(
            {
                "rule_name": "ContentClassifier",
                "tier": tier or "Yellow",
                "match_location": "FileContentAsString",
                "match_action": "Snaffle",
            }
        )
    fields = record.get("extracted_fields") or []
    if fields:
        max_conf = max((f.get("confidence", 0.0) for f in fields), default=0.0)
        rules.append(
            {
                "rule_name": "ShareSiftStructuredParser",
                "tier": tier or "Yellow",
                "match_location": "FileContentAsString",
                "match_action": "Snaffle",
                "extracted_max_confidence": max_conf,
            }
        )
    return rules


def _load_jsonl(path: Path) -> list[dict]:
    out = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _label_to_relevance(label: str) -> int | None:
    """Map TP/FP/discard label to LambdaRank relevance.

    discard means "don't train on this" — returns None to skip.
    """
    if label == "tp":
        return 1
    if label == "fp":
        return 0
    return None


def _build_training_records(
    hits: list[dict], labels_by_fp: dict[str, dict]
) -> list[dict]:
    from sharesift.ranker import extract_features

    out = []
    for hit in hits:
        fp = _fingerprint(hit)
        label_entry = labels_by_fp.get(fp)
        if label_entry is None:
            continue
        relevance = _label_to_relevance(label_entry.get("label"))
        if relevance is None:
            continue
        feats = extract_features(
            path=hit.get("path", ""),
            matched_rules=_synthetic_matched_rules(hit),
            path_classifier_prob=hit.get("path_probability", 0.0) or 0.0,
            path_tier=hit.get("path_tier"),
            content_p_literal=None,
        )
        out.append(
            {
                "share": _share_of(hit.get("path", "")),
                "has_credential": relevance,
                "features": feats,
                "fingerprint": fp,
            }
        )
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--hits", type=Path, required=True, help="hits.jsonl from scan-files")
    p.add_argument("--labels", type=Path, required=True, help="labels.jsonl from HTML report")
    p.add_argument(
        "--base-ranker",
        type=Path,
        default=None,
        help="Production ranker to compare against (metadata only for v0.17)",
    )
    p.add_argument("--output", type=Path, required=True, help="Output .joblib path")
    p.add_argument("--n-estimators", type=int, default=200)
    args = p.parse_args(argv)

    hits = _load_jsonl(args.hits)
    labels = _load_jsonl(args.labels)
    labels_by_fp = {entry.get("record_fingerprint"): entry for entry in labels}
    print(f"[load] hits={len(hits)} labels={len(labels)}", file=sys.stderr)

    train_records = _build_training_records(hits, labels_by_fp)
    if not train_records:
        print("ERROR: no labeled records found (check fingerprint join).", file=sys.stderr)
        return 1

    n_pos = sum(1 for r in train_records if r["has_credential"] == 1)
    n_neg = sum(1 for r in train_records if r["has_credential"] == 0)
    n_shares = len({r["share"] for r in train_records})
    print(
        f"[build] {len(train_records)} labeled records "
        f"({n_pos} TP / {n_neg} FP) across {n_shares} share(s)",
        file=sys.stderr,
    )

    from sharesift.ranker import ShareSiftRanker

    ranker = ShareSiftRanker(n_estimators=args.n_estimators)
    meta = ranker.train(train_records)
    ranker.save(args.output)

    metrics = {
        "n_records": len(train_records),
        "n_positives": n_pos,
        "n_negatives": n_neg,
        "n_shares": n_shares,
        "base_ranker": str(args.base_ranker) if args.base_ranker else None,
        **meta,
    }
    print("[done] retrained ranker saved")
    print(json.dumps(metrics, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
