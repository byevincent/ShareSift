"""v0.14 ranker — combines path / filename-rule / content-rule / P(literal)
features into a single per-file ranking score.

Sits downstream of pysnaffler + the ShareSift ML rules. Reads each
flagged file's features (which rules fired, what tier, classifier
probabilities) and emits a score in [0, 1]. The ranker exists because
Snaffler returns 1,000+ Red hits on a real share; analysts can read
~50. ShareSift's wedge is ordering Snaffler's noise so the top 50 are
the ones most likely to contain real credentials.

Architecture:
- LightGBM ``LGBMRanker`` with NDCG@10 objective
- Query groups = one share (don't cross-share rank)
- Label: 1 if file contains a real credential, 0 otherwise
- Features extracted from pysnaffler's matched_rules + ShareSift
  classifier outputs

The ranker is meant to be the FINAL stage in the v0.14 pipeline — it
doesn't change which files Snaffler/ShareSift flag, it just orders them.

Training data shape (`build_ranker_training_data`):
    Each record = (file_path, query_group, features_dict, label).
    `query_group` is the share name (e.g. "metasploitable3") so the
    ranker learns within-share ordering.

Inference:
    Each record = (file_path, features_dict).
    Output: ranking score in [0, 1], higher = more likely real credential.

Usage::

    # Train
    ranker = ShareSiftRanker()
    ranker.train(training_records)
    ranker.save("models/ranker_v0p14_v1.joblib")

    # Score
    ranker = ShareSiftRanker.load("models/ranker_v0p14_v1.joblib")
    scores = ranker.score(test_records)
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Tier ordinals — higher = more likely real credential. Black > Red > Yellow > Green > None
_TIER_ORD = {
    "Black": 4, "Red": 3, "Yellow": 2, "Green": 1, "Gray": 1, "None": 0, None: 0,
}

# Extensions we one-hot encode. Others fall into "other".
_TRACKED_EXTENSIONS = [
    "ps1", "psm1", "bat", "cmd", "xml", "yml", "yaml", "json",
    "php", "py", "rb", "properties", "ini", "conf", "config", "cfg",
    "keytab", "ccache", "pem", "key", "pfx", "p12",
    "sql", "bak", "mdf", "ldf",
    "vmdk", "vhd", "vhdx", "iso",
]


@dataclass
class RankerFeatures:
    """All features the ranker consumes per file."""
    path_classifier_prob: float = 0.0       # v0p2 probability
    path_tier_ord: int = 0                  # ShareSift path tier ordinal
    filename_rule_matched: int = 0          # any Keep filename rule fired?
    filename_rule_max_tier_ord: int = 0     # max tier across filename rules
    content_rule_matched: int = 0           # any Keep content rule fired?
    content_rule_max_tier_ord: int = 0      # max tier across content rules
    content_p_literal: float | None = None  # v0p7 probability (None if not scored)
    snaffler_top_tier_ord: int = 0          # max tier across all rules that fired
    n_rules_matched: int = 0                # total rules that flagged this file
    path_depth: int = 0                     # number of path separators
    file_size_log: float = 0.0              # log10(size in bytes); 0 for unknown
    is_sharesift_only: int = 0               # only ShareSift rules fired (no Snaffler)
    # v0.15 additions: structured parser hit + ShareSift blind-spot rule hit
    structured_parser_matched: int = 0      # ShareSiftStructuredParser fired?
    extracted_field_max_confidence: float = 0.0  # highest parser confidence
    blind_spot_rule_matched: int = 0        # any ShareSiftKeep* blind-spot rule fired?
    saas_rule_matched: int = 0              # any ShareSift SaaS detector fired?
    # File-extension one-hots (extras populated dynamically)
    ext_features: dict[str, int] | None = None

    def to_array(self) -> list[float]:
        """Serialize to a flat float vector for LightGBM. Order matters and
        must match :func:`feature_names` exactly."""
        ext_feats = self.ext_features or {}
        flat = [
            self.path_classifier_prob,
            float(self.path_tier_ord),
            float(self.filename_rule_matched),
            float(self.filename_rule_max_tier_ord),
            float(self.content_rule_matched),
            float(self.content_rule_max_tier_ord),
            self.content_p_literal if self.content_p_literal is not None else 0.5,
            float(self.snaffler_top_tier_ord),
            float(self.n_rules_matched),
            float(self.path_depth),
            self.file_size_log,
            float(self.is_sharesift_only),
            float(self.structured_parser_matched),
            self.extracted_field_max_confidence,
            float(self.blind_spot_rule_matched),
            float(self.saas_rule_matched),
        ]
        for ext in _TRACKED_EXTENSIONS:
            flat.append(float(ext_feats.get(ext, 0)))
        flat.append(float(ext_feats.get("other", 0)))
        # Missing-content-prob flag (lets the model distinguish "not scored"
        # from "scored at 0.5") — useful when content classifier wasn't run.
        flat.append(0.0 if self.content_p_literal is not None else 1.0)
        return flat


def feature_names() -> list[str]:
    names = [
        "path_classifier_prob",
        "path_tier_ord",
        "filename_rule_matched",
        "filename_rule_max_tier_ord",
        "content_rule_matched",
        "content_rule_max_tier_ord",
        "content_p_literal",
        "snaffler_top_tier_ord",
        "n_rules_matched",
        "path_depth",
        "file_size_log",
        "is_sharesift_only",
        "structured_parser_matched",
        "extracted_field_max_confidence",
        "blind_spot_rule_matched",
        "saas_rule_matched",
    ]
    names.extend(f"ext_{e}" for e in _TRACKED_EXTENSIONS)
    names.append("ext_other")
    names.append("content_p_literal_missing")
    return names


def _extension_features(path: str) -> dict[str, int]:
    import re as _re
    m = _re.search(r"\.([A-Za-z0-9]+)$", path)
    if not m:
        return {"other": 1}
    ext = m.group(1).lower()
    if ext in _TRACKED_EXTENSIONS:
        return {ext: 1}
    return {"other": 1}


def extract_features(
    path: str,
    matched_rules: list[dict],
    *,
    path_classifier_prob: float = 0.0,
    path_tier: str | None = None,
    content_p_literal: float | None = None,
    file_size: int | None = None,
) -> RankerFeatures:
    """Build a RankerFeatures from a path + the list of rule hits.

    matched_rules is a list of dicts with keys: rule_name, tier,
    match_location, match_action. Typically built from pysnaffler's
    enum_file output by walking the returned rules list.
    """
    import math
    filename_rule_matched = 0
    filename_rule_tiers = []
    content_rule_matched = 0
    content_rule_tiers = []
    snaffler_tiers = []
    n_rules = 0
    is_sharesift_only = 1 if matched_rules else 0
    structured_parser_matched = 0
    extracted_field_max_confidence = 0.0
    blind_spot_rule_matched = 0
    saas_rule_matched = 0
    # SaaS rule prefixes (per sharesift.rules.extra_rules._modern_saas_rules)
    _SAAS_TOKENS = ("Anthropic", "HuggingFace", "Bedrock", "Clickhouse",
                    "Databricks", "Gitlab", "OpenAi", "Perplexity", "Render",
                    "Datadog", "Dropbox", "Fastly", "Netlify")
    for rule in matched_rules:
        n_rules += 1
        tier = rule.get("tier")
        if rule.get("match_action") == "Discard":
            # Discards shouldn't count as flagging; skip from tier aggregation.
            continue
        snaffler_tiers.append(_TIER_ORD.get(tier, 0))
        rule_name = rule.get("rule_name", "")
        if not rule_name.startswith("ShareSift"):
            is_sharesift_only = 0
        if rule_name == "ShareSiftStructuredParser":
            structured_parser_matched = 1
            ec = rule.get("extracted_max_confidence")
            if isinstance(ec, (int, float)):
                extracted_field_max_confidence = max(
                    extracted_field_max_confidence, float(ec))
        if rule_name.startswith("ShareSiftKeep"):
            blind_spot_rule_matched = 1
            if any(tok in rule_name for tok in _SAAS_TOKENS):
                saas_rule_matched = 1
        loc = rule.get("match_location", "")
        if loc in ("FileName", "FilePath", "FileExtension"):
            filename_rule_matched = 1
            filename_rule_tiers.append(_TIER_ORD.get(tier, 0))
        elif loc == "FileContentAsString":
            content_rule_matched = 1
            content_rule_tiers.append(_TIER_ORD.get(tier, 0))
    path_depth = path.replace("\\", "/").count("/")
    file_size_log = math.log10(max(1, file_size)) if file_size else 0.0
    return RankerFeatures(
        path_classifier_prob=path_classifier_prob,
        path_tier_ord=_TIER_ORD.get(path_tier, 0),
        filename_rule_matched=filename_rule_matched,
        filename_rule_max_tier_ord=max(filename_rule_tiers, default=0),
        content_rule_matched=content_rule_matched,
        content_rule_max_tier_ord=max(content_rule_tiers, default=0),
        content_p_literal=content_p_literal,
        snaffler_top_tier_ord=max(snaffler_tiers, default=0),
        n_rules_matched=n_rules,
        path_depth=path_depth,
        file_size_log=file_size_log,
        is_sharesift_only=is_sharesift_only,
        structured_parser_matched=structured_parser_matched,
        extracted_field_max_confidence=extracted_field_max_confidence,
        blind_spot_rule_matched=blind_spot_rule_matched,
        saas_rule_matched=saas_rule_matched,
        ext_features=_extension_features(path),
    )


class ShareSiftRanker:
    """LightGBM LGBMRanker wrapping the feature-vector pipeline."""

    def __init__(self, **lgbm_kwargs):
        # Sensible defaults for small datasets (~1k labels per share).
        self._lgbm_kwargs = {
            "objective": "lambdarank",
            "metric": "ndcg",
            "n_estimators": 200,
            "learning_rate": 0.05,
            "num_leaves": 31,
            "min_child_samples": 10,
            "reg_alpha": 0.1,
            "reg_lambda": 0.1,
            "random_state": 2026,
            **lgbm_kwargs,
        }
        self._model = None
        self._feature_names = feature_names()

    def train(
        self,
        records: list[dict],
        *,
        query_group_field: str = "share",
        label_field: str = "has_credential",
        features_field: str = "features",
    ) -> dict:
        """Train the ranker on a list of {share, features (RankerFeatures
        or dict), has_credential} records. Returns a dict of training
        metadata (n_records, n_groups, n_positives, eval_ndcg)."""
        try:
            from lightgbm import LGBMRanker  # type: ignore[import-not-found]
        except ImportError:
            raise ImportError(
                "lightgbm not installed. Add to project deps: "
                "uv add lightgbm"
            )
        # Sort by share to form contiguous query groups (LGBMRanker requires this)
        records = sorted(records, key=lambda r: r[query_group_field])
        X = []
        y = []
        group_sizes = []
        prev_share = None
        for r in records:
            feats = r[features_field]
            if isinstance(feats, RankerFeatures):
                X.append(feats.to_array())
            elif isinstance(feats, dict):
                X.append(RankerFeatures(**feats).to_array())
            else:
                raise TypeError(f"features must be RankerFeatures or dict; got {type(feats)}")
            y.append(int(bool(r[label_field])))
            share = r[query_group_field]
            if share != prev_share:
                group_sizes.append(0)
                prev_share = share
            group_sizes[-1] += 1
        self._model = LGBMRanker(**self._lgbm_kwargs)
        self._model.fit(X, y, group=group_sizes)
        n_positives = sum(y)
        meta = {
            "n_records": len(X),
            "n_groups": len(group_sizes),
            "n_positives": n_positives,
            "positive_rate": n_positives / max(1, len(X)),
            "lgbm_kwargs": self._lgbm_kwargs,
        }
        return meta

    def score(self, features: Iterable[RankerFeatures | dict]) -> list[float]:
        """Score a batch of feature vectors. Returns raw LGBMRanker scores;
        callers can min-max normalize within a share if a [0,1] range is
        desired."""
        if self._model is None:
            raise RuntimeError("Ranker not trained or loaded.")
        X = []
        for f in features:
            if isinstance(f, RankerFeatures):
                X.append(f.to_array())
            elif isinstance(f, dict):
                X.append(RankerFeatures(**f).to_array())
            else:
                raise TypeError(f"features must be RankerFeatures or dict; got {type(f)}")
        return list(self._model.predict(X))

    def save(self, path: Path | str) -> None:
        import joblib
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            "model": self._model,
            "feature_names": self._feature_names,
            "lgbm_kwargs": self._lgbm_kwargs,
        }, path)

    @classmethod
    def load(cls, path: Path | str) -> "ShareSiftRanker":
        import joblib
        data = joblib.load(path)
        ranker = cls(**data.get("lgbm_kwargs", {}))
        ranker._model = data["model"]
        ranker._feature_names = data.get("feature_names", feature_names())
        return ranker


def build_ranker_training_data(
    scan_predictions_jsonl: Path,
    ground_truth_jsonl: Path,
    share_name: str,
) -> list[dict]:
    """Join ShareSift scan predictions + ground-truth labels into ranker training records.

    scan_predictions_jsonl: output of eval_v0p14_vs_snaffler.py predictions —
        each record has path, truffler_rules (list of rule names), etc.
        Will need to enrich with rule tier/location info to extract features.
    ground_truth_jsonl: build_msf3_ground_truth.py output with has_credential labels.
    share_name: query-group label (e.g. "metasploitable3").
    """
    gt = {}
    with ground_truth_jsonl.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                gt[r["path"].lower()] = r
            except json.JSONDecodeError:
                continue
    records: list[dict] = []
    with scan_predictions_jsonl.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                pred = json.loads(line)
            except json.JSONDecodeError:
                continue
            label_rec = gt.get(pred["path"].lower())
            if not label_rec or label_rec.get("has_credential") is None:
                continue
            # Stub: matched_rules needs rule metadata join (tier, location).
            # Caller must enrich. For now build a minimal feature record.
            matched_rules = pred.get("truffler_rules_meta", [])
            features = extract_features(
                path=pred["path"],
                matched_rules=matched_rules,
                path_classifier_prob=pred.get("path_classifier_prob", 0.0),
                path_tier=pred.get("path_tier"),
                content_p_literal=pred.get("content_p_literal"),
                file_size=pred.get("file_size"),
            )
            records.append({
                "share": share_name,
                "path": pred["path"],
                "has_credential": bool(label_rec["has_credential"]),
                "features": features,
            })
    return records
