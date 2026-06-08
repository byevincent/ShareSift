"""v0.21: cascade-aware reranker.

EXPERIMENTAL — DO NOT USE AS DEFAULT IN PRODUCTION SCANS.

Real-world validation on Metasploitable 3 (see
``docs/v0p21_real_world_validation.md``) showed this reranker is
trained on a distribution that does NOT transfer:

    v0.21 release headline (in-distribution): top-10 = 0.76
    MSF3 real-world (out-of-distribution):    top-10 = 0.20

This module ships as-is for reference and re-training, but the
default ``Scanner.scan_batch`` flow does NOT use it. The cascade
(parsers + rules + extractor) from v0.20 is the production stack.

If you want to experiment with reranking, you must retrain on data
that includes your target distribution AND evaluate on a frozen
held-out set you never iterate against.

---

v0.20 lifted recall +23 pp but legal top-10 precision regressed to
0.00 — the rule engine produces matches without distinguishing
which top-K files matter most. The reranker uses cascade source +
tier + path probability as features to put the genuinely-juicy files
in the top of the ranked list.

Features per scored file:

* ``path_probability``        — Stage 1 calibrated probability
* ``path_tier_rank``          — 0/1/2/3/4 for None/Green/Yellow/Red/Black
* ``cascade_tier_rank``       — same encoding for the v0.20 cascade tier
* ``cascade_source_*``        — one-hot encoded: parsers / rules / extractor / classifier
* ``n_rule_matches``          — count from the cascade verdict
* ``extension_*``             — one-hot for top common extensions
* ``directory_depth``         — number of path components

Model: LightGBM ranker with binary log loss (we treat the salted
label as the relevance score). LambdaRank would be more correct but
binary log loss is robust for the small-N training set (~400 files
across 5 themes) and the calibrated probabilities directly serve as
the rerank score.

Training data: the v0.19 themed manifests, leave-one-theme-out CV
during evaluation to measure cross-theme generalization. Production
training uses all 5 themes' manifests.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np

_TIER_RANK = {None: 0, "Green": 1, "Yellow": 2, "Red": 3, "Black": 4}
_CASCADE_SOURCES = ["parsers", "rules", "extractor", "classifier"]
_COMMON_EXTENSIONS = [
    ".txt", ".md", ".yaml", ".yml", ".json", ".env", ".conf", ".cfg", ".ini",
    ".csv", ".xlsx", ".docx", ".pdf", ".doc", ".xml", ".hl7", ".tfstate",
    ".pem", ".php", ".html",
]


@dataclass
class RerankFeatures:
    path_probability: float
    path_tier_rank: int
    cascade_tier_rank: int
    cascade_source_parsers: int
    cascade_source_rules: int
    cascade_source_extractor: int
    cascade_source_classifier: int
    n_rule_matches: int
    extension_one_hot: list[int]
    directory_depth: int

    def to_vector(self) -> list[float]:
        return [
            float(self.path_probability or 0.0),
            float(self.path_tier_rank),
            float(self.cascade_tier_rank),
            float(self.cascade_source_parsers),
            float(self.cascade_source_rules),
            float(self.cascade_source_extractor),
            float(self.cascade_source_classifier),
            float(self.n_rule_matches),
            *[float(v) for v in self.extension_one_hot],
            float(self.directory_depth),
        ]

    @staticmethod
    def feature_names() -> list[str]:
        names = [
            "path_probability",
            "path_tier_rank",
            "cascade_tier_rank",
            "cascade_source_parsers",
            "cascade_source_rules",
            "cascade_source_extractor",
            "cascade_source_classifier",
            "n_rule_matches",
        ]
        names.extend(f"ext_{ext.lstrip('.')}" for ext in _COMMON_EXTENSIONS)
        names.append("directory_depth")
        return names


def extract_features(record: dict) -> RerankFeatures:
    """Compute the v0.21 reranker feature vector from a v0.20 scored record.

    The record may come from either ``benchmarks/v0p20/<theme>/metrics.json``
    (theme-scored manifest+cascade) or a live ``sharesift scan-files`` JSONL
    output.
    """
    path = record.get("path") or ""
    extension = ""
    if "." in path:
        extension = "." + path.rsplit(".", 1)[-1].lower()

    ext_one_hot = [1 if extension == e else 0 for e in _COMMON_EXTENSIONS]

    cascade_src = record.get("cascade_source") or record.get("verdict_source")
    src_oh = {s: 0 for s in _CASCADE_SOURCES}
    if cascade_src in src_oh:
        src_oh[cascade_src] = 1

    return RerankFeatures(
        path_probability=record.get("path_probability") or record.get("probability") or 0.0,
        path_tier_rank=_TIER_RANK.get(record.get("path_tier"), 0),
        cascade_tier_rank=_TIER_RANK.get(
            record.get("cascade_tier") or record.get("verdict_tier"), 0
        ),
        cascade_source_parsers=src_oh["parsers"],
        cascade_source_rules=src_oh["rules"],
        cascade_source_extractor=src_oh["extractor"],
        cascade_source_classifier=src_oh["classifier"],
        n_rule_matches=record.get("n_matches", record.get("n_rule_matches", 0)) or 0,
        extension_one_hot=ext_one_hot,
        directory_depth=len(path.split("/")) if path else 0,
    )


class CascadeReranker:
    """LightGBM-backed reranker. Loaded from a joblib model artifact."""

    def __init__(self, model: Any) -> None:
        self._model = model

    @classmethod
    def load(cls, model_path: Path) -> "CascadeReranker":
        return cls(joblib.load(model_path))

    @classmethod
    def from_model(cls, model: Any) -> "CascadeReranker":
        return cls(model)

    def score(self, records: list[dict]) -> list[float]:
        if not records:
            return []
        X = np.array([extract_features(r).to_vector() for r in records], dtype=np.float32)
        # LightGBM's predict_proba returns class probabilities for
        # binary classifiers; column 1 is the positive class.
        probs = self._model.predict_proba(X)
        if probs.ndim == 2 and probs.shape[1] >= 2:
            return [float(p) for p in probs[:, 1]]
        return [float(p) for p in probs.ravel()]


__all__ = [
    "CascadeReranker",
    "RerankFeatures",
    "extract_features",
]
