"""v0.21: cascade reranker — feature extraction + scoring."""

from __future__ import annotations

import numpy as np
import pytest

from sharesift.reranker_v0p21 import (
    CascadeReranker,
    RerankFeatures,
    extract_features,
)


def test_feature_names_match_vector_length():
    """Vector dim must equal feature-names list — feature drift would
    silently corrupt training."""
    f = RerankFeatures(
        path_probability=0.5,
        path_tier_rank=2,
        cascade_tier_rank=3,
        cascade_source_parsers=0,
        cascade_source_rules=1,
        cascade_source_extractor=0,
        cascade_source_classifier=0,
        n_rule_matches=2,
        extension_one_hot=[0] * 20,
        directory_depth=4,
    )
    vec = f.to_vector()
    names = RerankFeatures.feature_names()
    assert len(vec) == len(names), (
        f"vector dim {len(vec)} != feature-names dim {len(names)}"
    )


def test_extract_features_handles_v0p20_record_shape():
    record = {
        "path": "/share/dev_eng/secrets/vault_root_token_0023.yaml",
        "path_probability": 0.72,
        "path_tier": "Red",
        "cascade_tier": "Black",
        "cascade_source": "rules",
        "n_matches": 3,
    }
    feats = extract_features(record)
    assert feats.path_probability == 0.72
    assert feats.path_tier_rank == 3  # Red
    assert feats.cascade_tier_rank == 4  # Black
    assert feats.cascade_source_rules == 1
    assert feats.cascade_source_parsers == 0
    assert feats.n_rule_matches == 3


def test_extract_features_handles_v0p19_record_shape():
    """v0.19 records use ``verdict_source`` / ``verdict_tier`` /
    ``probability``. Reranker must accept either shape."""
    record = {
        "path": "/share/finance/wire_instructions_0026.docx",
        "probability": 0.146,
        "verdict_tier": None,
        "verdict_source": "none",
        "n_matches": 0,
    }
    feats = extract_features(record)
    assert feats.path_probability == 0.146
    assert feats.cascade_tier_rank == 0
    assert feats.cascade_source_rules == 0


def test_reranker_score_ranks_higher_for_stronger_signal(tmp_path):
    """A stub model that just sums the input vector — the file with
    more cascade signal should rank higher."""

    class _StubModel:
        def predict_proba(self, X):
            # Probability proportional to sum of (path_prob + tier_rank).
            probs = (X[:, 0] + X[:, 2] / 10.0)
            probs = np.clip(probs, 0, 1)
            return np.stack([1 - probs, probs], axis=1)

    reranker = CascadeReranker.from_model(_StubModel())
    records = [
        {  # low signal
            "path": "/share/notes.md",
            "path_probability": 0.05,
            "path_tier": None,
            "cascade_tier": None,
            "cascade_source": None,
            "n_matches": 0,
        },
        {  # high signal
            "path": "/share/admin/id_rsa",
            "path_probability": 0.95,
            "path_tier": "Black",
            "cascade_tier": "Black",
            "cascade_source": "rules",
            "n_matches": 2,
        },
    ]
    scores = reranker.score(records)
    assert scores[1] > scores[0]


def test_reranker_handles_empty_records():
    class _StubModel:
        def predict_proba(self, X):
            return np.zeros((len(X), 2))

    reranker = CascadeReranker.from_model(_StubModel())
    assert reranker.score([]) == []
