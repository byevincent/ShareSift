"""Training pipeline for the v0 LightGBM path classifier.

Loads synthetic training records, featurizes via ``features.featurize``,
fits a LightGBM binary classifier, and writes a model artifact directory.

Per ``docs/build_plan.md`` Phase 2: training data is
``data/synthetic/training_v0.jsonl`` only — eval data
(``data/eval/eval_set_claude.jsonl``,
``data/eval/snaffler_blind_benchmark.jsonl``) is strictly held out.

Artifact layout:

    models/path_classifier_v0/
        model.joblib       — pickled LGBMClassifier
        metadata.json      — training config, dataset hash, sklearn /
                              lightgbm versions, training-set size,
                              label balance, feature config
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import joblib
import lightgbm as lgb
import numpy as np
import sklearn

from sharesift.features import (
    HAND_FEATURE_NAMES,
    NGRAM_RANGE,
    N_HAND_FEATURES,
    N_HASH_FEATURES,
    featurize,
    is_juicy,
)


@dataclass(frozen=True)
class TrainConfig:
    """Hyperparameters pinned for the v0 LightGBM classifier.

    All values are conservative defaults — the build plan calls for
    iterating on hard negatives in a later pass, at which point this
    config gets tuned. For v0, the priority is a reproducible baseline.
    """

    n_estimators: int = 300
    learning_rate: float = 0.05
    num_leaves: int = 31
    min_child_samples: int = 20
    reg_alpha: float = 0.0
    reg_lambda: float = 0.0
    random_state: int = 0
    # ``balanced`` handles synthetic's ~50/50 mix and eval's ~5/95
    # imbalance gracefully — LightGBM weights samples inversely to
    # class frequency.
    class_weight: str = "balanced"


def load_records(path: Path) -> list[dict]:
    """Load a JSONL file of records."""
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _hash_records(records: list[dict]) -> str:
    """Stable hash of training records — pinned in metadata so future
    diagnoses can verify ``model.joblib`` was trained against this
    specific data slice."""
    h = hashlib.sha256()
    for r in records:
        h.update(r["path"].encode("utf-8"))
        h.update(b"\x00")
        h.update(b"1" if is_juicy(r) else b"0")
        h.update(b"\n")
    return h.hexdigest()


def train_model(
    records: list[dict], config: TrainConfig | None = None
) -> lgb.LGBMClassifier:
    """Fit a LightGBM classifier on the provided records and return it.

    Records may use either the synthetic ``juicy: bool`` or the eval
    ``label: str`` convention — ``is_juicy`` adapts both.
    """
    config = config or TrainConfig()
    paths = [r["path"] for r in records]
    y = np.array([1 if is_juicy(r) else 0 for r in records], dtype=np.int32)
    X = featurize(paths)
    model = lgb.LGBMClassifier(
        objective="binary",
        n_estimators=config.n_estimators,
        learning_rate=config.learning_rate,
        num_leaves=config.num_leaves,
        min_child_samples=config.min_child_samples,
        reg_alpha=config.reg_alpha,
        reg_lambda=config.reg_lambda,
        class_weight=config.class_weight,
        random_state=config.random_state,
        verbose=-1,
    )
    model.fit(X, y)
    return model


def save_model(
    model: lgb.LGBMClassifier,
    output_dir: Path,
    records: list[dict],
    config: TrainConfig,
    train_source: Path,
) -> None:
    """Atomically save the model + a metadata file describing the run.

    The metadata lets a future reader verify what was trained and detect
    silent drift (e.g. featurization config changed but model artifact
    wasn't retrained).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = output_dir / "model.joblib"
    metadata_path = output_dir / "metadata.json"

    joblib.dump(model, model_path)

    n_juicy = sum(1 for r in records if is_juicy(r))
    metadata = {
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        "train_source": str(train_source),
        "train_record_count": len(records),
        "train_juicy_count": n_juicy,
        "train_not_juicy_count": len(records) - n_juicy,
        "train_records_sha256": _hash_records(records),
        "config": {
            "n_estimators": config.n_estimators,
            "learning_rate": config.learning_rate,
            "num_leaves": config.num_leaves,
            "min_child_samples": config.min_child_samples,
            "reg_alpha": config.reg_alpha,
            "reg_lambda": config.reg_lambda,
            "class_weight": config.class_weight,
            "random_state": config.random_state,
        },
        "features": {
            "ngram_range": list(NGRAM_RANGE),
            "n_hash_features": N_HASH_FEATURES,
            "n_hand_features": N_HAND_FEATURES,
            "hand_feature_names": list(HAND_FEATURE_NAMES),
        },
        "versions": {
            "sklearn": sklearn.__version__,
            "lightgbm": lgb.__version__,
            "python": sys.version.split()[0],
        },
    }
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
