"""Single-path inference for the v0 path classifier.

Loads the saved model artifact once at module import (lazy via ``_load``)
and exposes ``predict(path)`` returning the juicy probability. Callers
that need batched inference should use ``predict_batch(paths)`` which
amortizes the featurization cost.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import joblib

from sharesift.features import featurize

DEFAULT_MODEL_DIR = Path("models/path_classifier_v0")


@lru_cache(maxsize=1)
def _load(model_dir: Path = DEFAULT_MODEL_DIR):
    return joblib.load(model_dir / "model.joblib")


def predict(path: str, model_dir: Path = DEFAULT_MODEL_DIR) -> float:
    """Return the juicy probability for a single path."""
    model = _load(model_dir)
    X = featurize([path])
    return float(model.predict_proba(X)[0, 1])


def predict_batch(
    paths: list[str], model_dir: Path = DEFAULT_MODEL_DIR
) -> list[float]:
    """Return juicy probabilities for a batch — single featurization +
    single model call, much cheaper than calling ``predict`` in a loop."""
    if not paths:
        return []
    model = _load(model_dir)
    X = featurize(paths)
    return [float(p) for p in model.predict_proba(X)[:, 1]]
