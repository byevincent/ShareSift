"""Probability calibration for the v0 LightGBM path classifier.

LightGBM's raw probabilities are well-known to be "sharp" — predictions
cluster near 0 and 1 rather than spreading across the [0, 1] interval.
This is fine for ranking but makes the probability dishonest as a
confidence signal. Phase-2 closure (per ``docs/build_plan.md``) calls
for calibrating into Snaffler's tier taxonomy; the tier boundaries
(``src/eval/model/tier.py``) need monotonic-and-honest probabilities,
which is what calibration provides.

Implementation:

* ``sklearn.calibration.CalibratedClassifierCV`` with method='isotonic'
  (monotonic non-parametric fit — better than Platt scaling when the
  base model is already a strong classifier, which LightGBM is here).
* ``cv=5`` — fits 5 base models on training folds, calibrates each
  against the corresponding validation fold, then averages. Doesn't
  consume the held-out test split or benchmark — calibration stays
  inside training.

The calibrated wrapper is saved alongside the base model so callers
that want raw probabilities can still load the base.
"""

from __future__ import annotations

import numpy as np
import scipy.sparse as sp
from sklearn.calibration import CalibratedClassifierCV

from sharesift.features import featurize, is_juicy
from src.eval.model.train import TrainConfig
import lightgbm as lgb


def fit_calibrator(
    records: list[dict],
    config: TrainConfig | None = None,
    cv: int = 5,
) -> CalibratedClassifierCV:
    """Fit a CV-calibrated wrapper around the LightGBM base classifier.

    Training data is used for both base fitting and isotonic calibration
    via CV folding — no need to consume a separate held-out set.
    """
    config = config or TrainConfig()
    paths = [r["path"] for r in records]
    y = np.array([1 if is_juicy(r) else 0 for r in records], dtype=np.int32)
    X = featurize(paths)

    base = lgb.LGBMClassifier(
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
    calibrated = CalibratedClassifierCV(
        estimator=base, method="isotonic", cv=cv
    )
    calibrated.fit(X, y)
    return calibrated


def predict_calibrated_proba(
    calibrated: CalibratedClassifierCV, paths: list[str]
) -> np.ndarray:
    """Return calibrated juicy probabilities for a batch of paths."""
    X = featurize(paths)
    return calibrated.predict_proba(X)[:, 1]
