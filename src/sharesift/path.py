"""Path-classifier runtime wrapper — routes by path shape.

v0.5 split the single combined classifier into two: a Windows model
trained on UNC paths and a Linux model trained on Unix paths. Mixing
the two distributions in a single LightGBM caused systematic Windows
regression (33% of Windows juicy paths in test split lost >0.30 of
their probability), because the model's splits had to fit two
heterogeneous path shapes simultaneously. Separate models per shape
recover the v0.3 Windows quality and let the Linux model specialize.

This wrapper presents the same single-classifier API as before
(``score``, ``score_batch``, ``PathResult``), but dispatches each input
to whichever underlying model owns its path shape:

* paths starting ``\\\\`` (UNC) → Windows model
* everything else (``/...``, ``~/...``, naked basenames) → Linux model

The Samba-shared-Linux-home edge case (``\\\\srv\\users\\alice\\.bash_history``)
routes to Windows; the Windows model may underdetect basenames it didn't
see in training. Documented limitation for v0.5.

Featurization and tier-band semantics still live in ``sharesift.features``
and ``sharesift.tier`` — single source of truth, shared across both models.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np

from sharesift.features import featurize
from sharesift.tier import (
    DEFAULT_LINUX_THRESHOLDS,
    DEFAULT_WINDOWS_THRESHOLDS,
    TierThresholds,
    probability_to_tier,
)


def _resolve_model_dir(relpath: str) -> Path:
    """Resolve a model dir relative to the bundle root when frozen.

    PyInstaller ``--onefile`` extracts bundled data into a temp dir
    accessible via ``sys._MEIPASS``. The spec bundles models as
    ``models/path_classifier_v0_{windows,linux}/`` relative to that
    root. When not frozen, fall back to repo-relative (matches the
    pre-frozen default, where CLI commands are typically invoked from
    the repo root).
    """
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / relpath  # type: ignore[attr-defined]
    return Path(relpath)


class _OODCalibratedModel:
    """Raw LightGBM + isotonic calibrator with sklearn-compatible
    ``predict_proba`` interface.

    Built by ``tools/install_recalibrated_windows.py`` to address the
    v0.5-audit finding that the original CalibratedClassifierCV
    (trained on in-distribution data only) miscalibrates dramatically
    on the Snaffler-blind benchmark (ECE 0.30 vs 0.007 in-distribution).

    The fix: fit a single IsotonicRegression on raw LightGBM scores
    from (train_set ∪ a 30% slice of Snaffler-blind benchmark), so the
    calibrator sees both distributions. Reduces OOD ECE to ~0.19 while
    keeping in-distribution ECE essentially unchanged.

    Lives in ``sharesift.path`` rather than ``tools/`` so the joblib
    pickle can find the class at load time from the deployed runtime.
    """

    def __init__(self, raw_model, isotonic_calibrator) -> None:
        self._raw = raw_model
        self._iso = isotonic_calibrator

    def predict_proba(self, X) -> np.ndarray:
        raw_probs = self._raw.predict_proba(X)[:, 1]
        cal = self._iso.predict(raw_probs)
        cal = np.clip(cal, 0.0, 1.0)
        return np.column_stack([1.0 - cal, cal])

    def predict(self, X) -> np.ndarray:
        probs = self.predict_proba(X)[:, 1]
        return (probs >= 0.5).astype(int)


class _BetaCalibratedModel:
    """Raw LightGBM + beta calibrator with sklearn-compatible
    ``predict_proba`` interface.

    Companion to ``_OODCalibratedModel`` for the v0.15+ path classifiers,
    where the calibration approach is beta (Kull et al., 2017) instead
    of isotonic.

    Beta calibration was adopted because v0.15's raw LightGBM outputs
    cluster heavily in [0, 0.2] (mean=0.18), where isotonic produces a
    step function that collapses most of the mass to the same plateau.
    Beta calibration is parametric (3 params) and handles the
    "rare-positives-near-zero" pattern with a smooth function instead.

    Fitted on the snaffler-blind benchmark (50/50 balanced) so the
    tier thresholds align with v0.5-style precision-band semantics
    (Black >= P 0.95, Red >= P 0.80, Yellow >= P 0.50).
    """

    def __init__(self, raw_model, beta_calibrator) -> None:
        self._raw = raw_model
        self._cal = beta_calibrator

    def predict_proba(self, X) -> np.ndarray:
        raw_probs = self._raw.predict_proba(X)[:, 1]
        cal = self._cal.predict(raw_probs.reshape(-1, 1))
        cal = np.clip(cal, 0.0, 1.0)
        return np.column_stack([1.0 - cal, cal])

    def predict(self, X) -> np.ndarray:
        probs = self.predict_proba(X)[:, 1]
        return (probs >= 0.5).astype(int)


DEFAULT_WINDOWS_MODEL_DIR = _resolve_model_dir("models/path_classifier_v0_windows")
DEFAULT_LINUX_MODEL_DIR = _resolve_model_dir("models/path_classifier_v0_linux")
_CALIBRATED_ARTIFACT = "calibrated.joblib"


def is_unc_path(path: str) -> bool:
    """True if ``path`` looks like a UNC path (``\\\\host\\share\\...``).

    Routes the dispatch in :class:`PathClassifier`. The check is a
    prefix test, not full UNC validation — extraction-time filters
    upstream already weed out malformed candidates.
    """
    return path.startswith("\\\\")


@dataclass(frozen=True)
class PathResult:
    """One path scored by the path classifier.

    ``probability`` is the calibrated juicy probability in [0, 1].
    ``tier`` is the Snaffler-vocabulary label (``"Black"``, ``"Red"``,
    ``"Yellow"``) or ``None`` if the probability is below the lowest
    band (path is not flagged).
    """

    path: str
    probability: float
    tier: str | None


class _SingleModelClassifier:
    """Single-model wrapper. One per path shape; composed by :class:`PathClassifier`."""

    def __init__(self, model_dir: Path, thresholds: TierThresholds) -> None:
        artifact = model_dir / _CALIBRATED_ARTIFACT
        if not artifact.exists():
            raise FileNotFoundError(
                f"Path-classifier artifact not found: {artifact}. "
                f"Did you run tools/calibrate_path_classifier.py?"
            )
        self._model = joblib.load(artifact)
        self._thresholds = thresholds

    def score_batch(self, paths: list[str]) -> list[PathResult]:
        if not paths:
            return []
        X = featurize(paths)
        probs = self._model.predict_proba(X)[:, 1]
        return [
            PathResult(
                path=p,
                probability=float(prob),
                tier=probability_to_tier(float(prob), self._thresholds),
            )
            for p, prob in zip(paths, probs)
        ]


class PathClassifier:
    """Stateful router that dispatches by path shape to per-shape models.

    Instantiate once, reuse across calls — model loads are the expensive
    step (~15MB each, ~half a second cold). Inference is sub-millisecond
    per path after warm-up.

    Defaults load both Windows and Linux models from their canonical
    locations under ``models/``. For tests or specialized setups, pass
    ``windows_model_dir=None`` or ``linux_model_dir=None`` to skip that
    half — paths that would route to a missing model raise
    ``RuntimeError`` at score time.
    """

    def __init__(
        self,
        windows_model_dir: Path | None = DEFAULT_WINDOWS_MODEL_DIR,
        linux_model_dir: Path | None = DEFAULT_LINUX_MODEL_DIR,
        windows_thresholds: TierThresholds | None = None,
        linux_thresholds: TierThresholds | None = None,
    ) -> None:
        self._windows = (
            _SingleModelClassifier(
                windows_model_dir, windows_thresholds or DEFAULT_WINDOWS_THRESHOLDS
            )
            if windows_model_dir is not None
            else None
        )
        self._linux = (
            _SingleModelClassifier(
                linux_model_dir, linux_thresholds or DEFAULT_LINUX_THRESHOLDS
            )
            if linux_model_dir is not None
            else None
        )

    def score(self, path: str) -> PathResult:
        """Score a single path. Internally batches of one — prefer
        ``score_batch`` when classifying many paths since featurization
        amortizes."""
        return self.score_batch([path])[0]

    def score_batch(self, paths: list[str]) -> list[PathResult]:
        """Score N paths in one featurization + one model call per shape.

        Splits by path shape, dispatches each subset to the appropriate
        underlying model, then recombines in original input order. Empty
        input returns an empty list.
        """
        if not paths:
            return []

        windows_indices: list[int] = []
        linux_indices: list[int] = []
        for i, p in enumerate(paths):
            if is_unc_path(p):
                windows_indices.append(i)
            else:
                linux_indices.append(i)

        results: list[PathResult | None] = [None] * len(paths)

        if windows_indices:
            if self._windows is None:
                raise RuntimeError(
                    f"{len(windows_indices)} UNC path(s) routed but no Windows "
                    f"model loaded (windows_model_dir was None)"
                )
            windows_paths = [paths[i] for i in windows_indices]
            for idx, r in zip(windows_indices, self._windows.score_batch(windows_paths)):
                results[idx] = r

        if linux_indices:
            if self._linux is None:
                raise RuntimeError(
                    f"{len(linux_indices)} non-UNC path(s) routed but no Linux "
                    f"model loaded (linux_model_dir was None)"
                )
            linux_paths = [paths[i] for i in linux_indices]
            for idx, r in zip(linux_indices, self._linux.score_batch(linux_paths)):
                results[idx] = r

        # results is now fully populated — all None slots filled.
        return [r for r in results if r is not None]
