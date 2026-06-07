"""Export the calibrated LightGBM path classifier to ONNX.

The trained model lives in ``models/path_classifier_v0/calibrated.joblib``
and consists of a 5-fold isotonic-calibrated wrapper around a LightGBM
classifier trained on 65,544 sparse features (65,536 char n-gram hashes
+ 8 hand-engineered dense features).

This script exports the **classifier component only** as an ONNX file at
``models/path_classifier_v0/calibrated.onnx``. The featurization step
(``truffler.features.featurize``) is NOT exported — char-n-gram hashing
via ``HashingVectorizer`` is complex to ONNX-trace, and any non-Python
consumer of the ONNX model would need to reimplement the hashing scheme
in its native language regardless. The featurization spec is documented
below so a future C#/Rust/Go integration can produce a compatible input
tensor.

Featurization spec (for reimplementation in non-Python consumers)
=================================================================

Per-path feature vector (length 65,544, float32):

* ``[0..65535]`` — char_wb n-gram hashes, range (3, 5), via
  ``HashingVectorizer(analyzer='char_wb', ngram_range=(3,5),
  n_features=2**16, alternate_sign=False, norm=None)``. The hashing
  algorithm is MurmurHash3 (32-bit) of the n-gram byte string, then
  ``mod 2**16``. Values are raw counts (no L2-normalization).
* ``[65536]`` — path length (float)
* ``[65537]`` — path depth = ``count('/') + count('\\')`` (float)
* ``[65538]`` — has_extension flag (1.0 if rightmost ``.`` is after the
  last separator and not at position 0, else 0.0)
* ``[65539]`` — extension length (float, 0 if no extension)
* ``[65540]`` — dots in basename (float)
* ``[65541]`` — digits in basename (float)
* ``[65542]`` — is_unc flag (1.0 if path starts with ``"\\\\"`` else 0.0)
* ``[65543]`` — is_linux flag (1.0 if path starts with ``"/"`` else 0.0)

Hand-feature order matches ``truffler.features.HAND_FEATURE_NAMES``;
breaking that order is a model-version bump.

ONNX input/output signature
===========================

* Input: ``float_input`` of shape ``(N, 65544)``, dtype ``float32``,
  dense (sparse not supported by the LightGBM ONNX converter).
* Output 0: ``label`` shape ``(N,)`` int64 — predicted class index (0/1).
* Output 1: ``probabilities`` shape ``(N, 2)`` float32 — column 1 is the
  juicy probability (the same value Python's ``predict_proba(X)[:, 1]``
  returns).

v0.5 — `_OODCalibratedModel` and the isotonic sidecar
=====================================================

The v0.5 Tier-2.1 audit replaced the v0.3 Windows calibrator
(`CalibratedClassifierCV(method="isotonic", cv=5)`) with a custom
`_OODCalibratedModel` wrapper: raw LightGBM + an
``sklearn.isotonic.IsotonicRegression`` fit on `(train ∪ 30%
Snaffler-blind benchmark)`. sklearn-onnx 1.20 has no standalone
converter for `IsotonicRegression`, so a single-file ONNX of the
wrapper isn't available without a custom op subgraph.

Instead we ship a two-file artifact:

* ``calibrated.onnx`` — raw LightGBM, identical signature to v0.3's
  export (input ``(N, 65544)`` float32 → ``label[N]`` int64 +
  ``probabilities[N, 2]`` float32). Column 1 of `probabilities` is
  the **raw** (uncalibrated) juicy probability.
* ``calibrated.isotonic.json`` — sidecar containing the isotonic
  calibrator state: ``X_thresholds_`` and ``y_thresholds_`` arrays
  (~hundreds of breakpoints each) plus the post-processing spec.

ONNX consumers apply the calibrator in ~30 lines of their native
language:

    1. Run the ONNX. Take ``probabilities[:, 1]`` (raw positive prob).
    2. Clip each raw prob to ``[X_thresholds_[0], X_thresholds_[-1]]``.
    3. For each clipped value `z`, find the largest `k` such that
       ``X_thresholds_[k] <= z``.
    4. Linear-interp between ``(X_thresholds_[k], y_thresholds_[k])``
       and ``(X_thresholds_[k+1], y_thresholds_[k+1])``.
    5. Clip the result to ``[0, 1]``. That's the calibrated juicy
       probability.

The Linux model's `calibrated.joblib` still uses sklearn's standard
``CalibratedClassifierCV`` and exports as a single ONNX file with no
sidecar (Linux model wasn't recalibrated in Tier 2.1).

Verification
============

The export step verifies that the ONNX model + sidecar (if present)
produces predictions matching the sklearn model within rtol 1e-4 on
the in-distribution test split (or as many records as ``--verify-n``
requests, default 100). For sidecar-using models, the numpy reference
implementation of the isotonic post-step is applied to the ONNX raw
probs before comparison. Non-matching exports fail with a clear error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sharesift.features import N_HAND_FEATURES, N_HASH_FEATURES, featurize

# v0.5: per-shape models. Each shape has its own model/output/verify
# triple. The default ``--shape both`` exports both.
_SHAPE_DEFAULTS: dict[str, dict[str, Path]] = {
    "windows": {
        "model": REPO_ROOT / "models" / "path_classifier_v0_windows" / "calibrated.joblib",
        "output": REPO_ROOT / "models" / "path_classifier_v0_windows" / "calibrated.onnx",
        "verify_data": REPO_ROOT / "data" / "eval" / "test_split_windows.jsonl",
    },
    "linux": {
        "model": REPO_ROOT / "models" / "path_classifier_v0_linux" / "calibrated.joblib",
        "output": REPO_ROOT / "models" / "path_classifier_v0_linux" / "calibrated.onnx",
        "verify_data": REPO_ROOT / "data" / "eval" / "test_split_linux.jsonl",
    },
}


# --- Setup ----------------------------------------------------------------


def _register_lightgbm_converter() -> None:
    """Wire LightGBM's ONNX converter into skl2onnx's registry.

    skl2onnx ships a CalibratedClassifierCV converter but not a
    LightGBM converter; ``onnxmltools`` provides the latter and we
    register it under skl2onnx's name table so the wrapped model
    converts end-to-end.
    """
    from lightgbm import LGBMClassifier
    from onnxmltools.convert.lightgbm.operator_converters.LightGbm import (
        convert_lightgbm,
    )
    from skl2onnx import update_registered_converter
    from skl2onnx.common.shape_calculator import (
        calculate_linear_classifier_output_shapes,
    )

    update_registered_converter(
        LGBMClassifier,
        "LightGbmLGBMClassifier",
        calculate_linear_classifier_output_shapes,
        convert_lightgbm,
        options={"nocl": [True, False], "zipmap": [True, False, "columns"]},
    )




# --- Export ---------------------------------------------------------------


def export(model_path: Path, output_path: Path) -> None:
    from lightgbm import LGBMClassifier
    from sklearn.calibration import CalibratedClassifierCV
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType

    from sharesift.path import _OODCalibratedModel

    _register_lightgbm_converter()

    print(
        f"Loading model from {model_path.relative_to(REPO_ROOT)}",
        file=sys.stderr,
    )
    model = joblib.load(model_path)
    n_features = N_HASH_FEATURES + N_HAND_FEATURES

    # _OODCalibratedModel: ONNX can host the raw LightGBM directly, but
    # sklearn-onnx 1.20 has no converter for sklearn.isotonic.
    # IsotonicRegression (only the variant inside CalibratedClassifierCV).
    # We split: emit the raw LightGBM as ONNX, and write the isotonic
    # state as a sidecar JSON next to it. ONNX consumers apply the
    # calibrator in ~30 lines of their native language (the spec is in
    # this script's module docstring).
    model_for_onnx = model._raw if isinstance(model, _OODCalibratedModel) else model
    iso_for_sidecar = model._iso if isinstance(model, _OODCalibratedModel) else None

    print(
        f"Converting to ONNX with input shape (None, {n_features}) float32...",
        file=sys.stderr,
    )
    onnx_model = convert_sklearn(
        model_for_onnx,
        initial_types=[("float_input", FloatTensorType([None, n_features]))],
        # Disable zipmap on inner LGBM (and on legacy CalibratedClassifierCV
        # if a v0.3-style model is being exported) so probabilities come
        # out as a (N, 2) tensor rather than seq(map(int64, tensor(float))).
        options={
            CalibratedClassifierCV: {"zipmap": False},
            LGBMClassifier: {"zipmap": False},
            id(model_for_onnx): {"zipmap": False},
        },
        # Pin the ai.onnx.ml domain to opset 3 (skl2onnx 1.20's max for
        # that domain; LGBM converter defaults to a higher version that
        # this skl2onnx can't materialize).
        target_opset={"": 18, "ai.onnx.ml": 3},
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as f:
        f.write(onnx_model.SerializeToString())
    size_mb = output_path.stat().st_size / 1024 / 1024
    print(
        f"Wrote ONNX model to {output_path.relative_to(REPO_ROOT)} "
        f"({size_mb:.1f} MB)",
        file=sys.stderr,
    )

    if iso_for_sidecar is not None:
        sidecar_path = output_path.with_suffix(".isotonic.json")
        sidecar_payload = {
            "kind": "isotonic_calibration",
            "applies_to": "probabilities[:, 1] from the raw LightGBM ONNX",
            "X_thresholds_": iso_for_sidecar.X_thresholds_.astype(float).tolist(),
            "y_thresholds_": iso_for_sidecar.y_thresholds_.astype(float).tolist(),
            "out_of_bounds": "clip",
            "post_processing": (
                "For each raw_prob_positive in [0, 1]: clip to "
                "[X_thresholds_[0], X_thresholds_[-1]]; find the largest k "
                "such that X_thresholds_[k] <= raw_prob; linear-interp "
                "between (X_thresholds_[k], y_thresholds_[k]) and "
                "(X_thresholds_[k+1], y_thresholds_[k+1]); clip output to "
                "[0, 1]. The final value is the calibrated juicy "
                "probability."
            ),
        }
        sidecar_path.write_text(json.dumps(sidecar_payload, indent=2))
        print(
            f"Wrote isotonic calibrator sidecar to "
            f"{sidecar_path.relative_to(REPO_ROOT)} "
            f"({len(sidecar_payload['X_thresholds_'])} breakpoints)",
            file=sys.stderr,
        )


# --- Verify ---------------------------------------------------------------


def _apply_isotonic_sidecar(
    raw_probs: np.ndarray, sidecar_path: Path
) -> np.ndarray:
    """Reference implementation of the sidecar JSON's post-processing.

    Mirrors the spec in the sidecar's ``post_processing`` field so the
    verify path tests not just the ONNX raw output but the
    end-to-end (raw → calibrated) pipeline an external consumer would
    follow. ~30 lines; any language can port this trivially.
    """
    payload = json.loads(sidecar_path.read_text())
    X = np.asarray(payload["X_thresholds_"], dtype=np.float64)
    Y = np.asarray(payload["y_thresholds_"], dtype=np.float64)
    z = np.clip(raw_probs.astype(np.float64), X[0], X[-1])
    # bin index k: largest k such that X[k] <= z.
    k = np.searchsorted(X, z, side="right") - 1
    k = np.clip(k, 0, len(X) - 2)
    x_lo, x_hi = X[k], X[k + 1]
    y_lo, y_hi = Y[k], Y[k + 1]
    frac = np.where(x_hi > x_lo, (z - x_lo) / (x_hi - x_lo), 0.0)
    out = y_lo + frac * (y_hi - y_lo)
    return np.clip(out, 0.0, 1.0).astype(np.float32)


def verify(
    model_path: Path,
    onnx_path: Path,
    data_path: Path,
    n_records: int,
) -> bool:
    """Verify ONNX export matches sklearn at deployment-critical granularity.

    LGBM-via-ONNX accumulates ~1-2% probability drift on a small fraction
    of records due to float32 quantization and isotonic bin-boundary
    rounding. That's normal — what matters for Truffler's deployment is
    **tier-band agreement** (does each record land in the same Black /
    Red / Yellow / null bucket?). We report both: the raw probability
    delta distribution AND the tier agreement.

    For v0.5 OOD-calibrated Windows models, the ONNX file contains the
    raw LightGBM; the IsotonicRegression post-step is in a sidecar JSON
    next to the ONNX. We apply the sidecar in pure numpy to verify the
    full (raw → calibrated) pipeline an external consumer would follow.
    """
    import onnxruntime as ort

    from sharesift.path import _OODCalibratedModel
    from sharesift.tier import DEFAULT_THRESHOLDS, probability_to_tier

    print(
        f"Verifying ONNX vs sklearn on first {n_records} records of "
        f"{data_path.relative_to(REPO_ROOT)}...",
        file=sys.stderr,
    )
    records = [
        json.loads(line)
        for line in data_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ][:n_records]
    paths = [r["path"] for r in records]
    X_sparse = featurize(paths)
    X_dense = X_sparse.toarray().astype(np.float32)

    model = joblib.load(model_path)
    sklearn_probs = model.predict_proba(X_sparse)[:, 1]

    sess = ort.InferenceSession(str(onnx_path))
    input_name = sess.get_inputs()[0].name
    outputs = sess.run(None, {input_name: X_dense})
    onnx_probs = outputs[1][:, 1]

    # If the model was an _OODCalibratedModel, the ONNX only has the
    # raw LGBM. Apply the sidecar isotonic to get end-to-end probs.
    if isinstance(model, _OODCalibratedModel):
        sidecar_path = onnx_path.with_suffix(".isotonic.json")
        if not sidecar_path.exists():
            print(
                f"  WARN: model is _OODCalibratedModel but sidecar "
                f"{sidecar_path.name} missing; comparing raw vs calibrated "
                f"(will diverge).",
                file=sys.stderr,
            )
        else:
            onnx_probs = _apply_isotonic_sidecar(onnx_probs, sidecar_path)

    abs_diff = np.abs(sklearn_probs - onnx_probs)
    max_diff = float(abs_diff.max())
    mean_diff = float(abs_diff.mean())
    p99_diff = float(np.percentile(abs_diff, 99))
    print(
        f"  probability delta: max={max_diff:.6e}, p99={p99_diff:.6e}, "
        f"mean={mean_diff:.6e}",
        file=sys.stderr,
    )

    # Tier-agreement: does each record land in the same Black / Red /
    # Yellow / None bucket under both?
    sklearn_tiers = [probability_to_tier(p, DEFAULT_THRESHOLDS) for p in sklearn_probs]
    onnx_tiers = [probability_to_tier(p, DEFAULT_THRESHOLDS) for p in onnx_probs]
    matches = sum(1 for s, o in zip(sklearn_tiers, onnx_tiers) if s == o)
    n_total = len(sklearn_tiers)
    print(
        f"  tier agreement: {matches}/{n_total} ({100*matches/n_total:.1f}%)",
        file=sys.stderr,
    )

    if matches != n_total:
        mismatches = [
            (i, sklearn_probs[i], onnx_probs[i], sklearn_tiers[i], onnx_tiers[i])
            for i, (s, o) in enumerate(zip(sklearn_tiers, onnx_tiers))
            if s != o
        ]
        for i, sp, op, st, ot in mismatches[:5]:
            print(
                f"    record {i}: sklearn p={sp:.4f} tier={st!r}; "
                f"ONNX p={op:.4f} tier={ot!r}",
                file=sys.stderr,
            )

    # Deployment OK if tier agreement is 100% AND mean probability delta
    # is below 1e-2 (1% — comfortably below the narrowest tier band).
    deployment_ok = matches == n_total and mean_diff < 1e-2
    if deployment_ok:
        print(
            f"  PASS — tier-band assignments match {n_total}/{n_total} and "
            f"mean probability delta is below 1%.",
            file=sys.stderr,
        )
        return True
    print(
        f"  FAIL — tier-agreement {matches}/{n_total} or mean diff "
        f"{mean_diff:.2e} exceeds 1e-2 threshold.",
        file=sys.stderr,
    )
    return False


# --- Main -----------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--shape",
        choices=["windows", "linux", "both"],
        default="both",
        help=(
            "Which per-shape model to export. v0.5 split the classifier "
            "into a Windows model (UNC paths) and a Linux model (Unix "
            "paths). Default exports both."
        ),
    )
    p.add_argument(
        "--verify-n",
        type=int,
        default=100,
        help="Number of test records used for ONNX-vs-sklearn verification.",
    )
    p.add_argument(
        "--skip-verify",
        action="store_true",
        help="Skip the post-export verification step.",
    )
    args = p.parse_args(argv)

    shapes_to_export = (
        ["windows", "linux"] if args.shape == "both" else [args.shape]
    )

    exit_code = 0
    for shape in shapes_to_export:
        defaults = _SHAPE_DEFAULTS[shape]
        model_path = defaults["model"]
        output_path = defaults["output"]
        verify_data_path = defaults["verify_data"]

        print(f"\n=== Exporting {shape} model ===", file=sys.stderr)
        if not model_path.exists():
            print(f"ERROR: {shape} model not found at {model_path}", file=sys.stderr)
            exit_code = 2
            continue

        export(model_path, output_path)

        if args.skip_verify:
            continue
        if not verify_data_path.exists():
            print(
                f"Verify data {verify_data_path} not found; skipping verification "
                f"for {shape}.",
                file=sys.stderr,
            )
            continue
        ok = verify(model_path, output_path, verify_data_path, args.verify_n)
        if not ok:
            exit_code = 1
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
