"""Path featurization for the v0 LightGBM classifier.

Two feature families combined via horizontal sparse stacking:

1. **Character n-gram hashes** — scikit-learn ``HashingVectorizer`` with
   ``char_wb`` analyzer, n-gram range (3, 5), 2^16 hash buckets. Stateless
   (no vocab fit step), so no serialization concern beyond pinning the
   config. Captures path-token substring patterns (``\\.ssh\\``, ``.pem``,
   ``\\admin\\``, ``/etc/shadow``, etc.) without a hand-curated vocab.

2. **Hand-engineered structural features** — 8 dense floats per path
   capturing properties that char n-grams under-weight: total length,
   separator-count depth, has-extension flag, extension length, dot count
   in basename, digit count in basename, UNC-prefix flag, Linux-prefix
   flag. Tree splits on these give the model explicit structural priors
   that don't require learning from n-gram co-occurrence.

The combined feature matrix is sparse (n_samples × ~65K). LightGBM
handles sparse input natively.
"""

from __future__ import annotations

import numpy as np
import scipy.sparse as sp
from sklearn.feature_extraction.text import HashingVectorizer

# Config pinned for reproducibility. Changes here must come with a model
# version bump (e.g. path_classifier_v0 → v1) so saved artifacts stay
# tied to the featurization they were trained against.
NGRAM_RANGE: tuple[int, int] = (3, 5)
N_HASH_FEATURES: int = 2**16  # 65,536
N_HAND_FEATURES: int = 8


def build_vectorizer() -> HashingVectorizer:
    """Construct the canonical char-n-gram vectorizer.

    ``alternate_sign=False`` keeps feature values non-negative (LightGBM
    requirement on input). ``norm=None`` keeps raw n-gram counts rather
    than L2-normalized values, since tree models don't benefit from norm.
    """
    return HashingVectorizer(
        analyzer="char_wb",
        ngram_range=NGRAM_RANGE,
        n_features=N_HASH_FEATURES,
        alternate_sign=False,
        norm=None,
    )


def hand_features(path: str) -> np.ndarray:
    """Compute the 8 dense structural features for a single path.

    Order is load-bearing — must match ``HAND_FEATURE_NAMES`` and any
    saved model's expectations. Adding or reordering a feature is a
    breaking change.
    """
    has_unc = path.startswith("\\\\")
    has_linux = path.startswith("/")
    depth = path.count("\\") + path.count("/")
    # Find basename: rightmost separator of either flavor.
    sep_idx = max(path.rfind("\\"), path.rfind("/"))
    basename = path[sep_idx + 1 :] if sep_idx >= 0 else path
    dot_idx = basename.rfind(".")
    has_ext = dot_idx > 0
    ext_len = len(basename) - dot_idx - 1 if has_ext else 0
    num_dots = basename.count(".")
    num_digits = sum(1 for c in basename if c.isdigit())
    return np.array(
        [
            float(len(path)),
            float(depth),
            float(has_ext),
            float(ext_len),
            float(num_dots),
            float(num_digits),
            float(has_unc),
            float(has_linux),
        ],
        dtype=np.float32,
    )


HAND_FEATURE_NAMES: tuple[str, ...] = (
    "path_length",
    "path_depth",
    "has_extension",
    "extension_length",
    "num_dots_in_basename",
    "num_digits_in_basename",
    "is_unc_path",
    "is_linux_path",
)


def featurize(
    paths: list[str], vectorizer: HashingVectorizer | None = None
) -> sp.csr_matrix:
    """Vectorize a list of paths into the combined sparse feature matrix.

    ``vectorizer`` is optional — the default construction is identical
    across calls (HashingVectorizer is stateless), so callers don't need
    to plumb one through. Provided as a hook for tests that want to
    pin a specific instance.
    """
    vec = vectorizer if vectorizer is not None else build_vectorizer()
    char_X = vec.transform(paths)
    hand_X = np.vstack([hand_features(p) for p in paths])
    return sp.hstack([char_X, sp.csr_matrix(hand_X)]).tocsr()


def is_juicy(record: dict) -> bool:
    """Adapter for the two label conventions used in the codebase.

    Synthetic training records (``data/synthetic/training_v0.jsonl``) use
    a boolean ``juicy`` field. Eval records (``data/eval/eval_set*.jsonl``)
    use a string ``label`` field ``"juicy"``/``"not_juicy"``. Both
    expressions map to the same model target.
    """
    if "juicy" in record:
        return bool(record["juicy"])
    if "label" in record:
        return record["label"] == "juicy"
    raise ValueError(f"record has neither 'juicy' nor 'label' field: {record!r}")
