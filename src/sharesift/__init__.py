"""ShareSift v0 inference runtime + CLI.

This package is the user-facing layer that ships in a ShareSift install.
Everything under ``src/eval/`` outside this subpackage is dev-pipeline
code (data collection, training, audits, benchmarks) that an end user
doesn't need at runtime.

Two stages, both importable as Python and exposed through the
``sharesift`` CLI:

* ``path`` — wraps the LightGBM calibrated path classifiers
  (``models/path_classifier_v0_{windows,linux}/calibrated.joblib``,
  routed by path shape). Always loaded; fast and dep-light (sklearn +
  lightgbm + joblib).
* ``content`` — wraps the Qwen3-1.7B + LoRA content classifier
  (``models/content_classifier_v0p6_docx_salted/`` canonical since
  v0.10, trained on docx-corpus content + Kingfisher-derived salts;
  v0p3/v0p4/v0p5 remain available as alternatives for backward-compat
  or operating-point selection) via transformers + PEFT, with
  CUDA/CPU auto-detect. Loaded lazily — only paying the ~3GB dep cost
  when a caller actually requests a content check.

The split is intentional: a user who only wants path triage (the most
common pentest workflow) installs the lean core; the deep-scan
``scan-files`` pathway opt-in pulls in the heavier stack.

This module deliberately does NOT eagerly import either backend at
package import time, so ``import sharesift`` stays cheap and
``--help`` for the CLI returns instantly even without the content
deps installed.
"""

from __future__ import annotations

import sys
from importlib.metadata import PackageNotFoundError, version as _pkg_version

# Version fallback for PyInstaller-frozen binaries — importlib.metadata
# can't find the package's dist-info inside the frozen tree, so use a
# build-time-stamped fallback. Source of truth stays pyproject.toml.
_FROZEN_VERSION_FALLBACK = "0.46.0"

try:
    __version__ = _pkg_version("sharesift")
except PackageNotFoundError:
    __version__ = (
        _FROZEN_VERSION_FALLBACK
        if getattr(sys, "frozen", False)
        else "unknown"
    )

__all__ = ["__version__"]
