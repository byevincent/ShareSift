"""Path normalization shared across eval modules.

The helper here is the single source of truth for "are these the same
path?" — used by ``build_queue`` (input dedup + cross-file dedup against
the eval set) and ``validate`` (in-file duplicate detection). Both must
use the same normalization or they'll disagree about path identity,
which would mean ``build_queue`` could admit a path that ``validate``
later flags as a duplicate of an existing one, or vice versa.
"""

from __future__ import annotations

from pathlib import PureWindowsPath


def normalize_for_dedup(path: str) -> str:
    """Case-insensitive normalized form for dedup comparison.

    Backslash normalization comes from ``PureWindowsPath``; lowercasing
    handles cross-case identity. Matches how labeled-record paths get
    parsed via ``PureWindowsPath`` during schema validation.
    """
    return str(PureWindowsPath(path)).lower()
