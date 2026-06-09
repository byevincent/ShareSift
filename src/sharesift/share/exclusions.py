"""v0.40: default noise-exclusion globs.

Snaffler's #1 operator complaint (issue #178 et al.) is that it
walks ``Windows/System32/*.dll`` and similar noise for 20 minutes
on real shares before getting to anything interesting. The default
exclusion patterns here cover the high-volume / zero-credential
paths so a fresh ``sharesift scan`` is fast out of the box.

Patterns are POSIX-style globs matched against the full path
(case-insensitive, ``fnmatch.fnmatchcase`` against lowercased path
+ pattern). ``**`` matches any number of path components.

Operators opt out with ``--no-default-excludes`` and add their own
patterns with ``--exclude-glob PATTERN`` (repeatable).
"""

from __future__ import annotations

import fnmatch
from typing import Iterable


DEFAULT_EXCLUDE_GLOBS: tuple[str, ...] = (
    # Windows system binaries — heaviest noise on every Windows share
    "*/Windows/System32/*.dll",
    "*/Windows/System32/*.exe",
    "*/Windows/System32/drivers/*.sys",
    "*/Windows/SysWOW64/*.dll",
    "*/Windows/SysWOW64/*.exe",
    "*/Windows/winsxs/*",
    "*/Windows/assembly/*",
    "*/Windows/Microsoft.NET/*",
    "*/Windows/servicing/*",
    "*/Windows/Prefetch/*.pf",
    "*/Windows/Installer/$PatchCache$/*",
    # Program Files clutter
    "*/Program Files/*.dll",
    "*/Program Files/*.exe",
    "*/Program Files (x86)/*.dll",
    "*/Program Files (x86)/*.exe",
    "*/Program Files/Common Files/microsoft shared/*",
    # Dev-tool dependency directories — high file count, low cred signal
    "*/node_modules/*",
    "*/.git/objects/*",
    "*/.svn/*",
    "*/.hg/*",
    "*/venv/lib/*",
    "*/.venv/lib/*",
    "*/__pycache__/*",
    "*/target/dependency/*",
    "*/vendor/*",
    "*/Pods/*",
    "*/build/intermediates/*",
    # OS caches and indexers
    "*/Library/Caches/*",  # macOS
    "*/.Trash/*",
    "*/AppData/Local/Microsoft/Windows/INetCache/*",
    "*/AppData/Local/Temp/*",
    "*/Recent/*",
    # Binary artifacts that won't contain plaintext creds
    "*.pyc",
    "*.pyo",
    "*.class",
    "*.o",
    "*.obj",
    "*.lib",
    "*.a",
    "*.so",
    "*.dylib",
    # Heavy media — not credential-bearing
    "*.iso",
    "*.vmdk",
    "*.vdi",
    "*.vhd",
    "*.vhdx",
    "*.mp4",
    "*.mkv",
    "*.avi",
    "*.mov",
    "*.flv",
    "*.wmv",
    "*.jpg",
    "*.jpeg",
    "*.png",
    "*.gif",
    "*.bmp",
    "*.tiff",
    "*.tif",
)


def _normalize(path: str) -> str:
    """Lower-case + normalize slashes for case-insensitive cross-
    platform matching. UNC paths get their leading ``\\\\host\\share``
    preserved so patterns like ``*/Windows/System32/*.dll`` still
    fire against ``\\\\10.0.0.5\\C$\\Windows\\System32\\foo.dll``."""
    return path.lower().replace("\\", "/")


def _pattern_matches(path_norm: str, pattern: str) -> bool:
    pat_norm = pattern.lower().replace("\\", "/")
    return fnmatch.fnmatchcase(path_norm, pat_norm)


def is_excluded(path: str, patterns: Iterable[str]) -> bool:
    """True if ``path`` matches any glob in ``patterns``.

    Both path and patterns are normalized to forward-slash +
    lowercase for matching. UNC paths and Windows backslash paths
    work uniformly.
    """
    path_norm = _normalize(path)
    return any(_pattern_matches(path_norm, p) for p in patterns)


def filter_paths(
    paths: Iterable[str],
    *,
    extra_globs: Iterable[str] = (),
    use_defaults: bool = True,
) -> tuple[list[str], int]:
    """Filter a path iterable through the exclusion list.

    Returns ``(kept_paths, n_excluded)``. ``use_defaults=False``
    disables ``DEFAULT_EXCLUDE_GLOBS`` (operator's ``--no-default-excludes``).
    """
    patterns = list(extra_globs)
    if use_defaults:
        patterns = list(DEFAULT_EXCLUDE_GLOBS) + patterns

    if not patterns:
        return list(paths), 0

    kept: list[str] = []
    excluded = 0
    for p in paths:
        if is_excluded(p, patterns):
            excluded += 1
        else:
            kept.append(p)
    return kept, excluded
