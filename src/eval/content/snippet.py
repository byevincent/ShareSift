"""Context-window extraction around a kingfisher match position.

The content classifier sees a snippet — not the whole file — and decides
whether it contains a hardcoded secret. Snippet size budget is ~1-2KB
(roughly the token budget that lets Qwen3-1.7B classify in single-digit
ms on CPU after Q4_K_M quantization).

Two extraction modes:

* ``extract_around_line(file, target_line, before=8, after=8)`` — pulls
  ``before`` lines above and ``after`` lines below the match line.
  Default ±8 lines is the Wiz LoRA recipe's window size. Suitable for
  positive examples (centered on a kingfisher match).

* ``random_snippet(file, window_lines=16, rng=None)`` — picks a random
  starting line and returns ``window_lines`` lines from there. Used to
  generate negative examples from non-vulnerable code.
"""

from __future__ import annotations

import random
from pathlib import Path


_MAX_SNIPPET_BYTES = 2048  # 2KB upper bound — token budget at ~3 char/token


def _truncate(text: str, max_bytes: int = _MAX_SNIPPET_BYTES) -> str:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text
    return encoded[:max_bytes].decode("utf-8", errors="replace")


def extract_around_line(
    file: Path,
    target_line: int,
    *,
    before: int = 8,
    after: int = 8,
    max_bytes: int = _MAX_SNIPPET_BYTES,
) -> str | None:
    """Read ``before`` lines above and ``after`` lines below the 1-indexed
    ``target_line``. Returns ``None`` if the file can't be read or has
    too few lines to contain the target line.

    Truncated to ``max_bytes`` if the resulting window is too large —
    the truncation strips from the end so the match line stays in the
    window.
    """
    try:
        lines = file.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, UnicodeDecodeError):
        return None
    if not lines or target_line < 1 or target_line > len(lines):
        return None
    start = max(0, target_line - 1 - before)
    end = min(len(lines), target_line + after)
    window = "\n".join(lines[start:end])
    return _truncate(window, max_bytes)


def random_snippet(
    file: Path,
    *,
    window_lines: int = 16,
    rng: random.Random | None = None,
    max_bytes: int = _MAX_SNIPPET_BYTES,
) -> str | None:
    """Pick a random ``window_lines``-line window from the file.

    Returns ``None`` if the file is too short or unreadable. ``rng``
    is provided so the caller can seed deterministic negative sampling
    across runs.
    """
    rng = rng or random.Random()
    try:
        lines = file.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, UnicodeDecodeError):
        return None
    if len(lines) < window_lines // 2:
        # Too short — not worth extracting a tiny snippet from.
        return None
    if len(lines) <= window_lines:
        return _truncate("\n".join(lines), max_bytes)
    start = rng.randint(0, len(lines) - window_lines)
    return _truncate("\n".join(lines[start : start + window_lines]), max_bytes)
