"""Verbosity helper for the sharesift CLI.

Three levels — QUIET silences info/progress; NORMAL emits today's
stderr lines; VERBOSE adds debug detail (model dirs, batch sizes,
timings). Warnings and errors always print regardless of level.

Why not the standard library ``logging`` module? For a single-binary
CLI the ``basicConfig`` collisions with library code (transformers
in particular) are painful, and the per-call ceremony of logger
lookups adds no value at this scale. A 30-line class is easier to
reason about and easier to test.

The module exposes a singleton ``out`` that ``cli.main()`` configures
once after parsing top-level ``-q``/``-v`` flags. Subcommand handlers
import the same singleton and call ``out.info(...)`` /
``out.debug(...)`` instead of bare ``print(..., file=sys.stderr)``.

Usage::

    from sharesift._output import out, Verbosity

    out.configure(verbosity=Verbosity.NORMAL)
    out.info(f"loaded {n} records")
    out.debug(f"batch size = {bs}")
    out.warn("model file missing")
    out.error("could not read input")
"""

from __future__ import annotations

import sys
from enum import IntEnum
from typing import Iterable, TextIO, TypeVar


class Verbosity(IntEnum):
    QUIET = 0
    NORMAL = 1
    VERBOSE = 2


_T = TypeVar("_T")


class Output:
    """Verbosity-gated stderr writer.

    Not thread-safe — only ``cli.main()`` configures the singleton, and
    subcommand handlers run on the main thread.
    """

    def __init__(self, stream: TextIO | None = None) -> None:
        self._verbosity = Verbosity.NORMAL
        self._stream = stream if stream is not None else sys.stderr

    def configure(self, *, verbosity: Verbosity) -> None:
        self._verbosity = verbosity

    @property
    def verbosity(self) -> Verbosity:
        return self._verbosity

    def info(self, msg: str) -> None:
        if self._verbosity >= Verbosity.NORMAL:
            self._emit(msg)

    def debug(self, msg: str) -> None:
        if self._verbosity >= Verbosity.VERBOSE:
            self._emit(msg)

    def warn(self, msg: str) -> None:
        self._emit(msg)

    def error(self, msg: str) -> None:
        self._emit(msg)

    def progress(
        self,
        iterable: Iterable[_T],
        desc: str,
        total: int | None = None,
    ) -> Iterable[_T]:
        """Wrap iterable with a tqdm progress bar gated by verbosity.

        QUIET   → returns the iterable as-is (no tqdm import, no overhead).
        NORMAL  → tqdm with ``disable=None`` so it auto-suppresses on
                  non-TTY stderr (CI logs, file redirects).
        VERBOSE → tqdm with ``disable=False`` — always shown, even
                  non-TTY, so debugging operators see the bar in captured
                  logs.
        """
        if self._verbosity == Verbosity.QUIET:
            return iterable
        try:
            from tqdm import tqdm
        except ImportError:
            # tqdm should be installed (it's a direct dep) but be defensive.
            return iterable
        return tqdm(
            iterable,
            desc=desc,
            total=total,
            disable=None if self._verbosity == Verbosity.NORMAL else False,
            file=self._stream,
        )

    def _emit(self, msg: str) -> None:
        print(msg, file=self._stream, flush=True)


# Module-level singleton. cli.main() reconfigures after argparse.
out = Output()
