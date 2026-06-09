"""Local filesystem share — wraps ``Path.rglob`` to match the
``Share`` protocol.

The walk behavior preserves exactly what ``cmd_scan`` was doing
before the v0.35 refactor: recursive enumeration, files only,
sorted lexicographically, absolute-path strings.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator, TYPE_CHECKING

if TYPE_CHECKING:
    from sharesift.share import ShareEntry


class LocalShare:
    """Read-only walk over a local directory."""

    def __init__(self, root: Path | str) -> None:
        self._root = Path(root)

    @property
    def root(self) -> str:
        return str(self._root)

    def walk(self) -> Iterator["ShareEntry"]:
        from sharesift.share import ShareEntry

        for path in sorted(self._root.rglob("*")):
            if not path.is_file():
                continue
            yield ShareEntry(path=str(path), size=path.stat().st_size)
