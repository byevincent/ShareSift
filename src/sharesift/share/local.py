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
    """Read-only walk + read over a local directory.

    ``root`` is only used by ``walk()``. ``read_bytes(path)`` works
    against any path on the filesystem, not just paths under
    ``root`` — this lets a ``LocalShare`` instance act as a generic
    "filesystem reader" for callers that have absolute paths from a
    previous walk or file list.
    """

    def __init__(self, root: Path | str = ".") -> None:
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

    def read_bytes(
        self, path: str, *, max_bytes: int | None = None
    ) -> bytes | None:
        p = Path(path)
        try:
            if not p.is_file():
                return None
            if max_bytes is None:
                return p.read_bytes()
            with p.open("rb") as fh:
                return fh.read(max_bytes)
        except OSError:
            return None
