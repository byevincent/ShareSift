"""Atomic file-write primitives shared across eval modules.

Two primitives, one shared crash model:

* ``atomic_write_jsonl`` — full-file rewrite. Tempfile in the same
  directory, fsync, then ``os.replace`` for atomic swap. Used by
  ``build_queue`` (queue regeneration) and ``label_app`` (undo, which
  drops the last record from ``eval_set.jsonl``).
* ``atomic_append_jsonl`` — single-record append with fsync. Used by
  ``label_app`` for per-record commits to ``eval_set.jsonl``.

Crash model for ``atomic_append_jsonl``: a crash inside the fsync window
may leave a partial trailing line on disk. The standard recovery is on
the reader side — detect a malformed final line and either tolerate it
(``label_app`` startup rewrites the file without the partial line and
surfaces a one-time recovery notice) or hard-error (``validate.py``
flags it for explicit cleanup). The append primitive itself never
returns successfully on a partial write; if ``write`` or ``fsync``
raises, the caller knows the line wasn't durably committed.

Concurrency is *not* handled at this layer. Two writers racing on the
same file can interleave. ``label_app`` uses a lock file at the GUI
level to enforce single-session writes.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path
from typing import Protocol


class _JsonSerializable(Protocol):
    def model_dump_json(self) -> str: ...


def atomic_write_jsonl(path: Path, records: Iterable[_JsonSerializable]) -> None:
    """Write JSONL atomically via tempfile + fsync + os.replace.

    Creates parent directories if needed. On any failure during the
    write, the tempfile is removed and the target file (if it already
    existed) is left untouched.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        with tmp.open("w", encoding="utf-8") as f:
            for r in records:
                f.write(r.model_dump_json() + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
        raise


def atomic_append_jsonl(path: Path, record: _JsonSerializable) -> None:
    """Append a single JSON line with fsync.

    Creates parent directories if needed. The line is fully written and
    fsynced before the function returns; on any failure during the
    write, the exception propagates and the caller MUST assume the line
    was not durably committed. A crash inside the fsync window may
    leave a partial trailing line — readers tolerate this (see module
    docstring).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(record.model_dump_json() + "\n")
        f.flush()
        os.fsync(f.fileno())
