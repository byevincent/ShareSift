"""Share-access abstraction.

Reads are mediated through a ``Share`` so the cascade doesn't care
whether it's walking a mounted CIFS path, a plain local directory,
or a remote SMB target reached over the network.

v0.35 Sprint 1: only ``walk()`` is in the protocol. ``LocalShare``
preserves today's filesystem-walk behavior bit-for-bit; ``SmbShare``
arrives in Sprint 2 along with content-read methods on the
protocol.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Protocol, runtime_checkable

from sharesift.share.auth import Auth, build_credential
from sharesift.share.local import LocalShare
from sharesift.share.smb import ShareAccess, SmbShare
from sharesift.share.target import SmbTarget, is_smb_target, parse_target

__all__ = [
    "Auth",
    "LocalShare",
    "Share",
    "ShareAccess",
    "ShareEntry",
    "SmbShare",
    "SmbTarget",
    "build_credential",
    "is_smb_target",
    "parse_target",
]


@dataclass(frozen=True)
class ShareEntry:
    """One file discovered during share enumeration.

    ``path`` is the identifier downstream stages use to read the
    file. For ``LocalShare`` that's the absolute filesystem path; for
    ``SmbShare`` (Sprint 2) it will be a UNC string.
    """

    path: str
    size: int | None = None


@runtime_checkable
class Share(Protocol):
    """Read-only view over a target share root."""

    @property
    def root(self) -> str:
        """Human-readable identifier of the share root."""
        ...

    def walk(self) -> Iterator[ShareEntry]:
        """Yield every file under the root, in deterministic order.

        Directories are not yielded — only files. Order is sorted by
        path so reruns produce identical outputs (the eval harness
        relies on this).
        """
        ...

    def read_bytes(
        self, path: str, *, max_bytes: int | None = None
    ) -> bytes | None:
        """Read up to ``max_bytes`` from the file at ``path``.

        Returns ``None`` if the path doesn't exist, isn't a file, or
        can't be read. Never raises on transient I/O errors —
        callers treat ``None`` as "unreadable" the same way ``walk``
        treats missing files.

        ``max_bytes=None`` means "read the whole file." Callers
        scanning a remote share should always pass a cap; the
        default in ``load_content_from_share`` is 10 MB.
        """
        ...
