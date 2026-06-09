"""SMB-direct share — walks a remote SMB share via ``smbprotocol``
without requiring a CIFS mount.

Authentication uses pyspnego's pure-Python NTLM (validated against
Samba 4.12 SMB2/3 on 2026-06-08). No ``gss-ntlmssp`` system package,
no ``NTLM_USER_FILE`` env-var ceremony, no impacket fallback.

Sprint 2 ships walking only. Content-read methods join the
``Share`` protocol in a later sprint when the cascade's
``load_content`` is refactored to be share-aware.
"""

from __future__ import annotations

import uuid
from typing import Iterator, TYPE_CHECKING

from sharesift.share.auth import Auth, build_credential

if TYPE_CHECKING:
    from sharesift.share import ShareEntry
    from sharesift.share.target import SmbTarget


# FileIdBothDirectoryInformation — full metadata per entry
# (file_name, end_of_file, file_attributes). Confirmed against
# the lab validation script on 2026-06-08.
_FILE_ID_BOTH_DIR_INFO = 37

# FILE_ATTRIBUTE_DIRECTORY bit — distinguishes subdirs from files
# during the walk recursion.
_FILE_ATTR_DIRECTORY = 0x10

# SMB2 reads consume credits: 1 credit per 64 KB. Initial credit
# budget on a fresh connection is 64 (= 4 MB max single read), and
# Samba won't grant more until the client has done other exchanges.
# A 1 MB cap (= 16 credits) leaves headroom and covers the realistic
# size of credential / config files. Larger files chunk in v0.36.
_MAX_SINGLE_READ = 1 * 1024 * 1024


class SmbShare:
    """Read-only walk of a remote SMB share."""

    def __init__(
        self,
        target: "SmbTarget",
        auth: Auth,
        *,
        encrypt: bool = True,
        timeout: int = 30,
    ) -> None:
        self._target = target
        self._auth = auth
        self._encrypt = encrypt
        self._timeout = timeout
        self._connection = None
        self._session = None
        self._tree = None

    @property
    def root(self) -> str:
        return self._target.unc

    def walk(self) -> Iterator["ShareEntry"]:
        """Recursive walk yielding files only, in deterministic
        sorted order."""
        from sharesift.share import ShareEntry

        self._ensure_connected()

        # Collect all (path, size) pairs across the tree, then sort
        # so the output matches ``LocalShare.walk``'s contract.
        collected: list[tuple[str, int]] = []

        # BFS over directories. Each entry is the path under the
        # share root (e.g. "Finance/Q3" — no leading separator).
        to_visit: list[str] = [self._target.root_path or ""]
        while to_visit:
            rel_dir = to_visit.pop(0)
            for entry in self._list_directory(rel_dir):
                name = entry["name"]
                if name in (".", ".."):
                    continue
                rel_path = f"{rel_dir}\\{name}" if rel_dir else name
                if entry["is_directory"]:
                    to_visit.append(rel_path)
                else:
                    full_unc = self._build_unc(rel_path)
                    collected.append((full_unc, entry["size"]))

        for path, size in sorted(collected, key=lambda x: x[0]):
            yield ShareEntry(path=path, size=size)

    def read_bytes(
        self, path: str, *, max_bytes: int | None = None
    ) -> bytes | None:
        """Read up to ``max_bytes`` from a file on this share.

        ``path`` is a UNC string of the shape ``walk()`` yields:
        ``\\\\host\\share\\rel\\to\\file``. UNCs that don't belong
        to this share return ``None``.
        """
        rel = self._unc_to_rel(path)
        if not rel:
            return None
        self._ensure_connected()

        from smbprotocol.open import (
            CreateDisposition,
            CreateOptions,
            FileAttributes,
            FilePipePrinterAccessMask,
            ImpersonationLevel,
            Open,
            ShareAccess,
        )

        # Clamp to three limits: caller's max_bytes, server's
        # negotiated max_read_size, and our SMB credit-budget-safe
        # ceiling (1 MB). Without the credit clamp, fresh
        # connections fail on requests over ~4 MB.
        requested = max_bytes if max_bytes is not None else 10 * 1024 * 1024
        cap = min(requested, self._connection.max_read_size, _MAX_SINGLE_READ)
        handle = Open(self._tree, rel)
        try:
            handle.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.FILE_READ_DATA,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                ShareAccess.FILE_SHARE_READ,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
            return handle.read(0, cap)
        except Exception:
            # Permission denied, end-of-file past start, file vanished
            # between walk and read, etc. The cascade treats None as
            # "skip this file" — matches LocalShare's OSError handling.
            return None
        finally:
            try:
                handle.close(False)
            except Exception:
                pass

    def _unc_to_rel(self, unc_path: str) -> str | None:
        """Strip the ``\\\\host\\share\\`` prefix to recover the path
        relative to the share root. Case-insensitive on host/share
        per SMB semantics. Returns ``None`` if the UNC doesn't
        belong to this share."""
        target_prefix = rf"\\{self._target.host}\{self._target.share}"
        if not unc_path.lower().startswith(target_prefix.lower()):
            return None
        rel = unc_path[len(target_prefix):].lstrip("\\")
        return rel or None

    def close(self) -> None:
        """Tear down tree + session + connection. Idempotent."""
        if self._tree is not None:
            try:
                self._tree.disconnect()
            except Exception:
                pass
            self._tree = None
        if self._session is not None:
            try:
                self._session.disconnect()
            except Exception:
                pass
            self._session = None
        if self._connection is not None:
            try:
                self._connection.disconnect()
            except Exception:
                pass
            self._connection = None

    def __enter__(self) -> "SmbShare":
        self._ensure_connected()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Internal — connection lifecycle and directory listing
    # ------------------------------------------------------------------

    def _ensure_connected(self) -> None:
        if self._tree is not None:
            return

        from smbprotocol.connection import Connection
        from smbprotocol.session import Session
        from smbprotocol.tree import TreeConnect

        username, password, auth_protocol = build_credential(self._auth)

        self._connection = Connection(
            uuid.uuid4(), self._target.host, self._target.port
        )
        self._connection.connect(timeout=self._timeout)

        self._session = Session(
            self._connection,
            username=username,
            password=password,
            require_encryption=self._encrypt,
            auth_protocol=auth_protocol,
        )
        self._session.connect()

        tree_unc = rf"\\{self._target.host}\{self._target.share}"
        self._tree = TreeConnect(self._session, tree_unc)
        self._tree.connect()

    def _list_directory(self, rel_dir: str) -> list[dict]:
        """List one directory. Returns list of
        ``{"name": str, "size": int, "is_directory": bool}``.
        """
        from smbprotocol.open import (
            CreateDisposition,
            CreateOptions,
            DirectoryAccessMask,
            FileAttributes,
            ImpersonationLevel,
            Open,
            ShareAccess,
        )

        handle = Open(self._tree, rel_dir)
        handle.create(
            ImpersonationLevel.Impersonation,
            DirectoryAccessMask.FILE_LIST_DIRECTORY
            | DirectoryAccessMask.FILE_READ_ATTRIBUTES,
            FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
            ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
            CreateDisposition.FILE_OPEN,
            CreateOptions.FILE_DIRECTORY_FILE,
        )
        try:
            raw_entries = handle.query_directory(
                "*", file_information_class=_FILE_ID_BOTH_DIR_INFO
            )
        finally:
            handle.close(False)

        out: list[dict] = []
        for entry in raw_entries:
            name = entry["file_name"].get_value().decode("utf-16le")
            attrs = entry["file_attributes"].get_value()
            size = entry["end_of_file"].get_value()
            out.append(
                {
                    "name": name,
                    "size": size,
                    "is_directory": bool(attrs & _FILE_ATTR_DIRECTORY),
                }
            )
        return out

    def _build_unc(self, rel_path: str) -> str:
        unc = rf"\\{self._target.host}\{self._target.share}"
        if rel_path:
            unc += "\\" + rel_path
        return unc
