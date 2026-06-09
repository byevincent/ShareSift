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
from dataclasses import dataclass
from typing import Iterator, TYPE_CHECKING

from sharesift.share.auth import Auth, build_credential

if TYPE_CHECKING:
    from sharesift.share import ShareEntry
    from sharesift.share.target import SmbTarget


@dataclass(frozen=True)
class ShareAccess:
    """Pentester-facing share-level access verdict.

    Closes Snaffler #184 — Snaffler reports writable shares as ``R``
    (read-only) due to a bug in its effective-access calculation,
    silently throwing away the most operationally valuable finding
    (write access to a juicy share). ShareSift probes both rights
    explicitly via two cheap SMB2 CREATE exchanges on the share
    root: one with FILE_READ_DATA, one with FILE_WRITE_DATA. The
    server returns STATUS_ACCESS_DENIED when we don't have the
    requested right.
    """

    can_read: bool
    can_write: bool

    @property
    def display(self) -> str:
        """Snaffler-compatible R/W marker — used by the TSV output
        column 4/5 (CanRead) and column 5/6 (CanWrite)."""
        parts = []
        if self.can_read:
            parts.append("R")
        if self.can_write:
            parts.append("W")
        return "".join(parts) or "-"


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
        self._share_access: ShareAccess | None = None

    @property
    def root(self) -> str:
        return self._target.unc

    @property
    def share_access(self) -> ShareAccess | None:
        """Share-level R/W verdict from the probe in
        ``_ensure_connected``. ``None`` if the share isn't connected
        yet (no probe has run)."""
        return self._share_access

    def probe_share_access(self) -> ShareAccess:
        """Run two SMB2 CREATE exchanges on the share root to probe
        read + write access. Cheap (~2 round-trips), non-destructive
        (no file is created or modified), and indistinguishable from
        normal SMB access pattern on the wire.

        Idempotent — caches the result on the instance.
        """
        if self._share_access is not None:
            return self._share_access
        self._ensure_connected()
        # Probe the share root (a directory) with the right access
        # verbs: FILE_LIST_DIRECTORY → "can read", FILE_ADD_FILE → "can
        # write to share root."
        can_read = self._probe_access_mask("FILE_LIST_DIRECTORY")
        can_write = self._probe_access_mask("FILE_ADD_FILE")
        self._share_access = ShareAccess(can_read=can_read, can_write=can_write)
        return self._share_access

    def _probe_access_mask(self, mask_name: str) -> bool:
        """Try opening the share root with the named access right.

        Returns True if the server granted it, False on
        STATUS_ACCESS_DENIED. Other exceptions propagate — the caller
        treats them as "probe inconclusive" which is honest, not
        "no access" which would be wrong.
        """
        from smbprotocol.open import (
            CreateDisposition,
            CreateOptions,
            DirectoryAccessMask,
            FileAttributes,
            ImpersonationLevel,
            Open,
            ShareAccess as SmbShareAccess,
        )

        access = getattr(DirectoryAccessMask, mask_name)
        handle = Open(self._tree, self._target.root_path or "")
        try:
            handle.create(
                ImpersonationLevel.Impersonation,
                access,
                FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
                SmbShareAccess.FILE_SHARE_READ | SmbShareAccess.FILE_SHARE_WRITE,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_DIRECTORY_FILE,
            )
            return True
        except Exception as exc:
            # smbprotocol surfaces ACCESS_DENIED as
            # smbprotocol.exceptions.AccessDenied (or a generic
            # SMBResponseException with the same status). Both → False.
            name = type(exc).__name__
            msg = str(exc)
            if (
                "AccessDenied" in name
                or "STATUS_ACCESS_DENIED" in msg
                or "0xc0000022" in msg.lower()
            ):
                return False
            raise
        finally:
            try:
                handle.close(False)
            except Exception:
                pass

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

        try:
            from smbprotocol.connection import Connection
            from smbprotocol.session import Session
            from smbprotocol.tree import TreeConnect
        except ImportError as exc:
            # v0.37: friendlier message for the pipx-install case where
            # the operator forgot the smb extra.
            raise SystemExit(
                "SMB-direct support requires the smb extra. Install:\n"
                "    pipx install 'sharesift[smb]'   # if using pipx\n"
                "    pip install 'sharesift[smb]'    # if using pip\n"
                "    uv sync --extra smb             # if using uv\n"
                f"(missing: {exc.name})"
            ) from exc

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
