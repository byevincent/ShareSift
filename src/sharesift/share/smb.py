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


def _import_real_smbclient():
    """Import the ``smbclient`` package that ships with smbprotocol,
    not impacket's ``smbclient.py`` script in ``.venv/bin/``.

    ``uv run`` (and any other launcher that prepends the venv's
    ``bin/`` to ``sys.path``) makes ``import smbclient`` resolve to
    impacket's CLI script rather than the smbprotocol package.
    We work around this by temporarily stripping bin directories
    from sys.path during the import, then restoring afterwards
    and caching the right module in ``sys.modules``.
    """
    import sys

    cached = sys.modules.get("smbclient")
    if cached is not None and hasattr(cached, "ClientConfig"):
        return cached

    # Remove the wrong module from sys.modules so the next import
    # actually re-resolves.
    if cached is not None:
        del sys.modules["smbclient"]

    saved_path = sys.path[:]
    sys.path = [p for p in sys.path if not p.rstrip("/").endswith("/bin")]
    try:
        import smbclient as _real
        if not hasattr(_real, "ClientConfig"):
            raise ImportError(
                "smbclient package missing ClientConfig — check "
                "smbprotocol install"
            )
        sys.modules["smbclient"] = _real
        return _real
    finally:
        sys.path = saved_path


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
        require_encrypt: bool = False,
        timeout: int = 30,
        auto_resolve_dfs: bool = True,
    ) -> None:
        self._target = target  # may be rewritten to the resolved fileserver
        self._original_target = target  # frozen — operator's input
        self._auth = auth
        self._encrypt = encrypt
        # v0.54.2: when ``require_encrypt`` is False (default), and
        # the server doesn't support SMB3 GCM, fall back to an
        # unencrypted session rather than failing the whole hunt.
        # Operators who actually need encryption (opsec) pass
        # ``require_encrypt=True`` (CLI: ``--require-encrypt``).
        self._require_encrypt = require_encrypt
        self._timeout = timeout
        self._auto_resolve_dfs = auto_resolve_dfs
        self._connection = None
        self._session = None
        self._tree = None
        self._share_access: ShareAccess | None = None
        # v0.53: populated when tree-connect to the requested target
        # hit STATUS_PATH_NOT_COVERED and we chased the referral.
        self._dfs_resolution = None
        # v0.54.2: True when SMB3 wasn't negotiated and we fell back
        # to an unencrypted session. Surfaces in summary output.
        self._encryption_fallback_applied = False
        # v0.54.3: when auth.anonymous=True, smbprotocol+pyspnego
        # rejects the empty credential set. Delegate to an impacket
        # backend that handles null sessions natively. The backend
        # is lazy — we only construct it on first access so test
        # fixtures that mock smbprotocol but not impacket still work.
        self._use_impacket_backend = bool(
            getattr(auth, "anonymous", False)
        )
        self._impacket_backend = None

    def _ensure_impacket_backend(self):
        """v0.54.3: lazily construct the impacket walker. Deferred
        so test fixtures that mock smbprotocol but not impacket
        still work — the backend is built only when a public method
        actually needs it."""
        if self._impacket_backend is None and self._use_impacket_backend:
            from sharesift.share.smb_impacket import ImpacketSmbWalker

            self._impacket_backend = ImpacketSmbWalker(
                self._target, self._auth, timeout=self._timeout,
            )
        return self._impacket_backend

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
        # v0.54.3: anonymous → impacket backend
        if self._use_impacket_backend:
            backend = self._ensure_impacket_backend()
            access = backend.probe_share_access()
            self._share_access = access
            return access
        self._ensure_connected()
        # Probe the share root (a directory) with the right access
        # verbs: FILE_LIST_DIRECTORY → "can read", FILE_ADD_FILE → "can
        # write to share root."
        #
        # DFS-namespace-root shares (v0.54.1, surfaced on HTB Multimaster
        # `\\<dc>\dfs`) reject regular CREATE with STATUS_INVALID_PARAMETER
        # because they require DFS-aware Opens. Treat that case as
        # "probe inconclusive — assume read access so the walker reaches
        # the DFS links; write access is False (namespace roots aren't
        # writable)."
        can_read = self._probe_access_mask(
            "FILE_LIST_DIRECTORY", invalid_param_fallback=True,
        )
        can_write = self._probe_access_mask(
            "FILE_ADD_FILE", invalid_param_fallback=False,
        )
        self._share_access = ShareAccess(can_read=can_read, can_write=can_write)
        return self._share_access

    def _probe_access_mask(
        self, mask_name: str, *, invalid_param_fallback: bool = False,
    ) -> bool:
        """Try opening the share root with the named access right.

        Returns True if the server granted it, False on
        STATUS_ACCESS_DENIED. STATUS_INVALID_PARAMETER (the DFS-root
        signal) returns ``invalid_param_fallback`` so callers can
        choose how to interpret it per probe direction. Other
        exceptions propagate — the caller treats them as "probe
        inconclusive" which is honest, not "no access" which would
        be wrong.
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
            # v0.54.1: DFS-namespace-root rejection. The share IS
            # readable (the namespace serves DFS link entries), just
            # not via a regular CREATE on the root.
            if (
                "InvalidParameter" in name
                or "STATUS_INVALID_PARAMETER" in msg
                or "0xc000000d" in msg.lower()
            ):
                return invalid_param_fallback
            raise
        finally:
            try:
                handle.close(False)
            except Exception:
                pass

    def walk(self) -> Iterator["ShareEntry"]:
        """Recursive walk yielding files only, in deterministic
        sorted order."""
        # v0.54.3: anonymous → impacket backend
        if self._use_impacket_backend:
            yield from self._ensure_impacket_backend().walk()
            return

        from sharesift.share import ShareEntry

        self._ensure_connected()

        # Collect all (path, size) pairs across the tree, then sort
        # so the output matches ``LocalShare.walk``'s contract.
        collected: list[tuple[str, int]] = []

        # BFS over directories. Each entry is the path under the
        # share root (e.g. "Finance/Q3" — no leading separator).
        to_visit: list[str] = [self._target.root_path or ""]
        skipped_dfs_links: list[str] = []
        while to_visit:
            rel_dir = to_visit.pop(0)
            try:
                entries = self._list_directory(rel_dir)
            except Exception as exc:
                # v0.55: DFS links throw STATUS_PATH_NOT_COVERED when
                # we try to walk into them — the referral target is
                # on a different fileserver. The v0.53 resolver tells
                # us where; the actual walk requires the operator to
                # have DNS for that host (standard engagement-prep).
                # Skip the link with a warning instead of crashing.
                from sharesift.share.dfs import is_path_not_covered

                if is_path_not_covered(exc):
                    skipped_dfs_links.append(self._build_unc(rel_dir))
                    continue
                raise
            for entry in entries:
                name = entry["name"]
                if name in (".", ".."):
                    continue
                rel_path = f"{rel_dir}\\{name}" if rel_dir else name
                if entry["is_directory"]:
                    to_visit.append(rel_path)
                else:
                    full_unc = self._build_unc(rel_path)
                    collected.append((full_unc, entry["size"]))

        # Surface skipped DFS links so the operator knows what to
        # add to /etc/hosts and re-run.
        if skipped_dfs_links:
            self._skipped_dfs_links = skipped_dfs_links

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
        # v0.54.3: anonymous → impacket backend
        if self._use_impacket_backend:
            return self._ensure_impacket_backend().read_bytes(
                path, max_bytes=max_bytes,
            )

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
        if self._impacket_backend is not None:
            self._impacket_backend.close()
            self._impacket_backend = None
            return
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
        if self._use_impacket_backend:
            self._ensure_impacket_backend()._ensure_connected()
        else:
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

        # v0.54.2: SMB3 encryption was introduced in dialect 3.0
        # (0x0300). Older Windows (Server 2008 R2, anything below
        # SMB 3.0) negotiates SMB 2.0/2.1 and rejects sessions that
        # require encryption. Auto-detect and downgrade unless the
        # operator explicitly required encryption.
        effective_encrypt = self._encrypt
        if effective_encrypt and not self._require_encrypt:
            dialect = getattr(self._connection, "dialect", None)
            if isinstance(dialect, int) and dialect < 0x0300:
                effective_encrypt = False
                self._encryption_fallback_applied = True

        self._session = Session(
            self._connection,
            username=username,
            password=password,
            require_encryption=effective_encrypt,
            auth_protocol=auth_protocol,
        )
        self._session.connect()

        tree_unc = rf"\\{self._target.host}\{self._target.share}"
        self._tree = TreeConnect(self._session, tree_unc)
        try:
            self._tree.connect()
        except Exception as exc:
            # v0.53: STATUS_PATH_NOT_COVERED on tree-connect means
            # the host owns a DFS namespace, not the share itself.
            # Query referrals on IPC$, retarget to the resolved
            # fileserver, retry.
            from sharesift.share.dfs import is_path_not_covered

            if not (self._auto_resolve_dfs and is_path_not_covered(exc)):
                raise
            self._chase_dfs_and_reconnect()

    def _chase_dfs_and_reconnect(self) -> None:
        """v0.53: invoked when tree-connect returned
        STATUS_PATH_NOT_COVERED. Opens IPC$ on the current
        session, queries DFS referrals, retargets self to the
        resolved fileserver, and rebuilds the connection chain.

        On success, ``self._dfs_resolution`` is populated and
        ``self._target`` points at the fileserver.
        """
        from smbprotocol.connection import Connection
        from smbprotocol.session import Session
        from smbprotocol.tree import TreeConnect

        from sharesift.share.dfs import resolve_dfs_path
        from sharesift.share.target import SmbTarget

        original_unc = self._target.unc
        resolution = resolve_dfs_path(
            self._connection, self._session, original_unc,
        )
        if resolution is None or not resolution.target_unc:
            raise RuntimeError(
                f"DFS resolution returned no targets for {original_unc!r}"
            )

        # Parse \\fileserver\share[\subpath] → SmbTarget. We construct
        # the SmbTarget manually rather than going through parse_target
        # to preserve the operator's port.
        target_unc = resolution.target_unc
        # Strip leading \\
        rest = target_unc.lstrip("\\")
        parts = rest.split("\\", 2)
        if len(parts) < 2:
            raise RuntimeError(
                f"DFS resolution returned malformed UNC: {target_unc!r}"
            )
        new_host = parts[0]
        new_share = parts[1]
        new_root = parts[2].replace("/", "\\").strip("\\") if len(parts) >= 3 else ""

        # Tear down the IPC-session connection to the DFS root before
        # reconnecting to the fileserver. The fileserver is almost
        # always a different host.
        try:
            self._session.disconnect()
        except Exception:
            pass
        try:
            self._connection.disconnect()
        except Exception:
            pass
        self._session = None
        self._connection = None
        self._tree = None

        new_target = SmbTarget(
            host=new_host,
            share=new_share,
            port=self._target.port,
            root_path=new_root,
        )
        self._dfs_resolution = resolution
        self._target = new_target

        # Rebuild against the fileserver. Recurse into _ensure_connected
        # one level — if it fails AGAIN with PATH_NOT_COVERED, that's
        # an interlink referral chain which we don't support in v0.53.
        # Set auto_resolve_dfs=False temporarily to fail loudly rather
        # than loop.
        prior_auto = self._auto_resolve_dfs
        self._auto_resolve_dfs = False
        try:
            self._ensure_connected()
        finally:
            self._auto_resolve_dfs = prior_auto

    def _list_directory(self, rel_dir: str) -> list[dict]:
        """List one directory. Returns list of
        ``{"name": str, "size": int, "is_directory": bool}``.

        v0.55: DFS-namespace-root directories can't be enumerated via
        regular Open + query_directory — the server returns
        STATUS_INVALID_PARAMETER (validated against HTB Multimaster
        ``\\\\10.129.13.28\\dfs``). Fall back to ``smbclient.scandir``
        which handles the DFS-aware listing path internally.
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
        try:
            handle.create(
                ImpersonationLevel.Impersonation,
                DirectoryAccessMask.FILE_LIST_DIRECTORY
                | DirectoryAccessMask.FILE_READ_ATTRIBUTES,
                FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_DIRECTORY_FILE,
            )
        except Exception as exc:
            # v0.55: DFS namespace root rejects regular CREATE. Fall
            # back to smbclient.scandir which handles the DFS listing
            # via its internal _resolve_dfs path.
            name = type(exc).__name__
            msg = str(exc)
            is_dfs_share = bool(getattr(self._tree, "is_dfs_share", False))
            looks_invalid_param = (
                "InvalidParameter" in name
                or "STATUS_INVALID_PARAMETER" in msg
                or "0xc000000d" in msg.lower()
            )
            if is_dfs_share and looks_invalid_param:
                try:
                    handle.close(False)
                except Exception:
                    pass
                return self._list_directory_via_smbclient(rel_dir)
            try:
                handle.close(False)
            except Exception:
                pass
            raise

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

    def _list_directory_via_smbclient(self, rel_dir: str) -> list[dict]:
        """v0.55 DFS-root fallback. Uses ``smbclient.scandir`` which
        handles the namespace-root listing path internally via
        ``_resolve_dfs``.

        Registers our credentials with smbclient's connection pool
        once per share so the scandir call doesn't need to
        re-authenticate. The pool persists across calls within the
        same SmbShare lifetime.
        """
        smbclient = _import_real_smbclient()

        # Register session with our credentials (idempotent —
        # smbclient caches by (server, username)).
        _, password, _ = build_credential(self._auth)
        smbclient.ClientConfig(
            username=getattr(self._auth, "user", "") or "",
            password=password if isinstance(password, str) else None,
        )

        full_unc = self._build_unc(rel_dir)
        out: list[dict] = []
        for entry in smbclient.scandir(full_unc):
            try:
                stat_result = entry.stat()
                size = stat_result.st_size
            except Exception:
                size = 0
            out.append({
                "name": entry.name,
                "size": int(size),
                "is_directory": bool(entry.is_dir()),
            })
        return out

    def _build_unc(self, rel_path: str) -> str:
        unc = rf"\\{self._target.host}\{self._target.share}"
        if rel_path:
            unc += "\\" + rel_path
        return unc
