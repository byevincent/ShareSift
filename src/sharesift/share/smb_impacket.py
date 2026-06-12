"""v0.54.3: impacket-backed SMB walker for anonymous/null-session
targets.

Surfaced on HTB Active 2026-06-11: ``smbprotocol`` + ``pyspnego``
rejects empty credentials (``SpnegoError (16): Operation not
supported or available, Context: No username or password was
specified``). impacket's ``SMBConnection.login("", "", domain="")``
handles null session natively — which is what gets us into
classic "Replication"-style anonymous shares.

The two stacks have different APIs, so this module ships a
parallel ``ImpacketSmbWalker`` class that mirrors the public
surface of ``SmbShare`` (``walk``, ``read_bytes``,
``probe_share_access``). ``SmbShare.__init__`` dispatches to
this backend when ``auth.anonymous=True``.

Read-only; matches ``SmbShare``'s semantics. impacket's max-read
ceiling is its own — we cap at 1 MiB per read like the
smbprotocol walker.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from sharesift.share import ShareEntry
    from sharesift.share.auth import Auth
    from sharesift.share.smb import ShareAccess
    from sharesift.share.target import SmbTarget


# Match the smbprotocol walker's per-read ceiling so behavior is
# consistent across backends.
_MAX_SINGLE_READ = 1 * 1024 * 1024


class ImpacketSmbWalker:
    """Read-only SMB walker backed by impacket's SMBConnection.

    Implements the same triad as ``SmbShare`` (``walk``,
    ``read_bytes``, ``probe_share_access``) but goes through
    impacket instead of smbprotocol/pyspnego. The motivating use
    case is anonymous/null-session shares where pyspnego refuses
    empty credentials.
    """

    def __init__(
        self,
        target: "SmbTarget",
        auth: "Auth",
        *,
        timeout: int = 30,
    ) -> None:
        self._target = target
        self._auth = auth
        self._timeout = timeout
        self._conn = None
        self._share_access: "ShareAccess | None" = None

    @property
    def root(self) -> str:
        return self._target.unc

    @property
    def share_access(self) -> "ShareAccess | None":
        return self._share_access

    def __enter__(self) -> "ImpacketSmbWalker":
        self._ensure_connected()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def _ensure_connected(self) -> None:
        if self._conn is not None:
            return
        try:
            from impacket.smbconnection import SMBConnection
        except ImportError as exc:
            raise SystemExit(
                "Anonymous SMB walking requires the network-enum extra. Install:\n"
                "    pipx install 'sharesift[network-enum]'\n"
                "    pip install 'sharesift[network-enum]'\n"
                "    uv sync --extra network-enum\n"
                f"(missing: {exc.name})"
            ) from exc

        conn = SMBConnection(
            self._target.host, self._target.host,
            sess_port=self._target.port, timeout=float(self._timeout),
        )
        try:
            self._do_login(conn)
        except Exception:
            try:
                conn.close()
            except Exception:
                pass
            raise
        self._conn = conn

    def _do_login(self, conn) -> None:
        """Dispatch to the right impacket login method based on Auth.

        v0.54.3 ships the anonymous path as the primary use case
        (smbprotocol/pyspnego rejection workaround), but the same
        dispatch table covers PtH/Kerberos for callers that opt in.
        """
        domain = self._auth.domain or ""

        if self._auth.anonymous:
            conn.login("", "", domain="")
            return

        if self._auth.hash:
            from sharesift.share.auth import _parse_hash
            lm, nt = _parse_hash(self._auth.hash)
            conn.login(
                self._auth.user or "", "",
                domain=domain, lmhash=lm, nthash=nt,
            )
            return

        if self._auth.kerberos:
            kdc_host = self._auth.kdc_host or self._target.host
            # v0.55.1: auto-detect clock skew from ccache.
            from sharesift.share.auth import install_kerberos_clock_offset
            install_kerberos_clock_offset()
            conn.kerberosLogin(
                self._auth.user or "", "", domain=domain,
                lmhash="", nthash="", aesKey="",
                kdcHost=kdc_host, useCache=True,
            )
            return

        conn.login(
            self._auth.user or "", self._auth.password or "",
            domain=domain,
        )

    # ------------------------------------------------------------------
    # Share-access probe (Snaffler #184 equivalent for impacket path)
    # ------------------------------------------------------------------

    def probe_share_access(self) -> "ShareAccess":
        """v0.39-equivalent R/W probe via impacket.

        impacket's ``listPath`` opens FILE_LIST_DIRECTORY implicitly;
        a successful listing of the share root proves R.
        Write detection via ``connectTree`` doesn't expose the same
        granularity as smbprotocol's explicit access-mask Open, so
        we conservatively report W=False for anonymous probes.
        Operators who need a definitive W verdict should authenticate.
        """
        from sharesift.share.smb import ShareAccess

        if self._share_access is not None:
            return self._share_access

        self._ensure_connected()
        try:
            self._conn.listPath(
                self._target.share, self._target.root_path or "*",
            )
            can_read = True
        except Exception as exc:
            msg = str(exc)
            if (
                "STATUS_ACCESS_DENIED" in msg
                or "0xc0000022" in msg.lower()
                or "access denied" in msg.lower()
            ):
                can_read = False
            else:
                # Anything else (network, auth, broken share): treat
                # as inconclusive → probe says False, the walker will
                # surface the real error.
                can_read = False

        self._share_access = ShareAccess(can_read=can_read, can_write=False)
        return self._share_access

    # ------------------------------------------------------------------
    # Walk + read_bytes
    # ------------------------------------------------------------------

    def walk(self) -> Iterator["ShareEntry"]:
        """Recursive walk yielding files only, in deterministic
        sorted order — matches ``SmbShare.walk``'s contract."""
        from sharesift.share import ShareEntry

        self._ensure_connected()
        collected: list[tuple[str, int]] = []

        # impacket's listPath uses forward-slash separators in some
        # versions and backslash in others. We use backslash to
        # match the on-wire SMB convention.
        to_visit: list[str] = [self._target.root_path or ""]
        skipped_denied: list[str] = []
        while to_visit:
            rel_dir = to_visit.pop(0)
            try:
                entries = self._list_directory(rel_dir)
            except Exception as exc:
                # v0.55.2: a single ACCESS_DENIED on a subdirectory
                # crashed the whole share scan pre-fix. Surfaced on
                # HTB Cascade where r.thompson has read on `IT/*`
                # but not on `Contractors/`, `Finance/`, etc.
                # Record the skip and continue — partial walks are
                # operationally correct.
                msg = str(exc)
                name = type(exc).__name__
                if (
                    "AccessDenied" in name
                    or "STATUS_ACCESS_DENIED" in msg
                    or "0xc0000022" in msg.lower()
                ):
                    skipped_denied.append(self._build_unc(rel_dir))
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

        if skipped_denied:
            self._skipped_denied = skipped_denied

        for path, size in sorted(collected, key=lambda x: x[0]):
            yield ShareEntry(path=path, size=size)

    def _list_directory(self, rel_dir: str) -> list[dict]:
        """impacket's listPath returns SharedFile objects with
        ``get_longname()``, ``is_directory()``, ``get_filesize()``."""
        # impacket expects a glob; ``*`` lists everything in the dir
        search = (rel_dir + "/*") if rel_dir else "*"
        # impacket normalizes slashes internally
        results = self._conn.listPath(self._target.share, search)
        out: list[dict] = []
        for f in results:
            out.append({
                "name": f.get_longname(),
                "size": int(f.get_filesize()),
                "is_directory": bool(f.is_directory()),
            })
        return out

    def read_bytes(
        self, path: str, *, max_bytes: int | None = None,
    ) -> bytes | None:
        """Read up to ``max_bytes`` from a file on this share via
        impacket's ``getFile`` (with a buffer-collecting callback).

        Mirrors ``SmbShare.read_bytes``'s contract: UNCs that don't
        belong to this share return ``None``; on any read error
        returns ``None`` so the cascade treats the file as
        unreadable rather than crashing.
        """
        rel = self._unc_to_rel(path)
        if not rel:
            return None
        self._ensure_connected()

        requested = (
            max_bytes if max_bytes is not None else 10 * 1024 * 1024
        )
        cap = min(requested, _MAX_SINGLE_READ)

        buf = io.BytesIO()

        def _callback(data: bytes) -> None:
            remaining = cap - buf.tell()
            if remaining <= 0:
                return
            buf.write(data[:remaining])

        try:
            self._conn.getFile(
                self._target.share, rel, _callback,
            )
        except Exception:
            return None
        return buf.getvalue()

    def _unc_to_rel(self, unc_path: str) -> str | None:
        """Strip ``\\\\host\\share\\`` to recover the path relative
        to the share root, case-insensitive on host/share."""
        target_prefix = rf"\\{self._target.host}\{self._target.share}"
        if not unc_path.lower().startswith(target_prefix.lower()):
            return None
        rel = unc_path[len(target_prefix):].lstrip("\\")
        return rel or None

    def _build_unc(self, rel_path: str) -> str:
        unc = rf"\\{self._target.host}\{self._target.share}"
        if rel_path:
            unc += "\\" + rel_path
        return unc
