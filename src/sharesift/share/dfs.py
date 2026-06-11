"""v0.52/v0.53: DFS namespace detection + referral resolution.

v0.52 shipped detection-only utilities (``looks_like_dfs``,
``dfs_guidance``) plus an opt-in ``hunt --detect-dfs`` flag.

v0.53 adds real DFS referral resolution via
``FSCTL_DFS_GET_REFERRALS`` on an SMB connection's ``IPC$`` tree.
``SmbShare`` catches ``STATUS_PATH_NOT_COVERED`` on tree-connect,
chases the referral chain through the DC, and re-targets the
connection to the resolved fileserver.

Reference: smbclient._pool.dfs_request in jborean93/smbprotocol
(the de facto reference implementation; private API so we
reimplement the 20-line pattern using public smbprotocol primitives).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# UNC ``\\<server>\<share>``. Server with a dot looks domain-shaped.
_UNC_SERVER = re.compile(r"^\\\\([^\\]+)\\")


def looks_like_dfs(unc: str) -> bool:
    """Heuristic: does this UNC's server segment look like a
    domain (DFS root) rather than a single-host fileserver?

    Used by the opt-in ``hunt --detect-dfs`` flag for pre-flight
    warnings. The v0.53 ``SmbShare`` auto-resolver doesn't rely
    on this — it just catches ``STATUS_PATH_NOT_COVERED`` on
    tree-connect, which is authoritative.
    """
    m = _UNC_SERVER.match(unc)
    if not m:
        return False
    return "." in m.group(1)


def dfs_guidance(unc: str) -> str:
    """Operator-facing message for a detected DFS target.

    v0.53 still emits this only for the ``--detect-dfs`` opt-in
    flag — the auto-resolver in ``SmbShare`` handles resolution
    transparently without a warning when it succeeds.
    """
    m = _UNC_SERVER.match(unc)
    server = m.group(1) if m else unc
    return (
        f"DFS target detected: {unc}\n"
        "   v0.53 auto-resolution will chase referrals on actual "
        "tree-connect.\n   This pre-flight warning is informational "
        "only — run the scan and the resolver will handle it.\n"
        f"   Domain root: {server}"
    )


# --------------------------------------------------------------------
# v0.53 — referral resolution
# --------------------------------------------------------------------


@dataclass(frozen=True)
class DfsResolution:
    """One resolved DFS referral.

    ``original_unc`` is the path the operator asked for (e.g.
    ``\\\\corp.local\\dept\\hr``). ``target_unc`` is the fileserver
    UNC the DC pointed us at (e.g. ``\\\\fs01.corp.local\\hr``).
    ``path_consumed_chars`` is how many UTF-16 characters of the
    original path the referral covered — used to rewrite the
    remainder when the operator targeted a path under the share
    root.
    """

    original_unc: str
    target_unc: str
    path_consumed_chars: int

    def rewrite(self, sub_path: str) -> str:
        """Apply the DFS substitution to a deeper UNC.

        Example::

            res.original_unc = '\\\\corp.local\\dept\\hr'
            res.target_unc = '\\\\fs01.corp.local\\hr'
            res.rewrite('\\\\corp.local\\dept\\hr\\salary.xlsx')
              → '\\\\fs01.corp.local\\hr\\salary.xlsx'

        Returns the input unchanged if it doesn't start with the
        original referral root.
        """
        original_lower = self.original_unc.lower()
        if not sub_path.lower().startswith(original_lower):
            return sub_path
        suffix = sub_path[len(self.original_unc):]
        return self.target_unc + suffix


def dfs_request_via_ipc(connection, session, ipc_tree, dfs_path: str):
    """Send a DFS referral IOCTL on an open ``IPC$`` tree.

    Returns the parsed ``DFSReferralResponse``. The caller wraps it
    in ``ReferralEntry`` (or accesses ``referral_entries`` directly)
    to extract the resolved target.

    Mirrors ``smbclient._pool.dfs_request`` — private API in
    smbprotocol; we reimplement the public-primitive version so we
    don't bind to an internal that may move.

    Parameters
    ----------
    connection: smbprotocol.connection.Connection
    session: smbprotocol.session.Session
    ipc_tree: smbprotocol.tree.TreeConnect — connected to ``IPC$``
        on the server that should answer the referral (the DC for
        domain DFS, or the namespace server for standalone DFS).
    dfs_path: str — full UNC including leading ``\\\\``.
    """
    from smbprotocol.dfs import DFSReferralRequest, DFSReferralResponse
    from smbprotocol.ioctl import (
        CtlCode,
        IOCTLFlags,
        SMB2IOCTLRequest,
        SMB2IOCTLResponse,
    )

    req = DFSReferralRequest()
    req["max_referral_level"] = 4
    req["request_file_name"] = dfs_path

    ioctl = SMB2IOCTLRequest()
    ioctl["ctl_code"] = CtlCode.FSCTL_DFS_GET_REFERRALS
    ioctl["file_id"] = b"\xff" * 16
    ioctl["max_output_response"] = 56 * 1024
    ioctl["flags"] = IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL
    ioctl["buffer"] = req

    handle = connection.send(
        ioctl,
        sid=session.session_id,
        tid=ipc_tree.tree_connect_id,
    )
    raw_response = connection.receive(handle)

    ioctl_resp = SMB2IOCTLResponse()
    ioctl_resp.unpack(raw_response["data"].get_value())

    dfs_resp = DFSReferralResponse()
    dfs_resp.unpack(ioctl_resp["buffer"].get_value())
    return dfs_resp


def first_target_unc(dfs_response) -> str | None:
    """Extract the highest-priority target UNC from a parsed
    ``DFSReferralResponse``.

    Servers return referral entries already sorted by cost (lowest
    first), so the first entry is the right target unless we have
    a sticky hint cached. Returns None if the response is empty.
    """
    entries = dfs_response["referral_entries"].get_value()
    if not entries:
        return None
    # All entry versions expose ``.network_address`` as a property
    # via the smbprotocol DFS module.
    addr = entries[0].network_address
    if not addr:
        return None
    # Normalize: server may return without leading ``\\``; the
    # resolver downstream expects full UNC form.
    if not addr.startswith("\\\\"):
        addr = "\\\\" + addr.lstrip("\\")
    return addr


def resolve_dfs_path(
    connection,
    session,
    dfs_path: str,
) -> DfsResolution | None:
    """Resolve a DFS UNC to its fileserver UNC.

    Opens an ``IPC$`` tree on ``connection`` / ``session``, sends
    the referral request, parses the response. Returns a
    :class:`DfsResolution` on success, ``None`` when the server
    returned no referral entries.

    The IPC$ tree is torn down before return — the caller is free
    to reconnect to the resolved fileserver with a fresh
    connection.
    """
    from smbprotocol.tree import TreeConnect

    # IPC$ on the same server we already have a session for. The
    # server name comes from the Connection's server_name attribute
    # in modern smbprotocol; fall back to looking at the
    # connection's host.
    server = getattr(connection, "server_name", None) or getattr(
        connection, "_server_name", None,
    )
    if server is None:
        raise RuntimeError(
            "DFS resolution: cannot infer IPC$ server from connection"
        )
    ipc_unc = rf"\\{server}\IPC$"

    ipc_tree = TreeConnect(session, ipc_unc)
    ipc_tree.connect()
    try:
        response = dfs_request_via_ipc(
            connection, session, ipc_tree, dfs_path,
        )
    finally:
        try:
            ipc_tree.disconnect()
        except Exception:
            pass

    target_unc = first_target_unc(response)
    if target_unc is None:
        return None

    path_consumed_chars = (
        response["path_consumed"].get_value() // 2
    )  # bytes → UTF-16 chars
    return DfsResolution(
        original_unc=dfs_path,
        target_unc=target_unc,
        path_consumed_chars=path_consumed_chars,
    )


def is_path_not_covered(exc: Exception) -> bool:
    """True if ``exc`` indicates the server doesn't own the path
    (i.e. it's a DFS namespace pointing elsewhere).

    smbprotocol surfaces this as
    ``smbprotocol.exceptions.PathNotCovered``; older versions used
    a generic ``SMBResponseException`` with NTSTATUS
    ``0xC0000257``.
    """
    try:
        from smbprotocol.exceptions import PathNotCovered
        if isinstance(exc, PathNotCovered):
            return True
    except ImportError:
        pass
    msg = str(exc).lower()
    return (
        "path_not_covered" in msg
        or "0xc0000257" in msg
    )
