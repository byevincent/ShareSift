"""v0.39: NetrShareEnum-backed network share discovery.

Single-host share enumeration via impacket's
``SMBConnection.listShares()`` (which wraps the
``srvsvc.NetrShareEnum`` DCERPC call). Lets ShareSift answer "what
shares does this host expose to me?" — the recon step pentesters
do today with ``smbmap`` / ``nxc smb --shares``.

Composes with ``sharesift batch``:

    sharesift discover //10.10.10.5 -u user -p pass > targets.txt
    sharesift batch --targets targets.txt -u user -p pass \\
        --output-dir ./engagement

CIDR / network-wide host iteration is a follow-on step in v0.39.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sharesift.share.auth import Auth


# Share-type constants from MS-SRVS (NetrShareEnum / SHARE_INFO_1).
# impacket doesn't re-export them in a stable location, so we
# hardcode them here.
_STYPE_DISKTREE = 0x00000000
_STYPE_PRINTQ = 0x00000001
_STYPE_DEVICE = 0x00000002
_STYPE_IPC = 0x00000003
_STYPE_SPECIAL = 0x80000000  # high bit — overlay on base type


@dataclass(frozen=True)
class ShareSummary:
    """One share's metadata as returned by NetrShareEnum."""

    name: str
    type: str  # "disk" / "printer" / "device" / "ipc" / "special-<base>" / "unknown"
    comment: str

    def is_file_share(self) -> bool:
        """True if this is a disk share (not IPC, printer, device).
        Used by the default discovery output to filter for shares
        worth scanning."""
        return self.type in ("disk", "special-disk")


def enumerate_shares(
    host: str,
    auth: "Auth",
    *,
    port: int = 445,
    timeout: float = 15.0,
) -> list[ShareSummary]:
    """List shares on ``host`` via NetrShareEnum.

    Requires the ``network-enum`` optional extra (``impacket``).
    Missing-extra raises ``SystemExit`` with a friendly install
    guide (same pattern as the ``smb`` extra in v0.37).
    """
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError as exc:
        raise SystemExit(
            "Network share discovery requires the network-enum extra. Install:\n"
            "    pipx install 'sharesift[network-enum]'   # if using pipx\n"
            "    pip install 'sharesift[network-enum]'    # if using pip\n"
            "    uv sync --extra network-enum             # if using uv\n"
            f"(missing: {exc.name})"
        ) from exc

    conn = SMBConnection(host, host, sess_port=port, timeout=timeout)
    try:
        _do_login(conn, auth)
        raw = conn.listShares()
    finally:
        try:
            conn.close()
        except Exception:
            pass

    return [_decode_share(s) for s in raw]


def _do_login(conn, auth: "Auth") -> None:
    """Dispatch to the right impacket login method based on Auth."""
    domain = auth.domain or ""

    if auth.anonymous:
        # Null session — empty user + empty password.
        conn.login("", "", domain="")
        return

    if auth.hash:
        from sharesift.share.auth import _parse_hash
        lm, nt = _parse_hash(auth.hash)
        conn.login(auth.user or "", "", domain=domain, lmhash=lm, nthash=nt)
        return

    if auth.kerberos:
        # impacket reads the ccache from KRB5CCNAME when useCache=True
        conn.kerberosLogin(
            auth.user or "", "", domain=domain,
            lmhash="", nthash="", aesKey="", useCache=True,
        )
        return

    # Plain NTLM password
    conn.login(auth.user or "", auth.password or "", domain=domain)


def _decode_share(s) -> ShareSummary:
    """Decode one entry from ``conn.listShares()`` into a typed
    ShareSummary. impacket returns strings already; this layer
    strips null terminators and classifies the share type bitfield.
    """
    name = _strip_terminator(s["shi1_netname"])
    comment = _strip_terminator(s["shi1_remark"])
    type_int = int(s["shi1_type"])
    return ShareSummary(
        name=name,
        type=_classify_type(type_int),
        comment=comment,
    )


def _strip_terminator(value) -> str:
    """impacket returns NetrShareEnum strings as Python str with a
    trailing null. Strip it. Handle bytes too in case the wire
    format changes."""
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", errors="replace")
        except Exception:
            return ""
    return value.rstrip("\x00")


def expand_target_to_hosts(target: str) -> list[str]:
    """Expand a discover target string into a list of host strings.

    Accepts:

    - ``host`` or ``//host`` or ``\\\\host`` → single host
    - ``host/share`` or ``//host/share`` → strip the share, single host
    - ``CIDR`` (``10.0.0.0/24``) or ``//CIDR`` → iterate every host
      in the network (excluding network + broadcast for IPv4 /24+)
    - ``host:port`` → handled by the caller's port parsing — this
      function strips the ``:port`` suffix before returning

    Returns a list of bare host strings (no leading slashes, no
    port suffix). Order matches the network iteration order for
    CIDRs.
    """
    import ipaddress

    # Strip leading // or \\
    t = target.lstrip("/\\").replace("\\", "/")
    # Strip /share if present (host/share → host)
    if "/" in t:
        # But preserve CIDR: 10.0.0.0/24 has /24 as the mask, not a share
        head, _, tail = t.partition("/")
        if tail.isdigit() and len(tail) <= 2:
            # Looks like a CIDR mask — keep the whole thing
            pass
        else:
            t = head
    # Strip :port
    if ":" in t and not t.startswith("["):
        host_or_net, _, _ = t.partition(":")
        t = host_or_net

    # Is it a CIDR?
    try:
        net = ipaddress.ip_network(t, strict=False)
    except ValueError:
        # Single hostname or single IP
        return [t]

    if net.num_addresses == 1:
        return [str(net.network_address)]

    # Use .hosts() to skip network + broadcast for IPv4
    return [str(h) for h in net.hosts()]


def probe_smb_alive(host: str, port: int = 445, timeout: float = 1.5) -> bool:
    """Quick TCP connect to test liveness. Skip hosts where 445
    isn't reachable so we don't waste time on impacket auth.
    """
    import socket
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _classify_type(type_int: int) -> str:
    is_special = bool(type_int & _STYPE_SPECIAL)
    base = type_int & ~_STYPE_SPECIAL & 0x0FFFFFFF
    type_map = {
        _STYPE_DISKTREE: "disk",
        _STYPE_PRINTQ: "printer",
        _STYPE_DEVICE: "device",
        _STYPE_IPC: "ipc",
    }
    base_name = type_map.get(base, "unknown")
    return f"special-{base_name}" if is_special else base_name
