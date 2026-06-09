r"""UNC / SMB target parser.

Accepts the shapes a pentester actually types or pastes:

  \\host\share
  //host/share
  //host/share/sub/dir          # path within share
  //host:port/share             # explicit port
  //10.0.0.5/finance$           # IP + admin-style share
  host/share                    # bare (no leading slashes)

Returns a typed :class:`SmbTarget`. Local filesystem paths are NOT
this parser's job — :func:`is_smb_target` distinguishes UNC-shape
inputs from local paths.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SmbTarget:
    """A parsed SMB target."""

    host: str
    share: str
    port: int = 445
    root_path: str = ""  # path under the share root, "" for share root

    @property
    def unc(self) -> str:
        """UNC representation: ``\\\\host\\share[\\path]``."""
        unc = rf"\\{self.host}\{self.share}"
        if self.root_path:
            unc += "\\" + self.root_path.replace("/", "\\")
        return unc


# Matches one of:
#   \\host\share[\path]
#   //host/share[/path]
#   //host:port/share[/path]
# Case-insensitive host. Port and root_path optional.
_UNC_RE = re.compile(
    r"""
    ^                            # start
    (?:\\\\|//)                  # \\ or //  (UNC prefix)
    (?P<host>[^\\/:]+)           # host (no path / port / colon)
    (?::(?P<port>\d+))?          # optional :port
    [\\/]                        # separator
    (?P<share>[^\\/]+)           # share name (one segment)
    (?:[\\/](?P<root>.*))?       # optional path under share
    $
    """,
    re.VERBOSE,
)

# Bare form: host/share[/path] — no leading slashes. Allowed but
# discouraged; pentesters paste with leading slashes more often.
_BARE_RE = re.compile(
    r"""
    ^
    (?P<host>[a-zA-Z0-9][a-zA-Z0-9\-.]*)   # hostname or IP
    (?::(?P<port>\d+))?
    /
    (?P<share>[^/]+)
    (?:/(?P<root>.*))?
    $
    """,
    re.VERBOSE,
)


def parse_target(text: str) -> SmbTarget:
    """Parse a UNC/SMB-shape string. Raises :class:`ValueError` if
    it doesn't look like a target.

    Use :func:`is_smb_target` to gate on this — local paths should
    not be passed in.
    """
    if not text:
        raise ValueError("empty target")

    m = _UNC_RE.match(text) or _BARE_RE.match(text)
    if not m:
        raise ValueError(f"not a UNC/SMB target: {text!r}")

    host = m.group("host")
    port_text = m.group("port")
    share = m.group("share")
    root = m.group("root") or ""

    port = int(port_text) if port_text else 445
    if not (1 <= port <= 65535):
        raise ValueError(f"port out of range: {port}")

    # Normalize root path separators to backslash internally; the
    # smbprotocol layer talks UNC \-paths.
    root_normalized = root.replace("/", "\\").strip("\\")

    return SmbTarget(host=host, share=share, port=port, root_path=root_normalized)


def is_smb_target(text: str) -> bool:
    """Cheap shape check — does this string look like a UNC/SMB target?

    Used by the CLI first-arg dispatch to decide between
    :class:`LocalShare` and :class:`SmbShare`. Conservative: anything
    that starts with ``//`` or ``\\\\`` is treated as SMB; bare
    ``host/share`` is NOT auto-detected (too easy to confuse with a
    local relative path like ``downloads/output``).
    """
    if not text:
        return False
    return text.startswith("\\\\") or text.startswith("//")
