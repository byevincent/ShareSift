"""v0.52: DFS namespace detection + operator guidance.

Domain DFS namespaces use the AD domain name as the UNC server
segment (``\\\\corp.local\\departments\\hr``), which then redirects
to a real fileserver (``\\\\fs01.corp.local\\hr``) via DFS referral
requests.

Full DFS referral resolution is queued for v0.53 — it needs a real
DC to test against. v0.52 ships honest scope:

- Detect DFS-shaped UNCs (first segment looks like a domain).
- Emit an operator-facing warning explaining how to resolve
  manually (find the fileserver, re-run against it).

Heuristic: any UNC whose server segment contains a dot is treated
as a candidate DFS root. Single-label hostnames (``\\\\fs01\\share``)
are non-DFS file servers. This false-positives on hostnames with
DNS-suffix in the UNC (``\\\\fs01.corp.local\\share``), which is
fine — we emit a hint, not an error.
"""

from __future__ import annotations

import re

# UNC ``\\<server>\<share>``. Server with a dot looks domain-shaped.
_UNC_SERVER = re.compile(r"^\\\\([^\\]+)\\")


def looks_like_dfs(unc: str) -> bool:
    """Heuristic: does this UNC's server segment look like a
    domain (DFS root) rather than a single-host fileserver?

    Examples:

    - ``\\\\corp.local\\dfs\\hr`` → True (domain-shaped)
    - ``\\\\fs01\\hr`` → False (single label)
    - ``\\\\fs01.corp.local\\hr`` → True (also dotted — false-positive,
      operator gets a hint they can ignore)
    """
    m = _UNC_SERVER.match(unc)
    if not m:
        return False
    server = m.group(1)
    return "." in server


def dfs_guidance(unc: str) -> str:
    """Operator-facing message for a detected DFS target.

    Returned as a plain string so callers can log it via the right
    output channel (``out.warn`` from the CLI, ``logging.warning``
    in library code).
    """
    m = _UNC_SERVER.match(unc)
    server = m.group(1) if m else unc
    return (
        f"DFS target detected: {unc}\n"
        "   This release detects but does not resolve DFS referrals.\n"
        "   Resolve the fileserver via your AD recon tool of choice:\n"
        f"     nxc smb {server} -u U -p P  # lists shares the DC exposes\n"
        f"     nslookup -type=SRV _ldap._tcp.{server}  # finds the DCs\n"
        "   Then re-run against the resolved fileserver:\n"
        "     sharesift hunt //fs01.example/share -u U -p P\n"
        "   Full DFS referral chasing queues for v0.53."
    )
