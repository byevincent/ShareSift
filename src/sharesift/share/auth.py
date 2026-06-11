"""SMB authentication dispatch.

Lab-validated on 2026-06-08 against Samba 4.12 (SMB2/3): pyspnego's
pure-Python NTLM accepts an ``NTLMHash`` credential object directly
as the ``username`` parameter to ``smbprotocol.session.Session``.
No system packages, no ``NTLM_USER_FILE`` env-var ceremony, no
impacket fallback.

See ``docs/v0p35_smb_direct_plan.md`` ("Lab validation" section)
and the reference impl at ``/tmp/smb_lab/validate_v2.py``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

# Standard blank LM hash — used when the operator passes a bare NT
# hash (modern systems don't store LM hashes anymore).
BLANK_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"


def install_kerberos_clock_offset(ccache_path: str | None = None) -> int | None:
    """v0.55.1: detect clock skew from a Kerberos ccache and patch
    impacket's krb5 module to use the offset.

    HTB labs frequently run with clocks several hours off (Sauna
    surfaced ~7h ahead on 2026-06-11). KRB_AP_ERR_SKEW (Clock skew
    too great) breaks any Kerberos auth from an unsynced attacker
    box. Standard fix is ``ntpdate <DC>`` but that needs root.

    This helper reads the ccache's TGT ``authtime`` (the server's
    clock at issue) and compares to local time. If the offset is
    >60 seconds, it monkey-patches
    ``impacket.krb5.kerberosv5.datetime`` to add the offset to all
    ``datetime.datetime.now(tz)`` calls. The patch is surgical —
    only impacket's krb5 module is affected; the rest of Python
    sees real time.

    Returns the offset in seconds (positive = server ahead of
    local), or None if no ccache / no offset / impacket not
    importable.
    """
    import time
    import datetime as _dt

    path = ccache_path or os.environ.get("KRB5CCNAME")
    if not path or not os.path.isfile(path):
        return None

    try:
        from impacket.krb5.ccache import CCache
        import impacket.krb5.kerberosv5 as krbmod
    except ImportError:
        return None

    try:
        ccache = CCache.loadFile(path)
        if not ccache.credentials:
            return None
        authtime = ccache.credentials[0]["time"]["authtime"]
    except Exception:
        return None

    offset = int(authtime) - int(time.time())
    if abs(offset) < 60:
        # Within tolerance — no shim needed.
        return 0

    # Already patched? Don't double-wrap.
    if getattr(krbmod, "_sharesift_clock_offset", None) is not None:
        return krbmod._sharesift_clock_offset

    original_datetime_module = krbmod.datetime
    original_datetime_class = original_datetime_module.datetime

    class _OffsetDatetime(original_datetime_class):
        @classmethod
        def now(cls, tz=None):
            return original_datetime_class.now(tz) + _dt.timedelta(
                seconds=offset,
            )

    class _ShimDatetimeModule:
        timezone = original_datetime_module.timezone
        timedelta = original_datetime_module.timedelta
        datetime = _OffsetDatetime

    krbmod.datetime = _ShimDatetimeModule
    krbmod._sharesift_clock_offset = offset
    return offset


@dataclass(frozen=True)
class Auth:
    """SMB authentication parameters.

    Mutually-exclusive modes:
      - ``password`` set → NTLM password auth
      - ``hash`` set → NTLM Pass-the-Hash
      - ``kerberos=True`` → Kerberos via existing ``KRB5CCNAME``
        ccache; the operator must have run ``kinit`` (or a
        ticket-extraction tool) beforehand
      - ``anonymous=True`` → null session
    """

    user: str | None = None
    password: str | None = None
    hash: str | None = None
    kerberos: bool = False
    domain: str | None = None
    anonymous: bool = False
    # v0.55.1: explicit KDC host for impacket's kerberosLogin. When
    # None, the caller falls back to the SMB target host (works for
    # AD hunts where DC == target). Surfaced on HTB Sauna 2026-06-11
    # where impacket tried to resolve EGOTISTICAL-BANK.LOCAL:88 via
    # DNS and failed.
    kdc_host: str | None = None

    def __post_init__(self) -> None:
        set_modes = sum(
            bool(x)
            for x in (self.password, self.hash, self.kerberos, self.anonymous)
        )
        if set_modes == 0:
            raise ValueError(
                "Auth requires one of: password, hash, kerberos=True, anonymous=True"
            )
        if set_modes > 1:
            raise ValueError(
                "Auth modes are mutually exclusive — pick one of "
                "password / hash / kerberos / anonymous"
            )
        # Kerberos via ccache: the user principal is encoded in the
        # ticket — operator doesn't need to also pass -u. Validated
        # against HTB Sauna 2026-06-11 (would've forced -u redundantly).
        if not self.anonymous and not self.kerberos and not self.user:
            raise ValueError(
                "Auth requires a user (unless anonymous=True or kerberos=True)"
            )


def _qualify(user: str | None, domain: str | None) -> str | None:
    """Return ``DOMAIN\\user`` if domain is set, else ``user``."""
    if user is None:
        return None
    if domain:
        return f"{domain}\\{user}"
    return user


def _parse_hash(hash_text: str) -> tuple[str, str]:
    """Parse ``LM:NT`` or bare ``NT``. Returns ``(lm_hex, nt_hex)``,
    both lowercase. Blank LM is filled with the standard sentinel
    (real LM hashes haven't been stored on modern Windows since
    Server 2008+; pentesters paste bare NT all the time).
    """
    text = hash_text.strip()
    if ":" in text:
        lm, _, nt = text.partition(":")
        lm = lm.strip().lower() or BLANK_LM_HASH
        nt = nt.strip().lower()
    else:
        lm = BLANK_LM_HASH
        nt = text.lower()

    if not nt:
        raise ValueError(f"hash missing NT component: {hash_text!r}")
    if len(nt) != 32 or not all(c in "0123456789abcdef" for c in nt):
        raise ValueError(f"NT hash must be 32 hex chars: {nt!r}")
    if len(lm) != 32 or not all(c in "0123456789abcdef" for c in lm):
        raise ValueError(f"LM hash must be 32 hex chars: {lm!r}")
    return lm, nt


def build_credential(auth: Auth) -> tuple[Any, str | None, str]:
    """Build the ``(username, password, auth_protocol)`` triple that
    gets passed verbatim to ``smbprotocol.session.Session``.

    The ``username`` slot may be a string (password / Kerberos /
    anonymous) or an ``NTLMHash`` credential object (PtH). pyspnego
    accepts both via its ``unify_credentials`` dispatch.
    """
    qualified = _qualify(auth.user, auth.domain)

    if auth.anonymous:
        # Empty username + empty password = null session. smbprotocol
        # negotiates anonymous if the server allows it.
        return "", "", "ntlm"

    if auth.hash:
        from spnego._credential import NTLMHash

        lm, nt = _parse_hash(auth.hash)
        # NTLMHash takes a single ``username`` field; the domain is
        # encoded in ``DOMAIN\user`` form when set.
        cred = NTLMHash(
            username=qualified or auth.user or "",
            lm_hash=lm,
            nt_hash=nt,
        )
        # Per Sprint 2 lab validation: hand the NTLMHash to spnego as
        # the ``username`` arg with ``password=None``.
        return cred, None, "ntlm"

    if auth.kerberos:
        # smbprotocol picks up the ccache via ``KRB5CCNAME`` when
        # password is None and protocol is "kerberos".
        return qualified, None, "kerberos"

    # Plain NTLM password.
    return qualified, auth.password, "ntlm"
