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

from dataclasses import dataclass
from typing import Any

# Standard blank LM hash — used when the operator passes a bare NT
# hash (modern systems don't store LM hashes anymore).
BLANK_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"


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
        if not self.anonymous and not self.user:
            raise ValueError("Auth requires a user (unless anonymous=True)")


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
