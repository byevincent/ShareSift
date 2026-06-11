"""v0.52: LDAP-based Active Directory computer discovery.

Replaces Snaffler's "give me a domain, enumerate every joined
computer" step. Operator workflow:

    sharesift discover --domain corp.local --dc dc01.corp.local \\
        -u alice -p PW > targets.txt
    sharesift batch --targets targets.txt -u alice -p PW \\
        --output-dir ./engagement

Or, end-to-end via the v0.52 ``hunt`` command:

    sharesift hunt --domain corp.local --dc dc01.corp.local \\
        -u alice -p PW --output-dir ./engagement

Auth dispatches off the shared :class:`sharesift.share.Auth`:

- password → ldap3 NTLM bind, ``DOMAIN\\user`` / ``password``
- hash → ldap3 NTLM bind, ``DOMAIN\\user`` / ``lm:nt`` (ldap3's
  NTLM module parses ``lm:nt`` from the password field — well-known
  PtH pattern for ldap3)
- kerberos → SASL GSSAPI bind, ticket read from ``KRB5CCNAME``
  (operator runs ``kinit`` first)
- anonymous → ldap3 ANONYMOUS bind (often denied by AD but cheap
  to try)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from sharesift.share.auth import Auth


# userAccountControl bitfields per MS-ADTS section 2.2.16
_UAC_ACCOUNTDISABLE = 0x0002


def _install_md4_fallback() -> None:
    """OpenSSL 3.x removed MD4 from default providers; ldap3's NTLM
    module calls ``hashlib.new('md4', ...)`` which now raises
    ``ValueError: unsupported hash type MD4``.

    Surfaced against HTB Active on 2026-06-11: authenticated LDAP
    bind via NTLM failed at the hash step. Install a pure-Python
    fallback via ``Cryptodome.Hash.MD4`` (PyCryptodome) when the
    library is available — it is part of the standard ShareSift
    install via transitive deps.

    Idempotent — safe to call repeatedly. Bails silently if
    pycryptodome isn't installed; the original error surfaces
    from ldap3 in that case.
    """
    import hashlib

    # Already works (older OpenSSL, or someone else installed a fallback)
    try:
        hashlib.new("md4", b"")
        return
    except (ValueError, Exception):
        pass

    try:
        from Cryptodome.Hash import MD4
    except ImportError:
        return  # Original error from ldap3 will bubble up with no shim

    class _Md4Wrapper:
        """hashlib-compatible wrapper around Cryptodome's MD4."""

        name = "md4"
        digest_size = 16
        block_size = 64

        def __init__(self, data: bytes = b"") -> None:
            self._h = MD4.new()
            if data:
                self._h.update(data)

        def update(self, data: bytes) -> None:
            self._h.update(data)

        def digest(self) -> bytes:
            return self._h.digest()

        def hexdigest(self) -> str:
            return self._h.hexdigest()

        def copy(self) -> "_Md4Wrapper":
            new = _Md4Wrapper()
            new._h = self._h.copy()
            return new

    _original_new = hashlib.new

    def _patched_new(name, data=b"", **kwargs):
        if isinstance(name, str) and name.lower() == "md4":
            wrapper = _Md4Wrapper(data) if data else _Md4Wrapper()
            return wrapper
        return _original_new(name, data, **kwargs)

    hashlib.new = _patched_new


# Install at module import so any caller of discover_computers
# benefits without needing to know about the shim.
_install_md4_fallback()


@dataclass(frozen=True)
class ComputerObject:
    """One computer object from the AD LDAP query.

    ``dns_hostname`` is the field every share-enumeration call wants;
    ``sam_account_name`` is the NetBIOS fallback when DNS isn't set
    (stale objects, freshly joined hosts).
    """

    sam_account_name: str
    dns_hostname: str | None
    operating_system: str | None
    enabled: bool

    @property
    def host(self) -> str | None:
        """Best-guess hostname for SMB connection.

        Prefers ``dnsHostName`` (FQDN form) over ``sAMAccountName``
        (NetBIOS with trailing ``$``). Returns None when neither is
        present, which means the object is too broken to scan.
        """
        if self.dns_hostname:
            return self.dns_hostname
        if self.sam_account_name:
            return self.sam_account_name.rstrip("$")
        return None


def discover_computers(
    domain: str,
    auth: "Auth",
    *,
    dc: str | None = None,
    port: int = 389,
    use_tls: bool = False,
    base_dn: str | None = None,
    page_size: int = 500,
    timeout: float = 15.0,
    only_enabled: bool = True,
) -> list[ComputerObject]:
    """Query AD for every joined computer via LDAP.

    Returns a list of :class:`ComputerObject`. By default, disabled
    computer accounts are filtered out (``only_enabled=True``).

    Parameters
    ----------
    domain:
        AD domain name (e.g. ``corp.local``). Used to derive the
        base DN when ``base_dn`` isn't passed.
    auth:
        Shared :class:`sharesift.share.Auth` — same one as for
        ``enumerate_shares`` and ``SmbShare``. Kerberos mode picks
        up the ccache from ``KRB5CCNAME``.
    dc:
        DC hostname for the LDAP bind. Defaults to ``domain`` —
        works on most AD networks because the domain DNS record
        resolves to one of the DCs via SRV / round-robin.
    port:
        389 (default) or 636 for LDAPS. ``use_tls=True`` forces
        ldaps:// regardless of port.
    base_dn:
        Override the search base. Default: ``domain`` converted to
        DC components (``corp.local`` → ``DC=corp,DC=local``).
    page_size:
        Paged-search batch size. Default 500 is below AD's
        ``MaxPageSize`` default of 1000 — safe for any size forest.
    only_enabled:
        Drop accounts with ACCOUNTDISABLE set in
        ``userAccountControl``. Default True.

    Raises
    ------
    SystemExit:
        ``ldap3`` not installed — friendly install guide.
    RuntimeError:
        Bind failed (wrong creds, expired ccache, no LDAP service).
    """
    try:
        import ldap3
    except ImportError as exc:
        raise SystemExit(
            "AD discovery requires ldap3 (verify extra). Install:\n"
            "    pipx install 'sharesift[verify]'\n"
            "    pip install 'sharesift[verify]'\n"
            "    uv sync --extra verify\n"
            f"(missing: {exc.name})"
        ) from exc

    dc_host = dc or domain
    scheme = "ldaps" if use_tls or port == 636 else "ldap"
    url = f"{scheme}://{dc_host}:{port}"
    base = base_dn or _domain_to_base_dn(domain)

    server = ldap3.Server(
        url, get_info=ldap3.NONE, connect_timeout=int(timeout),
    )
    conn = _build_connection(server, auth, domain, ldap3)

    if not conn.bind():
        last_err = getattr(conn, "last_error", None) or "bind returned false"
        raise RuntimeError(f"LDAP bind to {url} failed: {last_err}")

    try:
        return list(_paged_computer_search(
            conn, base, page_size=page_size, only_enabled=only_enabled,
        ))
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def _build_connection(server, auth: "Auth", domain: str, ldap3_mod):
    """Build an ``ldap3.Connection`` for one of the four auth modes."""
    if auth.anonymous:
        return ldap3_mod.Connection(
            server, auto_bind=False, authentication=ldap3_mod.ANONYMOUS,
        )

    if auth.kerberos:
        # SASL GSSAPI reads the ticket from KRB5CCNAME via python-gssapi.
        return ldap3_mod.Connection(
            server,
            auto_bind=False,
            authentication=ldap3_mod.SASL,
            sasl_mechanism=ldap3_mod.GSSAPI,
        )

    # NTLM authority: prefer the explicit Auth.domain; fall back to
    # the LDAP domain's NetBIOS short name (first DNS label).
    nt_domain = auth.domain or domain.split(".")[0].upper()
    user_qualified = f"{nt_domain}\\{auth.user or ''}"

    if auth.hash:
        # ldap3 NTLM accepts password as "lmhash:nthash" — well-
        # known PtH pattern. Parse to validate the hash shape, then
        # re-emit in the lm:nt form ldap3 expects.
        from sharesift.share.auth import _parse_hash

        lm, nt = _parse_hash(auth.hash)
        return ldap3_mod.Connection(
            server,
            auto_bind=False,
            authentication=ldap3_mod.NTLM,
            user=user_qualified,
            password=f"{lm}:{nt}",
        )

    # Plain NTLM password
    return ldap3_mod.Connection(
        server,
        auto_bind=False,
        authentication=ldap3_mod.NTLM,
        user=user_qualified,
        password=auth.password or "",
    )


def _paged_computer_search(
    conn,
    base_dn: str,
    *,
    page_size: int,
    only_enabled: bool,
) -> Iterable[ComputerObject]:
    """Yield :class:`ComputerObject` from a paged LDAP search."""
    gen = conn.extend.standard.paged_search(
        search_base=base_dn,
        search_filter="(objectCategory=computer)",
        attributes=[
            "dnsHostName",
            "sAMAccountName",
            "operatingSystem",
            "userAccountControl",
        ],
        paged_size=page_size,
        generator=True,
    )
    for entry in gen:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") != "searchResEntry":
            continue
        obj = _decode_entry(entry)
        if only_enabled and not obj.enabled:
            continue
        yield obj


def _decode_entry(entry: dict) -> ComputerObject:
    """Decode one paged-search entry into a :class:`ComputerObject`."""
    attrs = entry.get("attributes") or {}

    def _scalar(key: str) -> str | None:
        v = attrs.get(key)
        if v is None:
            return None
        # ldap3 returns lists for multi-valued attrs and scalars
        # for single-valued. Normalize.
        if isinstance(v, list):
            return v[0] if v else None
        return v

    sam = _scalar("sAMAccountName") or ""
    dns = _scalar("dnsHostName")
    os_str = _scalar("operatingSystem")
    uac_raw = _scalar("userAccountControl") or 0
    try:
        uac = int(uac_raw)
    except (TypeError, ValueError):
        uac = 0

    enabled = not (uac & _UAC_ACCOUNTDISABLE)
    return ComputerObject(
        sam_account_name=sam,
        dns_hostname=dns or None,
        operating_system=os_str or None,
        enabled=enabled,
    )


def _domain_to_base_dn(domain: str) -> str:
    """``corp.local`` → ``DC=corp,DC=local``.

    Empty labels are skipped. Trailing dots are ignored.
    """
    parts = [p for p in domain.strip(".").split(".") if p]
    return ",".join(f"DC={p}" for p in parts)
