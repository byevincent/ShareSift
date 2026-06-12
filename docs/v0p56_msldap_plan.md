# v0.56 — msldap migration for Kerberos LDAP

## Why

ldap3's SASL GSSAPI binding requires `gssapi` (Python lib) which
needs `libkrb5-dev` on the build host. On stock Kali / Ubuntu /
Parrot this means apt-install with sudo — fine for engagement
boxes but blocks containerized deployments and PyInstaller
binaries (system lib dependency tree). The Sauna smoke test
(2026-06-11) surfaced this as the first hard wall on the LDAP-
Kerberos path:

```
$ sharesift discover --ad-domain corp.local -u user --use-kcache
ldap discovery failed: LDAPPackageUnavailableError: package gssapi
(or winkerberos) missing
```

msldap (skelsec) is a pure-Python LDAP library that uses
minikerberos for ticket handling. No system deps. NetExec uses it
for the same reason. Adopting msldap as the Kerberos LDAP path
closes the operational gap on a stock Kali / single-binary
ShareSift install.

## Scope

**In scope:**
- New `src/sharesift/share/ad_msldap.py` parallel to `ad.py`. Same
  public surface (`discover_computers(domain, auth, **kwargs)`).
- `discover_computers` dispatch in `ad.py`: when `auth.kerberos=True`
  AND msldap is importable, route to the msldap implementation.
- Add `msldap>=0.5` as a new `kerberos` optional extra.
- Tests with mocked msldap.

**Out of scope (deferred):**
- impacket SMB Kerberos session-setup bug (issue #1573). msldap
  fixes the LDAP path only. SMB Kerberos is a separate upstream
  problem.
- Replacing ldap3 entirely for password/NTLM/PtH paths. ldap3 NTLM
  works fine after the MD4 shim (v0.53.1); only the SASL GSSAPI
  path is broken.

## Why v0.56 alone doesn't unblock end-to-end Kerberos hunt

The Kerberos chain has two legs:

1. **LDAP discover** — what computers exist? Today ldap3 needs
   gssapi system lib. After v0.56: msldap, pure Python.
2. **SMB hunt** — walk each share. Today impacket; broken by
   issue #1573 (`STATUS_MORE_PROCESSING_REQUIRED` on SESSION_SETUP).
   Validated against Sauna + Forest live. Reproduces with bare
   impacket, no ShareSift involvement.

v0.56 fixes leg 1. Leg 2 still requires either an upstream impacket
fix OR switching SmbShare to smbprotocol+gssapi OR aiosmb (skelsec,
async API, multi-day refactor).

**Operational guidance until both legs land:** use PtH
(`-H lm:nt`) instead of `--use-kcache`. Most engagements with a
TGT cache can also recover the underlying NT hash via secretsdump.

## Implementation sketch

### `share/ad_msldap.py`

Pure-Python alternative to ldap3+gssapi. Same `ComputerObject`
output shape so `cmd_discover` and `cmd_hunt` don't change.

```python
async def _discover_computers_kerberos(domain, auth, dc, port, ...):
    from msldap.commons.url import MSLDAPURLDecoder

    dc_host = dc or domain
    ccache = os.environ.get("KRB5CCNAME", "/tmp/krb5cc")
    url = (
        f"ldap+kerberos-ccache://{auth.user}@{dc_host}"
        f"/?dc={dc_host}&ccache={ccache}"
    )
    client = MSLDAPURLDecoder(url).get_client()
    _, err = await client.connect()
    if err:
        raise RuntimeError(f"msldap connect: {err}")

    results = []
    async for entry, err in client.pagedsearch(
        search_filter="(objectCategory=computer)",
        attributes=[
            "dnsHostName", "sAMAccountName",
            "operatingSystem", "userAccountControl",
        ],
        page_size=page_size,
    ):
        if err:
            raise RuntimeError(f"msldap search: {err}")
        results.append(_msldap_entry_to_computer_object(entry))
    return results


def discover_computers_kerberos(...):
    return asyncio.run(_discover_computers_kerberos(...))
```

### Dispatch in `ad.py::discover_computers`

```python
if auth.kerberos:
    try:
        from sharesift.share.ad_msldap import (
            discover_computers_kerberos,
        )
        return discover_computers_kerberos(
            domain, auth, dc=dc, port=port, base_dn=base_dn,
            page_size=page_size,
        )
    except ImportError:
        # msldap not installed — fall back to ldap3+gssapi
        # (which may itself error if gssapi missing)
        pass
```

### Deps

```toml
[project.optional-dependencies]
kerberos = [
    "msldap>=0.5",
    # minikerberos is a transitive dep
]
```

## Test plan

1. Unit tests with mocked msldap client (`test_ad_msldap_v0p56.py`).
   Mock `MSLDAPURLDecoder().get_client()`, mock `client.connect()`
   and `client.pagedsearch()`. Verify the auth dispatch + URL
   construction + result decoding.
2. Live test against HTB Sauna or Forest (any AD with a TGT
   cache):
   ```bash
   getTGT.py 'domain/user:pass' -dc-ip <ip>
   KRB5CCNAME=/tmp/user.ccache sharesift discover \
       --ad-domain <domain> --dc <ip> -u <user> --use-kcache
   ```
   Expect: enumerate computer objects without `gssapi` system
   lib installed.

## Open questions

1. **Separate `kerberos` extra or merge with `verify`?** Lean
   separate to keep verify install lean.
2. **Auto-detect msldap or require `--use-msldap` flag?** Lean
   auto-detect — operators shouldn't need to know which Kerberos
   backend is active.
3. **Does msldap honor v0.55.1's clock-skew shim?** minikerberos
   has its own clock handling — needs investigation. May need a
   separate skew offset injected into minikerberos's time path.

## Estimated effort

- New module + dispatch: ~3 hours
- Mocked tests: ~1 hour
- Live validation against AD lab: ~30 min (once we have a TGT)
- Open-question investigation: ~1-2 hours

Total: ~5-7 hours focused work. Single session feasible.

## Status as of 2026-06-11

This plan is queued. v0.55.2 closes the Cascade engagement gaps
that were blocking 80% of common AD shapes. Kerberos is a smaller
operational gap (operators have PtH as fallback) and is gated on
the impacket upstream issue anyway. Recommend executing v0.56 as
a focused session when a working AD lab with TGT cache is
available for live validation.
