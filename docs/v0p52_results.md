# v0.52 — Snaffler-replacement enumeration sprint results

**Date:** 2026-06-10
**Goal recap:** ShareSift becomes a fully self-contained Snaffler
replacement on a Linux/Kali attacker workflow. One command (`hunt`)
takes a domain + creds and returns ranked credential findings.

## What shipped

| Capability | Module / CLI |
|---|---|
| LDAP-based AD computer object enumeration | `share/ad.py` — `discover_computers` |
| AD-wide share discovery | `sharesift discover --ad-domain corp.local -u U -p P` |
| End-to-end Snaffler-replacement sweep | `sharesift hunt --ad-domain corp.local -u U -p P --output-dir ./out` |
| DFS detection utilities (opt-in) | `share/dfs.py` — `looks_like_dfs`, `dfs_guidance`; `hunt --detect-dfs` |
| Pass-the-Hash via LDAP NTLM | `share/ad.py` (`lm:nt` password encoding, well-known ldap3 PtH pattern) |
| Kerberos via LDAP SASL GSSAPI | `share/ad.py` (`KRB5CCNAME` ccache, no kinit-in-tool) |

## What was already done before this sprint

The original plan called for a four-version sprint (v0.52-v0.55)
spanning AD discovery, ACL-aware share enum, DFS, and Kerberos
ccache. The audit revealed v0.39 + v0.40 already shipped most of
the foundation:

- `NetrShareEnum`-backed single-host share enumeration
- CIDR network expansion + concurrent SMB liveness probe
- Pass-the-Hash via `NTLMHash` (smbprotocol)
- Kerberos via `KRB5CCNAME` for impacket (`useCache=True`) and
  smbprotocol (`auth_protocol="kerberos"`)
- R/W ACL probe via SMB2 CREATE on share root (fixes Snaffler #184)
- Snaffler-style noise exclusions (`WinSxS`, `Program Files`, etc.)
- Multi-target batch scanning via `cmd_batch`
- End-to-end per-target pipeline via `cmd_scan`

The real gaps were three: LDAP discovery, DFS handling, and a
unified `hunt` command. v0.52 closes all three.

## Operator workflows enabled

**Drop-on-Kali Snaffler replacement:**
```bash
# Single command — AD-wide credential hunt
sharesift hunt \
    --ad-domain corp.local --dc dc01.corp.local \
    -u alice -p PW \
    --output-dir ./engagement
```

**Pass-the-Hash from a dumped NT hash:**
```bash
sharesift hunt --ad-domain corp.local \
    -u 'svc_backup' -H 'aad3b...:1c63...' \
    --output-dir ./engagement
```

**Kerberos via existing ccache:**
```bash
kinit alice@CORP.LOCAL
sharesift hunt --ad-domain corp.local --use-kcache \
    --output-dir ./engagement
```

**Anonymous fallback (null session):**
```bash
sharesift hunt --ad-domain corp.local --no-pass \
    --output-dir ./engagement
```

## Test discipline

- 35 new unit tests across `test_ad_discovery_v0p52.py` and
  `test_dfs_detection_v0p52.py` (LDAP auth dispatch matrix,
  paged-search filtering, UAC parsing, DFS heuristics).
- 11 new end-to-end orchestration tests in `test_hunt_v0p52.py`
  (arg validation, LDAP vs CIDR dispatch, share filtering, DFS
  opt-in).
- Full suite: 1299 passed, 51 skipped, 0 failed.

## Honest scope caveats

**1. LDAP path tested against mocks, not a live DC.**
The `ldap3.Connection` API surface is mocked in tests. The auth
dispatch matrix (NTLM password / NTLM hash / SASL GSSAPI /
ANONYMOUS) is well-documented but unvalidated against a live
Active Directory. The first time this runs against GOAD it will
reveal whether the SASL GSSAPI bind picks up `KRB5CCNAME` cleanly
on a stock Kali / how the paged search handles >1000-object
forests.

**2. DFS referral resolution is not yet shipped.**
`share/dfs.py` provides detection heuristics and operator guidance,
but does not chase DFS referrals through the DC. Operators hitting
a DFS namespace (`\\corp.local\dfs\hr`) need to manually resolve to
the fileserver UNC. The auto-detect on `hunt` is opt-in
(`--detect-dfs`) because the heuristic false-positives on every
FQDN host — `\\ws01.corp.local\X` is indistinguishable from a
domain DFS root by string shape alone.

**3. No live-AD head-to-head benchmark.**
The v0.51 release shipped `diskforge_winshare_v1` (head-to-head vs
Snaffler on a synthetic Windows share). v0.52's enumeration changes
are upstream of that benchmark — they target host/share *discovery*,
which `diskforge_winshare_v1` skips by handing ShareSift a pre-built
disk image. A GOAD-validated benchmark of `sharesift hunt` vs
`Snaffler.exe -s -d corp.local` is the v0.55 milestone.

## What v0.52 does NOT ship

- **Full DFS referral resolution** — needs a GOAD-class lab. v0.53.
- **Kerberoasting / AS-REP roasting** — out of scope; ShareSift's
  domain is share-content credential hunting, not auth surface.
- **Live KDC validation before LDAP bind** — if the ccache is
  expired, GSSAPI bind fails with a clear error message; we
  surface it as-is.
- **DC failover (multiple `--dc` args)** — single DC for v0.52.
  v0.53 if asked.
- **AD lab head-to-head benchmark (GOAD)** — v0.55.

## Files touched

| File | Change |
|---|---|
| `src/sharesift/share/ad.py` | NEW — LDAP computer discovery (220 lines) |
| `src/sharesift/share/dfs.py` | NEW — DFS detection utilities (50 lines) |
| `src/sharesift/cli.py` | +`_ldap_discover_hosts`, +`cmd_hunt`, +`--ad-domain`/`--dc`/`--ldap-port`/`--use-ldaps`/`--detect-dfs` flags, +`hunt` subparser |
| `tests/test_ad_discovery_v0p52.py` | NEW — 24 tests |
| `tests/test_dfs_detection_v0p52.py` | NEW — 11 tests |
| `tests/test_hunt_v0p52.py` | NEW — 11 tests |
| `docs/v0p52_snaffler_replacement_plan.md` | NEW — consolidated plan |
| `docs/v0p52_results.md` | NEW — this file |
| `CHANGELOG.md` | v0.52.0 entry |
| `pyproject.toml`, `src/sharesift/__init__.py` | version → 0.52.0 |
