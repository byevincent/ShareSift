# v0.53 HTB Active smoke test — what worked, what broke

**Date:** 2026-06-11
**Target:** HTB Active (10.129.13.21, DC.active.htb, Server 2008 R2)
**Tester:** automated via Claude Code agent over HTB VPN
**Outcome:** GPP cpassword caught as Red tier; three real bugs surfaced.

## Headline result

ShareSift caught the GPP `cpassword` leak in `Groups.xml` on the
`Replication` share — the exact credential the box is designed
to leak:

```json
{
  "path": "\\\\10.129.13.21\\Replication\\active.htb\\Policies\\...\\Groups.xml",
  "content_tier": "Red",
  "content_source": "parsers",
  "extracted_fields": [{
    "field_name": "cpassword[active.htb\\SVC_TGS]",
    "value": "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+...",
    "confidence": 0.99,
    "parser": "gpp_xml"
  }]
}
```

That's the canonical end-to-end validation: ShareSift's path
triage → SMB walk → content scan → parser-based extraction →
tier assignment all worked against a real AD lab.

## What worked

| Capability | Test | Result |
|---|---|---|
| Anonymous SMB share enumeration (v0.39) | `sharesift discover //10.129.13.21 --no-pass` | ✅ Listed all 6 shares correctly |
| Anonymous LDAP rootDSE bind (v0.52) | direct ldap3 query | ✅ Returned `defaultNamingContext=DC=active,DC=htb`, `dnsHostName=DC.active.htb` |
| Authenticated LDAP computer enumeration (v0.52) | `sharesift discover --ad-domain active.htb --dc 10.129.13.21 -u SVC_TGS -p ...` | ✅ (after MD4 shim) Returned 1 computer object with correct `sAMAccountName`, `dnsHostName`, `operatingSystem` |
| Authenticated SMB walk + content scan (v0.39) | `sharesift hunt //10.129.13.21 -u SVC_TGS -p ... --no-encrypt` | ✅ Walked Replication, NETLOGON, SYSVOL, Users (partial on the latter three due to ACL) |
| GPP cpassword parser (v0.20+) | content scan on `Groups.xml` | ✅ Red tier, gpp_xml parser, 0.99 confidence |
| Snaffler-style noise exclusions (v0.40) | applied during hunt | ✅ Filtered Windows system noise |

## What broke (real bugs surfaced)

### Bug 1 — smbprotocol anonymous auth fails

**Surfaced:** `sharesift hunt //10.129.13.21 --no-pass` →
`SpnegoError (16): Operation not supported or available`.

**Root cause:** `share/smb.py::SmbShare` uses `smbprotocol` +
`pyspnego` for SMB walks. pyspnego rejects empty credentials —
unlike impacket's `SMBConnection.login("", "", domain="")` which
handles null session natively. All four variations tested
(empty strings, `None`, `Guest`+empty, no encryption) failed.

**Impact:** Anonymous-readable shares (the classic Replication
share, public file servers with no auth) can't be hunted with
`--no-pass`. The `discover` path works because it uses impacket;
the SMB walk fails because it uses smbprotocol.

**Fix queued for v0.54:** dispatch SmbShare to impacket's
`SMBConnection` when `auth.anonymous=True`.

### Bug 2 — ldap3 NTLM bind fails on OpenSSL 3.x (FIXED)

**Surfaced:** `sharesift discover --ad-domain active.htb -u X -p Y`
→ `ValueError: unsupported hash type MD4`.

**Root cause:** OpenSSL 3.0+ removed MD4 from default providers.
ldap3's NTLM module calls `hashlib.new('md4', ...)` for the NT
hash computation, which fails on modern Python+OpenSSL.

**Fix shipped in v0.53.1:** `share/ad.py` installs a
`Cryptodome.Hash.MD4`-backed shim at module import. Idempotent;
no-op when hashlib already supports MD4 (older OpenSSL or legacy
provider enabled).

After the fix:
```
$ sharesift discover --ad-domain active.htb --dc 10.129.13.21 \
    -u SVC_TGS -p GPPstillStandingStrong2k18
ldap: 1 enabled computer object(s)
```

### Bug 3 — SMB encryption required by default on legacy servers

**Surfaced:** `sharesift hunt //10.129.13.21 -u X -p Y`
→ `SMB encryption is required but the connection does not support it`.

**Root cause:** ShareSift defaults `encrypt=True` (SMB3 GCM).
Server 2008 R2 only supports SMB 2.0/2.1 — no SMB3 encryption.
The connection negotiates lower-version SMB; the require-
encryption client check then rejects it.

**Workaround today:** pass `--no-encrypt`.

**Fix queued for v0.54:** detect the server-side dialect after
negotiation; auto-fallback to unencrypted if SMB3 isn't available
AND the operator hasn't explicitly required encryption (a new
`--require-encrypt` flag for the opsec-conscious case where
unencrypted is unacceptable).

### Minor finding — anonymous LDAP search blocked, silent CLI

**Surfaced:** `sharesift discover --ad-domain active.htb --no-pass`
→ `0 enabled computer object(s)` with no explanation.

**Root cause:** Anonymous bind succeeded, but AD returned
`operationsError: In order to perform this operation a successful
bind must be completed`. This is AD policy — not a bug.

**Fix shipped in v0.53.1:** when `auth.anonymous=True` and zero
results, print a hint pointing the operator at `-u/-p`, `-H`, or
`-k`.

### Non-finding — LDAP hostnames don't auto-resolve via DNS

**Surfaced:** LDAP returned `host=DC.active.htb`; the follow-on
SMB probe (`probe_smb_alive`) failed because DC.active.htb
doesn't resolve from my host.

**Verdict:** not a bug. Adding an `/etc/hosts` entry for the
target domain's hosts is standard engagement-prep workflow —
operators do this themselves and don't want the tool touching
`/etc/hosts`. No fix needed.

## What v0.53.1 ships (right now)

| Change | File | Why |
|---|---|---|
| MD4 fallback shim via Cryptodome | `src/sharesift/share/ad.py` | Unblocks v0.52 LDAP authenticated bind on modern Python+OpenSSL |
| Better empty-result hint | `src/sharesift/cli.py` (`_ldap_discover_hosts`) | "AD blocks anonymous search — pass real auth" instead of silent 0 |
| Smoke test results doc | `docs/v0p53_htb_smoke_test.md` | This file |

## Queued for v0.54

1. smbprotocol anonymous fallback to impacket for SMB walks
2. Auto-detect SMB3 capability and fallback to unencrypted
3. Better error message on STATUS_PATH_NOT_COVERED loops
4. Live-DC validation of v0.53 DFS resolver (still needs a DFS
   namespace to test against)

## Operational takeaway

After v0.53.1: a Kali operator on HTB Active can do this:

```bash
# Decrypt GPP cpassword to creds, then:
sharesift hunt //10.129.13.21 -u SVC_TGS \
    -p 'GPPstillStandingStrong2k18' --no-encrypt \
    --output-dir ./engagement --skip-verify --skip-report
```

…and get a Red-tier hit on Groups.xml in 9 seconds, with the
extracted cpassword field surfaced in `hits.jsonl`. That's the
operational scenario v0.52 was built for, and it works
end-to-end.

The remaining v0.54 fixes are about expanding the range of
labs where ShareSift "just works" without operator workarounds.
