# v0.52 — Snaffler-replacement enumeration sprint

**Goal:** ShareSift becomes a fully self-contained Snaffler replacement
on a Linux/Kali attacker workflow. One command takes a domain + creds
and returns ranked credential findings across every joined host — no
Snaffler, no NetExec `--shares`, no `nxc` glue.

## Scope after foundation audit

The original v0.52-v0.55 plan (sketched in the planning conversation)
called for: AD discovery, ACL-aware share enumeration, Snaffler skip-
list, DFS adapter, Kerberos ccache, and a one-shot `hunt` command.

After auditing the v0.39 / v0.40 / v0.46 codebase, most of that
shipped already under different names:

| Capability | Already shipped in |
|---|---|
| Single-host `NetrShareEnum` share enumeration | v0.39 (`share/discovery.py`) |
| CIDR network expansion + concurrent SMB liveness probe | v0.39 |
| Pass-the-Hash via `NTLMHash` | v0.35 (`share/auth.py`) |
| Kerberos via `KRB5CCNAME` ccache (impacket `useCache=True` + smbprotocol `auth_protocol="kerberos"`) | v0.35 / v0.39 |
| R/W ACL probe via SMB2 CREATE on share root (fixes Snaffler #184) | v0.39 (`share/smb.py::probe_share_access`) |
| Snaffler-style noise exclusions (`WinSxS`, `Program Files`, etc.) | v0.40 (`share/exclusions.py`) |
| Multi-target batch scanning | v0.37 (`cmd_batch`) |
| End-to-end one-shot pipeline per target | v0.18 (`cmd_scan`) |

The real gaps are smaller than the planning chat assumed:

1. **LDAP / AD computer object enumeration** — current `discover`
   requires an IP, hostname, or CIDR. There is no "give me a
   domain, query AD for the computer list" path.
2. **DFS namespace handling** — `SmbShare` uses `smbprotocol` but
   doesn't catch `STATUS_PATH_NOT_COVERED` or chase referrals.
3. **End-to-end `hunt` command** — `discover` + `batch` chain via
   shell pipe works, but isn't one command.

## v0.52 deliverables

### 1. `share/ad.py` — LDAP computer enumeration

New module that queries Active Directory via `ldap3` (already in
the `verify` extra) for every joined computer:

- Auth modes: password / hash (NTLM with `lm:nt` password
  encoding) / Kerberos (SASL GSSAPI reads `KRB5CCNAME`) / anonymous.
- Filter: `(objectCategory=computer)`.
- Returned attributes: `dnsHostName`, `sAMAccountName`,
  `operatingSystem`, `userAccountControl`.
- Honors `userAccountControl & ACCOUNTDISABLE` to skip disabled
  computer accounts.
- Paged search (default 500) so large forests don't hit `SizeLimit`.

CLI wiring: `cmd_discover` gains a `--domain corp.local` flag. When
set, the positional `target` becomes optional — LDAP replaces the
CIDR/host source of the host list, but `enumerate_shares` and the
liveness probe still run. Operators with a separate DC pass
`--dc dc01.corp.local`.

### 2. `share/dfs.py` — DFS detection utilities (opt-in)

DFS referral resolution is genuinely hard: `smbprotocol.dfs` exists
but the high-level walker that uses it (`smbclient`) is a different
API shape than `SmbShare`. Full DFS referral chasing needs a real
DC to test against.

v0.52 ships utilities (`looks_like_dfs`, `dfs_guidance`) plus a
`hunt --detect-dfs` opt-in flag. **Default is off** because the
heuristic ("server segment contains a dot") false-positives on
every FQDN host: `\\ws01.corp.local\X` and `\\corp.local\X` are
indistinguishable from string shape alone. The AD-discovery path
returns FQDN hosts by design, so auto-detection would skip every
legitimate share.

When `--detect-dfs` is set and a UNC looks DFS-shaped, the operator
gets a warning explaining how to resolve manually:

```
DFS target detected: \\corp.local\departments\hr
   This release detects but does not resolve DFS referrals.
   Find the fileserver via:
     nxc smb dc01.corp.local -u U -p P --query \
       "SELECT * FROM dfs_targets"
   Then re-run:
     sharesift hunt \\fileserver01\hr -u U -p P
```

Full DFS referral chasing queues for v0.53 with a GOAD-validated
test.

### 3. `cmd_hunt` — end-to-end command

Bundles LDAP discover + share enum + ACL filter + batch scan:

```bash
sharesift hunt --domain corp.local -u alice -p PW --output-dir ./out
```

Pipeline:

1. `share.ad.discover_computers(domain, auth, dc=args.dc)` → list of
   computer objects.
2. Filter to enabled + has `dnsHostName`.
3. Concurrent TCP probe `:445` → drop dead hosts (same
   `probe_smb_alive` v0.39 already uses).
4. For each live host: `enumerate_shares(host, auth)` → `ShareSummary`
   list, filter to file shares (`is_file_share()`).
5. For each share: open `SmbShare` → `probe_share_access()` →
   include only `R` shares (operator can opt-in to `W`-only with
   `--writable-only`).
6. Build `targets.txt` from `\\host\share` UNCs of the kept shares.
7. Call `cmd_batch` internals with the targets file.

Output is one Snaffler-compatible `batch_summary.jsonl` plus the
per-target subdirs (`sharesift-<host>-<share>/hits.jsonl`,
`report.html`).

### 4. Confirm Kerberos ccache flow through LDAP

`Auth.kerberos=True` already drives impacket `useCache=True` and
smbprotocol `auth_protocol="kerberos"`. The new ldap3 path needs
to do the same: `Connection(authentication=SASL,
sasl_mechanism=GSSAPI)`. Verify the `--use-kcache` flag wires
through `_build_auth_from_args` to the new domain mode. (It
already does — `Auth` is the single bundle every path reads.)

## What v0.52 does NOT ship

- **Full DFS referral resolution** — needs a GOAD or comparable
  lab. v0.53.
- **AD enumeration via Kerberoasting / AS-REP roasting** —
  separate tool; we focus on share content, not auth surface.
- **DCE/RPC NetSessionEnum / NetWkstaEnum host discovery** — LDAP
  is the canonical AD discovery path; SMB-host enumeration is a
  fallback for orgs without LDAP access (rare).
- **Live KDC validation of the ccache before LDAP bind** — if the
  ccache is expired, the GSSAPI bind fails with a clear error
  message; we surface it.

## Critical files (read-before-edit)

- `src/sharesift/share/discovery.py` — existing share enum, where
  LDAP discovery threads in.
- `src/sharesift/share/auth.py` — `Auth` dataclass, `_parse_hash`.
- `src/sharesift/share/smb.py` — `SmbShare` walker, where DFS
  detection hooks.
- `src/sharesift/verify/ldap.py` — reference for ldap3 patterns.
- `src/sharesift/cli.py:855` — `cmd_discover`; gains `--domain`.
- `src/sharesift/cli.py:968` — `cmd_batch`; `cmd_hunt` reuses
  most of its internals.

## Verification

1. **Module imports cleanly:**
   ```bash
   uv run python -c "from sharesift.share import ad, dfs; print('ok')"
   ```
2. **Mocked LDAP test:** `tests/test_ad_discovery_v0p52.py` — search
   filter, paged results, NTLM bind with hash, GSSAPI dispatch.
3. **CLI parser registers cleanly:**
   ```bash
   uv run sharesift discover --help | grep -- --domain
   uv run sharesift hunt --help
   ```
4. **DFS detection emits guidance:**
   ```bash
   uv run sharesift hunt //corp.local/departments -u u -p p
   # expect: "DFS target detected" warning, exit 1
   ```
5. **Full test suite green:** `uv run pytest -q`.

## Out of scope (deferred)

- Full DFS resolution → v0.53
- AD lab head-to-head benchmark (GOAD) → v0.55
- `--ccache` flag for explicit ccache path (vs `KRB5CCNAME` env) →
  v0.53 if asked
- LDAP timeout tuning + DC failover (multiple `--dc` args) → v0.53
