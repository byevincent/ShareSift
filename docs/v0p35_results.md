# v0.35 results — SMB-direct

Released 2026-06-08. First deliberate adoption-friction release
after the v0.22–v0.34 discipline arc. ShareSift no longer requires
mounting a CIFS share to scan it; operators point the tool at a
UNC + credentials and it talks SMB2/3 natively.

## Headline

| Dimension | v0.34 | v0.35 |
|---|---|---|
| Requires mounting CIFS share | ✗ Yes | ✅ No |
| Auth modes (NTLM password / PtH / Kerberos / anonymous) | n/a | ✅ All four |
| Operator-typed CLI to scan remote share | `mount.cifs` + `sharesift scan --share /mnt/...` | `sharesift //host/share -u user -p pass` |
| SMB3 message encryption default | n/a | ✅ On |
| Pre-flight auth check | n/a | ✅ `--check` |
| Tests passing (no flag) | 861 | **993** |
| Tests passing (live SMB) | n/a | **21** new |
| MIN top-10 (primary) | 0.20 | 0.20 (unchanged) |
| MIN recall (primary) | 0.90 | 0.90 (unchanged) |

The discipline metrics stay flat — v0.35 didn't touch the cascade
or the classifiers. The work was at the I/O boundary: where bytes
come from, how the operator describes the target, what credentials
get passed.

## What shipped

### Phase 1 — `Share` protocol + `LocalShare`

`src/sharesift/share/` module with the `Share` protocol
(`walk()` + `read_bytes(path, *, max_bytes)`) and `LocalShare`
implementation. `cmd_scan`'s share-walking switches from a direct
`Path.rglob` to `LocalShare(share).walk()`. Zero behavior change.

### Phase 1 — `SmbShare` + `Auth` + UNC parser

`SmbShare` uses `smbprotocol.connection.Connection` +
`smbprotocol.session.Session` + `TreeConnect`. Walk recurses via
`Open.query_directory` (`FileIdBothDirectoryInformation`). The
`Auth` dataclass validates mutually-exclusive auth modes
(password / hash / Kerberos / anonymous). `build_credential`
returns the `(username, password, auth_protocol)` triple the
`Session` constructor expects. For PtH, `username` is a pyspnego
`NTLMHash` credential object — no `NTLM_USER_FILE` env-var
ceremony required.

### Phase 1.5 — Share content-read methods + `extract.py` refactor

The plan as originally written stopped at `walk()`. During the
Sprint 2 → 3 transition we caught that `extract.py::load_content`
does `Path(p).read_text()` / `zipfile.ZipFile(str(p))` /
`pypdf.PdfReader(str(p))` — none of which work against a UNC.
Closed by:

- `read_bytes(path, *, max_bytes)` joins the `Share` protocol
- `extract.py` decomposed into pure `extract_text(data, ext, …)`
  + bytes-in PDF / OOXML extractors + share-aware
  `load_content_from_share(share, path, …)`. Existing
  `load_content(path)` preserved as a backward-compat wrapper —
  40+ existing tests pass unchanged.

### Phase 2 — CLI implicit-scan dispatch + nxc auth flags

`_rewrite_argv_for_implicit_scan` injects `scan` when the first
non-flag arg is UNC-shaped. Auth flags hoisted to the `scan`
subparser, matching netexec's `-u/-p/-H/-k/-d --use-kcache
--no-pass` conventions. `--check` mode pulled forward from the
v0.36 friendliness backlog.

### Phase 4 — Live SMB integration tests

21 tests against `dperson/samba` 4.x (SMB2/3-capable), env-gated
behind `SHARESIFT_SMB_TESTS=1`. The live suite caught two real
bugs that mocks couldn't see — those are the most important
v0.35 product decisions.

## Two bugs the live tests caught

**1. SMB credit-based flow control.** SMB2/3 uses credit-based
flow control: each read consumes ~1 credit per 64 KB, and a fresh
connection starts with 64 credits (= 4 MB max single read).
Initial implementation passed a 10 MB cap; smbprotocol returned
`Request requires 128 credits but only 64 credits are available`
and the silent except swallowed it as "unreadable file."

**Fix:** clamp single reads to
`min(max_bytes, server_max_read_size, 1 MB)`. 1 MB covers
realistic credential / config files (`.kdbx`, `.pem`, `.cfg`,
`web.config`, `unattend.xml`); larger files (10+ MB PDFs / OOXML)
need chunking — deferred to v0.36 alongside `--max-file-size`.

**2. Bind-mount file permission mismatches.** dperson/samba runs
`testuser` with a container-internal UID; pytest's
`tmp_path_factory` creates bind-mount sources with 700 perms
owned by the host user. Samba auth succeeded but file reads
returned `STATUS_ACCESS_DENIED`. Fixture-only fix: chmod 755 dirs
/ 644 files in the planted tree. Not a product bug but a real
"things mocks can't see" lesson.

## What pentester adoption looks like now

```bash
# Identify the share via netexec (existing workflow)
nxc smb 10.10.10.0/24 -u user -p pass --shares
# → Finance$ on 10.10.10.5 readable

# Pre-flight: confirm creds work before committing to a long walk
sharesift //10.10.10.5/Finance$ -u user -p pass --check
# → auth ok; tree-connected to \\10.10.10.5\Finance$

# Actual scan
sharesift //10.10.10.5/Finance$ -u user -p pass
# → ./sharesift-10.10.10.5-Finance$/ contains files.txt, paths.jsonl,
#   hits.jsonl, verified.jsonl, report.html

# PtH variant
sharesift //10.10.10.5/Finance$ -u CORP/user -H 'aad3:27c4'

# Kerberos
KRB5CCNAME=/tmp/krb5cc kinit alice@CORP.LOCAL
sharesift //dc01.corp.local/SYSVOL$ -u alice -k --use-kcache

# Anonymous / null session
sharesift //10.10.10.5/Public --no-pass
```

No `mount.cifs`. No root. No lingering CIFS mounts to forget about.
Standard pentester flags throughout.

## Lab validation reference

Documented in `docs/v0p35_smb_direct_plan.md` "Lab validation"
section. The pre-implementation lab against Samba 4.12 (lab script
at `/tmp/smb_lab/validate_v2.py`) confirmed:

- Password auth via `Session(conn, username=str, password=str)`
- PtH (LM:NT) via `Session(conn, username=NTLMHash(...), password=None)`
- PtH (bare NT, modern blank-LM form) — same API as above

All three work in pure Python with no `gss-ntlmssp` system
dependency. This is the load-bearing validation that justified
adopting `smbprotocol` instead of falling back to `impacket`.

## Sprint accounting

| Sprint | Scope | Status |
|---|---|---|
| 1 | `Share` abstraction + `LocalShare` refactor (no behavior change) | ✅ |
| 2 | `SmbShare` + `Auth` + UNC parser | ✅ |
| 3 | CLI implicit-dispatch + nxc auth flags + `--check` mode | ✅ |
| 3.5 | Share content-read methods + `extract.py` refactor | ✅ (added during 2→3 transition) |
| 4 | Test fixtures (Samba container) + live integration tests | ✅ |
| 5 | Auth refinements (encrypt=True production default validated) | ✅ |
| 6 | Docs, README, CHANGELOG, results doc | ✅ |
| 7 | Ship + tag + GitHub release | (next) |

Sprint 3.5 was a scope-gap discovery, not a plan failure — the
honest answer was to expand the plan rather than ship a
half-broken intermediate.

## What's queued

| Release | Theme |
|---|---|
| v0.36 | OpSec arc — noise-exclusion defaults, `--max-file-size` + chunked SMB reads, `--stealth` preset, Snaffler-TSV output, tier vocabulary, live-streaming hits, Markdown report bundle |
| v0.37 | Distribution — `pipx install sharesift`, PyInstaller single-file binary, Cobalt Strike Aggressor / Sliver SOCKS docs |
| v0.40 | Path classifier as a BOF via `treelite`-compiled LightGBM trees |

Full backlog: `docs/pentester_backlog.md`.

## Meta

v0.35 is the first release where the headline isn't about
methodology or capacity — it's about whether pentesters can
actually use this thing. The discipline arc (v0.22 → v0.34)
established that ShareSift could produce reproducible scoring on
multiple held-out sets. v0.35 starts the work of making that
reproducible scoring reach an operator without a Python
environment, without root, and without forgetting to `umount`.

The MIN top-10 = 0.20 / MIN recall = 0.90 chart stays flat. The
operator interface changed completely.
