# v0.35 — SMB-direct (no mount required)

Drafted 2026-06-08. The v0.22-v0.34 arc was a discipline / capacity
sprint; v0.35 is the first deliberate adoption-friction release.
The current workflow requires the operator to mount the target
share locally (CIFS, root-required) before pointing ShareSift at
it. Most pentester workflows in 2026 don't mount — they hand the
tool a UNC + credentials and it talks SMB directly. v0.35 closes
that gap.

The lab validation pass on 2026-06-08 (see "Lab validation"
section below) settled the implementation choice. v0.35 ships
`smbprotocol` as the single SMB engine with pyspnego's pure-Python
NTLM/PtH — no system packages, no impacket fallback, no
`NTLM_USER_FILE` env-var ceremony.

## Why now

The blocker every adoption-readiness discussion has hit is
deployment friction. Earlier framings ("3GB torch on a beachhead")
turned out to be wrong — pentesters run heavy tools on their own
Kali box, not on the beachhead. The real friction is the mount
step: `mount.cifs` needs root, leaves lingering mounts if you
forget `umount`, doesn't work cleanly on macOS, and Kerberos via
`cifs.upcall` is fragile. None of the tools pentesters reach for
(`smbclient`, `smbmap`, `nxc`, `impacket-smbclient`) require a
mount. ShareSift should match.

The pitch after v0.35:

```bash
sharesift //10.10.10.5/Finance$ -u user -p pass
sharesift //10.10.10.5/Finance$ -u CORP/user -H '00000000000000000000000000000000:27c4...'
sharesift //10.10.10.5/Finance$ -k --use-kcache
sharesift //10.10.10.5/Finance$ --no-pass
sharesift /mnt/local/finance              # still works for mounted/local
```

Six tokens. No `scan` subcommand on the canonical path. UNC
positional, nxc-shaped auth flags after.

## Scope

| In | Out (deferred) |
|---|---|
| `smbprotocol` backend reading UNC paths | Snaffler-TSV output (v0.36) |
| `Share` backend abstraction (local + smb) | Tier vocabulary realignment (v0.36) |
| Pure-Python NTLM password + PtH via `NTLMHash` | `--stealth` preset (v0.36) |
| Kerberos via existing `KRB5CCNAME` ccache | Markdown report bundle (v0.36) |
| First-arg dispatch (UNC → implicit scan) | `pipx` packaging + single-file binary (v0.37) |
| nxc-compatible auth flags hoisted to top-level | Path-classifier-as-BOF (v0.40) |
| Default output dir `./sharesift-<host>-<share>/` | `--share-concurrency`, jitter, rate limits (v0.36) |
| Integration tests against `dperson/samba` (SMB2/3) | SMB1 support (will not add — modern only) |

The cascade, content classifier, verifiers, reranker — all
untouched. v0.35 changes the file-walk and file-read boundary plus
CLI dispatch. Everything downstream of the path/content I/O is
unchanged.

## Lab validation (completed 2026-06-08)

Spent ~30min validating the load-bearing risk: whether PtH works
in pure Python without `gss-ntlmssp` as a system dep. Result: yes,
cleanly, via pyspnego's `NTLMHash` credential class.

| Test | Result | Notes |
|---|---|---|
| Password auth (NTLM) | ✅ PASS | `Session(conn, username="user", password="pass")` |
| PtH with `LM:NT` form | ✅ PASS | `Session(conn, username=NTLMHash(user, lm, nt), password=None)` |
| PtH with blank LM (modern) | ✅ PASS | Same as above, `lm_hash=""` |

All against `dperson/samba` 4.12.2 with SMB2/3 dialect, full
read of a planted file in the share. The scripts live at
`/tmp/smb_lab/validate_v2.py` (will be moved to
`tests/smb_lab/validate_pth.py` during Phase 4).

Two ancillary findings:

1. **MSF2 is not viable as the SMB-direct integration target.** It
   runs Samba 3.0.x which is SMB1-only; smbprotocol explicitly
   drops SMB1. MSF2 stays the Linux benchmark target for the
   content cascade (`_eval_msf2` in the harness); SMB-direct tests
   use `dperson/samba`.
2. **Docker MSF2 needs `-t` to keep bash alive.** Without TTY
   allocation the container exits ~5s after services start. Doesn't
   affect production but worth a comment in the test harness.

## Phases

### Phase 1 — `Share` backend abstraction

New module `src/sharesift/share/` with three files:

- `__init__.py` — exports `Share` protocol (walk, open, stat),
  `LocalShare`, `SmbShare`, `Auth`
- `local.py` — `LocalShare(path)` wraps `os.walk` + `open()`.
  Refactor of today's behavior behind the protocol.
- `smb.py` — `SmbShare(target, auth)`. Uses
  `smbprotocol.connection.Connection` + `smbprotocol.session.Session`
  + `smbprotocol.tree.TreeConnect` + `smbprotocol.open.Open`. Walks
  via `query_directory`. Reads via `Open.read`. Connection pooled per
  `(host, port)` for a single scan run.
- `auth.py` — `Auth` dataclass:
  ```python
  @dataclass(frozen=True)
  class Auth:
      user: str | None = None
      password: str | None = None
      hash: str | None = None         # "LM:NT" or bare "NT"
      kerberos: bool = False
      domain: str | None = None
      aes_key: str | None = None
      anonymous: bool = False
  ```
  Plus `build_credential(auth) -> str | NTLMHash | None` that
  dispatches to the right pyspnego credential form. Hash parsing
  splits on `:` — single field is treated as NT-only with blank
  LM (`aad3b435b51404eeaad3b435b51404ee`).
- `target.py` — UNC parser. Accepts
  `\\host\share`, `//host/share`, `host/share`, optional `:port`,
  optional `path/under/share`. Returns
  `SmbTarget(host, port, share, root_path)`.

Cascade entry points (`Scanner.scan_batch`,
`cmd_score_paths`, `cmd_scan_files`) take a `Share` instead of a
filesystem path. Internal calls to `os.walk` and `open()` go through
the share interface.

### Phase 1.5 — Share content-read methods (added 2026-06-08)

Discovered during Sprint 2 → 3 transition: the original plan
extended ``Share`` only with ``walk()``, but ``extract.py::load_content``
does ``Path(p).read_text()`` / ``zipfile.ZipFile(str(p))`` /
``pypdf.PdfReader(str(p))`` on the walked paths. For SMB targets
those paths are UNC strings — none of those calls work.

Closing this gap requires extending the ``Share`` protocol with
content-read methods and refactoring ``load_content`` to take a
``Share`` plus a relative path instead of a ``Path``.

| Change | Detail |
|---|---|
| ``Share`` protocol gets ``read_bytes(path: str, *, max_bytes: int \| None = None) -> bytes \| None`` | One method, returns full bytes (caller wraps in BytesIO for pypdf / zipfile) |
| ``LocalShare.read_bytes`` | ``Path(path).read_bytes()`` with ``max_bytes`` cap and OSError → None |
| ``SmbShare.read_bytes`` | smbprotocol ``Open(tree, rel).read(0, max_bytes)`` against an already-established session |
| ``extract.py::load_content(share, path, *, max_bytes, decode_base64)`` | Refactor to take a ``Share`` + path string. PDF and OOXML use ``BytesIO(share.read_bytes(path))``. |
| ``cmd_scan_files`` | Pass the active ``Share`` through to ``load_content`` instead of constructing ``Path`` per file |
| Cascade entry point in ``pipeline.py`` | Accepts a ``Share`` instead of bare paths |

Why this matters: without it, ``sharesift //host/share -u user -p
pass`` walks correctly but ``scan-files`` fails on UNC paths. The
v0.35 ship gate requires end-to-end SMB → walk → content scan →
verify, so this phase is non-negotiable.

### Phase 2 — CLI dispatch (UNC positional + auth flags)

`src/sharesift/cli.py` changes:

- New top-level positional `target` (UNC or local path).
- New top-level auth flags, all on the main parser so subcommands
  inherit:
  - `-u/--user USER`
  - `-p/--password PASS`
  - `-H/--hash 'LM:NT'` (or bare NT)
  - `-k/--kerberos`
  - `--use-kcache` (alias for kerberos with existing KRB5CCNAME)
  - `-d/--domain DOMAIN`
  - `--aes-key HEX` (reserved; documented but not wired in v0.35)
  - `--no-pass / --anonymous`
- First-arg dispatch in `main()`:
  - If `sys.argv[1]` matches a known subcommand → existing path
  - If it matches UNC shape (`^(\\\\|//)`) or starts with `/` or
    is a directory → implicit `cmd_scan(target=..., auth=...)`
  - Else → argparse error with usage

- `cmd_scan` (the v0.18 one-shot) gets the new shape. Default
  output dir when omitted: `./sharesift-<host>-<share>/` for SMB
  targets, `./sharesift-<basename>/` for local paths. `--output-dir
  DIR` overrides. `--stdout-only` suppresses disk write.

- All existing subcommands (`score-paths`, `scan-files`, `verify`,
  `render-report`, `scan`) keep working unchanged. Power users can
  still chain manually.

### Phase 3 — Auth dispatch through pyspnego

`src/sharesift/share/auth.py::build_credential`:

```python
def build_credential(auth: Auth):
    if auth.anonymous:
        return None, None   # smbprotocol handles null session
    if auth.hash:
        lm, sep, nt = auth.hash.partition(":")
        if not sep:
            nt = lm
            lm = "aad3b435b51404eeaad3b435b51404ee"
        return NTLMHash(username=_qualify(auth.user, auth.domain),
                        lm_hash=lm, nt_hash=nt), None
    if auth.kerberos:
        return _qualify(auth.user, auth.domain), None
    return _qualify(auth.user, auth.domain), auth.password
```

The returned `(username, password)` tuple is passed verbatim to
`smbprotocol.session.Session(conn, username=..., password=..., auth_protocol=...)`.

`auth_protocol` is:
- `"kerberos"` if `auth.kerberos` is set
- `"ntlm"` otherwise (covers password, PtH, anonymous)

We never use `"negotiate"` — too much surprise potential when the
operator expects NTLM (e.g. PtH) and Kerberos accidentally gets
picked up from a stale ccache.

### Phase 4 — Tests

Three test files:

- `tests/test_share_local_v0p35.py` — unit tests for `LocalShare`:
  walk produces same output as `os.walk`, `open` returns bytes
  matching `pathlib.Path.read_bytes`, large file read in chunks.
- `tests/test_share_smb_v0p35.py` — integration tests for
  `SmbShare` against a `dperson/samba` container fixture:
  - Password auth, list + read
  - PtH (LM:NT), list + read
  - PtH (bare NT), list + read
  - Anonymous to a public share, list + read
  - Wrong password → `SMBAuthenticationError`
  - Wrong host → `SMBConnectionClosed` / `ConnectionRefusedError`
  - Connection reuse across multiple file reads
- `tests/test_cli_smb_dispatch_v0p35.py` — CLI parsing:
  - `sharesift //host/share -u u -p p` → routes to `cmd_scan` with
    `SmbTarget(host="host", share="share")` and
    `Auth(user="u", password="p")`
  - `sharesift //host/share -u u -H 'AAAA...:BBBB...'` → Auth with
    parsed hash
  - `sharesift //host/share -u u -H 'BBBB...'` → bare-NT form,
    blank LM
  - `sharesift /mnt/local` → routes to `LocalShare(/mnt/local)`
  - `sharesift score-paths --stdin < paths.txt` → existing path
    still works
  - `sharesift //host/share` (no auth) → error message naming
    expected flags

Test container fixture (`tests/conftest.py` or new
`tests/fixtures/samba_container.py`):

```python
@pytest.fixture(scope="session")
def samba_container():
    if not _docker_available():
        pytest.skip("docker not available")
    cid = subprocess.check_output([
        "docker", "run", "-d", "-t",
        "--name", "sharesift_test_samba",
        "-p", "11445:445",
        "dperson/samba",
        "-u", "testuser;testpass",
        "-s", "tmp;/share;yes;no;no;testuser",
    ]).decode().strip()
    try:
        _wait_for_smb(("127.0.0.1", 11445), timeout=20)
        yield SambaTarget(host="127.0.0.1", port=11445,
                          user="testuser", password="testpass")
    finally:
        subprocess.run(["docker", "rm", "-f", cid], check=False)
```

CI gates the SMB tests behind a `SHARESIFT_SMB_TESTS=1` env var so
they only run when docker is available (matches the existing
pattern for MSF2 tests).

### Phase 5 — Bundle, docs, changelog

- `pyproject.toml`:
  - Bump to `0.35.0`
  - New optional group: `smb = ["smbprotocol>=1.16"]`
  - `pyspnego` and `cryptography` come in transitively
- `README.md`:
  - Update Quick Start to lead with
    `sharesift //host/share -u user -p pass`
  - Move the mounted/local example to "alternative" position
  - Document the auth flag matrix (password / hash / kerberos /
    anonymous)
- `docs/v0p35_results.md` — wrap-up matching the v0.34 pattern:
  what shipped, what's deferred, lab validation summary, before/after
  CLI examples
- `CHANGELOG.md` — entry naming smbprotocol as the SMB backend and
  the auth flag matrix
- Drop the `--share` flag mention from `sharesift scan` docs;
  positional target is the canonical interface

## Risks

| Risk | Mitigation |
|---|---|
| **SMB1 unsupported.** Modern Windows AD (Server 2008+) defaults to SMB2; legacy NAS / old Samba won't connect. | Document explicitly. Operators hitting legacy boxes use `smbclient -m SMB1` for enum and feed the file list to `sharesift score-paths --stdin`. |
| **`require_encryption=True` (smbprotocol default) breaks on some Samba/older Windows.** | Default to `True` (matches modern Windows). Add `--no-encrypt` flag that flips it. Document the v0.36 `--stealth` preset will leave it on. |
| **First-arg dispatch is magical.** Some CLI users prefer explicit subcommands. | Existing subcommands stay. The implicit-dispatch only kicks in when the first arg looks like a target. `sharesift scan //host/share` works identically. |
| **Hash flag parsing surface.** Operators paste hashes in various forms — `LM:NT`, bare `NT`, `:NT` (leading colon), `NT:` (trailing). | Parse with `partition(":")`. Single field → NT-only (blank LM). Two fields → LM:NT. Always lowercase. Document the accepted forms in `--help`. |
| **Connection pooling correctness.** A long scan reusing a session is faster but pyspnego/smbprotocol session lifetime semantics need care. | Single connection per `(host, port)` for one `scan` invocation. Reset on auth failure. Tests cover multi-file read on one session. |
| **Default `require_signing` behavior.** Connecting unsigned to a SMB relay setup is the classic trap. | smbprotocol's default `require_signing=True` stays on. No flag to disable in v0.35. |

## Sprint plan

| Sprint | Scope | Estimated |
|---|---|---|
| 1 | Phase 1 — `Share` abstraction + `LocalShare` refactor (no behavior change) | 0.5 day |
| 2 | Phase 1 — `SmbShare` + `Auth` + UNC parser | 0.75 day |
| 3 | Phase 2 — CLI first-arg dispatch + auth flag wiring + ``--check`` mode | 0.5 day |
| 3.5 | Phase 1.5 — Share content-read methods + extract.py refactor | 0.5 day |
| 4 | Phase 4 — Test fixtures (Samba container) + unit + integration tests | 1 day |
| 5 | Phase 3 — Auth dispatch refinements based on test findings | 0.25 day |
| 6 | Phase 5 — Docs, README, CHANGELOG, results doc | 0.5 day |
| 7 | Ship + tag + GitHub release | 0.25 day |

Total: ~4.25 days. Plan-gated, one-file-at-a-time per the
established workflow.

``--check`` mode (Sprint 3): ``sharesift //host/share -u user -p
pass --check`` auths + tree-connects + exits with success/failure.
No walk, no content scan. Pentester-friendly pre-flight before
committing to a long scan. Added to v0.35 from the friendliness
backlog because it's cheap.

## Follow-on arc (recap)

| Release | Theme | Headline ship |
|---|---|---|
| v0.35 (this) | SMB-direct | `sharesift //host/share -u u -p p` |
| v0.36 | OpSec polish + output format | Snaffler-TSV, `--stealth`, jitter, rate limits, Markdown report bundle |
| v0.37 | Distribution | `pipx install sharesift`, PyInstaller single-file binary, Cobalt Strike/Sliver SOCKS examples |
| v0.40 | On-target inference | Path classifier as BOF via `treelite`-compiled trees |

Each release stays in the 1-2 day window the discipline pattern
has held to, and each addresses a distinct adoption-friction axis.

## Out of scope for v0.35 (explicit)

- SMB1 support — modern only
- AES-key Kerberos auth (flag accepted, not wired)
- Snaffler-compatible TSV output — v0.36
- Tier vocabulary realignment (Black/Red/Yellow/Green) — v0.36
- `--stealth` preset, jitter, rate limits — v0.36
- Markdown report bundle — v0.36
- pipx packaging + single-file binary — v0.37
- Cobalt Strike Aggressor / Sliver extension docs — v0.37
- BOF path — v0.40+
- Output format change for `sharesift scan` — stays JSONL +
  HTML report for v0.35; format work is v0.36's job

## Critical files (read-before-edit)

- `src/sharesift/cli.py` — main parser, all subcommand handlers,
  argparse wiring
- `src/sharesift/pipeline.py` — `Scanner.scan_batch` (path/content
  I/O boundary)
- `src/sharesift/verify/runner.py` — file content reads during
  verification
- `pyproject.toml` — dependency groups
- `tests/conftest.py` — fixture conventions
- `/tmp/smb_lab/validate_v2.py` — lab-validated NTLMHash dispatch
  reference for the implementation
