# v0.53 — DFS referral resolution + GOAD benchmark harness

**Date:** 2026-06-11
**Headline:** ShareSift transparently resolves DFS namespace UNCs.
The v0.52 hunt command now works against domain DFS roots
(`\\corp.local\dept\hr`) without operator intervention — `SmbShare`
catches `STATUS_PATH_NOT_COVERED` on tree-connect, queries
`FSCTL_DFS_GET_REFERRALS` over IPC$, parses the response, and
retargets to the resolved fileserver.

## What shipped

### DFS referral resolution

| File | Change |
|---|---|
| `src/sharesift/share/dfs.py` | + `DfsResolution` dataclass with path-rewrite helper |
| | + `dfs_request_via_ipc(connection, session, ipc_tree, dfs_path)` — sends FSCTL_DFS_GET_REFERRALS IOCTL |
| | + `first_target_unc(response)` — extracts highest-priority target |
| | + `resolve_dfs_path(connection, session, dfs_path)` — orchestrates IPC$ tree-connect + IOCTL + teardown |
| | + `is_path_not_covered(exc)` — detects `PathNotCovered` exception or NTSTATUS in error string |
| `src/sharesift/share/smb.py` | `SmbShare` accepts `auto_resolve_dfs=True` (default), catches `PathNotCovered` on tree-connect, chases referrals via IPC$, retargets to fileserver, retries |
| | Original target preserved as `self._original_target`; resolution stored in `self._dfs_resolution` |
| `src/sharesift/cli.py` | `hunt --detect-dfs` now informational only — auto-resolution handles DFS regardless of the flag |

### GOAD benchmark harness

| File | Purpose |
|---|---|
| `tools/goad_benchmark.py` | Orchestrator: runs `sharesift hunt`, ingests operator-supplied Snaffler TSV, diffs find sets, emits per-category scorecard |
| `docs/goad_benchmark_methodology.md` | GOAD-Light setup recipe + Snaffler invocation + scoring methodology |

## Implementation notes

The DFS reference impl is `smbclient._pool.dfs_request` in
[jborean93/smbprotocol](https://github.com/jborean93/smbprotocol)
— private API, so we reimplement using public smbprotocol
primitives (`SMB2IOCTLRequest` + `DFSReferralRequest`
+ `DFSReferralResponse`).

The wire pattern:

1. Tree-connect to `\\corp.local\dept` returns `STATUS_PATH_NOT_COVERED`.
2. Open IPC$ tree on the same session.
3. Send `FSCTL_DFS_GET_REFERRALS` IOCTL with `request_file_name` =
   the original DFS UNC.
4. Server returns a `DFSReferralResponse` with referral entries
   sorted by cost (lowest first).
5. Extract `entries[0].network_address` (e.g. `\\fs01.corp.local\hr`).
6. Tear down the current connection.
7. Build a new `Connection` + `Session` + `TreeConnect` to the
   resolved fileserver.
8. Resume walking as if the operator had typed the resolved UNC.

`self._target` is rewritten to the fileserver so subsequent
`walk()` output emits resolved UNCs — operators get authoritative
file paths (where the file actually lives), not the namespace
pointer. The original is preserved as `self._original_target`
for any downstream code that needs to map back.

### What v0.53 doesn't handle

- **Interlink referrals** — when a referral chain crosses
  namespaces. The retry loop in `SmbShare` runs once with
  `auto_resolve_dfs=False` on the recursion to prevent infinite
  loops. Detection-only for v0.53; v0.54 if observed in the wild.
- **Referral caching** — every connection re-queries. Fine for
  small engagements; large hunts on big DFS forests will pay the
  RTT cost per share.
- **Sticky target hints** — we always pick `entries[0]`. If a
  target becomes unreachable mid-scan we don't fail over to
  `entries[1]`. Operator just sees the connect failure for that
  share.

## Test discipline

- 18 new DFS tests in `test_dfs_resolution_v0p53.py` (pure-function
  helpers + IOCTL construction + SmbShare integration via mocks).
- 18 new GOAD harness tests in `test_goad_benchmark_v0p53.py`
  (UNC normalization, category mapping, TSV parsing, scorecard
  computation).
- Full suite (after `uv sync --all-extras --all-groups`): **1391 passed, 29 skipped, 0 failed.**

## Operator workflows enabled

**Auto-resolved DFS hunt:**
```bash
# Just works — no flag needed
sharesift hunt //corp.local/dept/hr -u alice -p PW \
    --output-dir /tmp/dfs-hunt
```

Behind the scenes:
1. `SmbShare` opens connection to `corp.local`
2. Tree-connect to `dept` → `STATUS_PATH_NOT_COVERED`
3. IPC$ → DFS referral query → `\\fs01.corp.local\hr`
4. Reconnect to `fs01.corp.local`, walk normally

**GOAD head-to-head benchmark (when you stand up the lab):**
```bash
python tools/goad_benchmark.py \
    --ad-domain sevenkingdoms.local --dc 192.168.56.10 \
    -u khal.drogo -p horse \
    --snaffler-tsv ./snaffler_run.tsv \
    --output-dir ./goad_bench_2026-06-11
```

Produces `scorecard.md` with per-category recall comparison.

## Honest caveats

**1. DFS resolution mocked-only.** All tests against
`smbprotocol`'s response parsers + mocked connection/session
objects. No live DC validation — the first run against a real
domain DFS namespace will surface any wire-format edge cases
(V4-specific server_type bits, multi-target priority ordering when
proximity differs).

**2. GOAD benchmark untested against a live lab.** The harness's
pure-function pieces are tested. The actual `subprocess.run`
invocation and TSV-file roundtrip await the lab being up.

**3. v0.52 LDAP smoke test still pending.** Until the operator
points ShareSift at any real AD (HTB box, GOAD, work AD), the
v0.52 + v0.53 LDAP + DFS paths are mock-validated only.

## Files touched

| File | Change |
|---|---|
| `src/sharesift/share/dfs.py` | +180 lines (DfsResolution + resolve_dfs_path + helpers) |
| `src/sharesift/share/smb.py` | +95 lines (_chase_dfs_and_reconnect + retry loop) |
| `src/sharesift/cli.py` | --detect-dfs semantics flipped (informational, not skip) |
| `tools/goad_benchmark.py` | NEW (~500 lines) |
| `docs/goad_benchmark_methodology.md` | NEW |
| `tests/test_dfs_resolution_v0p53.py` | NEW (18 tests) |
| `tests/test_goad_benchmark_v0p53.py` | NEW (18 tests) |
| `tests/test_dfs_detection_v0p52.py` | Updated guidance test for v0.53 semantics |
| `tests/test_hunt_v0p52.py` | Updated DFS test for v0.53 semantics |
| `docs/v0p53_results.md` | This file |
| `CHANGELOG.md` | v0.53.0 entry |
| `pyproject.toml`, `src/sharesift/__init__.py` | 0.52.0 → 0.53.0 |
