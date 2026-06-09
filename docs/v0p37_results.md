# v0.37 results — drop-in workflows

Released 2026-06-09. v0.36 made the case that ShareSift's finder is
better than Snaffler's. v0.37 makes the case that ShareSift fits
the pentester loadout ergonomically — drop in your existing
Snaffler rule files, install in one command, scan multiple shares
at once.

## Headline

| Workflow | Before v0.37 | After v0.37 |
|---|---|---|
| Use existing Snaffler TOML rule files | rewrite to JSON manually | drop in unchanged |
| Install on Kali for a pentest | `git clone` + `uv sync --extra smb` | `pipx install 'sharesift[smb]'` |
| Scan multiple shares | shell loop | `sharesift batch --targets t.txt` |
| Missing smb extra error | `ModuleNotFoundError: No module named 'smbprotocol'` | three-line install guide |
| Tests passing (no flag) | 1069 | **1089** |

## What shipped

### Step 1 — Snaffler TOML rule format support

The content rule engine accepts both formats:

- **ShareSift native** (`.json`):

  ```json
  {"rules": [{"rule_name": "KeepFoo", "triage": "Black",
              "match_action": "Snaffle",
              "match_location": "FileExtension",
              "wordlist_type": "Exact",
              "wordlist": ["\\.foo"]}]}
  ```

- **Snaffler upstream** (`.toml`) — drops in unchanged:

  ```toml
  [[ClassifierRules]]
  RuleName = "KeepFoo"
  Triage = "Black"
  MatchAction = "Snaffle"
  MatchLocation = "FileExtension"
  WordListType = "Exact"
  WordList = ["\\.foo"]
  ```

Dispatch in `_load_rule_records` keys off file extension. PascalCase
keys map to snake_case internal records. `MatchLength` (Snaffler's
context-sizing field) is intentionally ignored — ShareSift doesn't
model it. No new dependency: `tomllib` is stdlib in Python 3.11+.

Operator workflow: a pentester's existing Snaffler rule TOML files
(from their team's internal ruleset, from someone else's blog post,
or from upstream Snaffler) all drop straight into ShareSift's
rules directory without conversion.

12 tests, including loading a real upstream Snaffler TOML
(`KeepPassMgrsByExtension.toml`) unchanged + mixed JSON+TOML in
the same engine construction.

### Step 2 — pipx-install distribution

Pentesters reach for `pipx install <tool>` first. ShareSift's entry
point (`sharesift.cli:main`) and project metadata were already
pipx-ready; v0.37 documents the workflow as the recommended
operator install and polishes the UX around the optional `[smb]`
extra.

Recommended install on Kali:

```bash
# SMB-direct workflow (recommended for pentesters)
pipx install 'sharesift[smb]'

# Stage 1 only — no torch, no transformers
pipx install sharesift
```

Verified end-to-end in a clean seeded venv: wheel installs, entry
point resolves, `sharesift --version` works, `to-snaffler-tsv`
subcommand functions without SMB extras, and SMB targets work
after installing `sharesift[smb]`.

When the operator forgets the extra, SMB targets used to fail with
a raw `ModuleNotFoundError: No module named 'smbprotocol'`. Now
they see:

```
SMB-direct support requires the smb extra. Install:
    pipx install 'sharesift[smb]'   # if using pipx
    pip install 'sharesift[smb]'    # if using pip
    uv sync --extra smb             # if using uv
(missing: smbprotocol)
```

README install section restructured: pipx workflow leads ("Quick
install — drop a binary on Kali"), full-source install demoted to
"if you want to develop, train, or run the content classifier."

### Step 3 — `sharesift batch` subcommand

Today's multi-share scan workflow is a shell loop:

```bash
for t in $(cat targets.txt); do
    sharesift "$t" -u user -p pass --output-dir "./out/${t//\//-}"
done
```

v0.37 absorbs that loop:

```bash
sharesift batch --targets targets.txt -u user -p pass \
    --output-dir ./engagement
```

Behavior:
- Each line in `--targets` is a UNC or local path; comments (`#`)
  and empty lines ignored.
- Each target gets its own subdirectory under `--output-dir`,
  named `sharesift-<host>-<share>` for SMB or `sharesift-<basename>`
  for local.
- Per-target `cmd_scan` failure doesn't abort the batch — the next
  target still runs.
- Top-level `batch_summary.jsonl` records `{target, output_dir, ok}`
  per target.
- Exit code: 0 if all succeeded, 1 if any failed.
- Auth flags and `--skip-verify` / `--skip-report` propagate to
  every per-target scan.

Pairs naturally with netexec's share discovery:

```bash
nxc smb 10.10.10.0/24 -u u -p p --shares | awk '/READ/{print "//"...}' > targets.txt
sharesift batch --targets targets.txt -u u -p p --output-dir ./engagement
```

6 tests including iteration, summary writing, continue-after-failure
semantics, SMB-target subdir naming, empty-targets-file error,
auth-flag propagation.

## What's queued

| Release | Theme |
|---|---|
| v0.38 | Speed + network: concurrent SMB reads (multi-threaded walk + reads), network-wide share discovery via NetrShareEnum (`sharesift //10.10.10.0/24 -u u -p p`), PyInstaller single-file binary |
| v0.39 | Engagement-shape: SQLite engagement datastore (smbcrawler-style), resume after crash, content-hash dedup, GhostWriter / SysReptor exporters |
| v0.40+ | OpSec polish: noise exclusions, `--max-file-size` + chunked reads, `--stealth` preset, status heartbeat, Markdown report bundle |

Full backlog: `docs/pentester_backlog.md`.

## Sprint accounting

| Step | Status | Tests added |
|---|---|---|
| 1 — Snaffler TOML rule format | ✅ | +12 |
| 2 — pipx-install distribution + friendlier missing-extra error | ✅ | +2 |
| 3 — `batch` subcommand for multi-target scans | ✅ | +6 |

**1089 passing total**, 29 skipped (21 SMB-gated + 8 pre-existing),
0 regressions across the whole arc.

## Meta

v0.35 = remote-share addressable. v0.36 = better finder than
Snaffler. v0.37 = drops into the pentester workflow without
friction. The displacement narrative now reads:

> "Drop in your Snaffler TOML rules unchanged. Install with
> `pipx install 'sharesift[smb]'`. Scan one share with
> `sharesift //host/share -u u -p p`, or many with
> `sharesift batch --targets t.txt -u u -p p`. Get more rule
> coverage than Snaffler (144 vs 89), correct R/W on shares
> (where Snaffler still gets it wrong, #184), encryption-aware
> PPK triage (Snaffler #191), 20 live credential verifiers
> Snaffler doesn't have, and output that drops into the same
> Snaffler-output ecosystem (SnafflerParser, Efflanrs)."

That's an unambiguous, demonstrable case at every claim.

The MIN top-10 = 0.20 / MIN recall = 0.90 chart still stays flat.
The operator-facing capability matrix moved another step.
