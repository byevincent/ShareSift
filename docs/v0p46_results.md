# v0.46 results — drop-on-Kali binary + DB exporters

Released 2026-06-09 as a combined ship. v0.46 closes the three
remaining top items from the v0.45 honest-assessment writeup:
engagement-DB exporters (GhostWriter / SysReptor / Markdown),
PyInstaller single-file binary (the v0.38 1.5GB problem), and a
path-prefix dedup investigation (deferred — the risk/reward isn't
there).

## Headline

| Workflow | Before | After |
|---|---|---|
| Get findings into the report tool | grep + hand-format | `sharesift export --format ghostwriter` |
| Get findings into SysReptor | not supported | `sharesift export --format sysreptor` |
| Drop ShareSift on a fresh Kali box | `pipx install` + 100MB deps | `wget .../sharesift && chmod +x` |
| Binary size | 1.5 GB (v0.38 attempt) | **77 MB** (20× smaller) |
| Tests passing | 1309 | 1309 |

## What shipped

### v0.46 step 1 — Engagement DB exporters

Three new formats off the v0.41 SQLite datastore:

    sharesift export --db engagement.db --format markdown \
        --output findings.md --title "Acme Q3 2026"

    sharesift export --db engagement.db --format ghostwriter \
        --output findings.csv

    sharesift export --db engagement.db --format sysreptor \
        --output sysreptor.json

**Markdown** — universal. Pastes into Dradis, GhostWriter,
SysReptor, Notion, Slack, plain delivery docs. Summary stats up
top, findings grouped by tier, per-finding shows path/host/share,
RW marker on the share, snippet truncated at 500 chars to keep
the doc scannable.

**GhostWriter CSV** — direct CSV import. Columns match the
GhostWriter findings page schema (title, severity, description,
recommendation, references, finding_type, cvss_score, cvss_vector).
Tier maps to severity: Black→Critical, Red→High, Yellow→Medium,
Green→Low, untiered→Info.

**SysReptor JSON** — `projects/v1` envelope. Lowercased severities
(`critical`, `high`, `medium`, `low`, `info`) per SysReptor's
expected schema. Per-finding metadata preserves `sharesift_rule`,
`first_seen`, and `share_writable` so downstream queries can
filter on them.

All three use the same ordering: tier (Black > Red > Yellow >
Green) > host > share > rel_path. The SQL query pre-joins hits +
share access + file size in one round-trip — cheap even on a
1000-finding engagement DB.

### v0.46 step 2 — PyInstaller single-file binary (77 MB)

v0.38 deferred this with the comment "PyInstaller bundled 1.5GB
of dependencies — needs aggressive trim." v0.46 solved it:

    wget https://github.com/byevincent/ShareSift/releases/latest/download/sharesift
    chmod +x sharesift
    ./sharesift --version
    # sharesift 0.46.0

The binary covers what an operator typically wants on a fresh
engagement box where they can't or don't want to install Python:

- `score-paths` — Stage 1 LightGBM + rule engine + tier engine
- `scan-files` — rule + extractor cascade (no content classifier)
- `to-snaffler-tsv` — output format conversion
- `sort` — verifier-first ranking
- `query` — engagement DB summary
- `export` — Markdown / GhostWriter CSV / SysReptor JSON

What it does NOT cover (pipx install for these):

- SMB-direct (smbprotocol excluded, saves ~30 MB)
- `discover` (impacket excluded, saves ~100 MB)
- `verify` (requests/paramiko/ldap3/jwt/boto3 excluded, ~50 MB)
- `render-report` (jinja2 excluded)
- Content classifier (torch excluded, saves ~1.5 GB)

#### How the 20× shrink happened

Two changes mattered:

**1. Minimal build venv.** The default dev venv has
torch+nvidia+triton+bitsandbytes (5.4 GB). PyInstaller's static
analysis catches these as reachable through the optional
`content-inference` group even when `--exclude-module` says
otherwise. Building from a dedicated 325 MB venv with only Stage-1
deps prevents the transitive pulls:

```bash
python3.12 -m venv /tmp/sharesift-build
/tmp/sharesift-build/bin/pip install --upgrade pip pyinstaller
/tmp/sharesift-build/bin/pip install -e . --no-deps
/tmp/sharesift-build/bin/pip install \
    tqdm pydantic scikit-learn lightgbm numpy joblib betacal
/tmp/sharesift-build/bin/python tools/build_pyinstaller.py
```

**2. Aggressive excludes.** 30+ excluded modules in the spec:
torch, transformers, peft, accelerate, bitsandbytes, datasets,
trl, unsloth, llama_cpp, kingfisher, datasketch, pandas,
matplotlib, seaborn, smbprotocol, spnego, impacket, pypdf,
requests, paramiko, ldap3, jwt, boto3, jinja2, pysnaffler,
streamlit, pytest. Plus a sklearn `/tests/` data trim.

Two PyInstaller gotchas worth recording:

- `strip=False` and `upx=False` are mandatory. Both corrupt
  scipy's OpenBLAS shared lib (`libscipy_openblas64_*.so`); the
  resulting binary crashes at import with `ELF load command
  address/offset not page-aligned`.
- `--clean` flag breaks PyInstaller's PYZ archive in some
  versions ("PYZ archive entry not found in the TOC"). Build
  without it.

#### Build artifacts

- `tools/build_pyinstaller.py` — source of truth. Generates the
  spec file and invokes pyinstaller.
- `tools/sharesift.spec` — generated, gitignored.
- `dist-binary/sharesift` — output, 77 MB.

Bundled at runtime via PyInstaller's `--add-data`:

- `src/sharesift/rules/snaffler_default.json`
- `src/sharesift/rules/extra_rules.json`
- `models/path_classifier_v0_windows/` (Stage 1 Windows)
- `models/path_classifier_v0_linux/` (Stage 1 Linux)

The `__init__.py` carries a `_FROZEN_VERSION_FALLBACK` constant
because `importlib.metadata` can't find dist-info inside the
frozen tree. Source of truth stays `pyproject.toml`; the constant
gets bumped each release.

### Path-prefix dedup penalty — deferred

The investigation that motivated this work:

After v0.45's MSF3 top-10 hit 8/10 TPs (all real SSH credentials
on the dvwa host), top-11 = SAM file (TP), but top-12-30 was
dominated by 19 copies of `brndlog.bak` (an Internet Explorer
cache backup that pysnaffler's `KeepRegexBlackPasswordSetCsv`
rule fires on for stray "password=" strings). The duplicates
already have heavy v0.44 filename-frequency dedup (rank ~0.113);
pushing them further requires either:

- A path-prefix dedup penalty (treat the same basename across
  similar parent dirs as a stronger duplicate), OR
- Rule-action awareness (treat Yellow-from-Relay-only as Green).

Both are research-y. v0.28's falsified extension-frequency
hypothesis (MSF2 top-10 0.80 → 0.40 when extension was added
to the dedup denominator) is the cautionary precedent. Top-10
already at 0.80 — not worth disturbing for a marginal gain on
top-20.

Re-open if a future benchmark shows the duplicate-backup pattern
materially hurting top-K precision. For now: deferred with
documented reason in CHANGELOG.

## Out of scope (rolled to v0.47+)

- **Status heartbeat** — operator visibility on long-running
  scans. Defer; the v0.18 verbosity controls already cover the
  immediate need.
- **Markdown report bundle** — distinct from the v0.46 Markdown
  exporter (which dumps findings in a doc-like format). The
  bundle would be the HTML report's Markdown twin
  (`render-report --format markdown`). Defer.
- **Resume after crash** — already shipped in v0.43.

## What this means for "ShareSift vs Snaffler for pentesting"

The v0.45 honest assessment said ShareSift was technically
on-par for most engagement workflows but lagged Snaffler on two
fronts: "drop binary on a box" (Snaffler is a single .NET exe;
ShareSift was pipx) and "feed straight into the report" (Snaffler
has the .TSV everyone's tooling already parses; ShareSift had
JSONL only). v0.46 closes both:

- 77 MB binary, single file, drops on Kali like a Snaffler `.exe`
- GhostWriter / SysReptor / Markdown exporters wire findings
  straight into the two report tools pentesters actually use

Open gaps remaining (v0.47+ candidates):
- Status heartbeat on long scans
- HTML report's Markdown twin
- Path-prefix dedup w/ rule-action awareness (research)
