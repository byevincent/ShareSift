# v0.40 + v0.41 results — engagement datastore + OpSec polish

Released 2026-06-09 as a combined ship. v0.40 lands the
smbcrawler-shape engagement datastore (the missing piece for
multi-day pentests) plus noise exclusions and `--max-file-size`
(the two biggest operator-noise complaints). v0.41 wraps the OpSec
defaults in a single `--stealth` flag.

## Headline

| Workflow | Before | After |
|---|---|---|
| Re-query findings after a scan | grep hits.jsonl | `sharesift query --db engagement.db` |
| Multi-day engagement state | per-target subdirs only | unified SQLite datastore |
| Noise files dominating scan time | scan everything | 53 default exclusions (Snaffler #178 fix) |
| Accidentally pulling a 5GB VMDK | no protection | `--max-file-size 10M` default + flag |
| OpSec-conscious scan | tune 4 flags individually | `sharesift //host/share --stealth` |
| Tests passing | 1133 | **1222** |

## What shipped

### v0.40 step 1 — Default noise-exclusion globs

53 patterns covering the noise-paths that actually dominate real
shares:

- **Windows binaries**: System32/*.dll, SysWOW64/*.dll, winsxs/,
  Prefetch/*.pf, assembly/, Microsoft.NET/, servicing/
- **Program Files** clutter: *.dll, *.exe, Common Files/
- **Dev directories**: node_modules/, .git/objects/, __pycache__/,
  venv/, vendor/, target/dependency/, Pods/, build/intermediates/
- **OS caches**: Library/Caches/ (macOS), AppData/Local/Temp/,
  INetCache/, Recent/
- **Binary artifacts**: *.pyc, *.so, *.dylib, *.class, *.o, *.lib
- **Heavy media**: *.iso, *.vmdk, *.mp4, *.jpg, etc.

Matched via case-insensitive `fnmatch.fnmatchcase` against
forward-slash-normalized paths so UNC + Windows + POSIX work
uniformly. Operator overrides:

- `--exclude-glob PATTERN` (repeatable) — add operator patterns
- `--no-default-excludes` — disable the default list

Closes Snaffler issue #178 (the most-referenced operator
complaint) by default.

### v0.40 step 2 — `--max-file-size` flag

Cap on raw bytes read per file. Default 10M (matches v0.35's
internal `DEFAULT_MAX_READ_BYTES`). Accepts human-readable
suffixes: `100K`, `5M`, `1G`. Invalid sizes raise a clean
`SystemExit` with a clear "use N, NK, NM, or NG" message.

Prevents accidentally pulling a 5GB VMDK or NTUSER.DAT over the
wire. Files larger than the cap are read up to the cap (partial
extraction rather than skip — sometimes the first 1MB of a 100MB
file is enough to surface a credential).

### v0.40 step 3 — SQLite engagement datastore

One `.sharesift.db` per engagement holds hosts, shares, files, and
hits across multi-day pentests. Schema:

```sql
hosts(host TEXT PK, alive INTEGER, port INTEGER,
      first_seen TEXT, last_seen TEXT)
shares(host TEXT, share TEXT, type TEXT, comment TEXT,
       can_read INTEGER, can_write INTEGER,
       first_seen TEXT, last_seen TEXT,
       PRIMARY KEY(host, share))
files(host TEXT, share TEXT, rel_path TEXT, size INTEGER,
      content_hash TEXT, first_seen TEXT, last_seen TEXT,
      PRIMARY KEY(host, share, rel_path))
hits(host TEXT, share TEXT, rel_path TEXT, rule TEXT,
     tier TEXT, snippet TEXT, ts TEXT,
     PRIMARY KEY(host, share, rel_path, rule))
```

Each tier (host / share / file / hit) carries `first_seen` +
`last_seen` for incremental-crawl resume semantics (v0.42+).
WAL journal mode + indexes on `hits(tier)`, `hits(rule)`,
`files(content_hash)`.

API:

```python
from sharesift.engagement import EngagementDB

with EngagementDB("engagement.db") as db:
    db.record_host("10.0.0.5", alive=True, port=445)
    db.record_share("10.0.0.5", "Finance", can_read=True, can_write=False)
    is_new = db.record_file("10.0.0.5", "Finance", "secrets.cfg",
                            size=42, content_hash="abc...")
    db.record_hit("10.0.0.5", "Finance", "secrets.cfg",
                  "ShareSiftKeepVaultToken", tier="Black",
                  snippet="hvs.AbCdEf...")
    print(db.summary())
    # { hosts_total: 1, shares_total: 1, hits_black: 1, ... }
```

Typed record methods only; `query(sql)` rejects non-SELECT
statements so the schema can't get clobbered by ad-hoc shell glue.

### v0.40 step 4 — `batch --db` integration

New flag on `sharesift batch`. When set, populates the engagement
DB as each target scans:

```bash
sharesift batch --targets t.txt -u u -p p \
    --output-dir ./engagement \
    --db ./engagement/.sharesift.db
```

Per-target `hits.jsonl` files get ingested into the `hits` table.
Per-target failures don't abort the batch — failed targets are
recorded in `batch_summary.jsonl` (existing behavior).

### v0.40 step 5 — `sharesift query` subcommand

Ad-hoc inspection plus pre-baked presets:

```bash
sharesift query --db engagement.db --summary
sharesift query --db engagement.db --preset live-creds
sharesift query --db engagement.db "SELECT host, COUNT(*) FROM hits GROUP BY host"
sharesift query --db engagement.db --json "SELECT * FROM hits WHERE tier='Black'"
```

Pre-baked presets:

| Preset | Query |
|---|---|
| `live-creds` | Black + Red hits ordered by tier/host/share |
| `writable-shares` | shares with `can_write = 1` |
| `hosts-by-hits` | host ranking by hit count |
| `rules-by-hits` | top 30 rules by hit count + host coverage |
| `blacks` | Black tier only |

Output as aligned text (default) or JSONL (`--json`). Read-only —
mutations go through `scan` / `batch`.

### v0.41 step 1 — `--stealth` preset

One flag wraps the OpSec-conscious defaults:

```bash
sharesift //10.10.10.5/Finance$ -u user -p pass --stealth
```

Equivalent to:

```bash
sharesift //10.10.10.5/Finance$ -u user -p pass \
    --max-file-size 256K \
    --read-threads 1
```

(SMB3 encryption is already on by default.)

Explicit operator overrides win: passing `--max-file-size 1M`
alongside `--stealth` keeps `1M` instead of `256K`. The override
detection treats `read_threads == 4` (the default) as "operator
didn't set it" so `--stealth` can replace it; any other value is
respected.

## End-to-end operator workflow

```bash
# Discover + scan + populate engagement DB in three commands
pipx install 'sharesift[smb,network-enum]'

sharesift discover //10.10.10.0/24 -u u -p p > targets.txt

sharesift batch --targets targets.txt -u u -p p \
    --output-dir ./engagement \
    --db ./engagement/.sharesift.db \
    --stealth

# Query the engagement
sharesift query --db ./engagement/.sharesift.db --summary
sharesift query --db ./engagement/.sharesift.db --preset live-creds
sharesift query --db ./engagement/.sharesift.db --preset writable-shares
```

## What didn't ship

**PyInstaller single-file binary** carries from v0.38. The 1.5GB
bundle problem needs proper investigation — sklearn submodule
trimming, a stage-1-only build mode. Defer to v0.42.

**Resume after crash** — the schema primitives (`first_seen` /
`last_seen` per row, `record_file` returning True/False for new
vs seen) are in place. The actual skip-already-seen-files logic in
the walk + content stages is a v0.42 wire-up.

**GhostWriter / SysReptor exporters** — engagement DB is now
queryable via SQL; v0.42 adds typed exporters for the common report
formats.

## Sprint accounting

| Step | Status | Tests added |
|---|---|---|
| v0.40 step 1 — Default noise-exclusion globs | ✅ | +40 |
| v0.40 step 2 — `--max-file-size` flag | ✅ | +19 |
| v0.40 step 3 — SQLite engagement datastore | ✅ | +18 |
| v0.40 step 4 — `batch --db` integration | ✅ | (covered by step 3 + smoke) |
| v0.40 step 5 — `sharesift query` subcommand | ✅ | +7 |
| v0.41 step 1 — `--stealth` preset | ✅ | +5 |

**1222 passing total**, 29 skipped, 0 regressions. 21 live SMB
integration tests pass.

## Meta

This release was deliberately a "batched" ship per the operator
feedback that the GitHub Releases page was getting noisy with
near-daily release pages. Going forward, ~3-4 versions land per
GitHub Release. v0.40.0 is tagged in git for historical accuracy
but only the v0.41.0 release page exists.

The six-release displacement arc through v0.41:

| Release | Theme |
|---|---|
| v0.35 | Remote-share addressable (no mount) |
| v0.36 | Finder quality (1.6× rule coverage + correct R/W) |
| v0.37 | Drop-in workflows (TOML, pipx, batch) |
| v0.38 | Parallel reads (1.5× speedup default) |
| v0.39 | Network-wide discovery (CIDR → discovered share list) |
| v0.40+v0.41 | Engagement-shape (SQLite DB + query + noise exclusions + max-file-size + --stealth) |

MIN top-10 = 0.20 / MIN recall = 0.90 chart still flat. Operator
capability matrix moved another major step — ShareSift now
supports the complete end-to-end "discover → scan → query"
engagement workflow that has been the missing piece since the
v0.37 research surfaced smbcrawler as the real competitor.
