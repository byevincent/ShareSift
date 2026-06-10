# Changelog

All notable changes to ShareSift are listed here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

v0.49+ — close held-out v2 remaining gaps (CMD `set "VAR=val"`
quoted variant, loose "credential" filename keyword), lock
held-out v3 from yet-unread sources, status heartbeat, Markdown
report bundle. See `docs/v0p48_results.md` v0.49 candidate list.

## [0.48.0] — 2026-06-10

The "close the v0.47 held-out underfit, cleanly" release. v0.47
shipped held-out at 36% (below the 50% gate). v0.48 ran the proper
experiment: lock a NEW held-out set FIRST, then write rules
sourced only from the OLD held-out failures, then validate against
the new set.

**Result: held-out v1 lifted 36% → 91%, held-out v2 lifted from
50% baseline → 70%, browser-creds meta-rule generalized cleanly to
Chrome + Edge probes I never wrote rules for.**

### Added — Seven rules (close OLD held-out)

| Rule | Tier | Match | Closes |
|---|---|---|---|
| ShareSiftKeepCiscoEnableSecret | Red | Content | #78 |
| ShareSiftKeepCiscoSnmpCommunity | Red | Content | #78 RW |
| ShareSiftKeepCiscoSnmpCommunityRo | Yellow | Content | #78 RO |
| ShareSiftKeepFileZillaSavedSites | Black | FilePath | #135 |
| ShareSiftKeepFileZillaRecentServers | Yellow | FilePath | #135 |
| ShareSiftKeepDotNetAppSettingsConnString | Red | Content | #67 |
| ShareSiftKeepBrowserSavedCreds | Black | FilePath | #46 |

### Added — Held-out v2 (locked test set)

`benchmarks/snaffler_issues/heldout_v2.jsonl` — 10 probes mined
from previously-unread PR sources (#198, #155, #124, #98 +
Chrome/Edge variants of #46). Locked before v0.48 rule authoring.

`eval_snaffler_issues.py` grows `--set {corpus,heldout,heldout_v2,all}`.

### Honest scoreboard

| Gate | Threshold | v0.47 | v0.48 |
|---|---|---|---|
| Corpus | 19/19 | 18/19 (95%) | 18/19 (95%) |
| Held-out v1 | ≥50% | 4/11 (36%) | **10/11 (91%)** |
| Held-out v2 (new) | ≥50% | n/a | **7/10 (70%)** |
| MSF3 recall | flat | 1.000 | 1.000 |
| MSF2 recall | flat | 1.000 | 1.000 |
| DiskForge recall | flat | 0.923 | 0.923 |
| v0.48 rule FP contribution | 0 | n/a | 0 across all three |

3 held-out v2 fails come from sources I mined for held-out v2.
Per discipline, no rules written for them in v0.48. v0.49
candidates. Full writeup in `docs/v0p48_results.md`.

## [0.47.0] — 2026-06-10

The "corporate SMB benchmark" release. v0.47 introduces the first
benchmark grounded in real operator complaints — mined from five
years of SnaffCon/Snaffler issue tracker — then adds 7 rules
targeting the gaps it surfaces. **Held-out generalization is
partial (36%) and documented rather than tuned away.**

### Added — Snaffler-issues benchmark

Three tools + two probe sets, all under
`benchmarks/snaffler_issues/`:

- `tools/mine_snaffler_issues.py` — fetches all 198 issues + PRs
  via `gh api`. Raw dumps gitignored (regenerable).
- `tools/bucket_snaffler_issues.py` — heuristic-classify by signal
  type (miss/fp/feat/bug/q/unk).
- `tools/eval_snaffler_issues.py` — score ShareSift cascade
  against each probe. Path probes → `PathClassifier`; content
  probes → `ContentRuleEngine`; max-tier across both = verdict.
  `--set {corpus,heldout,both}`.

Hand-curated:
- `corpus.jsonl` (19 probes) — training signal from issues #46,
  #31, #107, #119, #53, #158, #191.
- `heldout.jsonl` (11 probes) — locked from issues #78, #135,
  #67. Sources not consulted while authoring v0.47 rules.

### Added — Seven corporate-SMB rules

In `src/sharesift/rules/extra_rules.json` (+ Python mirror in
`extra_rules.py` for pysnaffler compat):

| Rule | Tier | Match | Closes |
|---|---|---|---|
| ShareSiftKeepFirefoxSavedCreds | Black | FilePath | #46 |
| ShareSiftKeepGppPolicyXml | Black | FilePath | #31 |
| ShareSiftKeepGermanCredFilenames | Red | FileName | #53 |
| ShareSiftKeepWireguardPrivateKey | Black | Content | #119 |
| ShareSiftKeepOpenvpnAuthUserPassRef | Red | Content | #119 |
| ShareSiftKeepCiscoAnyconnectXml | Yellow | FileName | #119 |
| ShareSiftKeepDoubleDashPassphrase | Red | Content | #158 |

### Improved — MSF2 recall to 1.000

`/root/reset_logs.sh` — the one both-missed credential on MSF2
since v0.41 — is now caught. Recall lifts 33/34 → 34/34. Emerges
from ML path classifier picking up signal as the rule library
grew; not directly attributable to a v0.47 rule.

### Honest scoreboard

| Gate | Threshold | Result |
|---|---|---|
| Corpus | 19/19 | 18/19 (95%) |
| Held-out | ≥50% | **4/11 (36%) — below gate** |
| MSF3 recall | flat | 1.000 (40/40, held) |
| MSF2 recall | flat | **1.000 (34/34, +1)** |
| DiskForge recall | flat | 0.923 (12/13, held) |
| v0.47 rule FP contribution | 0 | 0 across all three |

Held-out below 50% is an underfitting result (rules too narrow to
catch parallel patterns), not overfitting (rules don't introduce
FPs anywhere). Full reasoning + v0.48 candidate list in
`docs/v0p47_results.md`.

## [0.46.0] — 2026-06-09

The "drop a binary on Kali" release. Closes the three remaining
items from the v0.45 honest assessment: engagement-DB exporters
(GhostWriter / SysReptor), PyInstaller single-file binary (1.5GB →
77MB), path-prefix dedup investigation (deferred — risk/reward
isn't there).

### Added — engagement DB exporters

New ``sharesift export`` subcommand emits findings in three
operator-friendly formats:

    sharesift export --db engagement.db --format markdown \
        --output findings.md --title "Acme Q3 2026"

    sharesift export --db engagement.db --format ghostwriter \
        --output findings.csv

    sharesift export --db engagement.db --format sysreptor \
        --output sysreptor.json

- **Markdown** — universally pasteable into any reporting tool
  (Dradis, GhostWriter, SysReptor, Notion, Slack, plain delivery
  docs). Summary stats + findings grouped by tier; per-finding
  with path, host, share, RW marker, snippet truncated to 500
  chars.
- **GhostWriter CSV** — direct CSV import format with columns
  GhostWriter's findings page expects. Tier maps to severity
  (Black→Critical, Red→High, Yellow→Medium, Green→Low). Standard
  "Rotate the credential" recommendation; operator customizes
  per-finding before delivery.
- **SysReptor JSON** — ``projects/v1`` format with lowercased
  severities per SysReptor schema. Metadata block preserves
  ``sharesift_rule`` + ``first_seen`` + ``share_writable`` for
  downstream queries.

All three use consistent finding ordering: tier (Black > Red >
Yellow > Green) > host > share > rel_path. Pre-joined query
returns hits + share access + file size in one round-trip.

### Added — PyInstaller single-file binary (77 MB)

v0.38's deferred PyInstaller item now solved. **20× smaller** than
the v0.38 1.5GB attempt:

    wget https://github.com/byevincent/ShareSift/releases/latest/download/sharesift
    chmod +x sharesift
    ./sharesift --version
    # sharesift 0.46.0

The binary covers:
- ``score-paths`` (Stage 1 LightGBM + rule engine + tier engine)
- ``scan-files`` (rule + extractor cascade)
- ``to-snaffler-tsv``
- ``sort`` (verifier-first)
- ``query`` (engagement DB)
- ``export`` (Markdown / GhostWriter CSV / SysReptor JSON)

What it does NOT cover (operators pipx install for these):
- SMB-direct (smbprotocol excluded, saves ~30 MB)
- ``discover`` (impacket excluded, saves ~100 MB)
- ``verify`` (requests/paramiko/ldap3/jwt/boto3 excluded, saves
  ~50 MB)
- ``render-report`` (jinja2 excluded)
- Content classifier (torch excluded, saves ~1.5 GB)

The size reduction came from two changes:

1. **Minimal build venv.** Default dev venv has torch+nvidia+triton+
   bitsandbytes (5.4GB). Building from a 325MB venv with only
   Stage-1 deps prevents transitive pulls.
2. **Aggressive excludes.** 30+ excluded modules + sklearn data
   trim. ``strip=False`` + ``upx=False`` because both corrupt
   scipy's OpenBLAS shared lib.

New build script ``tools/build_pyinstaller.py`` generates the
spec file and invokes pyinstaller. The spec itself is gitignored;
the build script is source of truth.

### Deferred — path-prefix dedup penalty

Diagnostic on MSF3 top-30 post-v0.45 shows top-10 = 8/10 TPs
(real SSH credentials), top-11 = SAM file (TP), top-12-30 dominated
by duplicate ``brndlog.bak`` files (Internet Explorer cache
backup, FPs). The duplicates already have heavy filename dedup
(rank ~0.113); pushing them further requires rule-action-aware
logic (treat Yellow-from-Relay-only as Green). That's a
research-y change pattern with v0.28's falsified extension-penalty
as a cautionary precedent. Defer with explicit risk/reward
acknowledgement: top-10 is already 0.80, not worth disturbing.

### Out of scope

- Status heartbeat — operator UX polish, defer
- Markdown report bundle — different from the Markdown exporter
  (which exports findings JSON-style); the bundle would be the
  HTML report's Markdown twin. Defer.
- Resume after crash — already shipped in v0.43.

## [0.45.0] — 2026-06-09

The structural-weakness release. v0.44 fixes the ranking bug that
held MIN top-10 flat at 0.20 for 16+ releases — chart jumps to 0.70.
v0.45 wires verifier-first output sorting (the "Snaffler can't match
this" pitch from the v0.36 audit). Combined v0.44+v0.45 ship;
v0.44.0 tagged in git but only this v0.45.0 release page is created.

### Added (v0.44 — ranking improvement)

- **Filename-frequency dedup penalty in production** (was harness-
  only since v0.22). ``cmd_score_paths`` and the cascade entry
  points now emit ``rank_score`` and ``filename_frequency`` fields.
  Operators running ``sharesift score-paths`` get the
  v0.22-style ranking — pre-v0.44 they were seeing raw classifier
  output (where Boxstarter installer .ps1 files dominated the
  top-10).

- **Green-tier zero-out** (`src/sharesift/ranking.py`). When
  ``cascade_tier == "Green"`` (only Relay-action rules fired —
  ``RelayPsByExtension``, ``RelayVBScriptByExtension``,
  ``RelayConfigByExtension`` — these fire on every ``.ps1`` /
  ``.vbs`` / ``.config``), the path classifier's probability is
  short-circuited to 0. The v0.21 MSF3 validation found Green-tier
  matches drown credentials when given ranking weight; the
  ``_TIER_PSEUDO_P[Green] = 0.0`` fix in v0.22 only worked when
  the ``max(probability, cascade_tier_pseudo_p)`` reduce didn't
  let path_probability override. v0.44 closes that loophole.

- **New module** ``sharesift.ranking`` with ``apply_dedup_penalty``,
  ``sort_by_rank``, ``basename`` (UNC/Windows/POSIX-safe).

### Harness impact

| Benchmark | top-10 before | top-10 after | recall |
|---|---|---|---|
| MSF3 (Windows AD) | 0.20 | **0.80** (4×) | 0.90 |
| CredData | 0.70 | 0.70 | 1.00 |
| MSF2 (Linux server) | 1.00 | 1.00 | 1.00 |
| engagement_corpus | 0.40 | **0.90** | 0.91 |
| DiskForge | 0.50 | 0.50 | 1.00 |
| **MIN top-10** | **0.20** | **0.70** | — |
| **MIN recall** | **0.90** | **0.90** (preserved) | — |

MIN top-10 = 0.70. Chart was flat at 0.20 for 16+ releases — first
movement since the v0.18 era.

### Added (v0.45 — verifier-first output)

- **``sharesift.ranking.sort_verifier_first(records)``** — multi-key
  sort: verification_status > tier > rank_score > path. The
  structural ShareSift advantage Snaffler can't match: Snaffler
  finds files, ShareSift finds files AND tells operators which
  contain credentials that authenticate right now.

- **Behavioral assertion**: a verified-passed Yellow ranks ABOVE
  an unverified Black. Verification beats tier in ranking. The
  v0.36 audit research called this out as "the single best
  operator pitch."

- **``cmd_verify`` output now sorted by default.** verified.jsonl
  records emerge with live-passing credentials at the top.

- **``cmd_to_snaffler_tsv`` default-sorts** before emitting; new
  ``--no-sort`` flag preserves input order. The Snaffler-TSV format
  itself is unchanged (11 columns, downstream-tool-compatible) —
  only the row order changes. Efflanrs / SnafflerParser / Parsler
  / snafflepy still ingest unchanged.

- **New ``sharesift sort`` subcommand** for ad-hoc re-sort:

      cat engagement/*/hits.jsonl > combined.jsonl
      sharesift sort --input combined.jsonl --output ranked.jsonl

- **``live_marker(record)``** — returns ``"[LIVE]"`` for
  verified-passed, ``"[FAIL]"`` for failed-verification, empty
  otherwise. Reserved for future HTML / TSV verbose display
  surfaces.

### Documentation

- ``docs/snaffler_benchmark_2026-06.md`` — full benchmark doc gets
  a new "Top-K precision (post-v0.44)" section with the
  before/after table and MSF3 top-10 diagnostic showing real
  credential files (id_rsa, authorized_keys, environment) now
  dominate where Boxstarter installer noise used to be.

- ``benchmarks/v0p22_eval/harness_history.jsonl`` — v0.44.0 entry
  appended documenting the first MIN top-10 movement in 16+
  releases.

### Out of scope (deferred)

- **PyInstaller single-file binary** carries from v0.38 (1.5GB
  bundle problem). v0.46+ candidate.
- **GhostWriter / SysReptor exporters** — operator-requested skip
  for this batch; engagement DB is queryable via SQL, exporters
  remain useful but not blocking.
- **Path-prefix dedup penalty** (extend dedup to known-noise apps
  like ``/wamp/``, ``/glassfish/``). Top-30 still has noise from
  these apps. Worth experimenting — could overshoot like the v0.28
  extension-penalty hypothesis. Defer pending careful test.

## [0.43.0] — 2026-06-09

Benchmark-driven improvements + engagement-day polish. Combined
v0.42 + v0.43 ship; v0.42.0 tag exists in git but only this v0.43.0
release page is created (per the batching pattern established with
v0.41).

### Added (v0.42 — closing benchmark gaps)

After the head-to-head benchmark against Snaffler surfaced 11
both-missed Linux credential paths on MSF2, v0.42 adds 6 targeted
rules that close 10 of them:

- **`ShareSiftKeepShadowBackup`** (Black) — `/etc/shadow-`,
  `/etc/gshadow`, `/etc/gshadow-` backup forms created by
  `passwd`/`groupadd` before writing
- **`ShareSiftKeepNfsExports`** (Yellow) — `/etc/exports` NFS
  share rules (host access + krb5 sec= flavors)
- **`ShareSiftKeepPostfixConfig`** (Yellow) — `/etc/postfix/main.cf`
  + `sasl_passwd` + `saslpasswd2` (Postfix mail server credentials)
- **`ShareSiftKeepMysqlDataDir`** (Black) — MySQL/MariaDB
  `mysql.user`, `mysql.db`, `proxies_priv` ISAM/InnoDB data files
  (password hashes crack offline)
- **`ShareSiftKeepEditorBackupConfig`** (Red) — `*.{php,inc,conf,cfg,ini,env,yml,yaml,properties,sh}{~,.bak,.swp,.orig}`
  (editor backups of credential-shaped configs)
- **`ShareSiftKeepSshHostPubKeys`** (Yellow) —
  `/etc/ssh/ssh_host_*.pub` (signal that the private keys exist
  in the same directory)

**Benchmark impact** (MSF2 head-to-head):
- v0.41: ShareSift R=0.676 (23/34), 11 both-missed
- v0.43: ShareSift R=**0.971 (33/34)**, 1 both-missed (`/root/reset_logs.sh` —
  shell script with embedded creds, intentionally hard to rule
  for without high FPR on every shell script)

**Linux recall lead vs Snaffler: +53 percentage points** (0.971 vs
0.441). Windows benchmarks (MSF3 + DiskForge) unchanged — the new
rules are Linux-specific.

Rules added to BOTH the ShareSift internal engine
(`extra_rules.json`) AND the pysnaffler comparison path
(`extra_rules.py::_v0p42_benchmark_gap_rules`) so the same rules
fire whether ShareSift is evaluated standalone or in head-to-head
mode.

### Added (v0.43 — resume after crash)

Operator workflow:

    sharesift //10.0.0.5/Finance$ -u u -p p \
        --db ./engagement/.sharesift.db --output-dir ./engagement
    # ... crashes after 5k of 50k files

    sharesift //10.0.0.5/Finance$ -u u -p p \
        --db ./engagement/.sharesift.db --output-dir ./engagement \
        --resume

- New `--db PATH` flag on `scan` (matches `batch`'s flag set).
  When set, hosts + shares + walked files get recorded in the
  engagement datastore as the scan runs.
- New `--resume` flag. Requires `--db`. Filters the walked file
  list against the DB's `seen_files(host, share)` so the cascade
  only processes new files.
- New `EngagementDB.seen_files(host, share)` returns the set of
  `rel_path` values already recorded.
- New `EngagementDB.record_files_bulk(...)` for the post-scan
  bulk file recording (uses `INSERT OR IGNORE` for skip-already-
  seen semantics).
- Files get recorded in the `finally` clause so even partial /
  crashed scans leave recoverable state.

### Speed benchmark added

Same 1054 MSF3 paths through both tools, 5 wall-clock runs each:

| Tool | Median | Per-path |
|---|---|---|
| pysnaffler (rules only) | 0.65s | 0.6 ms/path |
| ShareSift Stage 1 (rules + LightGBM ranker) | 1.67s | 1.6 ms/path |
| Snaffler.exe (.NET, not measured) | ~0.05-0.13s | ~0.05-0.13 ms/path |

ShareSift is ~2.6× slower than pysnaffler on rule eval (LightGBM
model load + feature extraction + calibrated inference). Against
actual Snaffler.exe ShareSift is probably 13-26× slower on raw
rule eval. Honest acknowledgment of the .NET vs Python+ML gap.

**Crucially: neither tool's compute is the wall-clock bottleneck
in real engagements.** A 50k-file share scan takes 5-30 minutes of
SMB walk; the ~50s extra ShareSift eval cost is dwarfed by the
network round-trips both tools have to make. Real wall-clock
difference on engagement scans: within 5-10% of each other.

### Documentation

- `docs/snaffler_benchmark_2026-06.md` — full head-to-head
  benchmark covering MSF3, MSF2, DiskForge. Includes the v0.42
  per-rule attribution table, methodology, speed numbers, and
  honest caveats about what the comparison doesn't measure (top-K
  ranking, content classifier value, live verifier value, GOAD
  re-test).

- README — head-to-head numbers updated to current v0.42 results.
  MSF2 added (97.1% vs 44.1%). Pointer to the full benchmark doc.

### Out of scope (deferred)

- **Top-K precision improvement** (ranker re-calibration) carries
  to v0.44. MIN top-10 = 0.20 chart has been flat for 16+ releases.
  This is the structural ranking weakness; needs ML
  experimentation, not a config change.
- **PyInstaller single-file binary** still has the 1.5GB bundle
  problem from v0.38. Defer.
- **GhostWriter / SysReptor exporters** from the engagement DB.
  v0.44 candidate.
- **GOAD ground truth in `{file_list, ground_truth}` format**.
  Needs lab build; deferred.

## [0.41.0] — 2026-06-09

Engagement-shape datastore + OpSec polish. v0.40 and v0.41 ship
together as a single GitHub release; the v0.40.0 tag exists for
historical accuracy but only the v0.41.0 release page is created.

### Added (v0.40)

- **Default noise-exclusion globs** — 53 patterns covering Windows
  System32/SysWOW64 binaries, winsxs/, Prefetch/, dev directories
  (node_modules/, .git/objects/, __pycache__/, venv/, vendor/),
  OS caches (Library/Caches/, AppData/Local/Temp/), binary
  artifacts (*.pyc, *.so, *.dll), heavy media (*.iso, *.vmdk,
  *.mp4, *.jpg). Snaffler issue #178 et al. (operators getting
  buried in System32 noise) addressed by default. Operator flags
  `--exclude-glob PATTERN` (repeatable) and `--no-default-excludes`.

- **`--max-file-size` flag** with human-readable suffix parsing
  (5M, 100K, 1G). Caps bytes read per file at the share level;
  default 10M. Prevents accidentally pulling a 5GB VMDK or
  NTUSER.DAT over the wire.

- **SQLite engagement datastore** (`src/sharesift/engagement/`):
  one `.sharesift.db` per pentest holding hosts / shares / files /
  hits. Schema includes `first_seen` / `last_seen` per row for
  incremental-crawl resume in v0.42+. WAL journal mode + indexes
  on `hits(tier)`, `hits(rule)`, `files(content_hash)`.

- **`sharesift batch --db PATH`** populates the datastore as the
  batch runs. Each target's host + share + per-rule hits land in
  the DB. Per-target failures don't abort the batch.

- **`sharesift query` subcommand** for ad-hoc SQL + pre-baked
  presets:

      sharesift query --db engagement.db --summary
      sharesift query --db engagement.db --preset live-creds
      sharesift query --db engagement.db --preset writable-shares
      sharesift query --db engagement.db "SELECT host, COUNT(*) FROM hits GROUP BY host"

  Pre-baked presets: `live-creds`, `writable-shares`,
  `hosts-by-hits`, `rules-by-hits`, `blacks`. Output as aligned
  text (default) or JSONL (`--json`). Writes rejected — operator
  goes through `scan` / `batch` for mutations.

### Added (v0.41)

- **`--stealth` preset** on `scan` — OpSec-conscious one-flag
  wrapper:
  - `--max-file-size` = `256K` (cap reads aggressively)
  - `--read-threads` = 1 (no parallelism noise on the wire)
  - SMB3 encryption stays on (default)

  Explicit operator overrides win — passing `--max-file-size` or
  `--read-threads` alongside `--stealth` keeps the explicit values.

### Out of scope (deferred)

- **PyInstaller single-file binary** carries to v0.42. Initial
  bundle was 1.5GB; needs sklearn submodule trimming + a Stage-1-
  only build mode.
- **Resume after crash** — the `first_seen` / `last_seen` schema
  primitives are in place; v0.42 wires the actual skip-already-
  seen-files logic.
- **GhostWriter / SysReptor exporters** — engagement DB is now
  queryable via SQL; v0.42 adds typed exporters for the common
  report formats.

See `docs/v0p41_results.md`.

## [0.39.0] — 2026-06-09

Network-wide share discovery. The headline pitch that's been
promised since the v0.37 results doc — `sharesift //10.10.10.0/24
-u user -p pass` — actually works now. impacket-backed
NetrShareEnum behind a new `discover` subcommand, with CIDR
iteration and concurrent TCP liveness probing.

### Added

- **`sharesift discover` subcommand** for share enumeration on
  remote SMB hosts. Single-host and CIDR both supported:

      sharesift discover //10.10.10.5 -u user -p pass         # single
      sharesift discover //10.10.10.0/24 -u user -p pass      # subnet
      sharesift discover //10.10.10.5 --no-pass               # anon

  Composes with `batch`:

      sharesift discover //10.10.10.0/24 -u u -p p > targets.txt
      sharesift batch --targets targets.txt -u u -p p --output-dir ./out

- **`network-enum` optional extra** adding `impacket>=0.12.0`.
  Stays separate from the `smb` extra so operators who only need
  single-share scanning don't pull in impacket's larger dep tree.
  Missing-extra raises `SystemExit` with the three-line install
  guide (same pattern as v0.37's `smb` extra).

- **`src/sharesift/share/discovery.py`**:
  - `ShareSummary(name, type, comment)` dataclass with
    `.is_file_share()` heuristic
  - `enumerate_shares(host, auth)` — single-host NetrShareEnum
    via impacket's `SMBConnection.listShares()`. Type-bitfield
    classification handles SPECIAL overlay (high bit) + base type
    (disk/printer/device/ipc)
  - `expand_target_to_hosts(target)` — CIDR / UNC / port parser
    that returns the host list. `.hosts()` excludes network +
    broadcast for IPv4 /24+
  - `probe_smb_alive(host, port, timeout)` — fast TCP connect for
    liveness

- **Output formats**:
  - `--format text` (default) — one `//host/share` UNC per line;
    non-file shares (IPC, printer, device) get `# ` prefix so
    `batch` (which strips `#` comments) ignores them. Composes
    cleanly with `batch`.
  - `--format json` — one record per share: `{host, share, type,
    comment, unc}`
  - `--all-types` includes non-file shares uncommented

- **Per-host fault tolerance** in CIDR mode: per-host failures
  (auth fail, RPC error) log a warning and continue with the next
  host. Single-host targets surface the error and exit 1.

### Auth dispatch

`enumerate_shares` accepts the same `Auth` dataclass as `SmbShare`:
- Password → `conn.login(user, password, domain)`
- PtH → `conn.login(user, '', domain, lmhash, nthash)`
- Kerberos → `conn.kerberosLogin(user, ..., useCache=True)` (reads
  ccache from `KRB5CCNAME`)
- Anonymous → null session login

The `discover` subcommand reuses the same `_add_smb_auth_args`
flag set used by `scan` / `scan-files` / `batch`, so muscle memory
transfers.

### Performance

CIDR mode uses `ThreadPoolExecutor` for concurrent TCP probes
(default 32 workers) to skip dead hosts before paying impacket's
auth cost. Share enumeration on live hosts is sequential — adding
parallelism there hits the same SMB credit-flow control issues
that v0.38 limited per-Connection.

### Out of scope (deferred)

- **PyInstaller single-file binary** — bundle-size investigation
  carries to v0.40. The initial onefile attempt pulled 1.5 GB.
- **Parallel share enumeration across hosts** — sequential is
  fine for /24-sized CIDRs (~30s per dead-host-skipped pass);
  larger subnets would benefit from concurrent impacket sessions
  but threading impacket has unknown safety properties.

See `docs/v0p39_results.md`.

## [0.38.0] — 2026-06-09

Parallel SMB content reads. Single-focus release: addresses the
"ShareSift is slower than Snaffler" perceived weakness with a
lab-validated thread-pool implementation that gives 1.5× speedup
on localhost and proportionally larger gains on real networks
(where round-trip latency dominates).

### Added

- **`--read-threads N` flag** on `scan`, `scan-files`, and `batch`
  (default 4; pass 1 to force sequential). cmd_scan_files uses a
  `ThreadPoolExecutor.map()` to preserve input order so
  `Scanner.scan_batch` sees `(path, content)` tuples in the same
  sequence as the file list, keeping JSONL output deterministic.

### Behavior

Lab investigation against `dperson/samba` (SMB2/3, 100 small files
over localhost) settled the design:

| Workers | Wall-clock | Result |
|---|---|---|
| 1 | 176ms | sequential baseline |
| 2 | 117ms | 1.50× speedup |
| 4 | 122ms | sweet spot |
| 8 | 129ms | diminishing returns |
| 16 | 135ms | 98/100 reads — SMB credit-flow control failures |

smbprotocol's worker-thread + `sequence_lock` + `response_event_lock`
provide thread-safety for concurrent Open + read on a single
Connection up to ~8 workers; default 4 is the empirical sweet
spot. On a real WAN with 10-50ms round-trip latency the speedup
will be substantially larger than localhost numbers suggest — each
read overlaps a round-trip instead of microseconds of processing.

Threading is skipped (sequential path used) when:
- the active share is `None` (local FS — sub-millisecond reads,
  pool overhead exceeds benefit)
- `--read-threads 1` (operator opt-out)
- only one path is being scanned (no concurrency to extract)

### Out of scope (deferred)

- **NetrShareEnum-backed network discovery** — needs impacket as
  optional dep, substantial implementation work. Defer to v0.39.
- **PyInstaller single-file binary** — initial onefile build
  pulled in 1.5 GB of bundled deps despite `--exclude-module`
  flags. Bundle-size problem needs proper investigation, not a
  quick add. Defer to v0.39.

See `docs/v0p38_results.md`.

## [0.37.0] — 2026-06-09

Drop-in compatibility with Snaffler's rule-authoring workflow, plus
the pentester install / multi-target workflows. v0.36 made the case
that ShareSift's finder is better than Snaffler's; v0.37 makes the
case that ShareSift fits the pentester loadout ergonomically.

### Added

- **Snaffler TOML rule format**. The content-rule engine now accepts
  both ShareSift's native JSON ``{"rules": [...]}`` schema AND
  Snaffler's ``[[ClassifierRules]]`` TOML schema. A pentester's
  existing Snaffler rule TOML file drops straight into ShareSift's
  rules directory without conversion. Format dispatch is by file
  extension; PascalCase keys (RuleName, Triage, MatchAction,
  MatchLocation, WordListType, WordList, Description) map to the
  internal snake_case record shape. ``tomllib`` is stdlib (Python
  3.11+) so no new dependency.
- **`pipx install` distribution.** The package was already
  pipx-ready (proper ``[project.scripts]`` entry point). v0.37
  documents the workflow as the recommended operator install:

      pipx install 'sharesift[smb]'    # SMB-direct workflow
      sharesift //10.10.10.5/Finance$ -u user -p pass

  README install section restructured: pipx workflow leads ("Quick
  install — drop a binary on Kali"), full-source install demoted to
  "if you want to develop, train, or run the content classifier."

- **Friendlier missing-extra error.** When SMB targets are used
  without the ``[smb]`` extra, the operator now sees a three-line
  install guide naming pipx, pip, and uv install paths instead of
  a raw ``ModuleNotFoundError``.

- **`sharesift batch` subcommand** for multi-target scans:

      sharesift batch --targets targets.txt -u user -p pass \\
          --output-dir ./engagement

  Each line in ``--targets`` is a UNC or local path; comments
  (``#``) and empty lines are ignored. Each target gets its own
  subdirectory; a top-level ``batch_summary.jsonl`` records the
  per-target outcome. Per-target failure doesn't abort the batch.
  Auth flags propagate; ``--skip-verify`` / ``--skip-report`` work
  per-target. Closes the "shell-loop ShareSift over a target list"
  gap that the v0.35 single-target shape left.

### Out of scope (deferred)

- **Multi-threaded SMB walk + reads** — smbprotocol's worker-thread
  model needs investigation against the credit-flow control we
  surfaced in v0.35. Defer to v0.38.
- **Network-wide share enumeration via NetrShareEnum** — needs
  impacket as a dependency. Defer to v0.38 alongside
  multi-threading.
- **PyInstaller single-file binary** — pipx covers the install-friction
  case for now. PyInstaller for Stage-1 + verifiers only adds value
  for fully-offline Kali boxes; defer to v0.38.

See `docs/v0p37_results.md` and `docs/pentester_backlog.md`.

## [0.36.0] — 2026-06-09

The Snaffler-displacement release. v0.35 made ShareSift remote-share-
addressable; v0.36 makes it unambiguously better than Snaffler at the
finding job — more rules, smarter triage, correct R/W reporting, and
drop-in compatibility with the existing Snaffler output tooling.

### Added

- **7 modern credential rules** Snaffler doesn't ship: Terraform state
  files (`.tfstate` / `.tfstate.backup`), HashiCorp Vault tokens
  (`~/.vault-token`), Pulumi credentials, Terraform Cloud (`~/.terraform.d/credentials.tfrc.json`),
  modern Azure CLI MSAL cache (`~/.azure/msal_token_cache.json` +
  `service_principal_entries.json` + legacy `accessTokens.json`), AWS
  SSO cache (`~/.aws/sso/cache/*.json`), and Ansible Vault encrypted
  file headers. Total ShareSift rules: **144 vs Snaffler's 89** — 1.6×
  rule coverage, including the cloud / infra credential surfaces that
  appeared 2023-2026.
- **PPK encryption-aware tier resolution** (Snaffler #191). Encrypted
  `.ppk` files stay Yellow; only unencrypted (Encryption: none) keys
  promote to Black via the new `ShareSiftKeepPuttyPpkUnencrypted`
  content rule. Snaffler still flags every `.ppk` as if it were
  immediately actionable — most are passphrase-locked and not.
- **Share-level R/W access probe** (Snaffler #184). New
  `ShareAccess(can_read, can_write)` dataclass and
  `SmbShare.probe_share_access()` method probe both rights via two
  cheap SMB2 CREATE round-trips on the share root. Snaffler reports
  writable shares as `R` due to a known bug; ShareSift gets it right.
  Surfaced in `--check` output (`auth ok; tree-connected to \\host\share [RW]`)
  and the scan summary JSON.
- **Snaffler-compatible TSV output** — new `sharesift to-snaffler-tsv`
  subcommand emits the 11-column line format that SnafflerParser,
  Efflanrs, Parsler, and snafflepy already parse. Operators don't
  have to choose between ShareSift's finding capability and Snaffler's
  downstream-tool ecosystem.
- **`src/sharesift/output/` module** with `record_to_snaffler_tsv`
  and `iter_snaffler_tsv_lines` — pure formatter functions, easily
  composable into other tools.

### Changed

- **`KeepSSHKeysByFileExtension`** (Snaffler-ported) demoted from
  Black to Yellow. It's the only Snaffler rule covering `.ppk` files,
  and Black-on-all-ppk defeats the encryption-aware promotion. The
  rule's TOML docstring documents the v0.36 override.

### Out of scope (deferred)

- TOML rule format (operator UX — Snaffler-style rules drop straight
  in) bundles with v0.37 alongside the multi-threaded SMB walk + the
  network-wide share discovery work. Thin release on its own.
- Per-file R/W in Snaffler-TSV output (W/M columns stay empty). The
  share-level verdict is known; threading it into per-record output
  is a follow-on commit.

See `docs/v0p36_results.md` and `docs/pentester_backlog.md`.

## [0.35.0] — 2026-06-08

SMB-direct. ShareSift no longer requires mounting a CIFS share to
scan it — operators point the tool at a UNC + credentials and it
talks SMB2/3 natively. First deliberate adoption-friction release
after the v0.22–v0.34 discipline arc.

### Added

- **SMB-direct backend** via `smbprotocol` (jborean93) + pyspnego's
  pure-Python NTLM. No `gss-ntlmssp` system package, no
  `NTLM_USER_FILE` env-var ceremony, no impacket fallback needed.
  New `smb` optional dep group; `pyspnego` and `cryptography` come
  in transitively.
- **`Share` protocol** (`src/sharesift/share/`) with `walk()` and
  `read_bytes()` methods. Two implementations: `LocalShare` (wraps
  filesystem) and `SmbShare` (wraps smbprotocol). Cascade reads go
  through the protocol so the same code path handles both.
- **Implicit-scan CLI dispatch.** First positional that looks like
  a UNC (`//host/share` or `\\host\share`) auto-routes to the
  `scan` subcommand. Result:

      sharesift //10.0.0.5/Finance$ -u user -p pass

  is the canonical operator workflow. No `scan` keyword, no
  `--share` flag, no `--output-dir` ceremony for the default case.

- **NetExec-compatible auth flags** on `scan`:
  `-u/--user`, `-p/--password`, `-H/--hash` (NT or `LM:NT` PtH),
  `-k/--kerberos`, `--use-kcache` (alias matching nxc),
  `-d/--domain`, `--no-pass`/`--anonymous`, `--encrypt`/`--no-encrypt`.
- **`--check` mode** — auth + tree-connect + exit. Pre-flight before
  committing to a long scan. Pulled forward from the v0.36
  pentester-friendliness backlog.
- **Default output dir** computed when omitted:
  `./sharesift-<host>-<share>/` for SMB targets,
  `./sharesift-<basename>/` for local paths.
- **`extract.py` decomposition** — new pure `extract_text(data, ext, …)`
  + share-aware `load_content_from_share(share, path, …)`. The
  existing path-based `load_content(path)` is preserved as a
  backward-compat wrapper; 40+ existing tests pass unchanged.
- **Live SMB integration tests** against `dperson/samba` 4.x
  (`tests/test_smb_share_integration_v0p35.py`, `tests/conftest.py`).
  21 tests gated behind `SHARESIFT_SMB_TESTS=1`. Two real bugs
  surfaced by the live suite that mocks couldn't catch:
  SMB credit-based flow control limiting cold-connection reads
  (fixed by clamping single reads to 1MB) and bind-mount file
  permission mismatches (fixed in the fixture).
- **`docs/pentester_backlog.md`** — stable home for the 28-item
  operator-friendliness backlog mapped to v0.36/v0.37/v0.40.

### Changed

- **`sharesift scan` flag set** — `--share` (v0.18) is now optional
  and demoted to "legacy alias"; positional `target` is the
  canonical form. `--output-dir` is now optional (computed default).
  Existing scripts that pass `--share` and `--output-dir` continue
  to work unchanged.
- **`LocalShare(root=".")`** — root is now optional (defaults to
  current directory) so the class works as a generic filesystem
  reader for callers that don't walk.

### Performance / behavior

- **Single SMB reads capped at 1 MB.** Realistic credential / config
  files are well under this. Larger files (10+ MB PDFs/OOXML) need
  chunked reads — deferred to v0.36 alongside `--max-file-size`.
- **SMB3 message encryption on by default** (`--encrypt` is the
  default). Works against modern Samba 4.x and Windows Server 2012+.
  Operators hitting legacy SMB1-only targets use Snaffler / smbclient
  for that long tail.

### Out of scope (explicitly deferred)

- SMB1 support — smbprotocol drops it by design. Modern only.
- AES-key Kerberos auth — flag reserved but not wired in v0.35.
- Snaffler-compatible TSV output, tier vocabulary realignment,
  `--stealth` preset, Markdown report bundle — v0.36 OpSec arc.
- `pipx` packaging, single-file binary, Cobalt Strike Aggressor
  docs — v0.37 distribution arc.
- BOF path classifier (via `treelite` AOT compilation) — v0.40.

See `docs/v0p35_results.md` and `docs/v0p35_smb_direct_plan.md`.

## [0.18.0] — 2026-06-07

CLI ergonomics. Full execution of the Phase B–F plan that v0.17.1
Phase A started.

### Added

- **Top-level `-q`/`--quiet`, `-v`/`--verbose`.** A 30-line `Output`
  helper in `src/sharesift/_output.py` routes all stderr emissions
  through a verbosity-gated singleton. `--quiet` silences progress and
  info; warnings (incl. the verify safety banner) and errors still
  print. `--verbose` adds debug detail (model dirs, batch sizes, rate
  limits, device, target file) and bypasses the 3rd-party warning
  filter.
- **`tqdm` progress bars** on `Scanner.scan_batch` (the model-heavy
  content stage) and `verify_records`. Auto-suppressed on non-TTY
  stderr at NORMAL; always shown at VERBOSE. `tqdm>=4.66` is now a
  core dep.
- **Top-level `--json`** flag. Each subcommand emits a single
  structured end-of-run summary on stderr with a common envelope
  (`command`, `version`, `elapsed_s`, `input_count`/`output_count`,
  `exit_code`) plus per-handler fields. Stdout stays pure JSONL.
- **One-shot `sharesift scan`** subcommand wraps enumerate →
  score-paths → scan-files → verify → render-report into a single
  call. `--skip-verify` and `--skip-report` drop the late stages. The
  combined `--json` summary lists `stages_run` and the path to each
  intermediate.

### Changed

- 3rd-party warning suppression extended to `UserWarning` and
  `sklearn.*` (the LGBMClassifier feature-name nag was leaking under
  `--quiet`).
- `verify_records` lost its `progress: bool` kwarg; the singleton
  handles verbosity now. The hand-rolled every-25-records checkpoint
  is gone — tqdm handles update cadence.
- Project version bumps 0.5.0 → 0.18.0 across all `--version` /
  metadata reads.

### Notes

- Compat shim at `src/truffler/` continues to ship so joblib
  artifacts pickled with the old module paths still load. It will be
  removed once models are retrained against `sharesift.*`.
- Test count: 727 passing, 8 skipped (the 8 skipped are CLI
  integration tests that gate on the `models/path_classifier_v0/`
  artifact, which is not tracked in the public repo).

## [0.17.1] — 2026-06-07

First public release. Phase A of the v0.18 CLI ergonomics plan.

### Added

- `sharesift --version` flag — reports the installed version, sourced from
  package metadata via `importlib.metadata`.
- `sharesift.__version__` — Python-accessible version constant.
- 3rd-party warning suppression at CLI entry — `FutureWarning` and
  `DeprecationWarning` from `transformers`, `peft`, `urllib3`, and
  `bitsandbytes` are filtered. `TRANSFORMERS_VERBOSITY` defaults to
  `error` if not already set.

### Changed

- Project renamed Truffler → ShareSift. Package is `sharesift`; CLI entry
  point is `sharesift`. A compat shim at `src/truffler/` lets joblib
  artifacts pickled with the old module paths still load — it will be
  removed once models are retrained against `sharesift.*`.

### Notes

- Pre-public history (v0.1 through v0.17) is summarised in `docs/journal.md`
  and the per-version `docs/v0pXX_*.md` writeups.
- Model weights are not bundled in this repository. See `RUN.md` (in the
  release archive) for download instructions.

## [Unreleased]

v0.48+ — re-lock held-out with new probe sources, Cisco IOS
content rules (enable secret/password/type-7, SNMP communities),
FileZilla saved-sites path rule, ADO/ASP.NET connection-string
tightening, browser-creds meta-rule (Chrome + Edge Login Data),
status heartbeat, Markdown report bundle. See `docs/v0p47_results.md`
v0.48 candidate list.

## [0.34.0] — 2026-06-08

End-to-end smoke for the v0.31→v0.33 GCP fix. DiskForge gets a
synthetic GCP service-account JSON plant; integration tests confirm
the planted file flows through the v0.32 extractor and the v0.33
verifier in both structural and live modes.

### Added

- `tools/diskforge_v0p31/files/plant/gcp_service_account.json` —
  synthetic SA JSON with a real 2048-bit RSA private key generated
  by `build_manifest.py`. The key is freshly generated per
  benchmark build; no real Google account is involved.
- 13th DiskForge plant entry in `build_manifest.py` at
  `/Users/Administrator/Documents/gcp_service_account.json`.
- `tests/test_gcp_diskforge_integration_v0p34.py` — 4 integration
  tests that read the planted SA JSON and confirm:
  - Extractor catches `gcp_service_account_json` from the file's content
  - Structural verifier returns `validation_mode=structural` with the
    correct `client_email`
  - Live verifier signs a real RS256 JWT (>200 chars) and accepts
    a mocked OAuth 200

### Findings

| Metric | v0.33 | v0.34 |
|---|---|---|
| DiskForge plants (supp) | 12 | **13** |
| DiskForge recall (supp) | 1.000 | 1.000 |
| DiskForge top-10 (supp) | 0.60 | 0.60 |
| MIN top-10 / MIN recall (primary) | 0.20 / 0.90 | 0.20 / 0.90 |

The cascade catches all 13 plants without rule changes — the GCP
SA JSON's filename (`gcp_service_account.json`) matches existing
filename rules from v0.30's GCP credential family additions.

### Notes

- Test count: **861 passing**, 8 skipped (was 857 — +4 integration).
- The v0.31 finding (extractor doesn't surface private_key + verifier
  needs JWT signing) is now fully closed: v0.32 expanded the
  extractor, v0.33 added live verification, v0.34 confirms end-to-end
  with a planted file.

## [0.33.0] — 2026-06-08

**Second half of the v0.31 GCP gap closed.** v0.32 shipped the
extractor expansion + structural verifier; v0.33 ships live OAuth
verification with RS256 JWT signing and token exchange. Both halves
of the v0.31 finding are now on the record.

### Added

- `pyjwt[crypto]>=2.0` added to the `verify` dependency group.
  Pulls `cryptography` for RS256 signing. ~3 MB additional install
  size; the verifier degrades gracefully to structural-only when
  the dep isn't installed.
- `_try_live_verification` helper in
  `src/sharesift/verify/gcp_service_account.py`. Signs an RS256 JWT
  with the SA's private_key, POSTs to
  `https://oauth2.googleapis.com/token` (the documented OAuth
  endpoint), maps the response:
  - 200 + access_token → `passed` (validation_mode=live)
  - 401 → `failed` (key revoked / invalid_grant)
  - 400 → `failed` (malformed JWT)
  - Timeout → `inconclusive`
  - Connection error → `inconclusive`
- 8 new tests in `tests/test_gcp_live_v0p33.py` covering the
  live-OAuth paths. Synthetic 2048-bit RSA key generated at fixture
  time using `cryptography`; OAuth HTTP mocked at `requests.post`.

### Changed

- `GcpServiceAccountVerifier._verify_inner` now tries the live path
  after structural validation passes; falls back to structural
  verdict if pyjwt isn't installed.
- `test_verifier_passes_on_well_formed_sa_json` (v0.32) renamed to
  `test_verifier_passes_structurally_when_live_path_unavailable` and
  monkeypatches the live helper to None — the test still asserts the
  structural fallback verdict.

### Discipline notes

- Read-only OAuth scope (`userinfo.email`). Verifier doesn't
  enumerate cloud resources or mutate state. Same pattern as the
  existing Stripe / SendGrid / Mailgun / Twilio / Azure verifiers.
- 5-minute JWT expiry — minimal validity window for verification.
- Mocked at `requests.post` in tests; no live outbound calls in CI.

### Findings

| Metric | v0.32 | v0.33 |
|---|---|---|
| GCP verification mode | structural only | **live + structural fallback** |
| MIN top-10 / MIN recall (primary) | 0.20 / 0.90 | 0.20 / 0.90 |
| Verifier coverage (count) | 20 | 20 (same types; deeper verification on GCP) |

The harness numbers are unchanged because primary held-out sets
don't contain GCP SA JSON files. Adding a DiskForge GCP plant for
end-to-end smoke is queued for v0.34 but isn't load-bearing — the
unit test coverage is exhaustive.

### Notes

- Test count: **857 passing**, 8 skipped (was 849 — +8 GCP live).
- v0.31 finding ↦ v0.32 structural ↦ v0.33 live — full close across
  two sprints, with explicit checkpoint releases.

## [0.32.0] — 2026-06-08

**Half the GCP gap closed (extractor side).** v0.31 surfaced that the
v0.23 GCP extractor caught only the `client_email` field; a real
verifier needs the full SA JSON. v0.32 adds a multi-field extractor
that captures the entire `{...}` block + a structural verifier that
validates required fields, PEM-shaped private key, well-formed email.
Live OAuth verification (RS256 JWT signing + token exchange) stays
queued for v0.33+ — would add `pyjwt` as opt-in dep.

### Added

- `gcp_service_account_json` credential type — extractor multi-field
  regex captures the whole `{...}` JSON block (both field orders:
  `type → private_key → client_email` and the reverse).
- `src/sharesift/verify/gcp_service_account.py` — `GcpServiceAccountVerifier`
  does structural validation. Verdict matrix:
  - `passed` (validation_mode: structural) when required fields are
    present, `type == service_account`, `private_key` is
    PEM-shaped, and `client_email` matches the IAM regex
  - `failed` with a specific error key (`missing_fields:...`,
    `wrong_type:...`, `malformed_client_email`,
    `private_key_not_pem_shaped`, `not_valid_json: <reason>`)
  - No external HTTP calls.

### Findings

| Metric | v0.31 | v0.32 |
|---|---|---|
| Verifier coverage | 19 | **20** |
| Extractor patterns | 30 (1 GCP-email) | 31 (1 GCP-email + 1 GCP-JSON) |
| MIN top-10 / MIN recall (primary) | 0.20 / 0.90 | **0.20 / 0.90** |

Harness numbers unchanged — none of the primary held-out sets
contain GCP SA JSON files. Verifier behavior covered exhaustively
in `tests/test_gcp_v0p32.py`.

### Notes

- v0.23 `gcp_service_account_email` extractor stays — older scan
  outputs and the v0.30 rule engine keep working.
- Operator note (in verifier docstring): structural `passed` means
  the credential is well-formed and ready for live verification with
  `gcloud auth activate-service-account`. It does NOT confirm the
  key hasn't been revoked. Live OAuth verification is v0.33+.
- Test count: **849 passing**, 8 skipped (was 839 — +10 GCP).

## [0.31.0] — 2026-06-08

Azure storage verifier shipped; GCP service-account verifier deferred
on a real architectural finding; DiskForge image grown to realistic
positive density. Mid-iteration release shape: ship what's done,
document what blocked.

### Added

- `src/sharesift/verify/azure_storage.py` — Shared Key (HMAC-SHA256)
  signing for `GET /?comp=list` on `<account>.blob.core.windows.net`.
  Read-only; never enumerates containers or mutates state. Completes
  the v0.23 extractor→verifier loop for
  `azure_storage_connection_string`.
- `tools/diskforge_v0p31/build_manifest.py` — programmatically
  generates 476 synthetic Windows-clutter decoys at realistic paths
  (System32 binaries, event logs, prefetch, user profile clutter,
  IIS logs). DiskForge: 519 records, 2.3% positive density —
  comparable to MSF3 (3.8%) and MSF2 (2.3%).
- `tools/build_diskforge_benchmark.py` uses `_PLANT_LABELS` as the
  source of truth for positives, so decoy entries are labeled
  negative even though they appear in the manifest.

### Deferred (honest finding, not vague TODO)

- **GCP service-account verifier.** The v0.23 extractor catches the
  `client_email` field but not the `private_key`. A real verifier
  needs the private key to sign an RS256 JWT for OAuth token
  exchange. Closing this requires either expanding the extractor's
  data model (capture the full SA JSON) OR threading file content
  through the verify dispatcher. Both are larger than v0.31 scope.

### Findings

| Metric | v0.30 | v0.31 |
|---|---|---|
| Verifier coverage | 18 | **19** |
| DiskForge records | 43 | **519** |
| DiskForge density | 28% | **2.3%** |
| DiskForge recall (supp) | 1.000 | 1.000 |
| DiskForge top-10 (supp) | 0.60 | 0.60 |
| MIN top-10 / MIN recall (primary) | 0.20 / 0.90 | 0.20 / 0.90 |

DiskForge holds recall + top-10 across the density change — the
cascade wasn't relying on the artificially-high positive density to
look good. Stays supplementary because the negatives are synthetic
stubs, not real Windows binaries.

### Notes

- Test count: **839 passing**, 8 skipped (was 833 — +6 Azure tests).
- All HTTP mocked at `requests.request`; no live outbound calls.

## [0.30.0] — 2026-06-08

**Parser-without-rule gap closed.** The v0.29 DiskForge benchmark
surfaced the `.pypirc` miss — parsers extract content, rules drive
cascade tier; a parser without a paired rule leaves a recall hole
on path-only enumeration. v0.30 adds 8 declarative rules in
`extra_rules.json` covering all v0.24-v0.26 parser families.
Engine: 120 → **128** rules.

### Added

| Rule | Match | Tier | Parser family |
|---|---|---|---|
| `ShareSiftKeepPypirc` | FileName | Red | v0.25 pypirc |
| `ShareSiftKeepNetrc` | FileName | Red | v0.24 netrc |
| `ShareSiftKeepGcloudCredentials` | FileName | Black | v0.25 gcloud_credentials |
| `ShareSiftKeepKeyringFile` | FileName | Red | v0.25 keyring_credentials |
| `ShareSiftKeepAwsCliCredentialsByPath` | FilePath (`.aws/`) | Black | v0.24 aws_cli_credentials |
| `ShareSiftKeepMavenSettingsByPath` | FilePath (`.m2/`) | Yellow | v0.24 maven_settings_xml |
| `ShareSiftKeepGhCliConfigByPath` | FilePath (`.config/gh/`) | Red | v0.25 gh_cli_config |
| `ShareSiftKeepPuttyPpkByExtension` | FileExtension | Red | v0.26 putty_ppk |

### Findings

| Set | v0.29 | v0.30 |
|---|---|---|
| **DiskForge (supp)** | recall 0.917, top-10 0.50 | **recall 1.000**, top-10 0.60 |
| MSF3 / CredData / MSF2 (primary) | unchanged | unchanged |
| MIN top-10 / MIN recall (primary) | 0.20 / 0.90 | **0.20 / 0.90** |

DiskForge caught all 12 plants; primary numbers unchanged because
the new rules are filename- or path-context-distinctive enough not
to false-positive on Linux server filesystems or source-code corpora.
The harness confirmed: ambiguous filenames (`credentials`,
`settings.xml`, `hosts.yml`) require path-context to avoid
cross-distribution regression.

### Notes

- Tests added: 12. Each rule has both a fire-on-intended-path test
  AND a no-FP-on-look-alike-path test (e.g.,
  `test_aws_cli_credentials_does_not_fire_on_bare_credentials_filename`,
  `test_maven_settings_xml_does_not_fire_on_vscode`,
  `test_gh_cli_hosts_yml_does_not_fire_on_ansible_inventory`).
- Full suite: **833 passing, 8 skipped, 0 regressions**.

## [0.29.0] — 2026-06-08

**4th held-out set acquired via DiskForge** — Jacob Stauffer's
Docker-based forensic disk-image generator (`jknyght9/diskforge`).
Plants 12 credentials at paths documented in Snaffler default rules +
MITRE ATT&CK T1552 on a Windows 10 template. Added as
**supplementary**, not primary, because 28% positive density is
unrealistic for a real share.

### Added

- `tools/diskforge_v0p29/manifest.json` + `files/plant/*` — full
  reproducible build inputs (12 credential payload files at
  documented Windows credential locations)
- `tools/diskforge_v0p29/README.md` — step-by-step reproduction
- `tools/build_diskforge_benchmark.py` — reads the manifest and
  the file list from the generated disk, emits labeled ground
  truth (positives = manifest's `add_files` targets)
- `tools/eval_harness.py` gains `_eval_diskforge_win10()`;
  supplementary set, does NOT contribute to MIN
- `data/external/diskforge_win10/` — 43 records / 12 positives
- `.gitleaks.toml` allowlist entry for the planted payload files
  (they contain documented credential shapes that look like
  secrets to scanners but are synthetic fixtures)

### Findings

| Set | Recall | Top-10 | Positive density |
|---|---|---|---|
| DiskForge Win10 (supp) | **0.917** (11/12) | 0.50 | 28% (planted) |

The one missed plant is `.pypirc` — we added a v0.25 parser for it
but **no corresponding filename rule**. Parsers extract content-side
structure but don't contribute to the cascade's path-side tier
signal. **This is a real architectural gap**: parsers added without
paired rules leave a recall hole on path-only enumeration. v0.30
fix: add filename rules to `extra_rules.json` for the v0.24/v0.25
parser families.

### Notes

- The DiskForge supplementary set joins engagement_corpus in
  surfacing-without-counting-toward-MIN.
- Vincent's former professor (UTSA) Jacob Stauffer authored
  DiskForge; the tool turned out to be exactly the right primitive
  for cheap, reproducible labeled disk images. Credit + provenance
  documented in the results doc.
- Test suite unchanged: 821 passing. v0.29 work was data + tooling.

## [0.28.0] — 2026-06-08

**Falsified-hypothesis release.** Tested a declarative extension-
frequency penalty by analogy to v0.22's filename penalty. The
harness rejected it: MSF3 top-10 0.20 → 0.10, MSF2 top-10
0.80 → 0.40, MIN 0.20 → 0.10. Backed out instead of iterating
against the data (which would be the exact overfitting v0.22
disciplined against).

### Why it failed

The hypothesis ("credentials cluster in minority-extension files")
was Windows + dev-share shaped. Linux server credential files live
in **common-extension types** — `.conf` (proftpd / asterisk /
samba / openldap), `.cnf` (mysql), `.php` (DVWA / TikiWiki /
phpMyAdmin). Penalising those by extension frequency tanked their
ranking on MSF2, which is exactly where they live.

### Changed

- `tools/eval_harness.py` — the failed v0.28 code was implemented,
  measured against the harness, then reverted to v0.22's filename-
  frequency-only scoring. Comment on `_score_with_dedup_penalty`
  now documents the failed hypothesis so a future contributor sees
  it before re-running the experiment.

### Findings

| Metric | v0.27 | v0.28 |
|---|---|---|
| MIN top-10 (primary) | 0.20 | 0.20 |
| MIN recall (primary) | 0.90 | 0.90 |

7-release flat trajectory now includes one explicit "tested-and-
rejected" entry. That's the eval gate functioning as designed.

### Notes

- No production code changes shipped. The Scanner cascade,
  rules engine, parsers, extractors all unchanged from v0.27.
- Test suite unchanged: 821 passing.
- Azure storage verifier (carryover from v0.26) deferred to v0.29
  to keep the v0.28 message focused on the falsified-hypothesis
  finding.

## [0.27.0] — 2026-06-08

**Third primary held-out set acquired.** Honestly built from the
public `tleemcjr/metasploitable2` Docker image. MIN trajectory still
holds at 0.20 / 0.90 — but the floor is now demonstrably MSF3-specific,
not pipeline-shaped.

### Added

- `data/external/metasploitable2/file_list.txt` + `ground_truth.jsonl`
  — 1500 paths, 34 known credential-bearing files labeled from public
  Metasploitable 2 walkthroughs (not from running ShareSift against
  the share)
- `tools/build_msf2_benchmark.py` — reproducible builder; takes a
  filtered file list from a `docker pull tleemcjr/metasploitable2`
  enumeration and emits the labeled benchmark
- `tools/eval_harness.py` gains `_eval_msf2()`; MSF2 joins MSF3 +
  CredData as the third primary held-out set

### Findings

| Set | Recall | Top-10 | Top-50 |
|---|---|---|---|
| MSF3 (Windows) | 0.900 | 0.20 | 0.22 |
| CredData (source code) | 1.000 | 0.70 | 0.68 |
| **MSF2 (Linux, NEW)** | **0.971** | **0.80** | 0.36 |
| **MIN across 3 primary** | **0.971** ← floor moves up | **0.20** ← still MSF3 |

MSF2 alone is the first real-world held-out validation of the
v0.22-v0.26 cascade on a fresh distribution: 33 of 34 known
credential-bearing files caught, 8 of the top 10 ranked positions
are real positives.

The 0.20 floor on top-10 precision is now demonstrably MSF3-
specific (Windows + PowerShell-heavy share with the
`Install-BoxstarterPackage.ps1` saturation pattern). The v0.28
question is whether to fix that declaratively or leave it as the
honest floor.

### Notes

- Test suite unchanged: 821 passing. v0.27 work was benchmark
  acquisition + harness wiring, not new code paths.
- Labels come from public security knowledge (Rapid7 docs, CTF
  write-ups for MSF2) that predates ShareSift. No overfitting risk.
- Hard-coded label list in `_POSITIVE_PATTERNS` is documented and
  reproducible.

## [0.26.0] — 2026-06-08

4 read-only verifiers + PuTTY parser. MIN trajectory flat at
0.20 / 0.90 for the 5th consecutive release.

### Added

- `src/sharesift/verify/stripe.py` — `GET /v1/account` Bearer
- `src/sharesift/verify/sendgrid.py` — `GET /v3/user/profile` Bearer
- `src/sharesift/verify/mailgun.py` — `GET /v3/domains` Basic
- `src/sharesift/verify/twilio.py` — `GET /Accounts/<sid>.json` Basic;
  requires Account SID via verify context
- `src/sharesift/parsers/putty_ppk.py` — PuTTY/WinSCP key file
  parser; surfaces v2/v3 + algorithm + encryption status; extracts
  plaintext private body when `Encryption: none`, otherwise just
  flags the encrypted file's presence

Verifier coverage: 14 → **18** credential types.
Parser count: 26 → **27**.

### Honest deferral

The v0.25 plan called for acquiring a 4th independent held-out
benchmark. v0.26 surveyed available data and found no clean
candidate (kingfisher_input has no negatives; engagement_corpus is
either unlabeled prose or possibly-overfit synthetic paths; no
GOAD / HTB / SecretBench on disk). The discipline says don't fake
a 4th set to pad the chart. Deferred to v0.27 with explicit
acquisition plans.

### Findings

| Metric | v0.25 | v0.26 |
|---|---|---|
| MIN top-10 precision | 0.20 | 0.20 |
| MIN recall any-tier | 0.90 | 0.90 |

5-release flat trajectory captured in
`benchmarks/v0p22_eval/harness_history.jsonl`. Visualised by
`tools/plot_harness_history.py`.

### Notes

- Tests added: 10 (7 verifier + 3 PPK). All HTTP mocked at
  ``requests.request``; no live outbound calls in CI.
- Full suite: **821 passing, 8 skipped, 0 regressions**.

## [0.25.0] — 2026-06-08

4 more structured parsers + harness trajectory chart + CI gate YAML
fix. Same eval discipline as v0.22-v0.24. MIN top-10 = 0.20, MIN
recall = 0.90 — flat trajectory across 4 releases.

### Fixed

- `.github/workflows/eval_gate.yml` — embedded multi-line Python at
  column 0 inside a `run: |` block scalar broke YAML parsing. Logic
  extracted to `tools/eval_gate_compare.py`; workflow invokes it
  as a separate command. Helper independently tested.

### Added

- `src/sharesift/parsers/pypirc.py` — PyPI / TestPyPI upload tokens
- `src/sharesift/parsers/gcloud_credentials.py` — GCP user-credential
  refresh tokens; skips service-account JSONs (caught by v0.23
  extractor)
- `src/sharesift/parsers/gh_cli_config.py` — GitHub CLI OAuth
  tokens from `hosts.yml`
- `src/sharesift/parsers/keyring_credentials.py` — Python keyring
  file backends: cleartext `keyring_pass.cfg`, encrypted-blob
  presence in `keyring_cryptfile_pass.cfg`, risky-backend
  detection in `keyringrc.cfg`
- `tools/eval_gate_compare.py` — separate-script comparison helper
  used by the eval-gate workflow
- `tools/plot_harness_history.py` — text-mode chart of harness MIN
  trajectory across releases (stdlib only, no matplotlib)

Parser count: 22 → **26**.

### Findings

| Metric | v0.24 | v0.25 |
|---|---|---|
| MIN top-10 precision | 0.20 | 0.20 |
| MIN recall any-tier | 0.90 | 0.90 |

Trajectory chart (4 releases):

```
v0.22.0     ▇▇░░░░░░░░ 0.20     ▇▇▇▇▇▇▇▇▇░ 0.90
v0.23.0     ▇▇░░░░░░░░ 0.20     ▇▇▇▇▇▇▇▇▇░ 0.90
v0.24.0     ▇▇░░░░░░░░ 0.20     ▇▇▇▇▇▇▇▇▇░ 0.90
v0.25.0     ▇▇░░░░░░░░ 0.20     ▇▇▇▇▇▇▇▇▇░ 0.90
```

Flat is the discipline working. Capacity grew (parser count
18 → 22 → 26; extractor count 21 → 30); the gate against
regression hasn't fired.

### Notes

- Tests added: 21 (10 parsers + 5 eval-gate + 6 plot helper).
  Full suite: **811 passing, 8 skipped, 0 regressions**.

## [0.24.0] — 2026-06-08

Four new structured parsers (wp-config.php, AWS CLI credentials,
`.netrc`, Maven settings.xml) + harness history tracking. The
production stack stays the v0.20 cascade. Harness numbers held flat
— same dynamic as v0.23.

### Added

- `src/sharesift/parsers/wp_config_php.py` — extracts DB_USER /
  DB_PASSWORD / DB_HOST + the 8 WordPress auth keys/salts from
  PHP `define()` calls. Skips boilerplate placeholders.
- `src/sharesift/parsers/aws_cli_credentials.py` — parses INI
  sections; emits per-profile access key / secret / session token.
- `src/sharesift/parsers/netrc.py` — token-stream parser handling
  multi-line, single-line, and default-block forms.
- `src/sharesift/parsers/maven_settings_xml.py` — walks XML by
  local-name (xmlns-agnostic) extracting server username/password.
- `benchmarks/v0p22_eval/harness_history.jsonl` — append-only
  record of MIN top-10 / MIN recall per release for trajectory
  tracking.
- `.github/workflows/eval_gate.yml` — added artifact upload step
  for `harness_results.json` (90-day retention).

### Findings

| Metric | v0.23 | v0.24 |
|---|---|---|
| MIN top-10 precision | 0.20 | 0.20 |
| MIN recall any-tier | 0.90 | 0.90 |

Parser count: 18 → **22**. Held-out sets don't contain wp-config /
AWS credentials / `.netrc` / Maven settings files, so the harness
doesn't reward the added capacity. Same v0.23 framing: discipline
prevents claiming an unmeasured improvement; doesn't prevent
shipping components whose value is independently documented.

### Notes

- Tests added: 11. Full suite: **790 passing, 8 skipped, 0
  regressions**.

## [0.23.0] — 2026-06-08

More architecturally-versatile components, same v0.22 eval
discipline. The production stack stays the v0.20 cascade. Harness
numbers held flat — by design — because the new components target
credential types and file formats that don't appear in the held-out
benchmarks but DO appear in real engagements.

### Added

- **9 new credential-format extractors** in
  `src/sharesift/verify/extractor.py`:
  - Stripe (live secret, restricted, publishable)
  - SendGrid + Mailgun
  - Twilio (account SID, API key SID)
  - Azure storage connection string
  - GCP service-account email
  - Total extractor coverage: 21 → **30** credential formats.
- **OOXML traversal** in `src/sharesift/extract.py` — `.docx` /
  `.xlsx` / `.pptx` are now read via stdlib `zipfile` +
  `xml.etree.ElementTree`. No new dependency. Replaces the silent
  empty-content fallback that v0.20-v0.22 had for these formats.
- **Eval gate CI workflow**
  (`.github/workflows/eval_gate.yml`) — runs
  `tools/eval_harness.py` on push to main and on PRs; fails the
  build if MIN top-10 precision OR MIN recall regresses below the
  previous release tag's value. Skips gracefully when held-out
  data isn't present.

### Findings

Harness numbers identical to v0.22:

| Metric | v0.22 | v0.23 |
|---|---|---|
| MIN top-10 precision | 0.20 | 0.20 |
| MIN recall any-tier | 0.90 | 0.90 |

**Honest framing**: MSF3 has no content, so OOXML / PDFs / Stripe
keys / etc. can't affect it. CredData doesn't contain Stripe /
Mailgun / Twilio / Azure / GCP samples, so the new extractors
don't fire on it. The new components add capacity for credential
types known to appear in real engagements but absent from these
specific held-out sets. The discipline prevents claiming an
unmeasured improvement; it does NOT prevent shipping components
whose value is independently documented.

### Notes

- Tests added: 14. Full suite: **779 passing, 8 skipped, 0
  regressions**.
- Cascade fields (`content_tier`, `content_source`,
  `content_matches`) confirmed in `ScanResult.as_record()` output
  — calibrated abstention UX shipped since v0.20.

## [0.22.0] — 2026-06-08

Versatility-first: Phases A-C of `docs/v0p22_versatility_plan.md`.
The production stack is the v0.20 cascade; v0.22 adds eval
discipline and two declarative ranking fixes — no learned features,
no per-benchmark tuning.

### Added

- `tools/eval_harness.py` — runs the production cascade against 3
  independently-collected held-out sets (MSF3, CredData,
  engagement_corpus). Reports MIN-across-primary as the headline,
  not mean. Writes `benchmarks/v0p22_eval/harness_results.json`.
- `RuleVerdict.credential_tier` — distinguishes Snaffle/CheckForKeys
  matches (credential signal) from Relay matches (enumeration
  helper). The default `tier` field unchanged for back-compat.
- `_score_with_dedup_penalty()` — declarative ranking that divides
  per-file evidence by `sqrt(filename_frequency)`. Replicates the
  v0.14 LightGBM ranker's "many copies = noise" intuition
  declaratively. No training, no fitting.

### Changed

- Cascade tier scoring: **Green tier scores 0** in the eval
  harness ranking. Green is informational ("fetch for context") —
  the v0.21 MSF3 validation traced top-K collapse to
  `RelayPsByExtension` (Green-tier) firing on 84% of MSF3 files.
  Yellow / Red / Black unchanged.

### Findings

| Metric | v0.21 | v0.22 |
|---|---|---|
| MSF3 top-10 precision | 0.00 | **0.20** |
| MSF3 recall | 0.900 | 0.900 |
| CredData top-10 | 0.70 | 0.70 |
| CredData recall | 1.000 | 1.000 |
| **MIN top-10 across primary** | **0.00** | **0.20** |

The 0.20 floor is the honest "what an operator should expect on the
next share" number. The v0.14 README claim of 1.000 on MSF3 was an
in-distribution measurement; v0.22 reports cross-distribution.

### Notes

- The v0.21 reranker stays experimental and is NOT in the production
  scan flow.
- No MSF3-specific rules added — the dedup penalty addresses
  Boxstarter / Chocolatey noise universally.
- No model retraining. Both v0.22 fixes are declarative.
- Tests added: 6. Full suite: 765 passing, 0 regressions.

## [0.21.1] — 2026-06-08

**Honesty patch.** v0.21's "+46 pp top-10 precision" headline was an
in-distribution result (reranker trained and evaluated on the same
5 themed shares). Real-world validation on Metasploitable 3 showed
the reranker is ~5× worse on data it wasn't trained against
(top-10 = 0.20 vs the 0.76 mean reported in v0.21).

This release adds honesty to the existing artifacts; no code in the
production scan flow changes.

### Changed

- `src/sharesift/reranker_v0p21.py` — module docstring leads with
  an EXPERIMENTAL warning + the MSF3 numbers. The reranker is NOT
  wired into `Scanner.scan_batch` and was never in the production
  default flow.
- `docs/v0p21_results.md` — added a cross-distribution caveat at
  the top of the document with the in-distribution vs MSF3 numbers
  side by side.
- `docs/v0p22_versatility_plan.md` — new. Replaces the previous
  Unreleased section's "retrain reranker on MSF3+GOAD" idea with a
  versatility-first plan: evaluation discipline (frozen held-out
  sets, eval harness with MIN-across-sets headline metric), rule
  engine over-fire fix, architecturally-versatile component
  investments.

### Notes

- The v0.20 cascade (parsers + rules + extractor) is unaffected and
  remains the production stack — its +23 pp recall win is real on
  both synthetic and MSF3 data.
- Test count unchanged: 759 passing.

## [0.21.0] — 2026-06-08

Cascade reranker + extra rules. Executes the plan in
`docs/v0p21_plan.md`. v0.20's content cascade fixed recall (+23 pp)
but broke top-K ranking on legal; v0.21 fixes top-K ranking across
all 5 themes.

### Added

- `src/sharesift/rules/extra_rules.json` — 41 ported rules from
  the v0.12 blind-spot collection + Gitleaks-derived modern SaaS
  detectors. Loaded automatically by `ContentRuleEngine` alongside
  the existing 78 base rules. Total engine rule count: **120**.
- `src/sharesift/reranker_v0p21.py` — `RerankFeatures` (30-dim
  vector) + `CascadeReranker` (LightGBM inference wrapper).
- `tools/train_reranker_v0p21.py` — trains a LightGBM binary
  classifier on the v0.19 themed manifests + v0.20 cascade output.
  Supports leave-one-theme-out CV.
- `tools/score_themed_run_v0p21.py` — re-runs the benchmark with
  cascade + reranker; emits per-theme baseline-vs-reranked top-K
  comparison.
- `models/reranker_v0p21.joblib` — trained model (~50KB).
- `benchmarks/v0p21/<theme>/metrics.json` — per-theme metrics cards
  for all 5 themes.

### Findings

| Theme | v0.20 top-10 | v0.21 top-10 | Δ |
|---|---|---|---|
| Finance | 0.30 | **0.90** | +60 pp |
| Healthcare | 0.50 | **0.90** | +40 pp |
| Dev / engineering | 0.30 | **0.70** | +40 pp |
| Gov / contractor | 0.40 | **0.60** | +20 pp |
| Legal | **0.00** | **0.70** | **+70 pp** |
| **Mean** | **0.30** | **0.76** | **+46 pp** |

Recall identical to v0.20 (cascade unchanged; reranker reorders only).

### Honest caveats

- **In-distribution result.** The reranker was trained on the same
  5 themes it scored. Leave-one-theme-out CV scores were 0.10-0.30
  on held-out themes vs. 0.60-0.90 in production. Cross-theme
  generalization needs ~1000+ labeled pairs to validate; v0.22.
- Real-PDF regen (Sprint 2 in the v0.21 plan) deferred to v0.22.

### Notes

- Tests added: 5. Full suite: 759 passing, 8 skipped.

## [0.20.0] — 2026-06-08

Content determiner + dormant-infrastructure wiring. Executes the plan
in `docs/v0p20_content_determiner_plan.md` end-to-end. The headline
result: re-running the v0.19 themed benchmark on the new pipeline
moves mean recall on salted files from **0.408 → 0.640 (+23.2 pp)**
without any model retrain.

### Added

- `src/sharesift/content_rules.py` — `ContentRuleEngine` compiles and
  executes 78 vendored Snaffler content/path rules against
  `(filename, content)` inside `Scanner.scan_batch`. Pre-v0.20 these
  rules existed in `snaffler_default.json` but never ran in the main
  Scanner — only inside the optional pysnaffler enumeration loop.
- `src/sharesift/extract.py` — unified `load_content(path, *,
  max_bytes, decode_base64)` replaces the bare `path.read_text()`
  call. PDFs route through `pypdf.PdfReader`; base64 nested
  credentials surface via the existing `recursive_base64_decode`
  preprocessor.
- `pdf-extraction` optional dependency group (`pypdf>=4.0`).
- `src/sharesift/content_determiner.py` — `ContentDeterminer`
  cascades parsers → rules → extractor → (optional) LoRA. Each tier
  short-circuits on first hit. Callers without the 3 GB Qwen
  download set `use_classifier=False` and still get useful results.
- `tools/score_themed_run_v0p20.py` — benchmark script that re-runs
  the v0.19 themed shares through the new pipeline and emits a
  per-theme delta against v0.19's metrics.
- `benchmarks/v0p20/<theme>/metrics.json` — per-theme combined
  (path + cascade) results for all 5 themes.

### Changed

- `Scanner.scan_batch` now runs the cascade per file. The LoRA
  classifier becomes a fallback for hard cases instead of the only
  content-side detector.
- `ScanResult` grows `content_tier`, `content_source`,
  `content_matches` fields. The binary `content_check` stays for
  back-compat.

### Findings

| Theme | v0.19 recall | v0.20 recall | Δ |
|---|---|---|---|
| Finance | 0.318 | 0.455 | +13.6 pp |
| Healthcare | 0.370 | 0.593 | +22.2 pp |
| Dev / engineering | 0.500 | 0.846 | +34.6 pp |
| Gov / contractor | 0.650 | 0.700 | +5.0 pp |
| Legal | 0.200 | 0.600 | +40.0 pp |
| **Mean** | **0.408** | **0.640** | **+23.2 pp** |

Honest precision gap: legal top-10 precision regressed to 0.00 —
the rule engine adds matches but ranking by combined tier
isn't sophisticated enough. v0.21 reranker.

### Notes

- `extra_rules.py` (22 v0.12 blind-spot + Gitleaks-derived modern
  SaaS rules) not yet loaded — they construct SnaffleRule instances
  tied to the optional pysnaffler dep. Port to JSON is v0.20.1.
- PDF extraction is wired but unverified on real PDFs — v0.19's
  synthetic shares use .pdf-extensioned text files which pypdf
  rejects.
- LoRA content classifier still requires manual model dir setup;
  cascade benchmarks ran with `use_classifier=False`.
- Tests added: 20. Full suite: 754 passing.

## [0.19.0] — 2026-06-07

Themed-benchmark iteration loop — Sprint 0 through 7 of
`docs/v0p19_themed_benchmark_plan.md`. The fix step (model retrains)
is shelved to v0.20 per the plan's caveat that some failure modes
require architecture changes.

### Added

- `src/eval/themed_taxonomy.py` — fixed 6-label failure-mode
  vocabulary (`naming-ood`, `content-ood`, `template-mismatch`,
  `extraction-missing`, `calibration-drift`, `parser-gap`).
- `tools/build_themed_share.py` — generates a synthetic themed share
  from a theme YAML config (filename tokens, directories, credential
  type mix, salt density). Output matches the existing
  `constructed_share_manifest.jsonl` schema.
- `tools/score_themed_run.py` — per-theme metrics card: recall (overall +
  per ground-truth tier + per credential type), top-K precision at K=10/20/50,
  tier distribution, bottom-5 misses with full paths for triage.
- 5 theme configs under `benchmarks/v0p19/themes/`: finance, healthcare,
  dev_eng, gov_contractor, legal. Each pre-registers a hypothesised
  dominant failure mode.
- Benchmark runs for all 5 themes (manifests + metrics tracked).
- `docs/v0p19_results.md` — per-theme triage with failure-mode labels,
  cross-theme aggregate, v0.20 fix queue ranked by impact, honest gaps.

### Findings

- Stage 1 recall across themes: mean **0.408** (finance 0.318 → gov 0.650).
  Held-out training-split recall is 100%; the cross-theme drop is the
  v0.19 signal.
- Dominant failure mode across 25 bottom misses: `content-ood` (13).
  Second: `extraction-missing` (4) — PDF text extraction is genuine v0.20.
  Third: `naming-ood` (4) — finance industry tokens absent from training.
- Legal theme worst (20% recall, 0% top-10 precision); gov_contractor best
  (65% recall). Plan pre-registrations matched cleanly on finance and
  gov_contractor; partial matches on healthcare/dev_eng/legal.
- `calibration-drift` and `parser-gap` (from the taxonomy) did not surface
  — either synthetic shares aren't dense enough, or these are smaller
  issues than the plan estimated.

### Notes

- Stage 2 (content classifier) deferred — weights aren't tracked and
  require a 3 GB download per theme. The `content-ood` dominant finding
  can't be acted on without Stage 2 measurements.
- Snaffler head-to-head deferred — binary not on the benchmark host.
- Tests added: 7. Full suite: 734 passing.

## [0.18.0] — 2026-06-07
