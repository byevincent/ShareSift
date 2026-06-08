# v0.29 results — DiskForge Windows-shaped held-out set

Released 2026-06-08. The v0.27→v0.28 deferral closed: built a
Windows-shaped held-out set using Jacob Stauffer's DiskForge tool
(Docker-based forensic disk-image builder). Added as a
**supplementary** set because the synthetic disk has too high a
positive density to be a realistic top-K precision test.

## Headline (MIN held, supplementary set surfaces new data)

| Metric | v0.28 | v0.29 |
|---|---|---|
| MIN top-10 precision (primary) | 0.20 | 0.20 |
| MIN recall any-tier (primary) | 0.90 | 0.90 |
| Primary sets | 3 | 3 |
| Supplementary sets | 1 | **2** (engagement_corpus + diskforge_win10) |

## What we got from DiskForge

The 43-record disk contains 12 credential-bearing files at paths
documented in Snaffler default rules + MITRE ATT&CK T1552:

| Plant | Cascade caught? | Tier from path classifier | Tier from rule engine |
|---|---|---|---|
| `unattend.xml` | ✅ | Yellow | Red |
| `web.config` | ✅ | Red | Green |
| `Groups.xml` (GPP cpassword) | ✅ | Yellow | Red |
| `passwords.kdbx` | ✅ | Red | Black |
| `.aws/credentials` | ✅ | Red | Green |
| `.ssh/id_rsa` | ✅ | Black | Black |
| **`.pypirc`** | ❌ | None | None |
| PowerShell history | ✅ | Yellow | Green |
| `wp-config.php` | ✅ | Black | Red |
| `wp-config.php.bak` | ✅ | Red | Yellow |
| `server.ppk` | ✅ | Yellow | Black |
| `hosts.yml` (gh CLI) | ✅ | Red | Green |

**Recall: 11/12 = 0.917. Top-10 precision: 0.50** (5 of top-10 ranked
files are real positives; the high positive density of the planted
benchmark means random ranking already gets ~28%).

## Why DiskForge is supplementary, not primary

| Set | Positive rate | Realistic? |
|---|---|---|
| MSF3 | 3.8% (40/1054) | ✅ realistic enumeration |
| CredData | 33% (500/1500) | content-side, no path-rate concept |
| MSF2 | 2.3% (34/1500) | ✅ realistic enumeration |
| **DiskForge** | **28% (12/43)** | ❌ over-dense planted test |
| engagement_corpus | 23% (92/401) | ❌ already supplementary; overfit risk |

Making DiskForge primary would inflate the MIN trajectory chart
without telling us anything about real-share precision. The
discipline is **what counts as "the headline number" matters**.
Supplementary classification keeps it visible as a sanity check
without contaminating the primary signal.

## The .pypirc miss is a real finding

The one plant the cascade didn't catch is `.pypirc`. We added a
parser for it in v0.25 — but **no rule** in the engine. Parsers
extract structured fields (and would have caught content if the
file were content-scanned), but they don't contribute to the
cascade's path-side tier signal.

This is a real architectural gap: **a credential-bearing filename
that has a parser but no rule won't fire at the cascade tier
without content.** The v0.30 fix is straightforward — add filename
rules to `extra_rules.json` for the v0.24/v0.25 parser families:

| Parser added in | Filename rule needed |
|---|---|
| v0.24 wp_config_php | ✅ already in Snaffler defaults |
| v0.24 aws_cli_credentials | needed: `^credentials$` in `.aws/` dirs |
| v0.24 netrc | needed: `^\.netrc$` |
| v0.24 maven_settings_xml | needed: `^settings\.xml$` (but ambiguous) |
| v0.25 pypirc | needed: `^\.pypirc$` |
| v0.25 gcloud_credentials | needed: `^application_default_credentials\.json$` |
| v0.25 gh_cli_config | needed: `^hosts\.yml$` (but ambiguous with Ansible) |
| v0.25 keyring_credentials | needed: `^keyring_pass\.cfg$` |

The pattern: parsers added without paired rules left a recall gap on
path-only enumeration (where no content is available). v0.30 closes
this declaratively.

## What shipped

### Phase 1 — DiskForge benchmark builder

`tools/diskforge_v0p29/manifest.json` + `files/plant/*` document the
exact set of 12 credential payloads and where they get planted.
Reproduced by:

```bash
git clone https://github.com/jknyght9/diskforge.git /tmp/diskforge
cd /tmp/diskforge && docker build -t diskforge .
docker run --rm --privileged \
    -v $PWD/tools/diskforge_v0p29/manifest.json:/manifest.json \
    -v $PWD/tools/diskforge_v0p29/files:/files \
    -v /tmp/msf_diskforge/output:/output \
    diskforge /manifest.json
```

Full repro instructions in `tools/diskforge_v0p29/README.md`.

### Phase 2 — Wire as supplementary held-out set

`tools/eval_harness.py` gains `_eval_diskforge_win10()`. Marked
supplementary so it shows up in per-set metrics but doesn't
contribute to the MIN headline.

`tools/build_diskforge_benchmark.py` reads the manifest + the
extracted file list and writes `data/external/diskforge_win10/`
with the ground truth derived directly from the manifest's
`add_files` entries — no manual labeling, no overfitting.

### Phase 3 — Stauffer's tool credited

`README.md` Limitations + this results doc acknowledge DiskForge's
provenance. Vincent's former professor's tool turned out to be
exactly the right primitive for building reproducible labeled
disk images.

## Honest scope and limits

- **43 files is a small dataset.** Generating a larger DiskForge
  image with more negative-class noise would make top-K precision
  meaningful as a primary metric. Not done in v0.29; could be done
  with a deeper Windows 10 template + a larger disk size.
- **The planted credentials are realistic file SHAPES**, but the
  rest of the Windows 10 directory tree is sparse template stubs,
  not real Windows binary files. A real Windows share has lots of
  benign `.dll` / `.exe` / event log files; DiskForge templates
  don't simulate those.
- **The .pypirc miss is real but small.** It's the v0.30 fix
  candidate; not a v0.29 regression.

## Tests

Full suite unchanged: 821 passing. v0.29 work was data + tooling,
not new code paths.

## Sprint accounting

| Sprint | Status |
|---|---|
| 1 — Stauffer's DiskForge discovery + manifest + payloads | ✅ |
| 2 — Build docker image + generate disk + extract file list | ✅ |
| 3 — Harness wiring as supplementary | ✅ |
| 4 — Re-run, identify gaps (.pypirc miss = no rule for parser-only filenames) | ✅ |
| 5 — Document + ship | ✅ |

## What's queued for v0.30

| Item |
|---|
| **Close the parser-without-rule gap** documented above — add filename rules to `extra_rules.json` for the v0.24/v0.25 parser families |
| Generate a larger DiskForge image (more negatives) to consider promoting it to primary |
| Azure storage account verifier (carryover from v0.26→v0.27→v0.28) |
| GCP service-account verifier (carryover) |
| Registry hive parser when samples accessible |

## Meta

v0.29 is the first release where:
- We acquired a new held-out set
- AND it surfaced a real architectural gap (.pypirc — parser without rule)
- AND we documented the supplementary-vs-primary classification honestly
- AND we credited the third-party tool that made the acquisition cheap

The trajectory chart still says 0.20 / 0.90 — but the SHAPE of what
we know about the system grew. That's what disciplined releases
trade flat headline numbers for.
