# diskforge_winshare_v1 — first real-share-content benchmark

The Snaffler-blind 500-path Windows benchmark in `data/eval/` is
LLM-labeled paths, not real share content. That's been the one
honesty caveat in the v0.50.1 scorecard. This corpus, built via
Stauffer's [DiskForge](https://github.com/jknyght9/diskforge),
replaces the caveat with **2525 actual files on an NTFS partition
inside a 1GB .img** — 75 positives across 16 credential categories
mixed with 2420 realistic corporate-share noise files + 20
precision-stress files + 30 windows10-template stubs.

## Head-to-head vs upstream Snaffler

The corpus runs through both pipelines: ShareSift v0.50.1 cascade
(PathClassifier ∨ ContentRuleEngine) and upstream Snaffler's 56
bundled FileEnumeration rules. Same paths, same ground truth, same
keep-policy thresholds.

| Tool | Keep policy | TP | FP | FN | P | R | F1 |
|---|---|---:|---:|---:|---:|---:|---:|
| Snaffler | Yellow+ | 16 | 4 | 59 | **0.800** | 0.213 | 0.337 |
| Snaffler | Red+ | 16 | 4 | 59 | **0.800** | 0.213 | 0.337 |
| Snaffler | Black | 11 | 4 | 64 | 0.733 | 0.147 | 0.244 |
| **ShareSift** | Yellow+ | 63 | 336 | 12 | 0.158 | **0.840** | 0.266 |
| **ShareSift** | **Red+** | **54** | **62** | **21** | **0.466** | **0.720** | **0.565** |
| ShareSift | Black | 25 | 5 | 50 | 0.833 | 0.333 | 0.476 |

**At Red+ (operator triage policy), ShareSift F1 = 0.565 vs
Snaffler F1 = 0.337.** ShareSift catches 54 of 75 creds (72%);
Snaffler catches 16 (21%). Tradeoff: Snaffler surfaces 4 false
positives, ShareSift surfaces 62.

**Operator framing:** with Snaffler on this share you'd see ~20
findings (16 real, 4 fake) and never know about the 59 missed
creds. With ShareSift at Red+ you'd see ~116 findings (54 real, 62
fake) and miss 21. More triage work, but the missed-creds count
drops from 59 → 21.

### Honest caveat — corpus bias

The 16 positive categories were authored to exercise every
ShareSift rule generation v0.46→v0.50. Snaffler's defaults don't
ship with rules for German cred filenames, CMD `set "VAR=val"`,
browser-creds meta-coverage, etc, so part of Snaffler's 21% recall
is the corpus picking fights it wasn't built for. A neutral-curated
corpus would probably show Snaffler at 40–50%. But the categories
ShareSift covers are real corporate-share shapes (operator-reported
in Snaffler's own issue tracker), not invented for benchmark-
chasing — the operational gap is genuine, just amplified by
category selection.

## The headline number depends on the keep policy

ShareSift returns tier (Green/Yellow/Red/Black). A tiered tool
measured at one threshold lies about what it's actually doing. Run
at three operator-realistic policies:

| Keep policy | What this represents | TP | FP | TN | FN | P | R | F1 |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| **Yellow+** | Aggressive sweep — "give me everything indexed" | 63 | 336 | 2114 | 12 | 0.158 | **0.840** | 0.266 |
| **Red+** | Operator triage — "Red findings first" | 54 | 62 | 2388 | 21 | 0.466 | 0.720 | **0.565** |
| **Black-only** | High-confidence escalation | 25 | 5 | 2445 | 50 | **0.833** | 0.333 | 0.476 |

The **Red+ row is the production-realistic number**. F1 0.565 on
2525 real share files with a 47% precision rate is the honest
answer to "how does ShareSift perform on a corporate share."

## Per-category recall (cascade, Yellow+ keep policy)

| # | Category | TP | Total | Recall | Notes |
|---|---|---:|---:|---:|---|
| 01 | GPP cpassword | 5 | 5 | **1.000** | KeepGppPolicyXml |
| 02 | Unattend / autounattend | 2 | 5 | 0.400 | 3 fails sourced from v4-locked PR #186 — pending v0.51 rule |
| 03 | Cloud CLI creds | 3 | 6 | 0.500 | extensionless `credentials` in `.aws`/`.azure` not matched by current rule |
| 04 | SSH keys (RSA / ED25519 / PPK) | 6 | 6 | **1.000** | |
| 05 | KeePass DB | 3 | 3 | **1.000** | |
| 06 | PowerShell history | 0 | 4 | 0.000 | KeepPSHistoryByName fires at Green only — needs content scan to elevate |
| 07 | Browser saved creds | 6 | 6 | **1.000** | Chrome/Edge/Brave/Opera/Firefox all caught |
| 08 | web.config / appsettings.json | 5 | 5 | **1.000** | |
| 09 | wp-config.php | 3 | 3 | **1.000** | |
| 10 | Cisco IOS config | 5 | 5 | **1.000** | |
| 11 | SCCM artifacts | 6 | 6 | **1.000** | All 6 caught (REMINST, Variables, Policy, SCCMContentLib$) |
| 12 | Kerberos keytab / ccache | 4 | 4 | **1.000** | |
| 13 | FileZilla saved sites | 3 | 3 | **1.000** | |
| 14 | German cred filenames | 4 | 4 | **1.000** | |
| 15 | Credential-keyword filenames | 5 | 5 | **1.000** | |
| 16 | CMD batch `set "VAR=val"` | 3 | 5 | 0.600 | 2 fails need content scan (KeepCmdSetQuotedAssignment is FileContent) |
| | **All categories** | **63** | **75** | **0.840** | |

**12 of 16 categories at 100% recall on path alone.** The four
sub-1.000 categories all have honest, structural reasons documented
above — not silent misses.

## What the FPs are made of

| Noise class | FP | of | FP rate | What's tripping rules |
|---|---:|---:|---:|---|
| software_install | 169 | 300 | 0.563 | .msi/.iso/.exe path classifier confidence at Yellow tier |
| marketing_assets | 106 | 300 | 0.353 | .psd/.jpg/.zip likewise |
| log_archives | 37 | 300 | 0.123 | .log.gz/.evtx/.zip |
| precision-stress | 5 | 20 | 0.250 | 5/20 of the stress files (password_policy.docx etc) misfire |
| hr_policy | 11 | 300 | 0.037 | mostly clean |
| template_stub | 8 | 30 | 0.267 | NTUSER.DAT etc — Windows OS files |
| project_files | 0 | 300 | 0.000 | clean |
| vendor_pdfs | 0 | 300 | 0.000 | clean |
| public_templates | 0 | 300 | 0.000 | clean |
| finance_reports | 0 | 300 | 0.000 | clean |

**Insight:** the FP volume is concentrated in
software_install/marketing/log_archives, not in document-shaped
noise. Files with binary-extension shape get probabilistic Yellow
ratings from the path classifier; document noise stays clean.

## Compared to the existing scorecard

| Benchmark | F1 | P | R | What it measures |
|---|---:|---:|---:|---|
| Linux rule-blind (500) | 0.944 | 0.911 | 0.980 | Linux paths Snaffler doesn't rule on |
| Snaffler-blind Windows (500) | 0.842 | 0.984 | 0.736 | LLM-labeled Windows paths (synthetic) |
| **diskforge_winshare_v1 Red+ (2525)** | **0.565** | **0.466** | **0.720** | **Real Windows NTFS partition with corp share content** |

The 0.984 P on Snaffler-blind was always going to drop on real
share content — synthetic LLM-curated paths don't have the volume
of corporate noise a real share has. This corpus is the honest
floor under that number.

## What this corpus is and isn't

**It is:**
- 2525 actual files on an NTFS partition, generated by Stauffer's
  DiskForge tool from a reproducible JSON manifest.
- 75 positives format-shaped to fire on every rule generation
  ShareSift has added (v0.46→v0.50).
- 2420 realistic corporate-share noise + 20 precision-stress
  filenames designed to trip credential-keyword rules.
- Reproducible: `bash tools/diskforge_winshare/build_corpus.sh`
  produces a byte-identical corpus given the committed seed.

**It isn't:**
- Functional credential content. Every "password" is the literal
  string `FAKE-<descriptor>-2024!`; every AWS key is the AWS docs
  placeholder. Path-stage benchmark only.
- A v2 content-stage benchmark. ShareSift's content classifier
  (Qwen3-1.7B LoRA) isn't scored against this corpus yet.
  Categories that need content-scan elevation (PSHistory, CmdSet,
  some cloud creds) currently score 0–50% recall here; running
  the content classifier would lift them.
- An SMB enumeration benchmark. The disk image isn't served via
  smbd; paths are walked from the .img directly. ShareSift's SMB
  discovery / probe code is exercised by a separate benchmark
  (`metasploitable3` head-to-head).

## v0.51 candidates this corpus surfaces

1. **Extensionless `credentials` files in dotdir** (`.aws/credentials`,
   `.azure/credentials`, `.docker/config.json`). Current rule
   requires `\.<ext>$`. Worth a separate FileName rule:
   `(\\\.aws|\\\.azure|\\\.docker)\\credentials$`.
2. **Content scan integration in the benchmark.** PSHistory and
   CmdSet would jump from 0% / 60% to ~100% with content.
3. **Sysprep / answer.xml extension coverage** (v4-locked PR #186,
   v0.51 candidate already in CHANGELOG).
4. **Path classifier precision on software_install** — 169/300 FPs
   on .msi/.iso/.exe is high. The classifier seems to assign Yellow
   confidence to binary-extension paths regardless of share
   location. v0.51 candidate: a path-suffix-floor rule to demote
   bulk-install paths.

## Reproducing

```bash
# Requires: docker, 7z, python3, sharesift venv
cd tools/diskforge_winshare
bash build_corpus.sh
# → data/external/diskforge_winshare_v1/{file_list.txt, ground_truth.jsonl}
# → reports/v0p50_benchmark_sweep.json (after `tools/run_full_sweep.py`)
```

Same seed = byte-identical corpus (SHA256 of the file tree is
`41de2b197036fd60dc51273ab67b13aa741496358b9acecf932a49a8798bec1f`).
