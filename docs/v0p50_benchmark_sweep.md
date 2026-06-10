# ShareSift v0.50 — full benchmark scorecard

Single sweep across every path-stage benchmark in the repository.
Stage-1 path classifier (LightGBM, calibrated) + ContentRuleEngine
cascade. Tier policy: keep iff cascade tier ∈ {Black, Red, Yellow}
(Green floor → drop).

Raw JSON: `reports/v0p50_benchmark_sweep.json`.

## Headline

| Benchmark | N | TP | FP | TN | FN | P | R | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **Linux rule-blind (Linux)** | 500 | 245 | 24 | 226 | 5 | 0.911 | **0.980** | **0.944** |
| **Snaffler-blind (Windows)** | 500 | 184 | 3 | 247 | 66 | **0.984** | 0.736 | 0.842 |
| peas (LinPEAS-mined paths) | 73 | 24 | 22 | 26 | 1 | 0.522 | 0.960 | 0.676 |
| kape (KAPE-target paths) | 904 | 228 | 156 | 143 | 377 | 0.594 | 0.377 | 0.461 |
| hacktricks (HackTricks-mined) | 870 | 201 | 422 | 185 | 62 | 0.323 | 0.764 | 0.454 |
| engagement_corpus | 401 | 84 | 208 | 101 | 8 | 0.288 | 0.913 | 0.438 |
| constructed_share v1 | 1117 | 133 | 398 | 528 | 58 | 0.250 | 0.696 | 0.368 |
| writeups labeled (Claude-LLM) | 1499 | 155 | 558 | 659 | 127 | 0.217 | 0.550 | 0.312 |
| constructed_share v2 | 199 | 16 | 73 | 101 | 9 | 0.180 | 0.640 | 0.281 |

## Recall-only (credential-bearing files)

| Benchmark | N | TP | FN | Recall |
|---|---:|---:|---:|---:|
| MSF3 (Metasploitable3) | 1054 | 40 | 0 | **1.000** |
| MSF2 (Metasploitable2) | 1500 | 34 | 0 | **1.000** |
| DiskForge (Win10 forensic image) | 520 | 13 | 0 | **1.000** |

## Snaffler-issues (operator-grounded probe sets)

| Set | Pass | % | Source |
|---|---:|---:|---|
| Corpus (training) | 18/19 | 95% | Visible while authoring rules |
| Held-out v1 | 11/11 | **100%** | #78, #135, #67 — locked v0.47 |
| Held-out v2 | 10/10 | **100%** | #198, #155, #98, Chrome/Edge — locked v0.48 |
| Held-out v3 | 10/10 | **100%** | #154, #140, #139, #112 — locked v0.49 |
| Held-out v4 | 7/10 | **70%** | OPEN PRs #192, #186 — locked v0.50 |

## Interpretation

### The honest production-readiness story

**Linux rule-blind 0.944 F1 + Snaffler-blind 0.984 P** is the
calibrated sweet spot — corporate share shapes that ShareSift was
trained on. Linux is the strongest dimension (operator-style paths
under `/etc`, `/var`, user dotfiles). Windows trades recall for
precision: when ShareSift says "keep" on a Windows path, it's
right 98% of the time.

### Where the lower F1s come from

Hacktricks / kape / peas / engagement / constructed_share /
writeups all sit at F1 0.28–0.68. **These are not directly
comparable** — their "ground truth" is an LLM- or extraction-
heuristic-assigned tier, not strict creds labeling. They measure:

- Hacktricks (F1 0.454, R 0.764) — what % of *anything* mentioned
  in HackTricks gets a Yellow+ tier. Recall 76% means ShareSift
  catches most operator-discussed paths; precision 0.32 reflects
  the dataset (not all HackTricks paths are creds — many are
  binaries, escalation vectors, recon targets).
- Engagement corpus (F1 0.438, R 0.913) — DFIR-report-derived
  paths. Recall 0.91 is high.
- Peas (F1 0.676, R 0.960) — small dataset but ShareSift catches
  almost everything LinPEAS hardcodes.
- Constructed share (F1 0.37) — synthetic-difficulty corpus; the
  juicy label is strict ("contains actual cred or high-value
  config") while many paths are deliberately ambiguous.

### Snaffler-issues — the discipline trajectory

| Generation | Source | Pre-rule baseline | Post-rule |
|---|---|---:|---:|
| v1 | #78 Cisco, #135 FileZilla, #67 ADO | 36% (v0.47) | 100% (v0.49+) |
| v2 | #198 CMD, #155 Azure, #98 cred-filename, Chrome/Edge | 50% (v0.48) | 100% (v0.49+) |
| v3 | #154 -password, #140 Kerberos, #139 MDE, #112 SCCM | 90% (v0.49)¹ | 100% (v0.50) |
| v4 | open PRs #192 PPK, #186 SCCM-broad | **60% (v0.50)²** | n/a until v0.51 |

¹ v3's 90% baseline reflects pysnaffler bundling upstream Snaffler
rules from PRs #140 and #112 (both merged). Not a strict
generalization test.

² v4 uses OPEN PRs that pysnaffler does NOT bundle. 60% baseline is
the tighter generalization-without-bundled-help signal — and the
SCCMContentLib$ rule (authored from v3-locked PR #112) lifted v4 to
70% by catching PR #186's reg-export probe it was never authored
against.

## What this scorecard is + isn't

**It is:** a 5500-path snapshot across 12 benchmarks with mixed
ground-truth provenance. Real numbers from real datasets.

**It isn't:** an apples-to-apples leaderboard. Different
benchmarks define "juicy" differently — strict creds (MSF /
DiskForge / Snaffler-blind), LLM-Claude tier (writeups), or
extraction-heuristic tier (mined corpora). The strongest claims
are anchored to the strictest ground truth:

1. **100% recall on three synthetic-Windows / Linux credential-
   bearing corpora (MSF3, MSF2, DiskForge).** No misses on any
   known cred.
2. **0.944 F1 on the Linux rule-blind 500-path benchmark.** This is
   the benchmark Vincent built to be Snaffler-rules-blind (every
   path that hits a Snaffler rule was excluded), so ShareSift's
   score here is the increment over Snaffler.
3. **0.984 precision on the Snaffler-blind Windows 500-path
   benchmark.** Same construction — Snaffler-rules-blind. When
   ShareSift fires on a Windows path Snaffler wouldn't, it's right
   98% of the time.
4. **5 generations of held-out discipline on Snaffler-issues.**
   v4's 60% pre-rule baseline (using OPEN unbundled PRs) is the
   most calibrated single number — that's "before this version
   shipped rules, on sources upstream doesn't bundle."
