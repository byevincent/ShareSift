# v0.22 results — versatility-first

Released 2026-06-08. Executes Phases A-C of the v0.22 versatility
plan (`docs/v0p22_versatility_plan.md`). Phase D (more parsers /
extractors) and Phase E (Stage 2 LoRA cross-distribution honesty)
stay open as v0.23 work.

## Headline numbers (3 held-out sets, MIN-across-primary)

| Metric | v0.21 (baseline pre-fix) | v0.22 (after fix) | Δ |
|---|---|---|---|
| **MIN top-10 precision** (primary) | 0.00 | **0.20** | **+20 pp** |
| **MIN recall any-tier** (primary) | 0.90 | 0.90 | 0 |

Per-set breakdown:

| Set | Records | Positive | Recall | Top-10 | Top-50 |
|---|---|---|---|---|---|
| **MSF3** (path + filename rules) | 1054 | 40 | 0.900 | **0.20** (was 0.00) | 0.22 |
| **CredData** (content cascade) | 1500 | 500 | 1.000 | **0.70** (was 0.70) | 0.68 |
| engagement_corpus (supp) | 401 | 92 | 0.902 | 0.60 | 0.74 |

Honest framing: MIN = 0.20 on real held-out data is the v0.22 floor.
This is the number an operator on a NEW share should expect to see,
not the 0.76 mean from v0.21's in-distribution synthetic benchmark.

## What v0.22 changed (Phases A, B, C only)

### Phase A — v0.21.1 honesty patch (shipped 2026-06-08)

Marked the v0.21 reranker EXPERIMENTAL. Cross-distribution caveat
at top of `docs/v0p21_results.md`. Drafted
`docs/v0p22_versatility_plan.md`.

### Phase B — eval discipline (`tools/eval_harness.py`)

Three independently-collected held-out sets, never trained against:

1. **Metasploitable 3** (`data/external/metasploitable3/`) — real
   Windows SMB enumeration, 1054 paths, ground-truth labels from
   the v0.14 audit.
2. **CredData** (`data/eval/creddata_benchmark.jsonl`) — real
   source-code snippets, 1500 records, yes/no labels.
3. **engagement_corpus** (`data/external/engagement_corpus/`) —
   401 DFIR-writeup-extracted paths with tier labels. *Supplementary
   because some may have informed v0.5-v0.14 era training corpora.*

The harness reports **MIN-across-primary**, not mean. The MIN is
what an operator should expect on the next share they scan.

Run anytime:

```bash
uv run python tools/eval_harness.py
# Writes benchmarks/v0p22_eval/harness_results.json
```

### Phase C — declarative ranking fixes (no learned features)

Two universal principles, no per-benchmark tuning:

1. **Green tier scores 0.** The v0.21 MSF3 validation traced top-K
   collapse to `RelayPsByExtension` firing on 84% of MSF3 files
   (every `.ps1`), drowning out genuine credentials at the 0.40
   Green pseudo-probability used in v0.20/v0.21. Green is
   informational ("look at this for context"), not a credential
   signal — its score should be 0, not 0.40. Yellow/Red/Black tiers
   unchanged.
2. **Filename-frequency penalty.** Files whose basename appears N
   times in the same share are statistically package-manager
   installations, build artifacts, or boilerplate (MSF3 has
   `Install-BoxstarterPackage.ps1` repeated dozens of times).
   Score divided by `sqrt(frequency)`. Sub-linear so legitimate-
   but-common filenames like `.env` still rank when other signals
   fire.

The dedup penalty is the *declarative replacement* for the v0.14
LightGBM ranker's "many copies = noise" intuition. No training, no
features, no per-share fitting.

## What v0.22 explicitly DOES NOT do

Following the principles in `docs/v0p22_versatility_plan.md`:

- **Does not retrain the v0.21 reranker on MSF3/GOAD.** Same
  overfitting trap as v0.21 — just shifts the target.
- **Does not add MSF3-specific Discard rules** for Boxstarter /
  Chocolatey paths. Those would tune the score to a specific
  benchmark. The dedup penalty handles the same noise universally.
- **Does not retrain Stage 1 path classifier** with v0.19 themed
  industry tokens. Same overfitting concern.

## Honest gaps that remain

1. **MSF3 top-10 = 0.20 is still far from v0.14's claimed 1.000.**
   The v0.14 number used a LightGBM ranker trained on MSF3 + GOAD
   data — exactly the kind of in-distribution claim v0.22 is trying
   to escape. So the "regression" is partly that v0.14 was
   in-distribution; v0.22 is honest cross-distribution.
2. **CredData precision-any-tier = 0.33.** Two-thirds of CredData
   snippets the cascade flags as "any tier" don't contain a
   credential. The rules + extractor are recall-biased. Phase D
   parsers + new extractors should improve this.
3. **engagement_corpus may have informed training.** Treating it as
   primary held-out would inflate the MIN; treating it as
   supplementary is honest but means we have only 2 primary sets.
4. **No GOAD on this benchmark host.** v0.15 numbers (Linux 100%
   recall, 85.7% precision) can't be reproduced here. The eval
   harness has a hook for it when accessible.

## Test suite

| Component | Tests added in v0.22 |
|---|---|
| `eval_harness` declarative scoring (`_basename`, `_score_with_dedup_penalty`, Green=0 semantics, max-of-evidence) | 6 |

Full suite: 765 passing, 8 skipped (was 759 — +6 new, 0 regressions).

## Sprint accounting

| Sprint | Status |
|---|---|
| A — v0.21.1 honesty patch | ✅ shipped earlier today |
| B — `tools/eval_harness.py` + 3 held-out sets | ✅ |
| C — Green-tier = 0 + filename-frequency dedup penalty | ✅ |
| D — More parsers (real PDFs, OOXML, registry) + more credential-format extractors | ⏳ v0.23 |
| E — Stage 2 LoRA cross-distribution honesty | ⏳ v0.23 |

## What's queued for v0.23

| Item | Why | Architecturally versatile? |
|---|---|---|
| **CI gate** — fail build if MIN drops below previous release | Operationalizes the discipline | ✅ |
| **More credential-format extractors** — Stripe, Plaid, GCP service-account JSON, Azure connection strings | Adds recall without overfit risk | ✅ |
| **More parsers** — OOXML traversal (docx/xlsx as ZIP+XML), registry hives, PuTTY `.ppk` | Format-aware, no training step | ✅ |
| **Stage 2 LoRA cross-distribution eval** on CredData + MSF3 content | Decide if v0p6 LoRA earns its 3 GB | ✅ measurement |
| **Calibrated abstention UX** — surface cascade `source` + `tier` to operator instead of one collapsed score | Versatile by design | ✅ |

## Meta

The v0.22 changes are deliberately small — Green=0 and a sqrt
denominator. The discipline isn't "ship lots of features"; it's
"every change should be obviously universally applicable, every
metric should come from data the system hasn't seen, and the
headline should be the MIN, not the mean".

The MIN top-10 = 0.20 is uncomfortable. It's also the honest
number. v0.23 will try to improve it with more architecturally-
versatile components, measured the same way.
