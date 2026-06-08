# v0.21 real-world validation — honest findings

Run on 2026-06-08 against the Metasploitable 3 (MSF3) benchmark
data already on disk at `data/external/metasploitable3/` —
1054 paths, 40 verified-positive credential files, ground-truth
labels from the v0.14 audit pass.

## The numbers

| Metric | v0.14 reported | v0.21 measured | Δ |
|---|---|---|---|
| Recall on positive files (any tier flag) | 1.000 (40/40) | **0.900** (36/40) | **-10 pp** |
| Top-10 precision (baseline ranking) | 1.000 | **0.000** | **-100 pp** |
| Top-10 precision (reranked) | 1.000 (v0.14 ranker) | **0.200** | **-80 pp** |
| Top-50 precision (reranked) | 0.740 | 0.240 | -50 pp |
| K for full recall | (not measured) | 1054 / 1054 |  precision-at-full-recall = 0.038 |

**Conclusion: the v0.21 pipeline regresses on the v0.14 headline benchmark.**

## What the +46 pp top-10 claim from v0.21 *actually* meant

The v0.21 release reported "+46 pp mean top-10 precision" across 5
themed synthetic shares. That number was honest about being
**in-distribution** (reranker trained on the same 5 themes it
scored). The leave-one-theme-out CV scores (0.10-0.30) were already
the warning sign for cross-theme generalization.

This MSF3 run is the **strongest possible test of that warning**:

* Reranker trained on synthetic themed shares (~80 files each,
  industry naming pools, 25-40% salt density)
* MSF3 is a real Windows SMB enumeration with 1054 paths, 3.8%
  positive rate, completely different naming distribution and
  cred density

Top-10 precision = 0.20 on MSF3 is the **honest number for what
"cross-theme" looks like in practice**. The 0.76 mean from the
v0.21 release is what you get when you measure on the data you
trained on. The 0.20 here is what you get when you don't.

## Why the regression happened

### Recall: -10 pp (0.90 vs 1.00)

Less concerning. Stage 1 path classifier + filename-side rules catch
36 of 40 known credentials. The 4 misses are on file paths the path
classifier scored low and that no filename-shape rule matched. These
were likely caught at Stage 2 (content classifier) in v0.14 — but
v0.21 doesn't run Stage 2 here because MSF3 ground truth doesn't
include file content, and we wanted a path-only test to compare
honestly against v0.14's headline numbers.

### Top-10 precision: -80 pp (0.20 vs 1.00)

This is the load-bearing problem. Two causes:

1. **The rule engine over-fires on MSF3.** Out of 1054 paths, the
   v0.20 cascade tiers fire on ~1000 (the Snaffler default
   `KeepNameContainsGreen` rule matches `passw`/`secret`/`credential`
   as substrings; ~95% of MSF3's PowerShell + .NET source files
   mention these words in comments or symbol names). The cascade is
   producing tons of Yellow-tier matches that aren't credentials.
2. **The v0.21 reranker doesn't transfer from synthetic to real.**
   The reranker learned that `cascade_source=rules + cascade_tier=Yellow`
   was a strong signal on the themed shares because the salt
   density was high and rule matches were rare-positive. On MSF3,
   the same feature pattern fires on most of the share, so the
   reranker can't separate signal from noise.

The v0.14 result of 1.000 top-10 precision used a LightGBM ranker
trained directly on MSF3 + GOAD data. The v0.21 reranker doesn't see
those manifests during training — it sees synthetic themed shares.

## Caught-positive source distribution

Of the 36 positives the v0.21 pipeline caught:

| Source | Count |
|---|---|
| Cascade only (rule engine fired on filename, path classifier didn't) | 31 |
| Cascade + path classifier both fired | 5 |
| Path classifier only | 0 |

Interesting: filename-side rules carry most of the load. The path
classifier in isolation only catches the same files the rule engine
already catches. This is a *win* for the cascade — it adds recall.
But the rule engine's over-firing on benign files swamps top-K
precision.

## What this tells us about v0.21's "wins"

The +23 pp recall in v0.20 was real — caused by the rule engine
catching content-side matches the path classifier couldn't see. That
finding holds: on MSF3 the cascade adds 31 recovered positives the
path classifier alone missed.

The +46 pp top-10 precision in v0.21 was **not** transferable to
real data. The reranker overfit to themed-share feature
distributions. The CV scores told us this would happen; the MSF3
run confirms it.

## What v0.22 actually needs

Updates the v0.22 fix queue based on real evidence:

| Fix | Why (with v0.21 validation evidence) | Priority |
|---|---|---|
| **Retrain the reranker on MSF3 + GOAD manifests + synthetic themes** | The synthetic-only training is the immediate cause of the MSF3 regression. Adding the v0.14/v0.15 MSF3/GOAD ground-truth as training data gives the reranker real-world patterns. | **P0** |
| **Gate `KeepNameContainsGreen` behind a length / context check** | The rule fires on every PS1 file that mentions `passw` in a comment. Either tier it down to Green explicitly or require multiple matches. | P0 |
| Stage 1 path classifier retrain | The 10% recall loss on MSF3 is partly a real gap. ~1 GPU-hour to add MSF3 + GOAD patterns to training. | P1 |
| Wire the v0p7 literal-vs-referenced classifier into cascade | Distinguishes "code mentions credential" from "code contains credential" — addresses the rule-engine over-fire. Requires weights though. | P1 |
| Expand the reranker training set (the v0.21 results doc's main caveat) | The MSF3 result IS the expanded training set if we use it; the action is "retrain with MSF3+GOAD" rather than "find more synthetic themes". | folded into P0 |

The v0.21 release stands but the headline number is misleading
without this context. Action items:

1. Update `docs/v0p21_results.md` with an explicit pointer to this
   validation doc.
2. Open a v0.22 plan that leads with retraining the reranker on
   MSF3 + GOAD + themed shares combined.
3. Do NOT advertise the +46 pp top-10 number externally without the
   "in-distribution; cross-theme top-10 is 0.20" caveat.

## What didn't break

* Recall on MSF3: 0.90 vs 1.00 v0.14 baseline. The +23 pp cascade
  recall win in v0.20 holds: cascade-only catches 31 positives the
  path classifier alone missed, in the same direction as the v0.20
  themed-benchmark result.
* The cascade architecture is right. The problem is the rule weights
  and the reranker training data — both fixable in v0.22.
* No code regression: all 759 tests still pass.

## Honest meta-finding

This is exactly why real-world validation matters. The v0.19 → v0.20
→ v0.21 arc looked like steady progress on the synthetic benchmark.
The MSF3 run shows the v0.21 reranker as a ~5x worse top-10
predictor than v0.14's ranker. Without this validation step, v0.22
would have built more on top of an unstable foundation.
