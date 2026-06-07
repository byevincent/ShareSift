# v0.11 — Linux path classifier retrain (v0p2, alt — NOT default)

Follows [v0.10 content docx retrain](v0p10_content_docx_retrain.md).
v0.10 closed the Stage 2 (content) operational bottleneck by
retraining on docx-shaped data; end-to-end recall went 0.091 → 0.240
(2.6×) on the constructed share. The remaining gap was Stage 1 (path
classifier): v0p1 catches only ~30% of salted paths, so even a
perfect Stage 2 caps end-to-end recall around 30%.

v0.11 retrains the Linux LightGBM on a combined corpus (existing
1348-record GitHub-mined training + 80% of v0.9's 179 writeup-labeled
boxes) with a by-box split to prevent leakage on the held-out
writeup test. **Result is a precision win + recall regression** —
useful but not the new default.

## Why this is documented as alternative-not-default

v0p2 shows clear improvement on the writeup-realistic distribution
(the target):

| Metric | v0p1 (current default) | v0p2 (this retrain) | Δ |
|---|---|---|---|
| Writeup-held-out PR-AUC | 0.27 | **0.50** | **+0.23 (1.9×)** |
| Writeup-held-out F1@0.5 | 0.28 | **0.54** | **+0.26 (1.9×)** |
| Writeup-held-out Black precision | 0.41 | **0.75** | **+0.34** |
| Writeup-held-out Red precision | 0.23 | **0.50** | **+0.27** |
| In-distribution Snaffler-blind PR-AUC | 0.99 | 0.99 | — |

But on the constructed-share end-to-end pipeline, v0p2 trades recall
for precision in a way the two-stage tier filter compounds badly:

| Pipeline | Stage 1 P/R/F1 | Stage 2 P/R/F1 | E2E F1 | Salted caught |
|---|---|---|---|---|
| v0p1 + v0p5 (was default v0.7-0.9) | 0.33 / 0.30 / 0.32 | 0.93 / 0.09 / 0.17 | 0.17 | 14 / 154 |
| **v0p1 + v0p6 (v0.10 default)** | 0.33 / 0.30 / 0.32 | **1.00 / 0.24 / 0.39** | **0.39** | **37 / 154** |
| v0p2 + v0p6 (v0.11 candidate) | **0.90** / 0.09 / 0.17 | 1.00 / **0.07** / 0.13 | 0.13 | 11 / 154 |

Mechanism: v0.11 training added 739 v0.9 records, 591 of which were
not_juicy. The corpus class balance shifted 72% juicy → 51% juicy.
The calibrator recalibrates against the new distribution and moves
probability mass downward. Fewer paths clear the Yellow (≥0.45) tier
threshold; Stage 2 has fewer flagged paths to scan; end-to-end
recall regresses.

## What v0p2 is good at

The writeup-realistic improvements are real and substantial:

* **Black-tier precision recovers**: 0.41 → 0.75 (the v0.5 audit
  contract was 0.95; v0p2 closes 54% of that gap)
* **Red-tier precision recovers**: 0.23 → 0.50 (contract 0.80)
* **None-tier becomes informative**: precision 0.16 → 0.065 (lower
  is better for the "not flagged" bucket — base rate of 12% positives
  in the writeup-test means v0p2 is *correctly identifying* the
  not_juicy paths it's leaving in None tier)

For a *high-precision-low-recall* path-triage use case (e.g.,
automated alerting where every flag will be reviewed), v0p2 is the
right choice on writeup-realistic share topology. It's selectable
via `--linux-model-dir models/path_classifier_v0p2_linux`.

## Why we kept v0p1 as Linux default

v0.10 shipped v0p6 as the content default because it satisfied
strict-win on the operational target (end-to-end recall jump). v0.11
doesn't meet that bar — end-to-end recall went down (7.1% vs 24.0%).
The trade-off is real but ships v0p2 as an alternative, not a
replacement.

## What would close the gap

Two documented but deferred paths to recover end-to-end recall while
keeping v0p2's precision wins:

1. **OOD recalibration** — mirror of the v0.5 Tier 2.1 fix for
   Windows (`docs/audit_2026-05-31.md`). Refit the IsotonicRegression
   on (train ∪ 30% of constructed-share or writeup-realistic
   benchmark) so the calibrator sees both distributions. Should move
   probability mass back up for in-distribution-similar paths without
   sacrificing the precision win on writeup paths. ~half day of work.
2. **Lower tier thresholds for v0p2** — the v0.5 thresholds (Black
   0.90 / Red 0.65 / Yellow 0.45 for Linux) were calibrated for v0p1's
   probability distribution. v0p2's mass is shifted; a corresponding
   re-derivation of thresholds (target Yellow → flag-rate ~0.55 on
   the in-distribution test) might land v0p2 in a usable end-to-end
   regime. ~1 hour of work.

## v0.11.x finding — threshold sweep showed both deferrals would FAIL

After running both threshold sensitivity + manual probability-distribution
analysis on the constructed-share salted paths, the conservative-posture
issue is baked into v0p2's *ranking*, not its calibration:

| | v0p1 (deployed) | v0p2 (v0.11) |
|---|---|---|
| Median probability on salted paths | 0.290 | **0.064** |
| Mean probability on salted paths | 0.381 | 0.133 |
| Salted-recall @ threshold 0.10 | 96.7% | **34.0%** |
| Salted-recall @ threshold 0.30 | 47.7% | 15.0% |
| Salted-recall @ threshold 0.45 | 29.4% | 8.5% |

**101 of 153 salted paths get v0p2 probability < 0.10.** Lowering
the Yellow threshold to 0.10 (essentially flagging everything that
isn't near-certain not-juicy) still only catches 34% of salted
paths. OOD recalibration moves probability mass by ~10pp typical —
nowhere near enough.

### Why v0p2's ranking penalizes the salted paths

v0p2 *correctly* learned from v0.9 writeup labels that paths like
`/home/<user>/.cache/...`, `/var/log/...`, `/etc/<service>/conf.d/...`
are usually not-juicy. Our v0.9.5 constructed-share salting
methodology dropped credentials at *random* writeup paths regardless
of whether the path-shape was "juicy" by writeup-author judgment.

So the salted paths in the constructed share happen to look like
the "usually-not-juicy" patterns v0p2 was trained to dismiss. v0p2
ranks them low — which is the *right* behavior given its training
labels, just wrong for our constructed benchmark.

### What this actually means

**The constructed-share benchmark is measuring the wrong thing for
v0p2.** It rewards aggressive (low-precision) path classifiers because
it salts random paths uniformly. A path classifier that *correctly*
distinguishes juicy from not-juicy paths gets penalized for not
flagging the not-juicy ones we happened to drop credentials at.

The right end-to-end benchmark for v0p2 would salt credentials only
at paths a pentester would flag as juicy in the first place — i.e.,
at paths that align with the writeup-author judgment v0p2 is trained
to reproduce. Building that benchmark requires either:

* Manual ground-truth labeling of which constructed-share paths
  *should* be credential-bearing (operator judgment, slow), or
* Real engagement data (closes this loop end-to-end).

This is the same engagement-data wall every other v0.X iteration
has bumped into.

### Decision

* **OOD recalibration NOT performed**: probability mapping won't fix
  ranking — the threshold sweep is conclusive on this.
* **v0p2 ships as-is**, documented as a precision-first alternative
  whose strengths on the writeup-realistic distribution (PR-AUC 0.50,
  Black precision 0.75) are real and measurable.
* **The constructed-share benchmark is now flagged as inadequate** for
  evaluating path classifiers trained on writeup labels. A
  successor benchmark requires engagement-grade ground-truth label
  placement, which is the structural project ceiling.
* This is the natural stop for public-data path-classifier work.

## v0.11.x — Path-aware benchmark confirms the calibration-not-salting framing

After hypothesizing that the v0.9.5 random-salt methodology was the
bias source, we built a **path-aware fair benchmark** that salts
credentials only at writeup-juicy-labeled paths (the labels v0p2 was
trained against). The 199-file benchmark uses the 36 held-out boxes
that neither v0p1 nor v0p2 saw at training time:

* 26 paths labeled juicy by Sonnet (against the same calibration
  positions both classifiers' training data uses) → salted with
  Kingfisher credentials
* 173 paths labeled not_juicy → plain docx-corpus content, no salt

Construction in `tools/build_constructed_share_path_aware.py`; share
at `data/external/constructed_share_v2/`; eval via the existing
`tools/eval_constructed_share.py` with `--linux-model-dir` swap.

### Results — v0p2 still underperforms v0p1

| Pipeline | Stage 1 P / R | E2E F1 | E2E R | Salted caught |
|---|---|---|---|---|
| v0p1 + v0p6 (random-salt, v0.10 default) | 0.33 / 0.30 | 0.39 | 0.24 | 37/154 |
| **v0p1 + v0p6 (path-aware)** | 0.30 / 0.44 | 0.44 | **0.28** | **7/25** |
| v0p2 + v0p6 (random-salt) | 0.90 / 0.09 | 0.13 | 0.07 | 11/154 |
| v0p2 + v0p6 (path-aware) | 0.75 / 0.12 | 0.21 | 0.12 | 3/25 |

Even on a benchmark whose salting aligns with v0p2's training labels,
v0p2 only catches 3 of 25 writeup-juicy salted paths — worse than
v0p1's 7. The fair benchmark replaces speculation with measurement:
**v0p2 is not the better deployment choice regardless of benchmark
construction.**

### The real mechanism

v0p2's PR-AUC win on the standalone writeup-realistic test (0.50 vs
0.27) is real because the *ranking* is better. But the absolute
probability magnitudes on the positive class sit in the 0.05-0.25
range across both random and path-aware benchmarks. With the Linux
Yellow tier threshold at 0.45, almost everything gets filtered out
regardless of which way we slice the eval.

This is a deeper issue than salting-methodology bias. It's a
probability-magnitude problem inherent to v0p2's training setup:

* The corpus class balance shifted 72% juicy → 51% juicy
* The class_weight=balanced LightGBM setting compensates at the
  ranking level (which is why PR-AUC improves) but produces a
  flatter probability surface
* The isotonic calibrator preserves the flatter surface
* The deployed tier thresholds (calibrated against v0p1's
  probability distribution) filter out v0p2's lower-magnitude
  positive-class predictions

OOD recalibration would shift probabilities by ~10pp typical —
nowhere near the gap. The fix would require either: rerunning the
training with a different objective (focal loss, asymmetric class
weights) or re-deriving tier thresholds against v0p2-specific
probability distributions. Both are doable but neither is "fix this
benchmark" — they're "fix this model class" work.

### What this contributes

The v0.11.x finding is now sharper:

1. **v0.11 is genuinely a negative result, not a benchmark artifact.**
   The fair-benchmark experiment confirms v0p2 underperforms v0p1 in
   deployment regardless of how we measure.
2. **The "v0p2's ranking is better" defense is true but irrelevant
   for deployment.** ShareSift ships tier-thresholded outputs; ranking
   only matters in the band of probabilities that clear the threshold.
3. **The path forward isn't a different benchmark.** It's either
   different training methodology (focal loss / asymmetric balance)
   or different deployment thresholds. Neither belongs in the v0.11
   commit; both are deferred as structurally similar to the engagement-
   data ceiling we keep hitting.

This closes the public-corpus iteration cycle for the path classifier.

## Build

`tools/build_v0p11_linux_corpus.py`:

* Reads v0.9 labeled paths, filters to Linux (kind == "linux_abs"),
  groups by source_box.
* Deterministic shuffle (seed=2026), splits 179 boxes 80/20 by box
  → 143 train-boxes / 36 test-boxes.
* Converts v0.9 records to training-corpus JSONL shape (path + label
  + tier + category + source + added_date + added_by + notes).
* Combined train: 1348 existing + 739 v0.9-train-boxes = **2087
  records** (1057 juicy / 1030 not_juicy — well balanced).
* Writeup held-out test: 216 records (26 juicy / 190 not_juicy).

## Train + calibrate

Same pipeline as v0.5:

* `tools/train_path_classifier.py --train-data
  data/eval/train_split_linux_v0p11.jsonl --model-dir
  models/path_classifier_v0p2_linux/`
* `tools/calibrate_path_classifier.py --train-data <same> --model-dir
  <same>`

Wall time ~2 min total (LightGBM is fast).

Default config retained: 300 estimators, lr=0.05, balanced class
weight, 65,544 features (65,536 char-n-gram hashes + 8 hand features).

## Eval breakdown

**1. In-distribution regression check** (existing `test_split_linux`,
337 records / 241 juicy):

| Metric | v0p1 (deployed) | v0p2 |
|---|---|---|
| PR-AUC (Snaffler-blind benchmark) | 0.99 | 0.99 |
| Black tier precision | ~0.98 | 0.99 (in-distribution test) |
| Red tier precision | ~0.85 | 0.99 |

In-distribution preserved.

**2. Writeup-realistic held-out** (216 records / 26 juicy, 36 boxes
not seen in training):

| Metric | v0p1 | v0p2 |
|---|---|---|
| P@0.5 | 0.21 | **0.54** |
| R@0.5 | 0.44 | 0.54 |
| F1@0.5 | 0.28 | **0.54** |
| PR-AUC | 0.27 | **0.50** |

Strong win on the new distribution.

**3. Constructed-share end-to-end** (1117 files / 154 salted): see
table above. End-to-end recall regression to 0.07 makes v0p2
unsuitable as a default.

## What ships in v0.11

* `tools/build_v0p11_linux_corpus.py` — by-box-split + corpus builder
* `data/eval/train_split_linux_v0p11.jsonl` — 2087-record training
  corpus (1348 existing + 739 v0.9-train-boxes)
* `data/eval/test_split_linux_v0p11_writeup.jsonl` — 216-record
  writeup-realistic held-out test (36 boxes)
* `models/path_classifier_v0p2_linux/` — trained + calibrated v0p2
  artifact (model.joblib + calibrated.joblib + metadata)
* `tools/eval_constructed_share.py` extended with
  `--linux-model-dir` / `--windows-model-dir` overrides
* `reports/constructed_share_eval.json` —
  `constructed_share_v0p2_linux_v0p6_content` entry
* This document
* README updated to surface v0p2 as the alt-not-default Linux model

## v0.11 status — what this means for the project

The v0.10 end-to-end win (recall 9% → 24%) stands. v0.11 doesn't
extend it but produces a documented precision-first Linux alternative
and a clear blueprint for the actually-helpful follow-up (Tier-2.1-
style OOD recalibration for Linux). The "Stage 1 retrain compounds
with Stage 2 retrain" hypothesis from the v0.10 commit message did
not survive contact with the data — the regularization-shaped
trade-off the writeup-mined labels induce defeats the compounding.

This is, itself, an honest finding worth recording. The v0.5 audit's
Tier 2.1 fix is the right way to reconcile the two distributions;
that work is deferred but the pieces are in place to do it later
(`reports/recalibration_audit.json` has the precedent + the
`_OODCalibratedModel` wrapper exists in `src/sharesift/path.py`).

## References

* `docs/v0p10_content_docx_retrain.md` — v0.10 content-stage win
* `docs/v0p9_writeup_realistic_benchmark.md` — the writeup benchmark
  this retrain targets
* `docs/audit_2026-05-31.md` — v0.5 audit; Tier 2.1 is the
  OOD-recalibration precedent for the v0.11.x follow-up
* `memory:feedback_labeling_calibration` — the calibration positions
  driving the v0.9 labels used here
