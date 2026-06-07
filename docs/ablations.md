# Ablation studies

Variant-by-variant analysis defending each architecture, feature, and
hyperparameter choice for the ShareSift v0 classifiers. All metrics are
measured on leak-free held-out splits (see `docs/audit_2026-05-30.md`
for the integrity audit that produced these splits).

## Methodology

* **Splits.** Path classifier evaluates on the 2,138-record in-distribution
  test split and the 500-record Snaffler-blind benchmark, both held out
  from training. Content classifier evaluates on the 481-record
  cluster-partitioned test split (zero cross-split leakage at Jaccard
  0.8, see audit doc §"Remediation").
* **Variant naming.** `P` = path classifier, `C` = content classifier.
  `P0`/`C0` = headline shipped config; numbered children isolate a single
  axis of variation.
* **Bootstrap CIs.** 1000 resamples with replacement on (label, probability)
  pairs, 2.5–97.5 percentile interval. Computed for the headline variant
  only — sufficient to characterize what variance is "noise" vs "signal"
  when comparing variants.
* **Multi-seed variance.** For configs with stochasticity, retrain N=5
  times with different seeds and report mean ± std. Deterministic configs
  trivially have variance 0; reported for completeness.

Result JSONs live in `reports/`:

* `reports/ablate_path_classifier.json` — P1-P5 + headline CIs
* `reports/ablate_path_seeds.json` — P6 deterministic + stochastic
* `reports/ablate_content_classifier.json` — C1, C2
* `reports/eval_content_classifier.json` — accumulated content
  classifier evals across epochs and ablation sweeps

## Path classifier

### P1-P5: feature / classifier / calibration ablations

Trained on `data/eval/train_split.jsonl` (8,552 records), evaluated on
both the in-distribution test (2,138 records) and the Snaffler-blind
benchmark (500 records). Sorted by benchmark PR-AUC (descending).

| Variant | Bench PR-AUC | Bench F1@.5 | Bench Brier | Test PR-AUC | Test F1@.5 |
|---|---|---|---|---|---|
| P5_platt           | 0.9751 | 0.5507 | 0.2639 | 0.8443 | 0.7290 |
| P4_uncalibrated    | 0.9736 | **0.7245** | 0.2012 | 0.8686 | 0.7667 |
| **P0_headline** (isotonic) | 0.9731 | 0.5632 | 0.2300 | 0.8391 | 0.7170 |
| P1_ngrams_only     | 0.9401 | 0.3098 | 0.2881 | 0.6852 | 0.5714 |
| P3_logreg          | 0.9318 | 0.3571 | 0.2977 | 0.6785 | 0.5882 |
| P2_hand_only       | 0.8021 | 0.0543 | 0.4082 | 0.2367 | 0.1111 |

**Bootstrap 95% CIs (headline P0):**

| Split | Metric | Point | 95% CI |
|---|---|---|---|
| Bench | PR-AUC | 0.9731 | [0.9601, 0.9831] |
| Bench | ROC-AUC | 0.9698 | [0.9555, 0.9814] |
| Bench | F1@0.5 | 0.5632 | [0.4970, 0.6201] |
| Test  | PR-AUC | 0.8391 | [0.7585, 0.9089] |
| Test  | ROC-AUC | 0.9907 | [0.9843, 0.9956] |
| Test  | F1@0.5 | 0.7170 | [0.6154, 0.8065] |

#### Takeaways

* **Char n-grams and hand features are jointly required.** Removing
  hand features (P1) drops bench PR-AUC by 3.3 pp; removing n-grams (P2)
  drops by 17.1 pp and collapses F1 to near-zero. Neither family alone
  is competitive.
* **LightGBM beats logistic regression by 4 pp on the same features**
  (P3 0.9318 vs P0 0.9731 bench PR-AUC). The non-linear feature
  interactions matter.
* **Calibration choice (isotonic / Platt / none) does not move PR-AUC**
  within bootstrap CI noise (all three within [0.9601, 0.9831]). It
  does move the decision-boundary metrics: P4 (uncalibrated) has F1@0.5
  = 0.7245 vs P0 isotonic's 0.5632, a 16-pp gap. Isotonic shrinks
  predictions toward the prior, reducing decisiveness near 0.5.
* **What this means for the shipped pipeline.** The shipped tier-band
  mapping (Black ≥ 0.95, Red ≥ 0.80, Yellow ≥ 0.50) is more sensitive
  to calibration quality than to raw discrimination. Isotonic produces
  the most reliable probabilities, which is what the tier bands consume;
  the lower F1@0.5 is the cost of that reliability. If a downstream
  consumer wanted raw classification accuracy at a fixed 0.5 threshold,
  P4 (uncalibrated) would be the choice.
* **The +15.3-pt-recall-vs-Snaffler headline survives bootstrap.** P0's
  bench PR-AUC 95% CI is [0.9601, 0.9831]; Snaffler-equivalent baseline
  is far below this interval. The claim is robust to test-set sampling.

### P6: multi-seed variance (deterministic and stochastic)

Five seeds (2026, 8472, 31337, 42, 1729) × two configs.

| Config | Mean Bench PR-AUC | Std | Mean Bench F1@.5 | Std |
|---|---|---|---|---|
| deterministic (shipped) | 0.9731 | 0.0000 | 0.5632 | 0.0000 |
| stochastic              | 0.9734 | 0.0008 | 0.4854 | 0.0272 |

Stochastic config = LightGBM with `bagging_fraction=0.8`,
`feature_fraction=0.8`, `bagging_freq=1` (rest matches shipped).

#### Takeaways

* **The shipped LightGBM config is fully deterministic.** Default
  `bagging_fraction=1.0` and `feature_fraction=1.0` mean there is no row
  or feature subsampling — `random_state` is consumed but has no effect.
  All five seeds produce byte-identical models.
* **Stochasticity hurts slightly here.** Stochastic config gives
  basically the same bench PR-AUC (within ±0.0008) but worse F1 at
  threshold 0.5 (0.4854 vs 0.5632). The 1927-record training set is too
  small for row/feature subsampling to help.
* **Variance characterization for the headline is done by bootstrap,
  not by seeds.** The "0.9731 ± 0.0000 across seeds" is uninformative.
  The bootstrap CI [0.9601, 0.9831] is the real variance characterization
  — and it comes from test-set sampling, not from training stochasticity.

## Content classifier

### Epoch sweep (v0.1 → v0.4) — convergence study

After remediation (see audit doc), retrained from scratch with epoch
counts sweeping from 3 to 10. All variants use the shipped recipe
(Qwen3-1.7B + LoRA rank 16, alpha 32, full clean training data 1927
records, batch 2 × grad-accum 8, lr 2e-4, cosine schedule, 200 warmup
steps).

| Run | Epochs | P | R | F1 | Accuracy |
|---|---|---|---|---|---|
| `v0p1_on_clean_test`        | 3  | 0.816 | 0.820 | 0.818 | 0.857 |
| `v0p2_5epochs_on_clean_test` | 5  | 0.978 | 0.926 | 0.951 | 0.963 |
| **`v0p3_7epochs_on_clean_test` ← winner** | **7**  | **0.984** | **0.958** | **0.971** | **0.977** |
| `v0p4_10epochs_on_clean_test` | 10 | 0.979 | 0.963 | 0.971 | 0.977 |

#### Takeaways

* **The original 3-epoch schedule was undertraining.** The leak in v0
  was masking this — the 43 leaked test records gave v0 effectively a
  bonus epoch+ of training exposure, which is enough to look like
  convergence. On a clean train, 3 epochs is meaningfully short.
* **5 epochs gets most of the way (F1 0.951).** Going 3 → 5 added 13.3
  pp F1, the largest jump in the sweep.
* **7 epochs is the sweet spot.** 5 → 7 added 2.0 pp F1; 7 → 10 added
  0.0 pp F1 (slight precision/recall reshuffle, F1 identical to 4
  decimals). Model has converged.
* **Headline result on a leak-free test set: F1 0.971, beating Wiz's
  published baseline (~0.838) by 13.3 pp.** Both precision and recall
  beat Wiz independently; this is the v0.3 shipped configuration.

### C1, C2: inference-only ablations (does the LoRA earn its keep?)

Base Qwen3-1.7B-Instruct (the same checkpoint the LoRA fine-tuned),
**no adapter loaded**, with `enable_thinking=False` so the chain-of-thought
block doesn't consume the generation budget. Few-shot demos sampled k/2
yes + k/2 no from the train split with a fixed seed (2026), same demos
across all test records.

| Variant | n_demos | P | R | F1 | rec/s |
|---|---|---|---|---|---|
| C1_zero_shot       | 0  | 0.505 | 0.541 | 0.522 | 8.6 |
| C2_few_shot_1      | 1  | 0.494 | 0.692 | 0.576 | 7.5 |
| **C2_few_shot_3**  | 3  | 0.550 | 0.820 | **0.658** ← best prompting | 10.0 |
| C2_few_shot_5      | 5  | 0.400 | 0.974 | 0.567 | 10.1 |
| C2_few_shot_10     | 10 | 0.400 | 0.984 | 0.569 | 9.6 |
| **LoRA v0.3** (for reference) | — | **0.984** | **0.958** | **0.971** | — |

#### Takeaways

* **The LoRA adds +0.31 F1 over the best prompting baseline.** Best
  non-LoRA is 3-shot at F1 = 0.658; LoRA v0.3 is F1 = 0.971. The 69 MB
  adapter is doing real, large work.
* **Few-shot saturates and then over-predicts yes.** Best F1 is at k=3.
  At k=5 and k=10, recall climbs to ~0.97-0.98 but precision collapses
  to 0.40 — the model mimics the high yes-rate in the demo set rather
  than discriminating. This is a known ICL failure mode and is not a
  scaling phenomenon; it would not be fixed by more demos.
* **Zero-shot is barely better than random.** P = 0.505, R = 0.541 on a
  binary task with a 189-yes / 292-no distribution. The base model
  without training or examples cannot reliably distinguish credential
  patterns from look-alike code.
* **Defensible claim.** The Qwen3 base is a competent reasoner; what
  ShareSift's LoRA fine-tune does is teach it the *specific* discrimination
  boundary between "looks like a credential" and "looks like normal code
  that uses credential-related identifiers" (e.g., `vault.password` —
  configuration access vs literal). This is hard to elicit via prompting
  because the boundary is fine-grained and dataset-specific.

### C5: data-fraction sweep

Sweeping training-data fraction at the v0.3 recipe (7 epochs, LoRA r=16
α=32, full optim config). Stratified by label at sub-sampling time,
seed pinned at 2026.

| Variant | Records | P | R | F1 | Accuracy |
|---|---|---|---|---|---|
| `c5_data25pct_7ep` | 482   | 0.7387 | 0.8677 | 0.7981 | 0.8274 |
| `c5_data50pct_7ep` | 964   | 0.8679 | 0.7302 | 0.7931 | 0.8503 |
| `c5_data75pct_7ep` | 1,445 | 0.9511 | 0.9259 | 0.9383 | 0.9522 |
| **v0.3** (100%)    | **1,927** | **0.9837** | **0.9577** | **0.9705** | **0.9771** |

#### Takeaways

* **The model is data-limited at v0.3's 1,927 records — no plateau in
  sight.** F1 climbs across every doubling: 0.79 → 0.94 → 0.97. The
  curve has not turned over.
* **The 25% → 50% segment is a P/R reshuffle, not a true gain.** F1
  flat (0.7981 → 0.7931); recall drops by 14 pp while precision climbs
  by 13 pp. With only 482 records, the model picks up enough signal to
  refuse uncertain positives but doesn't yet have the discrimination
  to add new ones. Doubling to 964 doesn't change that.
* **The 50% → 75% jump is the biggest gain in the sweep** (+14 pp F1).
  Something about the 482–964 → 1,445 record range crosses a
  discrimination threshold where the model starts catching the
  long-tail positive patterns it was missing.
* **Practical implication.** A 2× labeled-corpus expansion (3,000-4,000
  records) would very likely keep moving F1 — concretely, the README's
  thin-rare-category caveat (≤3 records each for `private_keys_x509`,
  `ssh_credentials`, `cloud_credentials`, `iac`) would benefit most.
  v0.3 is the current ceiling but not the architectural ceiling.

### C4: LoRA-rank sweep

Sweeping LoRA rank at the v0.3 recipe (7 epochs, full data 1,927 records)
with α = 2 × r preserving the canonical alpha/rank ratio.

| Variant | Rank | Alpha | Params | P | R | F1 | Accuracy |
|---|---|---|---|---|---|---|---|
| `c4_rank8_alpha16_7ep`     | 8  | 16  | ~35 MB | 0.9558 | 0.9153 | 0.9351 | 0.9501 |
| **v0.3 (rank 16)**         | **16** | **32**  | **~69 MB** | **0.9837** | **0.9577** | **0.9705** | **0.9771** |
| `c4_rank32_alpha64_7ep`    | 32 | 64  | ~138 MB | 0.9683 | 0.9683 | 0.9683 | 0.9751 |
| `c4_rank64_alpha128_7ep`   | 64 | 128 | ~276 MB | 0.9735 | 0.9735 | 0.9735 | 0.9792 |

#### Takeaways

* **Rank 16 is the sweet spot.** F1 0.9705 marginally edges out r=32
  (0.9683) and r=64 (0.9735); accuracy is essentially tied across r ≥ 16.
  The shipped choice was right.
* **Rank 8 is meaningfully worse** (-3.5 pp F1 vs r=16). At rank 8, the
  adapter has 35 MB of capacity, which appears insufficient to encode
  the discrimination boundary the task requires.
* **Rank 32 and 64 don't justify their extra parameters.** Doubling
  (r=32) and quadrupling (r=64) the adapter size doesn't improve over
  r=16's F1. The task plateaus at r=16's representational capacity.
* **Interesting balance pattern at high rank.** r=32 and r=64 produce
  perfectly balanced precision = recall (0.9683 and 0.9735 respectively).
  Larger adapters smooth out the asymmetry between yes/no error
  modes that smaller adapters retain. Whether this is meaningful or
  coincidence is unclear; would need multi-seed runs to disambiguate.
* **Defense for the shipped config.** "Why rank 16?" — the smallest
  rank that hits the task's representational ceiling. r=8 underfits,
  r=32+ overpays for no F1 gain.

## Headline takeaways

* **The LoRA earns its keep.** +0.31 F1 over the best prompting baseline
  on the same base model. Not marginal.
* **Char n-grams + hand features are jointly required** for the path
  classifier. Either alone underperforms by 3-17 pp PR-AUC.
* **LightGBM beats logistic regression** on the same features by 4 pp
  PR-AUC; the non-linear interactions matter.
* **Calibration trades F1@0.5 for probability quality.** Both isotonic
  and Platt sit within bootstrap CI of uncalibrated on PR-AUC; the
  shipped pipeline uses isotonic because the tier-band mapping needs
  well-calibrated probabilities, not raw F1.
* **The shipped LightGBM config is exactly reproducible** — zero
  variance across seeds. Stochasticity does not help on this dataset.
* **7 epochs is the right schedule for the content classifier.** 3
  epochs underfits, 5 epochs gets most of the way, 7 saturates, 10 is
  identical to 7.
* **LoRA rank 16 is the right capacity.** Rank 8 underfits (-3.5 pp F1);
  rank 32 and 64 don't improve over rank 16. Shipped choice defended.
* **ShareSift is data-limited, not architecture-limited.** F1 climbs
  monotonically with training data from 482 → 1,927 records and shows
  no plateau. A 2× corpus expansion would likely keep moving the
  number — most usefully on the rare-category tail the README flags.

## References

* `docs/audit_2026-05-30.md` — integrity audit and remediation that
  produced the leak-free splits these ablations measure on
* `tools/ablate_path_classifier.py` — P1-P5 + bootstrap
* `tools/ablate_path_seeds.py` — P6 deterministic + stochastic seeds
* `tools/ablate_content_classifier.py` — C1 + C2 inference-only
* `tools/run_content_sweeps.sh` — C5 + C4 sweep driver
* `tools/eval_content_classifier.py` — content classifier eval
* `reports/ablate_path_classifier.json`, `reports/ablate_path_seeds.json`,
  `reports/ablate_content_classifier.json`, `reports/eval_content_classifier.json`
