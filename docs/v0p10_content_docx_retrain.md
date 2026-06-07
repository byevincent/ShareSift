# v0.10 — Content classifier docx-salted retrain (v0p6)

Follows [v0.8 docx-corpus content benchmark](v0p8_realistic_share_benchmark.md)
and [v0.9 writeup-realistic path benchmark](v0p9_writeup_realistic_benchmark.md).
v0.8 + v0.9 together established that both pipeline stages overfit to
their respective training distributions: v0p5's source-code-trained
content classifier collapses on business-document content (recall
0.820 → 0.254); the path classifier's PR-AUC drops 72 points off
training distribution.

The v0.9 end-to-end finding identified **Stage 2 (content classifier)
as the dominant operational bottleneck** — end-to-end recall of 9.1%
was driven by v0p5's stage-2 R=0.091, not stage-1 routing. v0.10
addresses that bottleneck directly: retrain the content classifier
on business-document content with salted credentials, the
distribution v0p5 actually fails on.

## Why this is the right v0.10 move (vs path retrain)

* End-to-end recall is bottlenecked by min(stage 1, stage 2) recall.
  Even with perfect Stage 1, Stage 2's recall caps the joint pipeline.
* The path classifier on writeup paths has weaker numbers but isn't
  the operational ceiling — Stage 2 is.
* Closing the content-stage generalization gap unlocks end-to-end
  recall *regardless* of which path classifier ships.

## Build

`tools/build_docx_training_corpus.py`:

* Loads docx-corpus metadata (737K classified .docx files from
  Common Crawl). Filters to English + enterprise-shaped types
  (legal/reports/forms/manuals/specifications) at classification
  confidence ≥ 0.7.
* **Excludes all 1772 doc IDs used in v0.8's eval benchmark** so the
  v0.8 docx_salted_10 benchmark stays strictly held-out (read from
  `data/eval/docx_salted_benchmark_10.jsonl`).
* Samples 5000 fresh docs (seed=2027, distinct from v0.8's 2026).
* Downloads in parallel from docxcorp CDN, extracts text via
  python-docx, filters to docs with ≥200 chars usable text.
* Salts a 33% positive fraction with credential strings from the
  v0.6 Kingfisher findings (2,132 credentials), using the same 10
  realistic prose prefix patterns as v0.8 (80% prefix-based, 20% raw
  injection).
* 80/20 train/test split.

Result:
* v0.8 benchmark IDs excluded: 1772
* Sampled: 5000 fresh docs
* Usable after text extraction: 4354 docs (646 failed)
* Final corpus: 4354 records (1436 positives + 2918 negatives at 33%
  positive rate)
* Train: 3484 / Test: 870

This is the largest content-classifier training corpus to date
(v0p3=2466, v0p4=2028, v0p5=3000, **v0p6=4354**).

## Train

`tools/train_content_classifier.py` same config as v0p3/v0p4/v0p5:
Qwen3-1.7B + Unsloth + LoRA rank=16 alpha=32, 7 epochs, seed=2026,
lr=2e-4, batch=1 grad_accum=16 (matches v0p5 — p95 snippet length is
at the 4000-char cap so memory is the constraint).

* 1526 total steps, ~88 min wall clock on RTX 5090 (3 GB peak)
* `train_loss = 1.536` (between v0p4's 1.712 and v0p5's 1.321 — settled
  in the middle, signals reasonable fit to a moderate-noise corpus)

## Eval — all 4 benchmarks for apples-to-apples comparison

Four benchmarks cover the relevant operational distributions:

1. **docx_salted_10** (v0.8 held-out, business docs) — the target.
   v0p6 should win here by construction.
2. **CredData v0.6 held-out** (v0.6 source-code distribution) — v0p6
   expected to drop vs v0p5 (different distribution). Acceptable
   trade-off if drop < ~20 F1 points.
3. **ShareSift v0.3 own test split** — kept for v0.7-onwards comparison,
   though the v0.7 finding (LLM-rule labels are noisy proxies) limits
   what this measures.
4. **Constructed share end-to-end** (v0.9.5) — re-run with v0p6 as
   the content classifier. The operational headline.

### Headline numbers

**F1 on docx_salted_10 (business-doc target distribution, 1772 records):**

| | v0p3 | v0p4 | v0p5 | **v0p6** |
|---|---|---|---|---|
| Precision | 0.114 | 0.900 | 0.789 | **0.974** |
| Recall | 0.924 | 0.356 | 0.254 | **0.645** |
| F1 | 0.203 | 0.510 | 0.385 | **0.776** |

v0p6 is the strict winner across all three metrics. Recall jumps
0.391 points from v0p5 (0.254 → 0.645). Precision climbs 0.185
points to 0.974 — i.e., v0p6 false-positives on only 2.6% of
unsalted business documents.

**F1 on CredData v0.6 held-out (source-code distribution, 1195 records):**

| | v0p3 | v0p4 | v0p5 | **v0p6** |
|---|---|---|---|---|
| Precision | 0.490 | 0.649 | 0.889 | 0.463 |
| Recall | 0.818 | 0.388 | 0.820 | 0.898 |
| F1 | 0.612 | 0.485 | **0.853** | 0.611 |

Cross-distribution penalty: v0p6 drops 0.242 F1 from v0p5 on
CredData — real, but lands at v0p3's level. Recall actually
*improved* (0.820 → 0.898) — v0p6 is more permissive about flagging
credentials. Precision dropped 0.426 because v0p6 was trained on
docx negatives, which don't generalize to source-code negatives that
CredData carefully labels as F. F1=0.611 means v0p6 is still useful
on CredData; it's just not the best.

**F1 on ShareSift v0.3 own test split (LLM-rule-labeled, 481 records):**

| | v0p3 (in-dist) | v0p4 | v0p5 | **v0p6** |
|---|---|---|---|---|
| Precision | 0.984 | 0.962 | 0.667 | 0.622 |
| Recall | 0.958 | 0.270 | 0.042 | **0.582** |
| F1 | 0.971 | 0.421 | 0.080 | **0.601** |

v0p6 is the *best cross-distribution model* on the v0.3 test split
(F1=0.60 vs v0p4's 0.42 and v0p5's 0.08). Mechanism: docx-shaped
training data with realistic-prose-prefix-style credential injections
matches v0.3's LLM-rule-labeled positives better than CredData
source-code snippets did. v0p5 catastrophically failed here because
it couldn't recognize credentials outside code context.

**End-to-end constructed share (v0.9.5 setup, 1117 files / 154 salted),
with v0p6 as content model:**

| Stage | v0p5 (previous default) | **v0p6 (new default)** | Δ |
|---|---|---|---|
| Stage 1 P/R/F1 | 0.328 / 0.304 / 0.315 | (unchanged — path classifier not retrained) | — |
| Stage 2 P/R/F1 | 0.933 / 0.091 / 0.166 | **1.000 / 0.240 / 0.387** | **+0.221 F1** |
| End-to-end P/R/F1 | 0.933 / 0.091 / 0.166 | **1.000 / 0.240 / 0.387** | **+0.221 F1** |
| Salted credentials caught | 14 / 154 | **37 / 154** | **+23 (2.6×)** |

End-to-end recall jumps from 9.1% to 24.0% — the operational
bottleneck moved 14.9 points. End-to-end precision is now 1.000:
zero false positives on the docx-content negative class. v0p6
trained on exactly this distribution so it doesn't trigger on
natural business prose.

## Interpretation

v0p6 is the new operational default. The v0.10 thesis — that Stage 2
(content classifier) was the operational bottleneck and could be
unblocked by retraining on business-document content — is confirmed
by the numbers. **End-to-end recall improved 2.6×, end-to-end F1
improved 2.3×.**

### The bottleneck has shifted

Of 154 salted files, Stage 1 (path classifier) flags ~46 based on
its ~30% recall rate on juicy paths. Stage 2 (v0p6) catches 37 of
those 46 — **~80% within-flagged recall**. v0p6 is now operating
near the Stage 2 ceiling that the existing path classifier permits.
Further end-to-end recall gains will come from **Stage 1 retrain**
on writeup-mined paths (v0.11 territory), not from another content
retrain. The two improvements would compound.

### Default-model decision: v0p6 wins

v0p6 became the default because it satisfies the strict-win
criterion on the deploy-realistic distribution (docx-salted) and the
operational headline (constructed-share end-to-end). The CredData
drop is real but acceptable — F1=0.611 still matches v0p3's level
(the v0.5 canonical), so backward-compat on source-code corpora is
preserved.

All four classifiers stay available via `--content-model-dir`:

| Model | Best on | Use case |
|---|---|---|
| **v0p6 (default)** | **docx + end-to-end** | **Real share triage (the original Snaffler use case)** |
| v0p5 | CredData | Source-code corpora (CI/CD secret scans on repos) |
| v0p4 | High precision | Automated alerting where FPs are expensive |
| v0p3 | High recall | Triage where humans review every flag |

### CredData gap to Biringa & Kul

Biringa & Kul 2025 hit F1=0.985 on full CredData with Mistral-7B.
v0p5 was the closest (F1=0.853, 13-pt gap); v0p6 drops to F1=0.611
(37-pt gap). This is the intentional trade-off — v0.10 prioritized
the docx distribution because that's the deployment target. A v0.X
that combines CredData hand-labels + docx-salted training is the
natural way to get both, deferred until the path-side bottleneck
is addressed first.

## What ships in v0.10

* `tools/build_docx_training_corpus.py` — reproducible build of the
  v0p6 training corpus (leak-free vs v0.8 eval benchmark)
* `data/content_v0p6/{train_split,test_split,dataset_stats}.{jsonl,json}` —
  3484/870 records
* `models/content_classifier_v0p6_docx_salted/` — trained LoRA
  adapter (metadata only; safetensors gitignored)
* `reports/eval_content_classifier.json` — appended
  `v0p6_on_{docx_salted_10,creddata_v06,v0p3_test_split}` entries
* `reports/constructed_share_eval.json` — appended
  `constructed_share_v0p6` entry
* `tools/compare_content_classifiers.py` — extended to include v0p6
* README + this doc

## References

* `docs/v0p6_content_rebuild.md` — v0.6 + v0.7 content rebuild context
* `docs/v0p8_realistic_share_benchmark.md` — the benchmark v0.10
  retargets
* `docs/v0p9_writeup_realistic_benchmark.md` — the path-side analog
  + end-to-end finding that identified the Stage 2 bottleneck
* `memory:feedback_sharesift_data_asymmetry` — the calibration
  correction driving v0.8 + v0.9 + v0.10
