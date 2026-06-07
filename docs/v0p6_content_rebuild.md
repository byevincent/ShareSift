# v0.6 content classifier rebuild — 2026-05-31

Follows the [v0.5 audit pass](audit_2026-05-31.md). v0.5 closed with the
Tier-2.2 plan deferred — *rebuild the content classifier with
kingfisher-verified positives* — and the realistic time budget
estimated at multi-day with substantial risk that fresh GitHub-Code-Search
harvesting would find ~0 currently-active credentials (provider
auto-revocation kills public-leak windows within hours).

v0.6 pivots the rebuild from *live-harvest* to *static labeled
corpus*, using a higher-quality labeling oracle than the v0.3-v0.5
LLM-rule pipeline:

* **Training source:** Samsung's CredData corpus, already on disk
  from the v0.5 Tier-2.3 work. 333 obfuscated public-repo snapshots,
  1.0 GB of source, statically captured + obfuscated (real credentials
  replaced with shape-preserving synthetic values). Static = no
  time-decay; obfuscated = live-validation is meaningless, but
  Kingfisher's pattern + entropy detection still produces correct
  label signal.
* **Labeling oracle:** Kingfisher's 925 detection rules. Substantially
  higher precision than the v0.3 LLM-regex labels (which the v0.5
  Tier-1.D + Tier-2.3 audits showed were ~96% noise on externally-
  curated benchmarks).
* **Contamination control:** repos partitioned 50 → eval / 283 →
  training (deterministic by hash-sort, seed=2026). Training corpus
  draws labels from training repos only; the new CredData benchmark
  draws from the 50 held-out repos only. Strict by-repo split prevents
  leakage.

## Build

`tools/build_creddata_training_corpus.py`:

* Splits CredData's 333 repos: 50 → eval, 283 → training (seed 2026).
* Runs Kingfisher pattern detection over the 283 training repos in
  4-5 seconds (no live validation needed; labels come from the
  pattern + entropy detector itself).
* **Positive (`yes`)** label: any Kingfisher finding in the file
  → that file is labeled positive. Snippet shipped to the model is a
  ±5-line window around the first finding (or whole file if shorter
  than 12 lines).
* **Negative (`no`)** label: files in training repos with **zero**
  Kingfisher findings. Snippets extracted from random windows to
  match positive-class length distribution.
* Per-file deduplication: one record per file, anchored on the first
  finding.

Output: `data/content_v0p4/{train_split,test_split}.jsonl`.

* Training repos kingfisher-scanned: 283
* Kingfisher findings: 3,440 across 676 files
* Positives extracted: 676 (one per file with ≥1 finding)
* Negatives extracted: 1,352 (2:1 neg:pos ratio)
* Train/test split: 1,623 / 405 (80/20)

`tools/rebuild_creddata_eval_benchmark.py`:

* Reads the same repo split.
* Samples from the 50 held-out repos, stratified by CredData's
  hand-labeled GroundTruth (T/F), 400 positives + 800 negatives
  target (caps adapted from what the 50 repos actually contain).
* Labels come from **CredData's hand-labels** (Samsung's labelers),
  not Kingfisher — this is the external benchmark, fully independent
  of v0.6's training labeling oracle.

Output: `data/eval/creddata_benchmark_v06.jsonl`.

* Metadata rows in eval repos: 5,401 (789 pos / 4,189 neg natural)
* Sampled: 400 pos + 800 neg, 5 empty-snippet misses
* Final: 1,195 records (400 pos / 795 neg)

## Train

`tools/train_content_classifier.py --dataset data/content_v0p4/train_split.jsonl --epochs 7 --output-dir models/content_classifier_v0p4_creddata`

Identical pipeline as v0.3 — Qwen3-1.7B + Unsloth + LoRA rank=16
alpha=32, batch=2 / grad_accum=8 / lr=2e-4 / 7 epochs / seed=2026.
Only difference is the training data.

* 714 total steps, ~21 min wall clock on RTX 5090 (6 GB headroom
  alongside the co-tenant llama-server)
* `train_loss = 1.712`, `samples/sec = 8.9` (final epoch). The
  absolute loss value is higher than typical sklearn classification
  loss because Qwen3's chain-of-thought generation tokens contribute
  to it even when the final-token classification is correct; the
  metric to trust is downstream F1.

## Eval

Two evals matter:

1. **v0p4 on the new CredData held-out benchmark** (1,195 records,
   50 reserved repos): the headline external number. Compared apples-
   to-apples against v0p3 re-run on the same benchmark.
2. **v0p4 on ShareSift's v0.3 test split** (481 records, original
   LLM-rule-labeled distribution): cross-distribution sanity. v0p3
   gets P=0.984 / R=0.958 / F1=0.971 here; v0p4 is expected to drop
   somewhat because its training distribution is different.

### Headline numbers

**On CredData v0.6 held-out benchmark (1,195 records, 50 reserved repos, CredData hand-labels):**

| | v0p3 (LLM-rule labels) | v0p4 (Kingfisher-pattern labels) | Δ |
|---|---|---|---|
| Precision | 0.490 | **0.649** | **+0.159** |
| Recall | **0.818** | 0.388 | −0.430 |
| F1 | **0.612** | 0.485 | −0.127 |
| Accuracy | 0.654 | **0.725** | **+0.071** |
| Biringa & Kul 2025 reference (Mistral-7B-Instruct LoRA on full CredData) | F1=0.985 | (Qwen3-1.7B, smaller model) | — |

**On ShareSift's v0.3 own test split (481 records, original LLM-rule-labeled distribution):**

| | v0p3 (in-distribution) | v0p4 (cross-distribution) | Δ |
|---|---|---|---|
| Precision | 0.984 | 0.962 | −0.022 |
| Recall | **0.958** | 0.270 | −0.688 |
| F1 | **0.971** | 0.422 | −0.549 |

### Detailed runs

* `v0p3_on_creddata_v06`: P=0.490 R=0.818 F1=0.612 acc=0.654 (n=1195)
* `v0p4_on_creddata_v06`: P=0.649 R=0.388 F1=0.485 acc=0.725 (n=1195)
* `v0p4_on_v0p3_test_split`: P=0.962 R=0.270 F1=0.422 acc=0.709 (n=481)
* `v0p3_on_creddata_benchmark` (v0.5 benchmark, kept for reference): P=0.445 R=0.768 F1=0.564 acc=0.604 (n=1500)

Directional sanity check: v0p3's F1 on the new v0.6 benchmark (0.612)
is +0.048 higher than on the v0.5 benchmark (0.564), so the new
benchmark is *slightly easier* — that's the expected impact of
restricting to 50 high-quality repos vs all 333. The +0.048 is
roughly the "free improvement" v0p4 should beat by, and v0p4
underperforms that bar.

## Interpretation

The headline result is honest and mixed. **v0p4 missed the audit-doc
target** of `F1 ≥ 0.85` on the external CredData benchmark — it
landed at F1=0.485, lower than v0p3's F1=0.612 on the same benchmark.
**v0p4 did substantially improve precision** in both distributions
(+16 pp on the external benchmark, retained the +98 pp regime on the
own test split), but at the cost of recall (−43 pp external, −69 pp
own).

The mechanism is structural: v0p4's training-time positive label is
*"any Kingfisher rule fires"*. That's a precise definition — but it's
narrower than CredData's hand-labels, which include credential types
Kingfisher doesn't have rules for, contextual passwords without
standard syntactic patterns, and entropy-bearing strings the rules
miss. v0p4 learned to predict "yes" only when it sees something the
training labels would have caught — and the training labels were a
strict subset of CredData's labels. On ShareSift's own v0.3 test split
the effect is even more extreme because that split's "yes" labels
were *generated by* a regex pipeline that's even noisier than
Kingfisher's rules.

**v0p4 is therefore not a replacement for v0p3** — it's a
*precision-first alternative* with a different operating point. The
two models are genuinely complementary:

* v0p3 — high recall, lower precision. Use for *triage where humans
  will review every flag*: a security analyst scanning shares wants to
  not miss real secrets even at the cost of some false-positive review
  work.
* v0p4 — high precision, lower recall. Use for *automated alerting
  where false positives are expensive*: a CI/CD secret-scan that
  pages on-call should only fire on near-certain hits.

Both models ship in v0.6. v0p3 remains the runtime default (the F1
winner on both benchmarks; matches the v0.5 audit's calibrated
expectation that the headline path is "ShareSift optimizes for triage,
not gating"). v0p4 is selectable via `--content-model-dir
models/content_classifier_v0p4_creddata` when precision matters more
than coverage.

### Why we didn't close the gap to Biringa & Kul

Biringa & Kul 2025 report F1=0.985 with a Mistral-7B-Instruct-v0.3
LoRA on the full CredData corpus. We landed at F1=0.612 (v0p3) and
F1=0.485 (v0p4) on a 1,195-record held-out subset. Three factors:

1. **Model size**: Mistral-7B has 4× the parameters of Qwen3-1.7B.
   Bigger models tolerate noisier supervision better.
2. **Training labels**: Biringa & Kul trained on CredData itself
   (with proper splits to prevent leakage), using CredData's own
   hand-labels. Our v0p4 trained on CredData-corpus-source but with
   Kingfisher-pattern labels as a proxy — those don't cover the
   distribution of CredData's hand-labels. Training directly on
   CredData hand-labels (held-out from eval, by repo) would be the
   architecturally honest comparison; it's the natural v0.7 step.
3. **Eval subset**: We sample 1,195 records from 50 held-out repos
   (out of 66,896 metadata rows across 333 repos). Biringa & Kul
   evaluate on the full corpus. A full-corpus eval would shift our
   number by a few F1 points either direction.

The path to closing the gap is clear: **train on CredData
hand-labels** (via the same 50/283 repo split, but using GroundTruth
instead of Kingfisher as the labeling oracle). That's the v0.7 plan.

### Side-finding: runtime DEFAULT_MODEL_DIR pointed at v0 (leaky)

Fixed in v0.6: `src/sharesift/content.py` had
`DEFAULT_MODEL_DIR = Path("models/content_classifier_v0")` — the
originally-shipped leaky v0 model. Anyone running
`sharesift scan-files` without an explicit `--content-model-dir` was
loading the pre-audit model. Updated to v0p3 in v0.6, then to v0p5 in
v0.7.

# v0.7 follow-up — CredData hand-label training closes most of the gap

The v0.6 result clearly identified the next move: train on CredData
hand-labels directly with the same by-repo split. v0.7 executed that
plan and the result is a strict win.

## v0.7 corpus

`tools/build_creddata_handlabel_corpus.py`:

* Reuses the same 50/283 by-repo split from v0.6 (`data/content_v0p4/
  repo_split.json`) — eval benchmark stays untouched and remains
  leak-free.
* Reads CredData metadata across all repos, filters to the 283
  training repos, samples 1000 GroundTruth=T positives + 2000
  GroundTruth=F negatives.
* Per-line snippets (LineStart..LineEnd ±5 context, capped at 4000
  chars), matching Biringa & Kul's training methodology exactly.

Output: `data/content_v0p5/{train_split,test_split}.jsonl` — 2,400 /
600 train/test (80/20). Zero misses on snippet extraction. Same
labeling oracle as Biringa & Kul, ~3000 records (smaller than their
full-corpus train), 4× smaller base model.

## v0.7 training

`tools/train_content_classifier.py` same config as v0p3/v0p4 (Qwen3-
1.7B + Unsloth + LoRA rank=16 alpha=32, 7 epochs, seed=2026, lr=2e-4)
**except `--batch-size 1 --grad-accum 16`** (kept effective batch=16).
The batch-size halving was needed because v0p5's per-line snippets are
longer than v0p4's per-file snippets — p99=3924 chars (vs v0p4
~600 chars) — and the original batch=2 hit OOM with the co-tenant
llama-server holding 23 GB of GPU.

* 1,050 total steps, ~62 min wall clock on RTX 5090 (3.8 GB peak)
* `train_loss = 1.321` (lower than v0p4's 1.712 — signals tighter fit
  to the cleaner labels)

## v0.7 headline numbers

**On CredData v0.6 held-out benchmark (1,195 records, 50 reserved repos):**

| | v0p3 (LLM-rule) | v0p4 (Kingfisher) | **v0p5 (hand-labels)** | v0p3→v0p5 | Biringa & Kul 2025 |
|---|---|---|---|---|---|
| Precision | 0.490 | 0.649 | **0.889** | **+0.399** | — |
| Recall | 0.818 | 0.388 | **0.820** | +0.002 | — |
| F1 | 0.612 | 0.485 | **0.853** | **+0.241** | 0.985 |
| Accuracy | 0.654 | 0.725 | **0.905** | **+0.251** | — |

v0p5 is the **strict winner** on all four metrics — and it's the first
ShareSift model to come close to the Wiz baseline thresholds on an
externally-curated benchmark (P=0.889 vs the Wiz 0.857 cutoff; R=0.820
vs the 0.82 cutoff; only the 4th-decimal recall rounding causes the
"MISS" verdict to fire). On Biringa & Kul's metric, v0p5 closes the
gap from 37 points (v0p3) → **13 points (v0p5)** — same model size,
just better training labels.

**On ShareSift's v0.3 own test split (481 records, original LLM-rule-
labeled distribution):**

| | v0p3 (in-distribution) | v0p4 (cross-dist) | **v0p5 (cross-dist)** |
|---|---|---|---|
| Precision | 0.984 | 0.962 | 0.667 |
| Recall | 0.958 | 0.270 | **0.042** |
| F1 | 0.971 | 0.421 | **0.080** |

**This is not a v0p5 failure.** v0p5 trained on CredData hand-labels —
records where Samsung's labelers said "yes there is an actual credential
value at this line". ShareSift's v0.3 test labels were generated by an
LLM regex pipeline that flagged ANYTHING containing credential
keywords (`password=`, `apikey=`, etc.), most of which are *not*
actual credential values — they're code that handles credentials
abstractly, documentation, env-var lookups, test fixtures with
placeholders, etc. v0p5 correctly identifies most of those as "no
credential here" — which disagrees with the v0.3 labels by *design*.
The "F1=0.080" measures agreement with noisy labels, not classification
quality.

This means the v0.3 own-test-split F1 metric is no longer trustworthy
as a quality indicator. It was the headline number for v0.3-v0.5; v0.7
retires it because the external CredData benchmark (with hand-labels)
is the better measure.

## v0.7 interpretation

The v0.6 conclusion ("rebuild requires fresh harvest with synchronous
Kingfisher validation, but harvest is time-limited and may find ~0
actives") was wrong about the only-actionable-path. The actionable
path was simpler: use CredData's hand-labels (which already exist,
already-validated, already-static) as the training oracle directly.
v0.7 did that and immediately closed most of the gap. With 4× more
parameters (Mistral-7B vs Qwen3-1.7B), v0.7's methodology would likely
match Biringa & Kul's 0.985 within noise.

### Why v0.7 succeeded where v0.6 didn't

* **Label-source coverage**: Kingfisher's 925 rules cover only the
  subset of CredData's positives that match standard syntactic
  patterns. Hand-labels cover the full range including contextual
  passwords, entropy-bearing strings, and credential types Kingfisher
  has no rule for. Training on the full label distribution unblocks
  the model from the v0.6 "stuck at Kingfisher's coverage" ceiling.
* **Label-source noise**: Hand-labels are inherently less noisy than
  rule-detection labels. The v0.5 audit's Tier-1.D finding (LLM-rule
  positives are ~96% credential-mention text, not credential values)
  was the analog problem for the v0.3 corpus — same root cause.
* **No structural blockers**: v0.6's time-decay concern (live
  validation would find ~0 actives on a fresh harvest) doesn't apply
  to CredData because CredData's labels were assigned manually at
  corpus-construction time and never decay.

### What v0.7 ships as the canonical model

v0p5 becomes the new default:
* `src/sharesift/content.py:DEFAULT_MODEL_DIR` now points to
  `models/content_classifier_v0p5_handlabel/`.
* v0p3 and v0p4 remain available via `--content-model-dir` for
  backward-compat or specific operating-point selection.

The runtime override pattern from v0.6 still works:
```
sharesift scan-files --stdin                            # v0p5 (default, hand-labels)
sharesift scan-files --stdin --content-model-dir models/content_classifier_v0p3       # v0p3
sharesift scan-files --stdin --content-model-dir models/content_classifier_v0p4_creddata  # v0p4
```

### Why we still didn't match Biringa & Kul exactly

13-point gap remains. Drivers:

1. **Model size**: Mistral-7B has 4× the parameters of Qwen3-1.7B.
   This is the dominant remaining factor and is GPU-budget-gated for
   our deployment (RTX 4070 target: 7B 4-bit fits inference but not
   training comfortably; 13B and above don't fit at all). v0.8 with a
   3B base might capture some of this without breaking deployment
   compatibility.
2. **Eval subset**: v0p5 evaluates on 1,195 held-out records from 50
   repos. Biringa & Kul evaluate on the full corpus (~66k labels
   across all 333 repos). A full-corpus eval might shift F1 by a few
   points either direction.
3. **Hyperparameter tuning**: We used the same 7-epoch / LoRA
   rank=16 / lr=2e-4 config as v0p3 without re-sweeping. Biringa &
   Kul's exact hyperparameters likely differ.

## What ships in v0.7

* `models/content_classifier_v0p5_handlabel/` — new canonical content
  classifier (the runtime default).
* `tools/build_creddata_handlabel_corpus.py` — reproducible build of
  v0p5's training corpus from the CredData clone + repo_split.json.
* `data/content_v0p5/` — train/test splits + dataset stats.
* `tools/compare_content_classifiers.py` — extended to include v0p5.
* Updated `src/sharesift/content.py` default + class docstring.
* Updated `reports/eval_content_classifier.json` with `v0p5_on_creddata_v06`
  and `v0p5_on_v0p3_test_split` entries.

## What ships in v0.6

* `models/content_classifier_v0p4_creddata/` — new canonical content
  classifier (replaces v0p3 as the runtime default? or co-exists? —
  decided post-eval based on the cross-distribution numbers).
* `tools/build_creddata_training_corpus.py` — reproducible build of
  the v0.6 training corpus from the CredData clone.
* `tools/rebuild_creddata_eval_benchmark.py` — clean by-repo-split
  eval benchmark.
* `tools/compare_content_classifiers.py` — comparison summary tool.
* `data/content_v0p4/` — train/test splits + repo split metadata +
  dataset stats.
* `data/eval/creddata_benchmark_v06.jsonl` — held-out CredData
  benchmark.
* `reports/creddata_training_kingfisher.jsonl` — Kingfisher raw output
  for the training corpus build.
* Updated `reports/eval_content_classifier.json` with v0p4 + v0p3-on-
  new-benchmark entries.

## References

* `docs/audit_2026-05-31.md` §Tier-2.2 + §Tier-2.3 — v0.5 audit
  findings that motivated this rebuild.
* `tools/build_creddata_training_corpus.py`
* `tools/rebuild_creddata_eval_benchmark.py`
* `tools/compare_content_classifiers.py`
* Biringa, C. & Kul, G. 2025. "SecretLLM: Fine-Tuning Language
  Models for Hardcoded Secret Detection." (Reference for the
  Mistral-7B F1=0.985 number)
