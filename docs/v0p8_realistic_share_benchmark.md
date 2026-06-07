# v0.8 — Realistic-share content benchmark (salted docx-corpus)

Follows the [v0.7 content rebuild](v0p6_content_rebuild.md). v0.7 closed
most of the gap to Biringa & Kul 2025 (F1=0.853 vs 0.985 on CredData
v0.6 held-out, same Qwen3-1.7B base). The implicit claim that
v0p5-on-CredData generalized to real-share deployment was tested in
v0.8 by building a benchmark from **business documents instead of
source code** — and the claim doesn't hold.

## Why this benchmark exists

CredData's positive class is source code containing credentials.
Negative class is source code without credentials. *Both classes are
source code.* Real ShareSift deployment targets SMB shares full of
.docx legal documents, .xlsx spreadsheets, .pdf reports — business
prose with credentials embedded rarely (perhaps 1:1000 file rate).
The negative-class distribution between CredData and a real share is
wildly different.

The 2026-06-01 conversation with Vincent surfaced the actually-
available correction: public corpora for business documents exist
(Govdocs1, docx-corpus, Enron, RealKIE) and CredData is *not* the
operational ceiling. The v0.8 benchmark exercises the negative-class
distribution CredData can't.

## Build

`tools/build_docx_corpus_benchmark.py`:

1. Loads docx-corpus (737K classified Common Crawl .docx files, ODC-BY)
   metadata from HuggingFace.
2. Filters to English documents of types `legal`, `reports`, `forms`,
   `manuals`, `specifications` at classification-confidence ≥ 0.7.
3. Samples N=2000 documents and downloads from the docxcorp CDN.
4. Extracts text via `python-docx`.
5. Salts a fraction K with real-shape credential strings extracted
   from `reports/creddata_training_kingfisher.jsonl` (3,440 Kingfisher
   findings, 2,132 usable after length filtering). Salting uses
   realistic prose prefixes 80% of the time
   (`"The password is: "`, `"API key: "`, `"Connection string: "`,
   etc.) and raw injection 20%.
6. Emits chat-template JSONL at `data/eval/docx_salted_benchmark_10.jsonl`.

Result:
- Downloads: 2000/2000 succeeded
- Usable after text extraction: 1772 documents (228 too small/empty)
- Doc-type distribution: 834 legal, 668 forms, 270 reports
- Output: 1772 records (177 positives, 1595 negatives) at a 1:10
  base rate

## Methodology bias caveat

The credential salt source matters. We pulled credential strings from
Kingfisher's CredData scan output. v0p4 was trained on Kingfisher
pattern labels. **Any v0p4 win on this benchmark is partly artifactual** —
the model is being tested on exactly the credential-string
distribution it was trained on. A more rigorous v0.8.x would re-run
the eval with a non-Kingfisher salt source (synthetic strings from
the rule-pack regexes, hand-curated plausible credentials, etc.) and
quantify the methodology-bias contribution to v0p4's score.

## Results

### Headline F1 at 1:10 base rate (177 pos / 1595 neg)

| | v0p3 (LLM-rule) | v0p4 (Kingfisher) | v0p5 (hand-labels) |
|---|---|---|---|
| Precision | 0.114 | **0.900** | 0.789 |
| Recall | **0.924** | 0.356 | 0.254 |
| F1 | 0.203 | **0.510** | 0.385 |
| Accuracy | 0.142 | TBD | TBD |

### Same benchmark vs same models on CredData v0.6 — inverted rankings

| Benchmark | v0p3 F1 | v0p4 F1 | v0p5 F1 |
|---|---|---|---|
| **CredData v0.6** held-out (source-code distribution) | 0.612 | 0.485 | **0.853** |
| **docx_salted_10** (business-document distribution) | 0.203 | **0.510** | 0.385 |

v0p5 wins by F1 on CredData; v0p4 wins by F1 on docx-salted. v0p3
loses on both. The "best content model" depends on which distribution
matches deployment — and the two public benchmarks we have give
opposite rankings.

### Precision-at-base-rate (analytical, from confusion matrix at 1:10)

The TPR (recall) and FPR (1−specificity) are base-rate-independent.
For any target base rate `p`, precision is recomputable as
`(p × TPR) / (p × TPR + (1−p) × FPR)`. This lets us project precision
at share-realistic 1:1000 base rates without needing a 1-million-
record benchmark.

| Model | TPR (recall) | FPR | Prec @ 1:10 | Prec @ 1:100 | Prec @ 1:1000 |
|---|---|---|---|---|---|
| v0p3 | 0.940 | 0.805 | 0.115 | 0.012 | 0.0012 |
| **v0p4** | 0.356 | **0.004** | **0.900** | **0.450** | **0.0750** |
| v0p5 | 0.254 | 0.008 | 0.789 | 0.254 | 0.0326 |

At a share-realistic 1:1000 positive rate:
- v0p3: 0.12% precision — would alert on 999 false positives per true
  positive. Unusable.
- v0p4: 7.5% precision — ~12 false positives per true positive.
  Borderline-tolerable for hand-triage; not for automated alerting.
- v0p5: 3.3% precision — ~30 false positives per true positive. Bad.

**The dominant factor at imbalanced base rates is FPR.** v0p4's FPR
of 0.4% is the only one that survives the 1:1000 reweighting at all.

## What this means

### v0p5-on-CredData was a misleading proxy for real-share quality

v0.7's F1=0.853 claim was real *for the CredData distribution*. On the
docx-salted distribution v0p5 drops to F1=0.385, with recall
collapsing 57 points (0.820 → 0.254). The mechanism is structural:
v0p5 trained on code-shape contexts and learned to depend on them as
a cue. Credentials in business prose ("The password is: AKIA…")
without surrounding code shape go undetected.

### The right default depends on the deployment target

v0p4 is the only operationally-viable model at realistic share base
rates, by a clear margin. **But** there's a methodology bias favoring
v0p4 on this specific benchmark (salt source = Kingfisher findings;
v0p4 trained on Kingfisher labels). The honest framing is:

- **For source-code-distribution targets** (CI/CD secret scanning,
  developer-tool integrations) → v0p5 (best F1 on CredData)
- **For business-document-distribution targets** (the original SMB
  share use case) → v0p4 (only operationally usable at realistic
  base rates)
- **For high-recall triage where a human reviews every flag** → v0p3
  (best recall, but only viable when alert volume is acceptable)

### v0.7's default-to-v0p5 decision is *not* being reverted

Two reasons:
1. The docx-salted benchmark has documented methodology bias favoring
   v0p4. Defaulting to v0p4 on its strongest benchmark would
   over-correct.
2. All three models are CLI-selectable via `--content-model-dir`. The
   "default" matters less than the explicit deployment-context choice.
   The documentation makes the trade-off legible.

If a future v0.8.x re-runs the benchmark with a non-Kingfisher salt
source AND v0p4 still wins by a similar margin, that's the trigger
for flipping the default.

## What ships in v0.8

* `tools/build_docx_corpus_benchmark.py` — reproducible benchmark
  build (downloads from HuggingFace + docxcorp CDN, salts, emits
  JSONL).
* `tools/precision_at_base_rate.py` — analytical precision projection
  from any confusion matrix to target base rates.
* `data/eval/docx_salted_benchmark_10.jsonl` — 1772-record benchmark.
* `data/external/docx_corpus_cache/` — gitignored; downloaded .docx
  files for reproducibility.
* `reports/eval_content_classifier.json` — appended
  `v0p{3,4,5}_on_docx_salted_10` entries.
* Updated `docs/v0p6_content_rebuild.md` cross-references and v0.7
  framing.
* This document.

## v0.9 forward look

The clear next move is **a corpus that exercises real-share path
topology** (the path-triage stage's analog gap to v0.8's content-stage
gap). The plan is to mine HackTheBox / VulnHub / Metasploitable 3
write-ups (CC-licensed, no VM disk cost) for path enumerations,
filter to the Snaffler-blind subset, and eval the existing Win/Linux
path classifiers. See task list for v0.9 scope.

A v0.10 candidate is **end-to-end construction of a synthetic share on
disk** that mirrors writeup-mined paths, populated with docx-corpus
content + Kingfisher salts, evaluated through the full
`sharesift scan-files` orchestration. This tests the tier-filter +
content-stage hand-off the existing eval scripts skip.

Neither v0.9 nor v0.10 substitutes for engagement data on either stage.
They close as much of the gap as public corpora can.

## References

* `docs/v0p6_content_rebuild.md` — v0.6 + v0.7 content rebuild context
* `docs/audit_2026-05-31.md` — v0.5 audit doc (CredData benchmark
  motivation)
* `tools/build_docx_corpus_benchmark.py`
* `tools/precision_at_base_rate.py`
* docx-corpus: https://github.com/superdoc-dev/docx-corpus
* Govdocs1 / Digital Corpora: https://digitalcorpora.org/corpora/file-corpora/
