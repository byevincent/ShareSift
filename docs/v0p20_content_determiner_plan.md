# v0.20 — content determiner + dormant-infra wiring

Drafted 2026-06-08 from the v0.19 themed-benchmark findings in
`docs/v0p19_results.md` plus a codebase audit of what's vendored vs.
wired.

## Context

v0.19 surfaced two structural problems with Stage 2:

1. **Content-ood was 52% of bottom misses** across 5 themed shares.
   Files with benign filenames (`intake_form`, `MSA_template`,
   `discharge_summary`) hide credentials inside content the
   path-only classifier can't see.
2. **Extraction-missing was 16% of misses**, all PDFs. The Scanner
   loads file content with `path.read_text()`; PDFs return empty.

The headline finding from the v0.20 codebase audit: **most of what's
needed to fix content-ood already exists, but isn't wired into the
main Scanner flow.**

| Vendored asset | Status in main scan |
|---|---|
| 88 Snaffler rules + 22 extra rules in `src/sharesift/rules/` | Never executes (only inside the pysnaffler integration) |
| 21 credential-format regex extractors in `verify/extractor.py` | Only used by the `verify` subcommand |
| Base64 decoder in `preprocess/base64_decode.py` | Exported, never called |
| Literal-vs-referenced classifier (v0p7) | Only inside the pysnaffler content rule |
| PDF / binary extraction | Doesn't exist |
| 18 structured parsers in `parsers/` | ✅ Wired — the one piece that does run |

So v0.20 is mostly a **wiring + orchestration** task plus PDF text
extraction. Model retrains are deferred to v0.21 because we want to
measure the wiring-alone delta first.

## Phases

Three phases that compound. Order matters: cheap wiring before any ML.

### Phase 1 — Wire the dormant infrastructure

| Component | New file | Outcome |
|---|---|---|
| `ContentRuleEngine` — load + execute the 110 vendored rules against `(filename, content)`; return tier + match list | `src/sharesift/content_rules.py` | Catches the content-ood failures from v0.19 (regex patterns the path classifier can't see) |
| PDF text extraction via `pypdf` | `src/sharesift/extract.py` (new module) | Resolves the 4 PDF misses in v0.19 (gov_contractor + legal). New optional group `pdf-extraction` |
| Base64 preprocessor wired into Scanner content load | edit `pipeline.py` | Recursively decodes nested credentials before rules + classifier see them |
| Re-run v0.19 benchmark with new pipeline | `benchmarks/v0p20/<theme>/metrics.json` | Real delta numbers per failure mode |

### Phase 2 — `ContentDeterminer` cascade

Unify the four content-side detection mechanisms into one class with
a tiered cascade:

```
ContentDeterminer.evaluate(path, content) →
  ContentVerdict(tier, source, matches, confidence)

Tier 1: structured parsers   (existing — already in Scanner)
Tier 2: content rule engine  (new in Phase 1)
Tier 3: verify extractor     (existing — exposed to scan path)
Tier 4: LoRA classifier      (existing — last resort)
```

Each tier escalates only if previous tiers were inconclusive. Output
is a single `ContentVerdict` with `tier`, `source`, `matches[]`,
`confidence`. Callers (cli, pysnaffler integration, verify) all use
the same API. Scanner.scan_batch returns a richer `ScanResult` with
the verdict attached.

Key design choice: **the LoRA classifier becomes the fallback for
hard cases**, not the only path. Users without the 3 GB Qwen
download still get useful results from Tiers 1-3.

### Phase 3 — Targeted ML (deferred to v0.21+)

After Phase 1+2 ship, re-measure on the themed benchmarks. Remaining
gaps fall into:

- **Naming-ood (Stage 1 retrain)** — add v0.19 themed filename tokens
  to path classifier training corpus
- **Lightweight content classifier** — small sklearn/fastText model
  for the cascade's smarter-than-regex tier, runnable without the
  3 GB HF download

These are real ML work; explicitly out of scope for v0.20. v0.20
ships the infrastructure and the measurement so v0.21 can be scoped
precisely.

## Sprint accounting

| Sprint | Scope | Deliverable |
|---|---|---|
| 1 | `ContentRuleEngine` + tests | `src/sharesift/content_rules.py` |
| 2 | PDF extraction + base64 wiring | `src/sharesift/extract.py` + Scanner edits |
| 3 | `ContentDeterminer` cascade + tests | `src/sharesift/content_determiner.py` |
| 4 | Re-run v0.19 themed benchmark with new pipeline | `benchmarks/v0p20/<theme>/metrics.json` per theme |
| 5 | `docs/v0p20_results.md`, version bump, CHANGELOG, bundle, tag | release v0.20.0 |

## What's out of scope (carryover to v0.21)

- Model retrains (Stage 1 filename or Stage 2 content)
- Lightweight content classifier training
- Multi-modal / OCR PDF handling — `pypdf` reads text PDFs, not scanned image PDFs
- Snaffler head-to-head re-measurement — `snaffler` binary still not installed
- Real engagement data validation — gated NDA, separate project

## Risks to watch

1. **Precision risk from the rule engine.** 110 regex patterns running
   on legal NDAs and healthcare templates will FP on `password` /
   `credential` mentions. Phase 1's themed-benchmark re-run catches
   this — if legal precision tanks further, the rules need gating.
2. **PDF extraction is OCR-blind.** `pypdf` doesn't read scanned PDFs.
   v0.19 synthetic PDFs are text-based so we'll see a clean win;
   real-world will be partial. Flag in docs.
3. **Cascade order vs. parallel.** The plan above cascades; the right
   answer may be parallel evaluation with reconciliation. Worth a
   small experiment in Phase 2.

## Verification (end-to-end, after Sprint 4)

```bash
# Re-run all 5 themes with the new pipeline:
for theme in finance healthcare dev_eng gov_contractor legal; do
  uv run sharesift score-paths \
    --input benchmarks/v0p19/$theme/paths.txt \
    --output benchmarks/v0p20/$theme/scores.jsonl
  uv run sharesift scan-files \
    --input benchmarks/v0p19/$theme/paths.txt \
    --output benchmarks/v0p20/$theme/hits.jsonl \
    --force-content  # so rule engine runs on every file
  uv run python tools/score_themed_run.py \
    --theme $theme \
    --theme-dir benchmarks/v0p19/$theme \
    --scores benchmarks/v0p20/$theme/scores.jsonl \
    --output benchmarks/v0p20/$theme/metrics.json
done
```

Expected: dramatic improvement on `extraction-missing` (PDFs become
readable). Significant improvement on `content-ood` (rule engine
fires on benign-named-but-salted files). Naming-ood unchanged
(Stage 1 retrain is v0.21).
