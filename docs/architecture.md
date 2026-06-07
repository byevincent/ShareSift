# ShareSift architecture

The implementation-level companion to `build_plan.md`. Where the build
plan is the project timeline and decision log, this doc is what a new
contributor reads to understand the running system.

## Two-stage pipeline

```
                       paths from share enumeration
                                   │
                                   ▼
              ┌────────────────────────────────────────┐
              │ Stage 1: Path classifier (v0.5 router) │
              │   src/sharesift/path.py                 │
              │   ────────────────────────             │
              │   Dispatches by path shape:            │
              │     UNC (\\…)  → Windows model         │
              │     else      → Linux model            │
              │                                        │
              │   models/path_classifier_v0_windows/   │
              │   models/path_classifier_v0_linux/     │
              │   (each: calibrated.joblib)            │
              │                                        │
              │   Char n-grams (3-5) + 8 hand          │
              │   features → LightGBM → isotonic       │
              │   calibration → per-model tier band    │
              └────────────────────────────────────────┘
                                   │
                          (probability, tier)
                                   │
                                   ▼
                        ┌──────────────────┐
                        │ tier-flagged?    │
                        └──────────────────┘
                          /                \
                         no                yes
                         │                  │
                         │                  ▼
                         │     ┌────────────────────────────────────┐
                         │     │ Stage 2: Content classifier        │
                         │     │   src/sharesift/content.py      │
                         │     │   ──────────────────────────       │
                         │     │   models/content_classifier_v0/    │
                         │     │   adapter_model.safetensors        │
                         │     │                                    │
                         │     │   Qwen3-1.7B base (4-bit CUDA /    │
                         │     │   bf16 CPU) + LoRA adapter         │
                         │     │   → chat template → yes/no         │
                         │     └────────────────────────────────────┘
                         │                  │
                         ▼                  ▼
                  ScanResult (path + tier + content_check)
                                   │
                                   ▼
                            JSONL output
```

Both stages are independently usable. The combined `Scanner`
(`src/sharesift/pipeline.py`) is the glue.

## Module map

### Runtime (Phase 4 — what ships to users)

| Module | Purpose |
|---|---|
| `src/sharesift/path.py` | `PathClassifier` — v0.5 router; loads two per-shape LightGBM artifacts (Windows + Linux), dispatches via `is_unc_path()` |
| `src/sharesift/pysnaffler_rule.py` | `ShareSiftPathRule` — SnaffleRule subclass wrapping `PathClassifier` for pysnaffler integration |
| `src/sharesift/pysnaffler_run.py` | `build_ruleset(include_defaults=False)` — convenience constructor for a pysnaffler-compatible ruleset with ShareSift loaded |
| `src/sharesift/content.py` | `ContentClassifier` — lazy-loads transformers+PEFT, CUDA/CPU auto-detect, `score()` returning `ContentResult` |
| `src/sharesift/pipeline.py` | `Scanner` — combines both stages, lazy content construction, `ScanResult` record |
| `src/sharesift/cli.py` | `sharesift` CLI: `score-paths` (Stage 1) + `scan-files` (Stage 1+2) |

### Training / eval pipeline (dev-only, not shipped at runtime)

| Module | Purpose |
|---|---|
| `src/eval/model/{features,train,evaluate,tier,calibrate,predict}.py` | Path-classifier training pipeline |
| `src/eval/content/{kingfisher,snippet,dedup,prompt,corpus}.py` | Content-classifier training-data pipeline |
| `src/eval/generator/{postprocess,ingest_paste,name_pool}.py` | Synthetic-data generator |
| `src/eval/{schema,validate,build_queue,label_app}.py` | Eval-set construction + integrity |
| `src/eval/source_{github,stackexchange}.py` | Public-corpus collectors |
| `src/eval/negative_validator.py` | Rule-5 anti-contamination tripwire (regex-tier patterns forbidden in negative class) |
| `tools/*.py` | CLI orchestration for training, benchmarking, audits |

## Key design decisions

### §1 Two-stage rather than monolithic

A single LLM-on-every-path classifier would be ~1000× more expensive
than the LightGBM stage at no quality gain on the obvious 95% of
benign paths. Stage 1 filters the millions-of-paths firehose to
hundreds of candidates; Stage 2 spends its CPU budget where it
matters.

### §2 LightGBM over a transformer for Stage 1

Paths are 20-80 chars of highly structured tokens. Char n-grams +
LightGBM hit PR-AUC 0.97 on the Snaffler-blind benchmark with
sub-millisecond inference and a 15MB artifact. A transformer encoder
(ModernBERT, MiniLM) was considered and rejected — over-spec'd for
this string length and label distribution (~95/5 imbalance, ~10K
labeled records). The architecture pressure-test rationale is in
`build_plan.md` §6.2.

### §3 Qwen3-1.7B over Llama-3.2-1B for Stage 2

The Wiz LoRA recipe (April 2025) used Llama-3.2-1B. 2026 SOTA research
showed Qwen3-1.7B beats Llama-3.2-1B by ~5pt on classification
benchmarks (Distil Labs) and was ~5× faster pre-finetune in Wiz's own
comparison. ShareSift beats Wiz's published numbers (precision 0.892
vs 0.857, recall 0.832 vs 0.82) on a held-out set, using Qwen3.
Rationale in `build_plan.md` §6.1.

### §4 transformers + PEFT, not GGUF

We built GGUF artifacts at Q4_K_M, Q5_K_M, Q8_0, and f16. All four
showed ~50pt recall degradation vs the transformers+PEFT inference
path — even f16 (no quantization at all). This is a llama.cpp runtime
issue specific to small fine-tuned models with thin LoRA decision
margins, not a quantization issue. v0 ships transformers+PEFT.

CUDA path: bnb-4bit base matches training exactly. CPU path: full
precision Qwen3-1.7B in bf16 (~3.4GB RAM, ~5-8s per record on Ryzen 5
3600). One install, two devices.

### §5 Lazy content-classifier import

`import sharesift` brings in stdlib + LightGBM only. The
torch+transformers+peft+bitsandbytes stack imports inside
`ContentClassifier.load()`, triggered by the first content
`score()` call. Three reasons:

1. Lean install (just Stage 1) is usable without the ~3GB
   content-inference deps.
2. `sharesift score-paths --help` returns instantly even without the
   heavy stack.
3. Tests for the path side don't need transformers installed.

### §6 Calibrated probabilities → Snaffler tier vocabulary

LightGBM's raw probabilities are "sharp" (cluster at 0/1).
Isotonic calibration via 5-fold CV (`src/eval/model/calibrate.py`)
gives honest probabilities, then `TierThresholds(0.95, 0.80, 0.50)`
maps them to Snaffler's Black / Red / Yellow. The thresholds are a
frozen dataclass — callers can override per-run without mutating the
default. Calibration intentionally produces more conservative output
than the raw model; the trade is fewer flags but higher precision
within each tier band, which is the right posture for operator-facing
triage.

### §7 Synthetic vs labeled as training data

Synthetic data (2,661 records, generator at `src/eval/generator/`) was
a useful Phase-1 bootstrap but distribution-mismatch failed it for
the path-classifier training (synthetic-only training produced
PR-AUC 0.38). The labeled queue (Claude-rule + Codex-audited,
11,190 records) is what actually trains the path classifier. The
synthetic stays in the repo for two reasons: (a) it covers regex-tier
patterns the labeler may underweight, useful as supplementary
training material in future revisions; (b) it documents what an
LLM-generated training corpus looks like for this domain.

## Data flow at runtime

### `sharesift score-paths` (Stage 1 only)

```
stdin/file ─► strip blanks ─► PathClassifier.score_batch()
                                      │
                                      ▼
                  featurize() char-ngram hash + hand features (CSR)
                                      │
                                      ▼
                  LightGBM predict_proba (isotonic-calibrated)
                                      │
                                      ▼
                  probability_to_tier (threshold band)
                                      │
                                      ▼
                  PathResult (path, probability, tier)
                                      │
                                      ▼
                  JSONL emit (stdout or --output)
```

### `sharesift scan-files` (Stage 1 + Stage 2)

```
stdin/file ─► strip blanks ─► read local files (skip unreadable)
                                      │
                                      ▼
                              Scanner.scan_batch()
                                      │
                          Stage 1 batched on all paths
                                      │
                                      ▼
                          PathResult per item
                                      │
                              tier-flagged AND content available?
                                /                    \
                              no                     yes
                              │                       │
                              │                       ▼
                              │           ContentClassifier.score()
                              │           (lazy load on first call)
                              │                       │
                              │             apply_chat_template
                              │                       │
                              │             generate up to N tokens
                              │                       │
                              │             strip <think>...</think>
                              │                       │
                              │             parse leading word → bool
                              │                       │
                              ▼                       ▼
                  ScanResult (content_check=None) | ScanResult (content_check="yes"/"no")
                                      │
                                      ▼
                  JSONL emit (stdout or --output)
```

## Phase-by-phase artifacts produced

| Phase | Artifacts |
|---|---|
| 1 | `data/eval/queue.jsonl` (11,190 records), `data/eval/eval_set_claude.jsonl`, `data/eval/snaffler_blind_benchmark.jsonl`, `data/synthetic/training_v0.jsonl` (2,661 records) |
| 2 | `models/path_classifier_v0_windows/{model,calibrated}.{joblib,onnx}` + metadata (v0.3 Windows model, unchanged in v0.5) |
| 3 | `data/content/{train_split,test_split}.jsonl`, `models/content_classifier_v0/adapter_model.safetensors` |
| 4 | `src/sharesift/` + CLI entrypoint, `README.md`, `docs/architecture.md` |
| B (v0.5) | `data/eval/eval_set_claude_linux.jsonl` (1500 LLM-labeled + 147 canonical seed + 38 hand-curated hardneg = 1685 Linux records), `models/path_classifier_v0_linux/{model,calibrated}.{joblib,onnx}` + metadata |
| C (v0.5) | `src/sharesift/pysnaffler_rule.py`, `src/sharesift/pysnaffler_run.py`, `tests/test_pysnaffler_rule.py` |

## Tests

```
tests/test_model.py            — path classifier (Phase 2)
tests/test_model_tier.py       — tier-band mapping
tests/test_content.py          — content data pipeline (Phase 3)
tests/test_runtime.py          — runtime + CLI (Phase 4)
tests/test_*.py                — eval-set / validator / source modules
```

`uv run pytest` runs the full suite (~635 tests). Some Phase-4 tests
skip when the trained model artifact isn't present.
