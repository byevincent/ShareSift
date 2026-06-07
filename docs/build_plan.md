# ShareSift Build Plan

Ten-week realistic / 6-week aggressive timeline. Bottleneck is labels, not
compute. This plan supersedes the informal build plan Vincent shared in chat
on 2026-05-29; the architecture decisions in §6 reflect a 2026 SOTA pressure-
test rather than the original picks (which were from late 2024).

## Phase 1 — Foundation + data (weeks 1-3)

- Read tier-1 blogs. ✓
- Set up pysnaffler dev env. ✓ (`references/pysnaffler/`)
- Pull Snaffler + Kingfisher rule files. ✓ (`references/{Snaffler,kingfisher}/`)
- Build synthetic share generator. ✓ — 7 passes, 1,851 records, 87 Linux
  paths. Manual LLM prompt-driven (ChatGPT + DeepSeek + Qwen) via
  `src/eval/generator/postprocess.py` + `ingest_paste.py`.
- Build labeled eval corpus from public sources. ✓ — 11,190 records via
  GitHub Code Search + ServerFault + SuperUser + Stack Overflow, rule-labeled
  by `tools/claude_label.py` and Codex-audited (88% combined agreement).
  Vincent's plan originally called for 500-1000 hand-labeled paths; the
  hand-labeling step was dropped in favor of the rule + Codex audit pipeline.
  Known ceiling: model is bounded by patterns Vincent + Claude + Codex agree
  are juicy.
- Build held-out benchmark of 500 paths Snaffler's rules weren't designed for.
  **Pending.** Phase 2 needs this as a measurement target — without it, "did
  the ML model beat Snaffler" has no answer.
- Linux corpus extension (per Vincent's friend's "what helps in a pentest"
  ask). **Pending.** Synthetic side is started (5% Linux); eval-side
  extraction not built.

## Phase 2 — Path classifier (weeks 4-5)

**Updated approach** (see §6 for rationale):

1. Baseline first: **fastText or LightGBM on hashed character n-grams**.
   If this hits ≥0.90 PR-AUC on the held-out benchmark, ship it and skip
   the transformer for stage 1 entirely. Sub-millisecond inference, no
   GPU, trivial to deploy.
2. Transformer fallback: **MiniLM-L6 (~33M) or DistilBERT (~67M)**, not
   ModernBERT-base. Fine-tune via vanilla HuggingFace `Trainer` + `accelerate`.
3. Benchmark vs Snaffler's default classifier on the held-out set.
4. Hard-negative mining loop: surface least-confident predictions, label,
   retrain.
5. Calibrate output scores into Snaffler's tier taxonomy (Black/Red/Yellow).

## Phase 3 — Content classifier (weeks 6-8)

**Updated approach** (see §6):

1. Base model: **Qwen3-1.7B-Instruct** (was: Llama-3.2-1B). Apache-2.0,
   beats Llama by ~5 points on classification benchmarks, ~5× faster
   pre-finetune.
2. LoRA fine-tune via **Unsloth** (memory-efficient, 2-5× faster than
   FlashAttention-2 baseline, Red Hat-shipped in 2026).
3. Training data: Kingfisher verified matches as positives, regex-only
   matches as soft positives, random snippets as negatives. Follow the
   Wiz LoRA recipe shape (April 2025 Wiz blog) — replicate on Qwen3
   rather than Llama.
4. Quantize to int4 (GGUF Q4_K_M default; IQ4_XS as a tuning option).
   Benchmark CPU latency at typical file-snippet sizes (~1-2KB).
5. Integrate as Kingfisher's denoising stage.

## Phase 4 — Integration + packaging (weeks 9-10)

1. Wire path tier + content tier into `pysnaffler` as a custom classifier.
2. **ONNX int8** export for the path classifier (dynamic int8 via
   `optimum.onnxruntime`, expect 1.5–3× CPU speedup on AVX-512 VNNI).
3. **GGUF Q4_K_M** export for the SLM (via llama.cpp).
4. CPU inference benchmarks on a commodity laptop.
5. Architecture doc + public blog post + Mandiant-specific handoff doc.

## §5. Resources

**Existing tools to build on:**
- [pysnaffler](https://github.com/skelsec/pysnaffler) — Python Snaffler
  port, TOML rule compat, `aiosmb`-based
- [Snaffler classifiers](https://github.com/SnaffCon/Snaffler/tree/master/Snaffler/Classifiers)
  — TOML rule pack
- [Kingfisher](https://github.com/mongodb/kingfisher) — Rust, 942 rules
  + 484 validators, Apache-2.0
- [Titus](https://github.com/praetorian-inc/titus) — Praetorian's Go port
  of Nosey Parker; 450+ rules, Burp integration
- SmbCrawler — newer credentialed spider with SQLite output

**Models:**
- **Qwen3-1.7B-Instruct** (content classifier) — Apache-2.0
- **MiniLM-L6 / DistilBERT** (path classifier fallback, if fastText baseline
  insufficient)
- **Qwen3-35B** (local synthetic data generation, sibling project
  `qwen_cyber`)

**Data sources for bootstrap:**
- Snaffler `default.toml` — positive seeds for path patterns
- Kingfisher rules dir — positive seeds for content patterns + working
  scanner for weak labels
- arxiv 2410.23657 — labeled secrets-in-context corpus
- Synthetic generation via local Qwen3 35B (`qwen_cyber` pipeline)

## §6. Architecture decisions (2026 SOTA pressure-test)

Three updates to the original informal plan after a 2026 research pass
(2026-05-29). All decisions reviewed and signed off by Vincent.

### §6.1 Content classifier: Qwen3-1.7B-Instruct (was: Llama-3.2-1B)

**Decision:** Switch from Llama-3.2-1B to Qwen3-1.7B-Instruct as the LoRA
base for the content classifier.

**Rationale:** Distil Labs' 2025 SLM benchmark (12 models, 8 tasks) puts
Qwen3-1.7B at 91.3% classification accuracy vs Llama-3.2-1B at 86.7%.
The Wiz secrets-detection blog's own pre-finetune numbers show their Qwen
baseline at 87.5% precision / 71% recall and 143 tok/s vs Llama at 85.7% /
82% / 27 tok/s — Wiz picked Llama only because recall was higher, but LoRA
fine-tuning is expected to close that gap. Qwen3 is Apache-2.0 with mature
GGUF support and stronger code tokenization.

**Alternatives considered:** Phi-4-mini (3.8B, larger with no obvious
classification benefit); Gemma-3-2B (Apache-2.0 but lower benchmark numbers
than Qwen3-1.7B); SmolLM-3 (interesting but unproven for this task size).

### §6.2 Path classifier: try non-transformer baseline first

**Decision:** Start with fastText or LightGBM on hashed character n-grams
as the path-classifier baseline. Only escalate to a transformer (MiniLM-L6
or DistilBERT, not ModernBERT-base) if the baseline misses ≥0.90 PR-AUC
on the held-out Snaffler-blind benchmark.

**Rationale:** Path strings are 20-80 chars of highly structured tokens.
ModernBERT-base's main advantages (8K context, code-aware pretraining mix)
are mostly wasted at this length. Phil Schmid's ModernBERT-vs-BERT
comparison shows ~3pt F1 gain on Banking77 but only on harder multi-class
problems; for binary classification with ~95/5 imbalance and ~10K labels,
the marginal accuracy gain is unlikely to justify ~4-6× the CPU cost vs
MiniLM. fastText explicitly handles imbalanced classes well at sub-ms
inference. Stage 1 throughput matters (classifying millions of paths per
share); cheap-and-fast wins until proven otherwise.

**Alternatives considered:** Full ModernBERT-base (over-spec'd for the task
shape); character-level transformer (architecturally interesting per the
TransURL 2024 work, but adds complexity for an unproven gain).

### §6.3 Training framework split

**Decision:** Unsloth for the SLM LoRA, vanilla HF Transformers `Trainer`
+ `accelerate` for the encoder.

**Rationale:** Unsloth in 2026 is 2-5× faster than FlashAttention-2 baseline
with up to 80% VRAM reduction; Red Hat ships it in their Training Hub —
strong production-stability signal. Adapter format is HF-compatible (no
lock-in). For the small encoder, Unsloth is overkill; vanilla Trainer is
faster to set up and has more mature evaluation hooks.

**Alternatives considered:** Axolotl (production-mature for multi-GPU, but
YAML-config friction for a solo single-GPU build, slightly slower than
Unsloth); TRL (oriented at RLHF/GRPO which ShareSift doesn't need); torchtune
(slower than Unsloth in independent benchmarks).

## §7. Competitive positioning

Kingfisher (MongoDB, June 2025) and Titus (Praetorian, Feb 2026) are both
regex + validator architectures — no LLM content classifier. Wiz operates an
LLM secret detector internally but the model itself is closed-source. **No
open-source secret-finder currently pairs rule-based path triage with an LLM
content classifier.** ShareSift would be the open replication. This is the
story to tell when shipping.
