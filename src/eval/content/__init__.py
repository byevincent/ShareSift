"""Phase-3 content classifier data pipeline + training scaffolds.

Per ``docs/build_plan.md`` Phase 3 + §6.1 architecture decisions:

* **Base model:** Qwen3-1.7B-Instruct (NOT Llama-3.2-1B — research pass
  showed Qwen3 beats it by ~5pt on classification benchmarks and is
  ~5x faster at inference)
* **LoRA framework:** Unsloth (Red Hat-shipped in 2026, 2-5x faster
  than baseline FlashAttention-2)
* **Training data recipe:** Kingfisher verified matches → positives,
  regex-only matches → soft positives, random snippets → negatives
* **Quantization target:** GGUF Q4_K_M via llama.cpp (CPU laptop target)

This package contains:

* ``kingfisher`` — subprocess wrapper around the kingfisher CLI
* ``snippet`` — extract context windows around matches
* ``dedup`` — MinHash/LSH near-duplicate detection
* ``corpus`` — file iteration / extension filtering

The chat-template prompt formatting (``prompt``) module was moved to the
shipped ``sharesift`` package in v0.5 — runtime inference needs it. Import
via ``from sharesift.prompt import format_inference_messages, SYSTEM_PROMPT,
format_sft_example``.
"""
