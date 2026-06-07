"""Export the LoRA-tuned content classifier to GGUF Q4_K_M.

Phase-4 deliverable per ``docs/build_plan.md``: the content classifier
ships as a GGUF artifact that ``llama.cpp`` (or any GGUF-compatible
runtime) can load on CPU. Q4_K_M is the practical sweet spot per the
2026 SOTA research pass — ~92% perplexity retention, predictable
behavior, no imatrix calibration drama.

Pipeline:

1. Load base + LoRA via Unsloth (same path the eval script uses).
2. Merge the LoRA weights into the base via ``model.merge_and_unload()``
   so the GGUF carries a single set of weights, no adapter side-load.
3. Save as GGUF Q4_K_M to ``models/content_classifier_v0/qwen3-1.7b-content-v0.Q4_K_M.gguf``.
4. Print the resulting file size so we can sanity-check against the
   ~1.0-1.3GB expected for a Q4_K_M Qwen3-1.7B.

The CPU latency benchmark is a separate script.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_MODEL_DIR = REPO_ROOT / "models" / "content_classifier_v0"
DEFAULT_OUTPUT_NAME = "qwen3-1.7b-content-v0"
DEFAULT_BASE_MODEL = "unsloth/Qwen3-1.7B-unsloth-bnb-4bit"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    p.add_argument("--base-model", default=DEFAULT_BASE_MODEL)
    p.add_argument("--output-name", default=DEFAULT_OUTPUT_NAME)
    p.add_argument(
        "--quant-method",
        default="q4_k_m",
        help="GGUF quantization method (q4_k_m default, also try q5_k_m, q8_0).",
    )
    args = p.parse_args(argv)

    from unsloth import FastLanguageModel  # type: ignore[import-not-found]

    print(f"Loading base + LoRA from {args.model_dir}")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=str(args.model_dir),
        max_seq_length=2048,
        load_in_4bit=False,  # full-precision merge target
    )

    output_dir = args.model_dir
    print(
        f"Exporting to GGUF ({args.quant_method}) at "
        f"{output_dir}/{args.output_name}.{args.quant_method}.gguf"
    )
    # Unsloth's save_pretrained_gguf merges LoRA, converts via llama.cpp's
    # convert_hf_to_gguf.py internally, and quantizes in one shot.
    model.save_pretrained_gguf(
        str(output_dir / args.output_name),
        tokenizer,
        quantization_method=args.quant_method,
    )

    # Report size for sanity-check.
    candidates = list(output_dir.glob(f"{args.output_name}*.gguf"))
    for f in candidates:
        size_mb = f.stat().st_size / 1024 / 1024
        print(f"  {f.name}: {size_mb:.1f} MB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
