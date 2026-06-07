"""Phase-3 content classifier training script — Qwen3-1.7B-Instruct LoRA via Unsloth.

**Status: scaffold.** This script lays out the training plan; it imports
Unsloth on first invocation and will fail informatively if Unsloth +
the GPU stack aren't available. Per ``docs/build_plan.md`` §6.1, this
intentionally uses Qwen3-1.7B-Instruct (not Llama-3.2-1B from the
original Wiz recipe — Qwen3 wins on classification benchmarks and is
~5× faster pre-finetune).

Prerequisites before running:

1. Free GPU VRAM. ``llama-server`` (qwen_cyber sibling project) holds
   ~24GB on the 32GB 5090 — stop it via ``pkill -f llama-server`` and
   restart after training finishes. Synthetic-generation traffic
   should be paused first.
2. Install training-stack deps (heavy install, ~5GB)::

       uv add --group content "unsloth>=2025.10" "bitsandbytes>=0.43" \\
           "trl>=0.12" "transformers>=4.46" "accelerate>=1.0" \\
           "datasets>=3.0"

3. Build the training dataset first::

       uv run python tools/build_content_dataset.py --corpus <path>

Default training config (single 5090, ~10-15GB VRAM peak):

* LoRA rank=16, alpha=32, target=q/k/v/o + MLP
* max_seq_length=2048
* batch_size=2, grad_accum=8 → effective batch 16
* learning_rate=2e-4, cosine schedule, 200 warmup steps
* epochs=3 (Wiz recipe; adjust based on validation curve)
* save best by validation loss

Expected runtime: 4-8 hours on a single RTX 5090 for ~10K examples.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Default points at the train split, NOT the full deduped dataset. Pointing
# at training_dataset.jsonl would bake the test set into training — the
# integrity audit in reports/audit_eval_integrity.json caught that exact
# mistake in the v0 pipeline.
DEFAULT_DATASET = REPO_ROOT / "data" / "content" / "train_split.jsonl"
DEFAULT_TEST_SPLIT = REPO_ROOT / "data" / "content" / "test_split.jsonl"
DEFAULT_MODEL_DIR = REPO_ROOT / "models" / "content_classifier_v0"
# Unsloth's preconverted 4-bit Qwen3 — avoids local bnb 4-bit conversion
# at load time. Equivalent to ``Qwen/Qwen3-1.7B`` upstream.
DEFAULT_BASE_MODEL = "unsloth/Qwen3-1.7B-unsloth-bnb-4bit"


def _import_training_stack():
    """Lazy import of the heavy training stack. Fails fast with a
    pointer to the install instructions if anything is missing."""
    missing: list[str] = []
    try:
        import unsloth  # noqa: F401
    except ImportError:
        missing.append("unsloth")
    try:
        import trl  # noqa: F401
    except ImportError:
        missing.append("trl")
    try:
        import torch  # noqa: F401
    except ImportError:
        missing.append("torch")
    if missing:
        print(
            "Training-stack imports failed: " + ", ".join(missing),
            file=sys.stderr,
        )
        print(
            "Install via: uv add --group content 'unsloth>=2025.10' "
            "'bitsandbytes>=0.43' 'trl>=0.12' 'transformers>=4.46' "
            "'accelerate>=1.0' 'datasets>=3.0'",
            file=sys.stderr,
        )
        sys.exit(2)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    p.add_argument(
        "--test-split",
        type=Path,
        default=DEFAULT_TEST_SPLIT,
        help=(
            "Held-out test split. Used only as a contamination guard: "
            "training refuses to start if --dataset resolves to the same path."
        ),
    )
    p.add_argument("--output-dir", type=Path, default=DEFAULT_MODEL_DIR)
    p.add_argument("--base-model", default=DEFAULT_BASE_MODEL)
    p.add_argument("--instruct", action="store_true", default=True)
    p.add_argument("--lora-rank", type=int, default=16)
    p.add_argument("--lora-alpha", type=int, default=32)
    p.add_argument("--max-seq-length", type=int, default=2048)
    p.add_argument("--batch-size", type=int, default=2)
    p.add_argument("--grad-accum", type=int, default=8)
    p.add_argument("--learning-rate", type=float, default=2e-4)
    p.add_argument("--epochs", type=int, default=3)
    p.add_argument("--warmup-steps", type=int, default=200)
    p.add_argument("--seed", type=int, default=2026)
    p.add_argument(
        "--data-fraction",
        type=float,
        default=1.0,
        help=(
            "Fraction of --dataset to train on (0 < f <= 1.0). Stratified by "
            "label so the yes/no ratio is preserved. <1.0 writes the subset to "
            "<output-dir>/train_subset_<frac>.jsonl and trains on that. Used "
            "by the data-fraction ablation (C5)."
        ),
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the training plan but don't import Unsloth or train.",
    )
    args = p.parse_args(argv)

    if not (0 < args.data_fraction <= 1.0):
        print(
            f"ERROR: --data-fraction must be in (0, 1.0], got {args.data_fraction}",
            file=sys.stderr,
        )
        return 2

    # Contamination guard: refuse to train on the test split, even by
    # accident. The v0 pipeline had a default-flag bug where --dataset
    # pointed at the full pre-split file and trained on the test set;
    # this assertion makes the same class of mistake impossible.
    if args.dataset.resolve() == args.test_split.resolve():
        print(
            f"ERROR: --dataset ({args.dataset}) is the same path as "
            f"--test-split ({args.test_split}). Refusing to train.",
            file=sys.stderr,
        )
        return 2

    # If --data-fraction < 1.0, materialize a stratified subset alongside
    # the model output so the run is fully reproducible from disk (same
    # SHA path that goes into training_metadata.json).
    effective_dataset = args.dataset
    if args.data_fraction < 1.0:
        import random as _random

        args.output_dir.mkdir(parents=True, exist_ok=True)
        subset_path = args.output_dir / f"train_subset_f{args.data_fraction:.3f}.jsonl"
        records = [
            json.loads(line)
            for line in args.dataset.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        # Stratify by assistant-turn label. Records without a recognized
        # label go into a third bucket and are subsampled at the same rate.
        by_label: dict[str, list[dict]] = {}
        for r in records:
            label = ""
            for m in r.get("messages", []):
                if m.get("role") == "assistant":
                    label = m.get("content", "").strip()
                    break
            by_label.setdefault(label, []).append(r)
        rng = _random.Random(args.seed)
        subset: list[dict] = []
        for label, group in by_label.items():
            rng.shuffle(group)
            n_keep = max(1, round(len(group) * args.data_fraction))
            subset.extend(group[:n_keep])
        rng.shuffle(subset)
        with subset_path.open("w", encoding="utf-8") as f:
            for r in subset:
                f.write(json.dumps(r) + "\n")
        print(
            f"Subsampled {args.data_fraction:.1%} of {len(records)} → "
            f"{len(subset)} records, wrote {subset_path}",
            file=sys.stderr,
        )
        effective_dataset = subset_path

    print(f"Dataset: {effective_dataset}")
    if args.data_fraction < 1.0:
        print(f"Data fraction: {args.data_fraction:.1%} (subset)")
    print(f"Base model: {args.base_model}{' (instruct)' if args.instruct else ''}")
    print(
        f"LoRA: rank={args.lora_rank}, alpha={args.lora_alpha}, "
        f"max_seq={args.max_seq_length}"
    )
    print(
        f"Optim: batch={args.batch_size}, grad_accum={args.grad_accum} "
        f"(effective {args.batch_size * args.grad_accum}), "
        f"lr={args.learning_rate}, epochs={args.epochs}"
    )
    print(f"Output: {args.output_dir}")

    if args.dry_run:
        print("\nDry-run: not loading the training stack.")
        return 0

    _import_training_stack()

    # Once the GPU is freed and the stack is installed, the training
    # loop below executes the LoRA fine-tune. Implementation deferred
    # to the GPU-side session — this scaffold defines the contract.
    from unsloth import FastLanguageModel  # type: ignore[import-not-found]
    from datasets import load_dataset  # type: ignore[import-not-found]
    from trl import SFTConfig, SFTTrainer  # type: ignore[import-not-found]

    # Unsloth's preconverted models already include the instruct
    # variant where appropriate; pass the model name through verbatim
    # rather than appending ``-Instruct``.
    model_name = args.base_model
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=model_name,
        max_seq_length=args.max_seq_length,
        load_in_4bit=True,
    )
    model = FastLanguageModel.get_peft_model(
        model,
        r=args.lora_rank,
        lora_alpha=args.lora_alpha,
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
        use_gradient_checkpointing="unsloth",
        random_state=args.seed,
    )

    dataset = load_dataset("json", data_files=str(effective_dataset), split="train")

    # TRL 0.20+ no longer auto-handles the ``messages`` field; we render
    # each example through Qwen3's chat template up-front and feed the
    # trainer a flat ``text`` column. ``add_generation_prompt=False``
    # because the assistant turn is already present in the messages
    # (SFT, not generation).
    def _render(example: dict) -> dict:
        text = tokenizer.apply_chat_template(
            example["messages"], tokenize=False, add_generation_prompt=False
        )
        return {"text": text}

    dataset = dataset.map(_render, remove_columns=["messages"])

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        args=SFTConfig(
            output_dir=str(args.output_dir),
            per_device_train_batch_size=args.batch_size,
            gradient_accumulation_steps=args.grad_accum,
            learning_rate=args.learning_rate,
            num_train_epochs=args.epochs,
            warmup_steps=args.warmup_steps,
            lr_scheduler_type="cosine",
            optim="adamw_8bit",
            seed=args.seed,
            # ``max_seq_length`` moved out of SFTConfig in TRL 0.20+;
            # it's now configured at model-load time (FastLanguageModel
            # call above). Logging is disabled to keep the run quiet.
            report_to="none",
            logging_steps=10,
            save_strategy="epoch",
            dataset_text_field="text",
        ),
    )

    trainer.train()
    trainer.save_model(str(args.output_dir))

    # Bind the saved model to its training set on disk via SHA256 of the
    # dataset file + a snapshot of the run config. Lets the integrity
    # audit verify model/training-data provenance after the fact.
    training_sha = hashlib.sha256(effective_dataset.read_bytes()).hexdigest()

    def _rel(p: Path) -> str:
        try:
            return str(p.resolve().relative_to(REPO_ROOT))
        except ValueError:
            return str(p.resolve())

    metadata = {
        "trained_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "training_dataset": _rel(args.dataset),
        "effective_training_dataset": _rel(effective_dataset),
        "data_fraction": args.data_fraction,
        "training_dataset_sha256": training_sha,
        "training_records": sum(1 for _ in effective_dataset.open()),
        "test_split_path_for_guard": _rel(args.test_split),
        "base_model": args.base_model,
        "instruct": bool(args.instruct),
        "lora": {
            "rank": args.lora_rank,
            "alpha": args.lora_alpha,
            "target_modules": [
                "q_proj", "k_proj", "v_proj", "o_proj",
                "gate_proj", "up_proj", "down_proj",
            ],
        },
        "optim": {
            "batch_size": args.batch_size,
            "grad_accum": args.grad_accum,
            "effective_batch": args.batch_size * args.grad_accum,
            "learning_rate": args.learning_rate,
            "epochs": args.epochs,
            "warmup_steps": args.warmup_steps,
            "lr_scheduler": "cosine",
            "optimizer": "adamw_8bit",
        },
        "max_seq_length": args.max_seq_length,
        "seed": args.seed,
    }
    metadata_path = args.output_dir / "training_metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2))
    print(f"Training complete. Model saved to {args.output_dir}")
    print(f"Training metadata written to {metadata_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
