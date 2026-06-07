"""v0.13 Phase 4 — train the literal-vs-referenced credential classifier.

Inherits the v0p6 Unsloth/Qwen3-1.7B/LoRA stack from
``tools/train_content_classifier.py`` but with three differences:

  1. **Input shape:** 500-char snippets (~125 tokens) instead of v0p6's
     4000-char snippets. max_seq_length drops 2048 → 512, freeing VRAM
     for larger batches.
  2. **Class imbalance handling:** the corpus runs ~10–35% literal vs
     65–90% referenced. SFTTrainer doesn't natively support class
     weighting on the assistant token, so we balance via oversampling
     of the minority class up to a target ratio.
  3. **Self-contained dataset prep:** reads the scraped/split JSONL
     directly (snippet + label fields) and renders to chat-template
     messages in-process. No separate ``build_content_dataset.py``
     step.

Output goes to ``models/content_classifier_v0p7_literal_vs_referenced/``
per the v0.13 spec. v0p6 remains the deployed default content classifier;
this model is a dedicated head consumed by v0.14's ranker.

Prerequisites:

  1. Free GPU VRAM (this stack peaks around 8–10GB with 512-token seqs).
  2. ``uv sync --group content`` (Unsloth + bitsandbytes + trl + …).
  3. Phase 3 split files exist at
     ``data/external/literal_vs_referenced/splits/{train,val,test}.jsonl``.

Usage::

    uv run python tools/train_literal_vs_referenced.py \\
        --output-dir models/content_classifier_v0p7_literal_vs_referenced \\
        --epochs 3 \\
        --target-balance 0.5

    # Dry run to verify the dataset prep without loading Unsloth
    uv run python tools/train_literal_vs_referenced.py --dry-run
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import random
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_TRAIN = REPO_ROOT / "data" / "external" / "literal_vs_referenced" / "splits" / "train.jsonl"
DEFAULT_VAL = REPO_ROOT / "data" / "external" / "literal_vs_referenced" / "splits" / "val.jsonl"
DEFAULT_TEST = REPO_ROOT / "data" / "external" / "literal_vs_referenced" / "splits" / "test.jsonl"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "models" / "content_classifier_v0p7_literal_vs_referenced"
DEFAULT_BASE_MODEL = "unsloth/Qwen3-1.7B-unsloth-bnb-4bit"

SYSTEM_PROMPT = (
    "You are a credential-snippet classifier. Given a short context window "
    "from a file flagged by a credential scanner, decide whether it contains "
    "a LITERAL credential value (a real password, key, or token written "
    "directly in the file) or a REFERENCED credential (a variable reference, "
    "function parameter, example block, or template pattern that mentions "
    "credentials but does not store one). Answer with exactly one word: "
    "literal or referenced."
)


def _render_messages(record: dict) -> list[dict]:
    """Convert a {snippet, label, file_extension, matched_text} record
    into the chat-template messages format expected by the SFT trainer."""
    snippet = record["snippet"]
    ext = record.get("file_extension", "?")
    matched = record.get("matched_text", "")[:120]
    user_content = (
        f"File extension: .{ext}\n"
        f"Match: {matched}\n"
        f"---\n"
        f"{snippet}\n"
        f"---\n"
        f"Classify the credential context."
    )
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
        {"role": "assistant", "content": record["label"]},
    ]


def _load_jsonl(path: Path) -> list[dict]:
    records: list[dict] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def _balance_corpus(
    records: list[dict],
    target_minority_fraction: float,
    seed: int,
) -> list[dict]:
    """Oversample the minority class to bring it up to the target fraction.

    Returns a shuffled list with the original records plus duplicates of
    minority-class records as needed. Does not downsample the majority.
    """
    by_label: dict[str, list[dict]] = {"literal": [], "referenced": []}
    for r in records:
        by_label.setdefault(r["label"], []).append(r)
    n_literal = len(by_label["literal"])
    n_referenced = len(by_label["referenced"])
    if n_literal == 0 or n_referenced == 0:
        return records

    # Identify the minority class
    if n_literal < n_referenced:
        minority_label, minority_count = "literal", n_literal
        majority_count = n_referenced
    else:
        minority_label, minority_count = "referenced", n_referenced
        majority_count = n_literal

    # Compute how many minority duplicates needed to reach target fraction:
    #   target = (minority_count + k) / (majority_count + minority_count + k)
    #   solve for k → k = (target * (majority + minority) - minority) / (1 - target)
    if target_minority_fraction >= 0.5:
        target = 0.5  # Don't make it the majority
    else:
        target = target_minority_fraction
    needed = (target * (majority_count + minority_count) - minority_count) / max(1e-9, 1.0 - target)
    needed_int = max(0, int(round(needed)))
    if needed_int == 0:
        return records

    rng = random.Random(seed)
    duplicates: list[dict] = []
    while len(duplicates) < needed_int:
        duplicates.extend(by_label[minority_label])
        rng.shuffle(duplicates)
    duplicates = duplicates[:needed_int]
    print(
        f"[balance] minority='{minority_label}' was {minority_count} / "
        f"{majority_count + minority_count} ({minority_count / (majority_count + minority_count):.1%}); "
        f"oversampling +{needed_int} duplicates to reach {target:.0%}",
        file=sys.stderr,
    )
    balanced = records + duplicates
    rng.shuffle(balanced)
    return balanced


def _prepare_rendered_jsonl(
    records: list[dict],
    output_path: Path,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps({"messages": _render_messages(r)}) + "\n")


def _import_training_stack() -> None:
    missing: list[str] = []
    for mod in ("unsloth", "trl", "torch", "datasets", "transformers"):
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    if missing:
        print(f"Training stack missing: {', '.join(missing)}", file=sys.stderr)
        print(
            "Install via: uv add --group content 'unsloth>=2025.10' "
            "'bitsandbytes>=0.43' 'trl>=0.12' 'transformers>=4.46' "
            "'accelerate>=1.0' 'datasets>=3.0'",
            file=sys.stderr,
        )
        sys.exit(2)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--train", type=Path, default=DEFAULT_TRAIN)
    p.add_argument("--val", type=Path, default=DEFAULT_VAL)
    p.add_argument("--test", type=Path, default=DEFAULT_TEST,
                   help="Held-out test split. Contamination guard only.")
    p.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    p.add_argument("--base-model", default=DEFAULT_BASE_MODEL)
    p.add_argument("--lora-rank", type=int, default=16)
    p.add_argument("--lora-alpha", type=int, default=32)
    p.add_argument("--max-seq-length", type=int, default=512,
                   help="Snippets are ~125 tokens; 512 covers the system+user prompt scaffolding.")
    p.add_argument("--batch-size", type=int, default=4)
    p.add_argument("--grad-accum", type=int, default=4,
                   help="effective batch = batch_size * grad_accum = 16 by default")
    p.add_argument("--learning-rate", type=float, default=2e-4)
    p.add_argument("--epochs", type=int, default=3)
    p.add_argument("--warmup-steps", type=int, default=100)
    p.add_argument("--target-balance", type=float, default=0.5,
                   help="Target minority-class fraction after oversampling (default 0.5 = balanced).")
    p.add_argument("--seed", type=int, default=2026)
    p.add_argument("--dry-run", action="store_true",
                   help="Print the training plan + dataset stats but don't load Unsloth or train.")
    args = p.parse_args(argv)

    # Contamination guards: refuse to train on val or test, even by accident
    for guard_path, guard_name in [(args.val, "--val"), (args.test, "--test")]:
        if args.train.resolve() == guard_path.resolve():
            print(
                f"ERROR: --train ({args.train}) resolves to the same path as "
                f"{guard_name} ({guard_path}). Refusing to train.",
                file=sys.stderr,
            )
            return 2

    if not args.train.exists():
        print(f"ERROR: --train missing: {args.train}\n"
              f"Run tools/split_literal_vs_referenced_corpus.py first.",
              file=sys.stderr)
        return 2

    raw_train = _load_jsonl(args.train)
    raw_val = _load_jsonl(args.val) if args.val.exists() else []
    print(f"[load] train: {len(raw_train)} records, val: {len(raw_val)} records",
          file=sys.stderr)

    label_counts_train = Counter(r["label"] for r in raw_train)
    label_counts_val = Counter(r["label"] for r in raw_val)
    subtype_counts_train = Counter(r.get("subtype") for r in raw_train if r["label"] == "referenced")
    print(f"  train labels: {dict(label_counts_train)}", file=sys.stderr)
    print(f"  train negative subtypes: {dict(subtype_counts_train)}", file=sys.stderr)
    print(f"  val labels: {dict(label_counts_val)}", file=sys.stderr)

    # Oversample minority class. We do this AFTER the split (not before)
    # so val/test ratios reflect the natural corpus distribution; only
    # the train set gets rebalanced.
    train_balanced = _balance_corpus(raw_train, args.target_balance, args.seed)
    print(f"[balance] train balanced size: {len(train_balanced)}", file=sys.stderr)

    # Render to chat-template JSONL on disk so the training run is fully
    # reproducible from the artifact alone.
    args.output_dir.mkdir(parents=True, exist_ok=True)
    rendered_train = args.output_dir / "rendered_train.jsonl"
    rendered_val = args.output_dir / "rendered_val.jsonl"
    _prepare_rendered_jsonl(train_balanced, rendered_train)
    if raw_val:
        _prepare_rendered_jsonl(raw_val, rendered_val)
    print(f"[render] wrote {rendered_train}", file=sys.stderr)

    print(f"Base model: {args.base_model}", file=sys.stderr)
    print(f"LoRA: rank={args.lora_rank}, alpha={args.lora_alpha}, "
          f"max_seq={args.max_seq_length}", file=sys.stderr)
    print(f"Optim: batch={args.batch_size}, grad_accum={args.grad_accum} "
          f"(effective {args.batch_size * args.grad_accum}), "
          f"lr={args.learning_rate}, epochs={args.epochs}", file=sys.stderr)
    print(f"Output: {args.output_dir}", file=sys.stderr)

    if args.dry_run:
        print("\n[dry-run] Stopping before training-stack import.", file=sys.stderr)
        return 0

    _import_training_stack()
    from unsloth import FastLanguageModel  # type: ignore[import-not-found]
    from datasets import load_dataset  # type: ignore[import-not-found]
    from trl import SFTConfig, SFTTrainer  # type: ignore[import-not-found]

    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.base_model,
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

    train_dataset = load_dataset("json", data_files=str(rendered_train), split="train")
    eval_dataset = (
        load_dataset("json", data_files=str(rendered_val), split="train")
        if rendered_val.exists() and raw_val else None
    )

    def _render_chat(example: dict) -> dict:
        text = tokenizer.apply_chat_template(
            example["messages"], tokenize=False, add_generation_prompt=False,
        )
        return {"text": text}

    train_dataset = train_dataset.map(_render_chat, remove_columns=["messages"])
    if eval_dataset is not None:
        eval_dataset = eval_dataset.map(_render_chat, remove_columns=["messages"])

    sft_args = {
        "output_dir": str(args.output_dir),
        "per_device_train_batch_size": args.batch_size,
        "gradient_accumulation_steps": args.grad_accum,
        "learning_rate": args.learning_rate,
        "num_train_epochs": args.epochs,
        "warmup_steps": args.warmup_steps,
        "lr_scheduler_type": "cosine",
        "optim": "adamw_8bit",
        "seed": args.seed,
        "report_to": "none",
        "logging_steps": 25,
        "save_strategy": "epoch",
        "dataset_text_field": "text",
    }
    if eval_dataset is not None:
        sft_args.update({
            "eval_strategy": "epoch",
            "per_device_eval_batch_size": args.batch_size,
        })

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        args=SFTConfig(**sft_args),
    )

    trainer.train()
    trainer.save_model(str(args.output_dir))

    # Provenance metadata — binds the saved adapter to its training data
    train_sha = hashlib.sha256(args.train.read_bytes()).hexdigest()
    rendered_sha = hashlib.sha256(rendered_train.read_bytes()).hexdigest()

    def _rel(p: Path) -> str:
        try:
            return str(p.resolve().relative_to(REPO_ROOT))
        except ValueError:
            return str(p.resolve())

    metadata = {
        "trained_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "objective": "literal_vs_referenced_credential_classification",
        "training_split": _rel(args.train),
        "training_split_sha256": train_sha,
        "rendered_training_jsonl": _rel(rendered_train),
        "rendered_training_sha256": rendered_sha,
        "val_split": _rel(args.val) if raw_val else None,
        "test_split_path_for_guard": _rel(args.test),
        "n_raw_train_records": len(raw_train),
        "n_balanced_train_records": len(train_balanced),
        "n_val_records": len(raw_val),
        "label_counts_raw_train": dict(label_counts_train),
        "label_counts_val": dict(label_counts_val),
        "negative_subtypes_train": dict(subtype_counts_train),
        "target_minority_fraction": args.target_balance,
        "base_model": args.base_model,
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
        "system_prompt": SYSTEM_PROMPT,
    }
    metadata_path = args.output_dir / "training_metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2))
    print(f"\n[done] Training complete. Model + metadata → {args.output_dir}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
