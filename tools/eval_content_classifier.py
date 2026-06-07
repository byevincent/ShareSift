"""Phase-3 content classifier evaluation harness.

Loads the LoRA-tuned Qwen3-1.7B model from ``models/content_classifier_v0``,
runs it over ``data/content/test_split.jsonl`` (held-out 20% from the same
dataset the training script consumed), and reports precision/recall/F1 +
per-confidence-tier breakdown.

Per ``docs/build_plan.md`` Phase 3 success criterion: replicate or beat
the Wiz LoRA recipe's numbers (precision ≥0.857, recall ≥0.82) on a
comparable held-out set. Throughput target (≥27 tok/s on CPU after
Q4_K_M quantization) is measured separately during the
quantization-benchmarking pass.

Inference shape: for each record, render the same chat template used at
training time WITHOUT the assistant turn, generate up to ``--max-new-tokens``
(default 4) tokens, take the first non-whitespace token, and check if it
starts with "yes" or "no". Single-token classification keeps eval cheap.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sharesift.prompt import format_inference_messages

DEFAULT_TEST_SET = REPO_ROOT / "data" / "content" / "test_split.jsonl"
DEFAULT_MODEL_DIR = REPO_ROOT / "models" / "content_classifier_v0"
DEFAULT_BASE_MODEL = "unsloth/Qwen3-1.7B-unsloth-bnb-4bit"
DEFAULT_RESULTS_OUT = REPO_ROOT / "reports" / "eval_content_classifier.json"


def _classify_first_token(generated_text: str) -> str | None:
    """Read the model's response and reduce to 'yes' / 'no' / None.

    Qwen3 emits a chain-of-thought ``<think>...</think>`` block before
    the answer; strip it before checking the leading token. Also
    tolerant of trailing chat-template residue (``<|im_end|>``).
    """
    txt = generated_text
    # Strip <think>...</think> block (may be empty).
    if "</think>" in txt:
        txt = txt.split("</think>", 1)[1]
    txt = txt.strip().lower()
    if txt.startswith("yes"):
        return "yes"
    if txt.startswith("no"):
        return "no"
    return None


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--test-set", type=Path, default=DEFAULT_TEST_SET)
    p.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    p.add_argument("--base-model", default=DEFAULT_BASE_MODEL)
    p.add_argument("--max-records", type=int, default=None)
    p.add_argument("--max-new-tokens", type=int, default=16)
    p.add_argument(
        "--results-out",
        type=Path,
        default=DEFAULT_RESULTS_OUT,
        help="Write evaluation results JSON here (default: reports/eval_content_classifier.json).",
    )
    p.add_argument(
        "--label",
        default="v0",
        help=(
            "Tag written into the results JSON to identify this evaluation run "
            "(e.g. 'v0_on_clean_test', 'v0.1_retrained')."
        ),
    )
    p.add_argument("--dry-run", action="store_true")
    p.add_argument(
        "--predictions-out",
        type=Path,
        default=None,
        help="Write per-record predictions JSONL here for downstream analysis.",
    )
    args = p.parse_args(argv)

    if args.dry_run:
        print(f"Would evaluate model {args.model_dir} on {args.test_set}")
        return 0

    # Load via HF Transformers + PEFT directly. Unsloth's fast-inference
    # path has a known shape-mismatch issue on Qwen3 first-token
    # generation (rotary-embedding broadcast); the vanilla HF path is
    # slower per-token but correctness-wise reliable.
    import torch  # type: ignore[import-not-found]
    from peft import PeftModel  # type: ignore[import-not-found]
    from transformers import (  # type: ignore[import-not-found]
        AutoModelForCausalLM,
        AutoTokenizer,
        BitsAndBytesConfig,
    )

    print(f"Loading base model {args.base_model}")
    bnb = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
    )
    tokenizer = AutoTokenizer.from_pretrained(args.base_model)
    base = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        quantization_config=bnb,
        device_map="cuda",
        torch_dtype=torch.bfloat16,
    )
    print(f"Loading LoRA adapter from {args.model_dir}")
    model = PeftModel.from_pretrained(base, str(args.model_dir))
    model.eval()

    records = [
        json.loads(line)
        for line in args.test_set.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if args.max_records is not None:
        records = records[: args.max_records]
    print(f"Evaluating on {len(records)} records")

    tp = fp = fn = tn = 0
    abstain = 0
    pred_counts: Counter[str | None] = Counter()
    label_counts: Counter[str] = Counter()
    per_record_predictions: list[dict] = []

    for i, rec in enumerate(records, 1):
        snippet = rec["messages"][1]["content"]
        true_label = rec["messages"][2]["content"]  # "yes" | "no"
        msgs = format_inference_messages(snippet)
        prompt_text = tokenizer.apply_chat_template(
            msgs, tokenize=False, add_generation_prompt=True
        )
        inputs = tokenizer(prompt_text, return_tensors="pt").to(model.device)
        outputs = model.generate(
            **inputs,
            max_new_tokens=args.max_new_tokens,
            do_sample=False,
            pad_token_id=tokenizer.pad_token_id,
        )
        gen_text = tokenizer.decode(
            outputs[0][inputs["input_ids"].shape[1] :], skip_special_tokens=True
        )
        pred = _classify_first_token(gen_text)

        if args.predictions_out is not None:
            per_record_predictions.append(
                {
                    "idx": i - 1,
                    "snippet": snippet,
                    "true_label": true_label,
                    "predicted_label": pred,
                    "raw_generation": gen_text,
                }
            )

        label_counts[true_label] += 1
        pred_counts[pred] += 1
        if pred is None:
            abstain += 1
            continue
        if pred == "yes" and true_label == "yes":
            tp += 1
        elif pred == "yes" and true_label == "no":
            fp += 1
        elif pred == "no" and true_label == "yes":
            fn += 1
        else:
            tn += 1

        if i % 50 == 0:
            print(
                f"  [{i}/{len(records)}] TP={tp} FP={fp} FN={fn} TN={tn} "
                f"abstain={abstain}"
            )

    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    accuracy = (tp + tn) / max(len(records) - abstain, 1)

    print("\n=== Phase-3 content classifier eval ===")
    print(f"  records: {len(records)} ({label_counts})")
    print(f"  predictions: {pred_counts}")
    print(f"  precision: {precision:.4f}")
    print(f"  recall:    {recall:.4f}")
    print(f"  F1:        {f1:.4f}")
    print(f"  accuracy:  {accuracy:.4f}")
    print(
        f"  vs Wiz baseline (precision ≥ 0.857, recall ≥ 0.82): "
        f"{'PASS' if precision >= 0.857 and recall >= 0.82 else 'MISS'}"
    )

    import hashlib

    def _rel(p: Path) -> str:
        # Tolerate relative inputs from the command line by resolving first.
        try:
            return str(p.resolve().relative_to(REPO_ROOT))
        except ValueError:
            return str(p.resolve())

    results = {
        "label": args.label,
        "test_set": _rel(args.test_set),
        "test_set_sha256": hashlib.sha256(args.test_set.read_bytes()).hexdigest(),
        "model_dir": _rel(args.model_dir),
        "base_model": args.base_model,
        "records": len(records),
        "label_distribution": dict(label_counts),
        "prediction_distribution": {
            str(k): v for k, v in pred_counts.items()
        },
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "abstain": abstain},
        "metrics": {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "accuracy": accuracy,
        },
        "wiz_baseline": {
            "precision": 0.857,
            "recall": 0.82,
            "passes": bool(precision >= 0.857 and recall >= 0.82),
        },
    }
    args.results_out.parent.mkdir(parents=True, exist_ok=True)
    # Append-friendly: if file exists, load and update by label key; otherwise
    # write a new dict keyed by label. Keeps a history of eval runs without
    # callers needing to manage filenames.
    existing: dict = {}
    if args.results_out.exists():
        try:
            existing = json.loads(args.results_out.read_text())
            if not isinstance(existing, dict):
                existing = {}
        except json.JSONDecodeError:
            existing = {}
    existing[args.label] = results
    args.results_out.write_text(json.dumps(existing, indent=2))
    try:
        rel = args.results_out.resolve().relative_to(REPO_ROOT)
    except ValueError:
        rel = args.results_out
    print(f"\nResults written to {rel} under label '{args.label}'.")
    if args.predictions_out is not None:
        args.predictions_out.parent.mkdir(parents=True, exist_ok=True)
        with args.predictions_out.open("w", encoding="utf-8") as f:
            for rec in per_record_predictions:
                f.write(json.dumps(rec) + "\n")
        print(
            f"Per-record predictions written to {args.predictions_out}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
