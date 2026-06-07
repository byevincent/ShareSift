"""Content-classifier inference-only ablations: C1 + C2.

Variants
========

* **C1_zero_shot** — base Qwen3-1.7B (no LoRA), same system prompt as
  training. Asks: "does the LoRA earn its 69MB?". If zero-shot is already
  at the LoRA's precision/recall, the fine-tune adds nothing.

* **C2_few_shot_k** for k in {1, 3, 5, 10} — base Qwen3-1.7B with k
  in-context labeled demonstrations (k/2 yes + k/2 no, sampled from
  ``train_split.jsonl`` with a fixed seed so every test record sees the
  same demos). Asks: "how close does prompting alone get? Does the LoRA
  still beat 10-shot ICL?".

All variants use the same Qwen3 chat template that training uses, so the
LoRA-trained model's performance is directly comparable.

Output
======

* ``reports/ablate_content_classifier.json`` — keyed by variant name,
  each value carries the same shape as ``reports/eval_content_classifier.json``
  (test-set SHA, confusion, metrics) so it can be cross-referenced.
* Console summary table at the end.

LoRA-variant numbers are NOT re-run here; they are already in
``reports/eval_content_classifier.json`` under labels ``v0_on_clean_test``
and ``v0p1_on_clean_test``. The writeup should compare across both files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import time
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sharesift.prompt import SYSTEM_PROMPT

DEFAULT_TRAIN_SPLIT = REPO_ROOT / "data" / "content" / "train_split.jsonl"
DEFAULT_TEST_SET = REPO_ROOT / "data" / "content" / "test_split.jsonl"
DEFAULT_BASE_MODEL = "unsloth/Qwen3-1.7B-unsloth-bnb-4bit"
DEFAULT_RESULTS_OUT = REPO_ROOT / "reports" / "ablate_content_classifier.json"

# Default few-shot k values to sweep. k=0 is the zero-shot variant.
DEFAULT_K_VALUES = (0, 1, 3, 5, 10)


# --- Data helpers --------------------------------------------------------


def load_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def record_snippet(record: dict) -> str:
    for m in record.get("messages", []):
        if m.get("role") == "user":
            return m.get("content", "")
    return ""


def record_label(record: dict) -> str:
    for m in record.get("messages", []):
        if m.get("role") == "assistant":
            return m.get("content", "").strip()
    return ""


def sample_balanced_demos(
    train_records: list[dict], k: int, seed: int
) -> list[tuple[str, str]]:
    """Return k (snippet, label) demos, balanced k/2 yes + k/2 no.

    If k is odd, the extra demo goes to "yes" (matches the slight
    positive-class emphasis that helps the model surface positives).
    """
    if k == 0:
        return []
    rng = random.Random(seed)
    yes_records = [r for r in train_records if record_label(r) == "yes"]
    no_records = [r for r in train_records if record_label(r) == "no"]
    rng.shuffle(yes_records)
    rng.shuffle(no_records)
    n_yes = (k + 1) // 2
    n_no = k - n_yes
    demos: list[tuple[str, str]] = []
    for r in yes_records[:n_yes]:
        demos.append((record_snippet(r), "yes"))
    for r in no_records[:n_no]:
        demos.append((record_snippet(r), "no"))
    rng.shuffle(demos)
    return demos


def build_messages(snippet: str, demos: list[tuple[str, str]]) -> list[dict]:
    msgs: list[dict] = [{"role": "system", "content": SYSTEM_PROMPT}]
    for demo_snippet, demo_label in demos:
        msgs.append({"role": "user", "content": demo_snippet})
        msgs.append({"role": "assistant", "content": demo_label})
    msgs.append({"role": "user", "content": snippet})
    return msgs


def classify_first_token(generated_text: str) -> str | None:
    """Identical to tools/eval_content_classifier.py's parser."""
    txt = generated_text
    if "</think>" in txt:
        txt = txt.split("</think>", 1)[1]
    txt = txt.strip().lower()
    if txt.startswith("yes"):
        return "yes"
    if txt.startswith("no"):
        return "no"
    return None


# --- Inference loop ------------------------------------------------------


def run_variant(
    variant_name: str,
    demos: list[tuple[str, str]],
    test_records: list[dict],
    tokenizer,
    model,
    device,
    max_new_tokens: int,
) -> dict:
    print(
        f"\n  variant {variant_name}: {len(demos)} demos, {len(test_records)} test records",
        file=sys.stderr,
    )
    if demos:
        demo_labels = [d[1] for d in demos]
        print(f"    demo label balance: {Counter(demo_labels)}", file=sys.stderr)

    tp = fp = fn = tn = abstain = 0
    pred_counts: Counter = Counter()
    label_counts: Counter = Counter()
    t_start = time.time()

    for i, rec in enumerate(test_records, 1):
        snippet = record_snippet(rec)
        true_label = record_label(rec)
        msgs = build_messages(snippet, demos)
        # Qwen3 wraps assistant turns in <think>...</think> reasoning by
        # default. The LoRA-trained model learned to emit an empty think
        # block (so 16-token generation reaches the yes/no answer). For
        # a fair comparison, suppress thinking on the base model too —
        # otherwise the response is "<think>... reasoning that exceeds
        # max_new_tokens..." and the model abstains by construction.
        prompt_text = tokenizer.apply_chat_template(
            msgs,
            tokenize=False,
            add_generation_prompt=True,
            enable_thinking=False,
        )
        inputs = tokenizer(prompt_text, return_tensors="pt").to(device)
        outputs = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=False,
            pad_token_id=tokenizer.pad_token_id,
        )
        gen_text = tokenizer.decode(
            outputs[0][inputs["input_ids"].shape[1] :],
            skip_special_tokens=True,
        )
        pred = classify_first_token(gen_text)

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
            elapsed = time.time() - t_start
            rate = i / elapsed
            print(
                f"    [{i}/{len(test_records)}] "
                f"TP={tp} FP={fp} FN={fn} TN={tn} abstain={abstain}  "
                f"({rate:.1f} rec/s)",
                file=sys.stderr,
            )

    elapsed = time.time() - t_start
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    accuracy = (tp + tn) / max(len(test_records) - abstain, 1)

    return {
        "variant": variant_name,
        "n_demos": len(demos),
        "records": len(test_records),
        "elapsed_seconds": elapsed,
        "throughput_records_per_sec": len(test_records) / elapsed if elapsed else 0,
        "label_distribution": dict(label_counts),
        "prediction_distribution": {str(k): v for k, v in pred_counts.items()},
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "abstain": abstain},
        "metrics": {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "accuracy": accuracy,
        },
    }


# --- Main ----------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--train-split", type=Path, default=DEFAULT_TRAIN_SPLIT)
    p.add_argument("--test-set", type=Path, default=DEFAULT_TEST_SET)
    p.add_argument("--base-model", default=DEFAULT_BASE_MODEL)
    p.add_argument("--output", type=Path, default=DEFAULT_RESULTS_OUT)
    p.add_argument(
        "--k-values",
        type=int,
        nargs="+",
        default=list(DEFAULT_K_VALUES),
        help="Few-shot k values to evaluate. k=0 is zero-shot.",
    )
    p.add_argument("--max-new-tokens", type=int, default=16)
    p.add_argument("--seed", type=int, default=2026)
    p.add_argument(
        "--max-records",
        type=int,
        default=None,
        help="Cap test records (smoke-test mode).",
    )
    args = p.parse_args(argv)

    print(f"Loading test set from {args.test_set.relative_to(REPO_ROOT)}", file=sys.stderr)
    test_records = load_jsonl(args.test_set)
    if args.max_records is not None:
        test_records = test_records[: args.max_records]
    print(f"  {len(test_records)} test records", file=sys.stderr)

    print(f"Loading train split from {args.train_split.relative_to(REPO_ROOT)}", file=sys.stderr)
    train_records = load_jsonl(args.train_split)
    print(f"  {len(train_records)} train records (demo pool)", file=sys.stderr)

    print(f"Loading base model {args.base_model}", file=sys.stderr)
    import torch
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        BitsAndBytesConfig,
    )

    bnb = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
    )
    tokenizer = AutoTokenizer.from_pretrained(args.base_model)
    model = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        quantization_config=bnb,
        device_map="cuda",
        torch_dtype=torch.bfloat16,
    )
    model.eval()
    device = model.device

    test_sha = hashlib.sha256(args.test_set.read_bytes()).hexdigest()

    # Load existing results so this script can be re-run for individual
    # k values without losing prior variants' data.
    results: dict = {}
    if args.output.exists():
        try:
            results = json.loads(args.output.read_text())
            if not isinstance(results, dict):
                results = {}
        except json.JSONDecodeError:
            results = {}

    for k in args.k_values:
        variant_name = f"C1_zero_shot" if k == 0 else f"C2_few_shot_{k}"
        demos = sample_balanced_demos(train_records, k, args.seed)
        variant_result = run_variant(
            variant_name,
            demos,
            test_records,
            tokenizer,
            model,
            device,
            args.max_new_tokens,
        )
        variant_result["test_set"] = str(args.test_set.resolve().relative_to(REPO_ROOT))
        variant_result["test_set_sha256"] = test_sha
        variant_result["base_model"] = args.base_model
        variant_result["seed_for_demo_sampling"] = args.seed
        results[variant_name] = variant_result

        # Persist incrementally so a long run that's interrupted doesn't
        # lose completed variants.
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(results, indent=2))

        m = variant_result["metrics"]
        print(
            f"  {variant_name}: P={m['precision']:.4f} R={m['recall']:.4f} "
            f"F1={m['f1']:.4f} (n_demos={len(demos)}, "
            f"{variant_result['throughput_records_per_sec']:.1f} rec/s)"
        )

    # --- Final summary ---
    print()
    print("=" * 90)
    print("CONTENT-CLASSIFIER INFERENCE-ONLY ABLATIONS")
    print("=" * 90)
    print(f"{'variant':<22}  {'n_demos':>8}  {'P':>7}  {'R':>7}  {'F1':>7}  {'rec/s':>7}")
    print("-" * 90)
    for name in sorted(results.keys()):
        r = results[name]
        if "metrics" not in r:
            continue
        m = r["metrics"]
        print(
            f"{name:<22}  {r['n_demos']:>8}  "
            f"{m['precision']:>7.4f}  {m['recall']:>7.4f}  {m['f1']:>7.4f}  "
            f"{r['throughput_records_per_sec']:>7.1f}"
        )
    print("=" * 90)
    print(
        f"\nResults written to {args.output.relative_to(REPO_ROOT)}.\n"
        f"For LoRA-variant comparison, cross-reference "
        f"reports/eval_content_classifier.json (v0_on_clean_test, v0p1_on_clean_test)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
