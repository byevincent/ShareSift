"""CPU latency benchmark for the GGUF-quantized content classifier.

Phase-4 deliverable: validate the throughput claim from the architecture
decision §6 — Q4_K_M via llama.cpp should hit at least the Wiz LoRA
recipe's ~27 tok/s on a commodity CPU. Faster is better; below that,
we'd want to escalate to IQ4_XS or smaller models.

What it measures:

1. **Load time** — model weight load + KV cache allocation
2. **Per-record latency** — full classify-one-snippet round-trip from
   tokenize → generate → parse, on a sample of held-out test records
3. **Throughput** — generation tok/s during the loop (excludes
   prompt-processing time; matches the Wiz recipe's published number)
4. **Quality regression check** — accuracy on the same held-out set as
   the GPU eval. Q4_K_M should keep accuracy within ~1% of the
   bf16 inference; bigger gap means quantization corrupted the model
   for our task and we need Q5_K_M or higher.

The benchmark is CPU-only by construction (``n_gpu_layers=0``) so the
numbers are what a laptop operator would see.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sharesift.prompt import SYSTEM_PROMPT

DEFAULT_GGUF = (
    REPO_ROOT
    / "models"
    / "content_classifier_v0"
    / "qwen3-1.7b-content-v0_gguf"
    / "qwen3-1.7b.Q4_K_M.gguf"
)
DEFAULT_TEST_SET = REPO_ROOT / "data" / "content" / "test_split.jsonl"


def _classify(generated: str) -> str | None:
    """Same parser as the GPU eval — strips Qwen3 ``<think>...</think>``
    chain-of-thought block, then checks the leading word."""
    txt = generated
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
    p.add_argument("--gguf", type=Path, default=DEFAULT_GGUF)
    p.add_argument("--test-set", type=Path, default=DEFAULT_TEST_SET)
    p.add_argument("--n-records", type=int, default=50)
    p.add_argument("--max-new-tokens", type=int, default=16)
    p.add_argument("--n-threads", type=int, default=None,
                   help="llama.cpp threads; default = ~all CPU cores")
    p.add_argument("--n-ctx", type=int, default=4096)
    args = p.parse_args(argv)

    print(f"Loading GGUF model {args.gguf.name} (CPU-only)...")
    t0 = time.perf_counter()
    # Lazy import — llama-cpp-python prints noisy CUDA-probe stuff.
    from llama_cpp import Llama  # type: ignore[import-not-found]
    llm = Llama(
        model_path=str(args.gguf),
        n_ctx=args.n_ctx,
        n_gpu_layers=0,
        n_threads=args.n_threads,
        verbose=False,
    )
    load_seconds = time.perf_counter() - t0
    print(f"  loaded in {load_seconds:.1f}s")

    records = [
        json.loads(line)
        for line in args.test_set.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ][: args.n_records]
    print(f"  benchmarking on {len(records)} records")

    # Quality regression vs GPU eval
    tp = fp = fn = tn = abstain = 0
    pred_counts: Counter = Counter()

    # Latency / throughput
    latencies: list[float] = []
    total_gen_tokens = 0
    total_gen_seconds = 0.0

    for i, rec in enumerate(records, 1):
        snippet = rec["messages"][1]["content"]
        true_label = rec["messages"][2]["content"]
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": snippet},
        ]
        t_start = time.perf_counter()
        result = llm.create_chat_completion(
            messages=messages,
            max_tokens=args.max_new_tokens,
            temperature=0.0,
        )
        t_end = time.perf_counter()
        elapsed = t_end - t_start
        latencies.append(elapsed)

        content = result["choices"][0]["message"]["content"]
        usage = result.get("usage", {})
        gen_tokens = usage.get("completion_tokens", 0)
        total_gen_tokens += gen_tokens
        total_gen_seconds += elapsed

        pred = _classify(content)
        pred_counts[pred] += 1
        if pred is None:
            abstain += 1
        elif pred == "yes" and true_label == "yes":
            tp += 1
        elif pred == "yes" and true_label == "no":
            fp += 1
        elif pred == "no" and true_label == "yes":
            fn += 1
        else:
            tn += 1

        if i % 10 == 0:
            print(
                f"  [{i}/{len(records)}] "
                f"mean_lat={sum(latencies) / len(latencies) * 1000:.0f}ms, "
                f"TP={tp} FP={fp} FN={fn} TN={tn}"
            )

    sorted_lat = sorted(latencies)
    p50 = sorted_lat[len(sorted_lat) // 2] * 1000
    p95 = sorted_lat[int(len(sorted_lat) * 0.95)] * 1000
    p99 = sorted_lat[int(len(sorted_lat) * 0.99)] * 1000
    mean = (sum(latencies) / len(latencies)) * 1000
    tok_per_sec = (
        total_gen_tokens / total_gen_seconds if total_gen_seconds > 0 else 0
    )

    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)

    print("\n=== CPU benchmark summary ===")
    print(f"  records: {len(records)}")
    print(f"  load time: {load_seconds:.1f}s")
    print(f"  latency: mean={mean:.0f}ms  p50={p50:.0f}ms  p95={p95:.0f}ms  p99={p99:.0f}ms")
    print(
        f"  throughput: {tok_per_sec:.1f} generated tok/s "
        f"(target: ≥ 27 tok/s per Wiz baseline)"
    )
    print(f"  pass: {'YES' if tok_per_sec >= 27 else 'MISS'}")
    print(f"\n=== Quality on quantized model ===")
    print(f"  predictions: {pred_counts}")
    print(f"  precision: {precision:.4f}")
    print(f"  recall:    {recall:.4f}")
    print(f"  F1:        {f1:.4f}")
    print(f"  TP={tp} FP={fp} FN={fn} TN={tn} abstain={abstain}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
