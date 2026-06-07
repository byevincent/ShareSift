"""v0.13 Phase 5a — held-out test eval for the literal-vs-referenced classifier.

Loads the v0p7 LoRA adapter, runs it against the by-repo test split from
Phase 3, and reports:

  * Per-class precision / recall / F1
  * Calibration (Brier score + reliability bins)
  * Per-subtype breakdown (which negative shapes the model gets wrong)
  * Per-file-extension breakdown (PS1 vs BAT vs XML)
  * ROC AUC for the ranking-feature use case in v0.14

Inference uses logit comparison: for each input, we compute the
probability of the next token being "literal" vs "referenced" under the
adapter, then normalize. This is faster than greedy generation + parsing
and gives us a calibrated probability directly.

The script writes both the per-record predictions JSONL and a summary
JSON. The predictions file feeds the v0.14 ranker training; the summary
is for the v0.13 results writeup.

Usage:
    uv run python tools/eval_literal_vs_referenced.py \\
        --adapter models/content_classifier_v0p7_literal_vs_referenced \\
        --test data/external/literal_vs_referenced/splits/test.jsonl \\
        --predictions reports/v0p7_test_predictions.jsonl \\
        --summary reports/v0p7_test_summary.json
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_ADAPTER = REPO_ROOT / "models" / "content_classifier_v0p7_literal_vs_referenced"
DEFAULT_TEST = REPO_ROOT / "data" / "external" / "literal_vs_referenced" / "splits" / "test.jsonl"
DEFAULT_PREDICTIONS = REPO_ROOT / "reports" / "v0p7_test_predictions.jsonl"
DEFAULT_SUMMARY = REPO_ROOT / "reports" / "v0p7_test_summary.json"

# Must match training-time system prompt exactly — drift here would
# silently degrade calibration. The constant lives in the training
# script's metadata.json too as a check.
SYSTEM_PROMPT = (
    "You are a credential-snippet classifier. Given a short context window "
    "from a file flagged by a credential scanner, decide whether it contains "
    "a LITERAL credential value (a real password, key, or token written "
    "directly in the file) or a REFERENCED credential (a variable reference, "
    "function parameter, example block, or template pattern that mentions "
    "credentials but does not store one). Answer with exactly one word: "
    "literal or referenced."
)


def _build_user_prompt(record: dict) -> str:
    snippet = record["snippet"]
    ext = record.get("file_extension", "?")
    matched = record.get("matched_text", "")[:120]
    return (
        f"File extension: .{ext}\n"
        f"Match: {matched}\n"
        f"---\n"
        f"{snippet}\n"
        f"---\n"
        f"Classify the credential context."
    )


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


def _classify_batch(model, tokenizer, records: list[dict], device: str) -> list[float]:
    """For each record, return P(literal | snippet). Uses logit comparison
    on the next-token distribution at the assistant's first generated
    position — no sampling, fully deterministic."""
    import torch

    literal_id = tokenizer.encode("literal", add_special_tokens=False)
    referenced_id = tokenizer.encode("referenced", add_special_tokens=False)
    # Most tokenizers will produce a single token for these; if not, take the
    # first token of each. Calibration is approximate but consistent.
    literal_tok = literal_id[0]
    referenced_tok = referenced_id[0]

    probs: list[float] = []
    for rec in records:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": _build_user_prompt(rec)},
        ]
        text = tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True,
        )
        # Qwen3's chat template starts every assistant turn with an empty
        # thinking block: ``<think>\n\n</think>\n\n``. Training included it
        # verbatim, so to read the classification token's logit we must
        # advance past this prefix BEFORE measuring the next-token logits.
        text = text + "<think>\n\n</think>\n\n"
        inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512).to(device)
        with torch.no_grad():
            outputs = model(**inputs)
        # Logit at the final position predicts the first generated token.
        last_logits = outputs.logits[0, -1, :]
        lit_logit = last_logits[literal_tok].item()
        ref_logit = last_logits[referenced_tok].item()
        # Softmax over the two competing tokens (ignoring all others)
        m = max(lit_logit, ref_logit)
        p_lit = math.exp(lit_logit - m) / (math.exp(lit_logit - m) + math.exp(ref_logit - m))
        probs.append(p_lit)
    return probs


def _import_inference_stack():
    missing: list[str] = []
    for mod in ("unsloth", "torch", "transformers"):
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    if missing:
        print(f"Inference stack missing: {', '.join(missing)}", file=sys.stderr)
        print("Install via the same uv group as training.", file=sys.stderr)
        sys.exit(2)


def _binary_prf(y_true: list[int], y_pred: list[int]) -> dict:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    prec = tp / max(1, tp + fp)
    rec = tp / max(1, tp + fn)
    f1 = 2 * prec * rec / max(1e-9, prec + rec)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": prec, "recall": rec, "f1": f1}


def _brier(y_true: list[int], probs: list[float]) -> float:
    if not y_true:
        return float("nan")
    return sum((p - t) ** 2 for p, t in zip(probs, y_true)) / len(y_true)


def _reliability_bins(y_true: list[int], probs: list[float], n_bins: int = 10) -> list[dict]:
    bins: list[dict] = []
    for i in range(n_bins):
        lo = i / n_bins
        hi = (i + 1) / n_bins
        in_bin = [(t, p) for t, p in zip(y_true, probs) if lo <= p < hi or (i == n_bins - 1 and p == hi)]
        if not in_bin:
            bins.append({"bin_lo": lo, "bin_hi": hi, "n": 0,
                         "mean_pred": None, "mean_true": None})
            continue
        mean_pred = sum(p for _, p in in_bin) / len(in_bin)
        mean_true = sum(t for t, _ in in_bin) / len(in_bin)
        bins.append({"bin_lo": lo, "bin_hi": hi, "n": len(in_bin),
                     "mean_pred": mean_pred, "mean_true": mean_true})
    return bins


def _auc(y_true: list[int], probs: list[float]) -> float:
    """ROC AUC via the rank-based formula. Returns NaN if either class is empty."""
    positives = [p for t, p in zip(y_true, probs) if t == 1]
    negatives = [p for t, p in zip(y_true, probs) if t == 0]
    n_pos = len(positives)
    n_neg = len(negatives)
    if n_pos == 0 or n_neg == 0:
        return float("nan")
    paired = sorted([(p, 1) for p in positives] + [(p, 0) for p in negatives])
    sum_ranks_pos = 0.0
    for i, (_, lab) in enumerate(paired, start=1):
        if lab == 1:
            sum_ranks_pos += i
    return (sum_ranks_pos - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--adapter", type=Path, default=DEFAULT_ADAPTER)
    p.add_argument("--test", type=Path, default=DEFAULT_TEST)
    p.add_argument("--predictions", type=Path, default=DEFAULT_PREDICTIONS)
    p.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    p.add_argument("--threshold", type=float, default=0.5,
                   help="P(literal) threshold for binary class decisions in the report")
    p.add_argument("--max-records", type=int, default=None,
                   help="Cap test records (smoke testing)")
    args = p.parse_args(argv)

    if not args.test.exists():
        print(f"ERROR: --test missing: {args.test}", file=sys.stderr)
        return 2
    if not args.adapter.exists():
        print(f"ERROR: --adapter missing: {args.adapter}\n"
              f"Run tools/train_literal_vs_referenced.py first.",
              file=sys.stderr)
        return 2

    test_records = _load_jsonl(args.test)
    if args.max_records is not None:
        test_records = test_records[: args.max_records]
    print(f"[load] {len(test_records)} test records", file=sys.stderr)

    _import_inference_stack()
    from unsloth import FastLanguageModel  # type: ignore[import-not-found]
    import torch

    print(f"[load-model] {args.adapter}", file=sys.stderr)
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=str(args.adapter),
        max_seq_length=512,
        load_in_4bit=True,
    )
    FastLanguageModel.for_inference(model)
    device = "cuda" if torch.cuda.is_available() else "cpu"

    probs = _classify_batch(model, tokenizer, test_records, device=device)

    y_true = [1 if r["label"] == "literal" else 0 for r in test_records]
    y_pred = [1 if p >= args.threshold else 0 for p in probs]

    # Write per-record predictions for downstream v0.14 ranker training
    args.predictions.parent.mkdir(parents=True, exist_ok=True)
    with args.predictions.open("w", encoding="utf-8") as fh:
        for rec, prob in zip(test_records, probs):
            out = {
                "source_repo": rec["source_repo"],
                "source_path": rec["source_path"],
                "match_offset": rec["match_offset"],
                "label_true": rec["label"],
                "subtype_true": rec.get("subtype"),
                "file_extension": rec.get("file_extension"),
                "p_literal": prob,
            }
            fh.write(json.dumps(out) + "\n")
    print(f"[predictions] wrote {len(probs)} → {args.predictions}", file=sys.stderr)

    # Compute summary metrics
    overall_prf = _binary_prf(y_true, y_pred)
    brier = _brier(y_true, probs)
    auc = _auc(y_true, probs)
    reliability = _reliability_bins(y_true, probs)

    # Per-subtype FP analysis (for referenced predictions vs each subtype)
    subtype_stats: dict[str, dict] = {}
    by_subtype = defaultdict(list)
    for rec, prob, pred in zip(test_records, probs, y_pred):
        if rec["label"] == "referenced":
            st = rec.get("subtype") or "?"
            by_subtype[st].append((prob, pred))
    for st, items in by_subtype.items():
        n_total = len(items)
        n_pred_lit = sum(1 for _, p in items if p == 1)
        mean_prob = sum(prob for prob, _ in items) / max(1, n_total)
        subtype_stats[st] = {
            "n": n_total,
            "fp_rate": n_pred_lit / max(1, n_total),  # fraction wrongly called literal
            "mean_p_literal": mean_prob,
        }

    # Per-extension breakdown
    ext_stats: dict[str, dict] = {}
    by_ext = defaultdict(lambda: ([], []))
    for rec, prob, pred in zip(test_records, probs, y_pred):
        ext = rec.get("file_extension", "?")
        by_ext[ext][0].append(1 if rec["label"] == "literal" else 0)
        by_ext[ext][1].append(pred)
    for ext, (ts, ps) in by_ext.items():
        ext_stats[ext] = {
            "n": len(ts),
            **_binary_prf(ts, ps),
        }

    summary = {
        "n_test_records": len(test_records),
        "n_literal_truth": sum(y_true),
        "n_referenced_truth": len(y_true) - sum(y_true),
        "threshold": args.threshold,
        "literal_class_metrics": overall_prf,
        "calibration": {
            "brier_score": brier,
            "reliability_bins": reliability,
        },
        "ranking_auc": auc,
        "per_subtype_fp_rate": subtype_stats,
        "per_extension": ext_stats,
    }
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, indent=2))

    # Console summary
    print(f"\n=== v0p7 held-out test eval ===", file=sys.stderr)
    print(f"  n_test={len(test_records)} "
          f"(literal={sum(y_true)}, referenced={len(y_true)-sum(y_true)})",
          file=sys.stderr)
    print(f"  literal-class: P={overall_prf['precision']:.3f} "
          f"R={overall_prf['recall']:.3f} F1={overall_prf['f1']:.3f}",
          file=sys.stderr)
    print(f"  Brier score: {brier:.4f}", file=sys.stderr)
    print(f"  ROC AUC (ranking): {auc:.4f}", file=sys.stderr)
    print(f"\n  Per-subtype FP rate (fraction of negatives wrongly flagged literal):",
          file=sys.stderr)
    for st, stats in sorted(subtype_stats.items(), key=lambda x: -x[1]["fp_rate"]):
        print(f"    {st:25s} n={stats['n']:4d}  fp_rate={stats['fp_rate']:.3f}  "
              f"mean_p={stats['mean_p_literal']:.3f}",
              file=sys.stderr)
    print(f"\n  Per-extension F1:", file=sys.stderr)
    for ext, stats in sorted(ext_stats.items(), key=lambda x: -x[1]["n"]):
        print(f"    .{ext:8s} n={stats['n']:4d}  P={stats['precision']:.3f}  "
              f"R={stats['recall']:.3f}  F1={stats['f1']:.3f}",
              file=sys.stderr)
    print(f"\n[done] summary → {args.summary}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
