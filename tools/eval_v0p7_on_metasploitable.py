"""v0.13 Phase 5b — reality-check the literal-vs-referenced classifier
against Snaffler's 1,279 Metasploitable 3 hits.

This is the eval that matters. The github held-out test (Phase 5a) tells
us whether the classifier generalizes within its training distribution.
This test tells us whether the classifier separates TP from FP on the
actual distribution v0.14 has to handle — Snaffler match snippets from
a real Windows server.

Inputs:
  * ``data/external/metasploitable3/ground_truth.jsonl`` — built by
    ``tools/build_msf3_ground_truth.py`` after the Snaffler-ingester
    patch. Records with ``source=snaffler_flag`` carry the Snaffler
    match snippet in ``snaffler_match`` and the eventual ground-truth
    label in ``has_credential`` (manually verified).

Outputs:
  * Per-record predictions with P(literal) and ground-truth label
  * Summary: AUC, confusion matrix at threshold 0.5, per-Snaffler-rule
    breakdown, sample of misclassified records for failure analysis

Decision criteria from the spec:
  * AUC ≥ 0.85 → green-light v0.14
  * AUC < 0.80 → reassess (corpus / training / framing)

Usage:
    uv run python tools/eval_v0p7_on_metasploitable.py \\
        --adapter models/content_classifier_v0p7_literal_vs_referenced \\
        --ground-truth data/external/metasploitable3/ground_truth.jsonl \\
        --predictions reports/v0p7_metasploitable_predictions.jsonl \\
        --summary reports/v0p7_metasploitable_summary.json
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_ADAPTER = REPO_ROOT / "models" / "content_classifier_v0p7_literal_vs_referenced"
DEFAULT_GT = REPO_ROOT / "data" / "external" / "metasploitable3" / "ground_truth.jsonl"
DEFAULT_PREDICTIONS = REPO_ROOT / "reports" / "v0p7_metasploitable_predictions.jsonl"
DEFAULT_SUMMARY = REPO_ROOT / "reports" / "v0p7_metasploitable_summary.json"

# Must match training-time system prompt exactly (drift = silent calibration loss).
SYSTEM_PROMPT = (
    "You are a credential-snippet classifier. Given a short context window "
    "from a file flagged by a credential scanner, decide whether it contains "
    "a LITERAL credential value (a real password, key, or token written "
    "directly in the file) or a REFERENCED credential (a variable reference, "
    "function parameter, example block, or template pattern that mentions "
    "credentials but does not store one). Answer with exactly one word: "
    "literal or referenced."
)


def _unescape_snaffler(s: str) -> str:
    """Snaffler's match snippets are escaped for TSV safety — backslash-space
    becomes space, backslash-newline becomes newline, etc. Unescape before
    feeding to the classifier so the input distribution matches training."""
    # Order matters: do backslash-backslash last to avoid double-unescaping.
    out = s
    out = re.sub(r"\\ ", " ", out)
    out = re.sub(r"\\n", "\n", out)
    out = re.sub(r"\\r", "\r", out)
    out = re.sub(r"\\t", "\t", out)
    out = re.sub(r"\\\"", "\"", out)
    out = re.sub(r"\\'", "'", out)
    out = re.sub(r"\\\\", "\\\\", out)
    return out


def _infer_extension_from_path(path: str) -> str:
    m = re.search(r"\.([A-Za-z0-9]+)$", path)
    return m.group(1).lower() if m else "?"


def _build_user_prompt(snippet: str, extension: str, matched: str) -> str:
    return (
        f"File extension: .{extension}\n"
        f"Match: {matched[:120]}\n"
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


def _classify_batch(model, tokenizer, prompts: list[tuple[str, str, str]], device: str) -> list[float]:
    """prompts is a list of (snippet, extension, matched) tuples. Returns P(literal) per item."""
    import torch
    literal_tok = tokenizer.encode("literal", add_special_tokens=False)[0]
    referenced_tok = tokenizer.encode("referenced", add_special_tokens=False)[0]
    probs: list[float] = []
    for snippet, ext, matched in prompts:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": _build_user_prompt(snippet, ext, matched)},
        ]
        text = tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True,
        )
        # Qwen3's chat template injects an empty thinking block before the
        # assistant's actual content. Training preserved it, so we must
        # advance past ``<think>\n\n</think>\n\n`` to land on the
        # classification token's position when reading logits.
        text = text + "<think>\n\n</think>\n\n"
        inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512).to(device)
        with torch.no_grad():
            outputs = model(**inputs)
        last_logits = outputs.logits[0, -1, :]
        lit_logit = last_logits[literal_tok].item()
        ref_logit = last_logits[referenced_tok].item()
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
        sys.exit(2)


def _auc(y_true: list[int], probs: list[float]) -> float:
    pos = [p for t, p in zip(y_true, probs) if t == 1]
    neg = [p for t, p in zip(y_true, probs) if t == 0]
    if not pos or not neg:
        return float("nan")
    paired = sorted([(p, 1) for p in pos] + [(p, 0) for p in neg])
    sum_ranks_pos = 0.0
    for i, (_, lab) in enumerate(paired, start=1):
        if lab == 1:
            sum_ranks_pos += i
    return (sum_ranks_pos - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))


def _confusion(y_true: list[int], y_pred: list[int]) -> dict:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": tp / max(1, tp + fp),
        "recall": tp / max(1, tp + fn),
        "f1": 2 * tp / max(1, 2 * tp + fp + fn),
        "accuracy": (tp + tn) / max(1, tp + fp + fn + tn),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--adapter", type=Path, default=DEFAULT_ADAPTER)
    p.add_argument("--ground-truth", type=Path, default=DEFAULT_GT)
    p.add_argument("--predictions", type=Path, default=DEFAULT_PREDICTIONS)
    p.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    p.add_argument("--threshold", type=float, default=0.5)
    args = p.parse_args(argv)

    if not args.ground_truth.exists():
        print(f"ERROR: --ground-truth missing: {args.ground_truth}\n"
              f"Run tools/build_msf3_ground_truth.py with --snaffler-output first.",
              file=sys.stderr)
        return 2

    gt_records = _load_jsonl(args.ground_truth)
    # Keep only Snaffler-flagged records that carry a snippet AND have a
    # ground-truth label. Snaffler-only-unverified records (has_credential=null)
    # are excluded from metrics but kept in the predictions file for review.
    snaffler_records = [r for r in gt_records if r.get("snaffler_match")]
    labeled = [r for r in snaffler_records if r.get("has_credential") is not None]
    unlabeled = [r for r in snaffler_records if r.get("has_credential") is None]
    print(
        f"[load] {len(snaffler_records)} Snaffler hits "
        f"({len(labeled)} labeled, {len(unlabeled)} unverified)",
        file=sys.stderr,
    )

    if not labeled:
        print(
            "WARN: no labeled Snaffler hits. The eval will run on unverified "
            "records to produce P(literal) but cannot compute AUC. Label "
            "records via the manual verification queue first.",
            file=sys.stderr,
        )

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

    # Score everything (labeled + unlabeled) so the predictions file is
    # complete for v0.14 ranker training.
    prompts = []
    for r in snaffler_records:
        snippet = _unescape_snaffler(r["snaffler_match"])
        ext = _infer_extension_from_path(r["path"])
        matched = r.get("snaffler_rule", "")
        prompts.append((snippet, ext, matched))
    probs = _classify_batch(model, tokenizer, prompts, device=device)

    # Write predictions
    args.predictions.parent.mkdir(parents=True, exist_ok=True)
    with args.predictions.open("w", encoding="utf-8") as fh:
        for r, prob in zip(snaffler_records, probs):
            fh.write(json.dumps({
                "path": r["path"],
                "snaffler_tier": r.get("snaffler_tier"),
                "snaffler_rule": r.get("snaffler_rule"),
                "has_credential": r.get("has_credential"),
                "credential_type": r.get("credential_type"),
                "p_literal": prob,
                "verified": r.get("verified", False),
            }) + "\n")
    print(f"[predictions] wrote {len(probs)} → {args.predictions}", file=sys.stderr)

    if not labeled:
        return 0

    # Compute metrics on the labeled subset
    labeled_probs = [prob for r, prob in zip(snaffler_records, probs)
                     if r.get("has_credential") is not None]
    y_true = [1 if r["has_credential"] else 0 for r in labeled]
    y_pred = [1 if p >= args.threshold else 0 for p in labeled_probs]

    auc = _auc(y_true, labeled_probs)
    conf = _confusion(y_true, y_pred)

    # Per-Snaffler-rule breakdown — where does the classifier help / hurt?
    by_rule: dict[str, dict] = {}
    rule_buckets: dict[str, tuple[list[int], list[int], list[float]]] = defaultdict(
        lambda: ([], [], []))
    for r, prob, pred in zip(labeled, labeled_probs, y_pred):
        rule = r.get("snaffler_rule", "?")
        rule_buckets[rule][0].append(1 if r["has_credential"] else 0)
        rule_buckets[rule][1].append(pred)
        rule_buckets[rule][2].append(prob)
    for rule, (ts, ps, prs) in rule_buckets.items():
        by_rule[rule] = {
            "n": len(ts),
            "n_true_positive": sum(ts),
            "n_predicted_literal": sum(ps),
            "mean_p_literal": sum(prs) / max(1, len(prs)),
            "rule_auc": _auc(ts, prs) if (sum(ts) and sum(ts) < len(ts)) else None,
        }

    # Sample misclassifications for the writeup
    fps_sample = []
    fns_sample = []
    for r, prob, pred in zip(labeled, labeled_probs, y_pred):
        t = 1 if r["has_credential"] else 0
        if pred == 1 and t == 0 and len(fps_sample) < 10:
            fps_sample.append({"path": r["path"], "rule": r.get("snaffler_rule"),
                               "p_literal": prob,
                               "match_excerpt": r.get("snaffler_match", "")[:200]})
        if pred == 0 and t == 1 and len(fns_sample) < 10:
            fns_sample.append({"path": r["path"], "rule": r.get("snaffler_rule"),
                               "p_literal": prob,
                               "match_excerpt": r.get("snaffler_match", "")[:200]})

    decision = (
        "GREEN: green-light v0.14 ranker (AUC >= 0.85)" if auc >= 0.85
        else "YELLOW: AUC in [0.80, 0.85) — proceed to v0.14 but expect marginal lift"
        if auc >= 0.80
        else "RED: AUC < 0.80 — reassess corpus/training/framing before v0.14"
    )

    summary = {
        "n_snaffler_hits_total": len(snaffler_records),
        "n_labeled": len(labeled),
        "n_unlabeled": len(unlabeled),
        "threshold": args.threshold,
        "ground_truth_positive_rate": sum(y_true) / max(1, len(y_true)),
        "auc_separating_tp_from_fp": auc,
        "confusion_matrix_at_threshold": conf,
        "decision": decision,
        "per_snaffler_rule": by_rule,
        "fp_sample": fps_sample,
        "fn_sample": fns_sample,
    }
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, indent=2))

    print(f"\n=== v0p7 Metasploitable reality check ===", file=sys.stderr)
    print(f"  n_labeled={len(labeled)} "
          f"(TPs={sum(y_true)}, FPs={len(y_true)-sum(y_true)})",
          file=sys.stderr)
    print(f"  AUC = {auc:.4f}", file=sys.stderr)
    print(f"  At threshold {args.threshold}: "
          f"P={conf['precision']:.3f} R={conf['recall']:.3f} F1={conf['f1']:.3f}",
          file=sys.stderr)
    print(f"\n  >>> {decision} <<<", file=sys.stderr)
    print(f"\n  Per-rule breakdown:", file=sys.stderr)
    for rule, stats in sorted(by_rule.items(), key=lambda x: -x[1]["n"]):
        auc_str = (f"AUC={stats['rule_auc']:.3f}" if stats['rule_auc'] is not None
                   else "AUC=NA (single class)")
        print(f"    {rule:30s} n={stats['n']:3d} TPs={stats['n_true_positive']:3d}  "
              f"meanP={stats['mean_p_literal']:.3f}  {auc_str}",
              file=sys.stderr)
    print(f"\n[done] summary → {args.summary}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
