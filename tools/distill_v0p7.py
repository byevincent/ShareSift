"""Distill v0p7 (Qwen3-1.7B LoRA) → DistilBERT — 3-7× faster inference.

The v0p7 content classifier is over-modeled for its binary task
(literal vs referenced credential): 4-bit Qwen3-1.7B inference at
~150ms/file, AUC 0.9996 on the github held-out test. Distilling into
DistilBERT-base (66M params) gives ~25ms/file at expected AUC within
0.005 of teacher.

Recipe (Hinton-style soft-label distillation):
- Teacher generates probabilities on the train + val + test snippets
- Student trained with combined loss: KL(teacher_soft, student_soft)
  + BCE(hard_label, student) with α=0.7 weighting toward soft labels
- Temperature scaling (T=2) on teacher to expose probability gradient

Background reading: arXiv 2504.15027 (DistilQwen2.5 — same recipe in
Qwen family). Distillation has been the speed lever in NLP since
Sanh et al. 2019.

Usage::

    uv run python tools/distill_v0p7.py \\
        --output-dir models/content_classifier_v0p7_distilled \\
        --student-base distilbert-base-uncased
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_TEACHER = REPO_ROOT / "models" / "content_classifier_v0p7_literal_vs_referenced"
DEFAULT_TRAIN = REPO_ROOT / "data" / "external" / "literal_vs_referenced" / "splits" / "train.jsonl"
DEFAULT_VAL = REPO_ROOT / "data" / "external" / "literal_vs_referenced" / "splits" / "val.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "models" / "content_classifier_v0p7_distilled"
DEFAULT_STUDENT_BASE = "distilbert-base-uncased"
TEACHER_TEMP = 2.0


def _build_input_text(rec: dict) -> str:
    """Same prompt scaffolding as the teacher used."""
    return (
        f"File extension: .{rec.get('file_extension', '?')}\n"
        f"Match: {(rec.get('matched_text') or '')[:120]}\n"
        f"---\n"
        f"{rec.get('snippet', '')}\n"
        f"---\n"
        f"Classify the credential context."
    )


def _load_jsonl(path: Path) -> list[dict]:
    records = []
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


def _generate_teacher_soft_labels(teacher_dir: Path, records: list[dict],
                                   temperature: float) -> list[float]:
    """Run teacher inference and return P(literal) per record."""
    import math
    from unsloth import FastLanguageModel
    import torch

    print(f"[teacher] loading {teacher_dir}", file=sys.stderr)
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=str(teacher_dir), max_seq_length=512, load_in_4bit=True,
    )
    FastLanguageModel.for_inference(model)
    literal_tok = tokenizer.encode("literal", add_special_tokens=False)[0]
    referenced_tok = tokenizer.encode("referenced", add_special_tokens=False)[0]

    sys_prompt = (
        "You are a credential-snippet classifier. Given a short context "
        "window from a file flagged by a credential scanner, decide whether "
        "it contains a LITERAL credential value (a real password, key, or "
        "token written directly in the file) or a REFERENCED credential "
        "(a variable reference, function parameter, example block, or "
        "template pattern that mentions credentials but does not store one). "
        "Answer with exactly one word: literal or referenced."
    )

    probs = []
    for i, rec in enumerate(records):
        messages = [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": _build_input_text(rec)},
        ]
        text = tokenizer.apply_chat_template(messages, tokenize=False,
                                              add_generation_prompt=True)
        text = text + "<think>\n\n</think>\n\n"
        inputs = tokenizer(text, return_tensors="pt", truncation=True,
                          max_length=512).to(model.device)
        with torch.no_grad():
            outputs = model(**inputs)
        last_logits = outputs.logits[0, -1, :] / temperature
        lit = last_logits[literal_tok].item()
        ref = last_logits[referenced_tok].item()
        m = max(lit, ref)
        p = math.exp(lit - m) / (math.exp(lit - m) + math.exp(ref - m))
        probs.append(p)
        if (i + 1) % 500 == 0:
            print(f"  [{i+1}/{len(records)}]", file=sys.stderr)
    return probs


def _train_student(args, train_records, train_soft, val_records, val_soft) -> None:
    """Train the DistilBERT student with KL + BCE combined loss."""
    import torch
    import torch.nn.functional as F
    from torch.utils.data import Dataset, DataLoader
    from transformers import (
        AutoTokenizer, AutoModelForSequenceClassification,
        get_linear_schedule_with_warmup,
    )

    print(f"[student] loading {args.student_base}", file=sys.stderr)
    student_tokenizer = AutoTokenizer.from_pretrained(args.student_base)
    student = AutoModelForSequenceClassification.from_pretrained(
        args.student_base, num_labels=2,
    )
    device = "cuda" if torch.cuda.is_available() else "cpu"
    student.to(device)

    class DistillDataset(Dataset):
        def __init__(self, records, soft_labels):
            self.records = records
            self.soft_labels = soft_labels
        def __len__(self):
            return len(self.records)
        def __getitem__(self, i):
            r = self.records[i]
            text = _build_input_text(r)
            enc = student_tokenizer(text, truncation=True, max_length=512,
                                     padding="max_length", return_tensors="pt")
            return {
                "input_ids": enc["input_ids"].squeeze(0),
                "attention_mask": enc["attention_mask"].squeeze(0),
                "hard_label": 1 if r.get("label") == "literal" else 0,
                "soft_label": float(self.soft_labels[i]),
            }

    train_ds = DistillDataset(train_records, train_soft)
    val_ds = DistillDataset(val_records, val_soft)
    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True,
                              num_workers=2)
    val_loader = DataLoader(val_ds, batch_size=args.batch_size, shuffle=False,
                            num_workers=2)

    optim = torch.optim.AdamW(student.parameters(), lr=args.learning_rate)
    total_steps = len(train_loader) * args.epochs
    sched = get_linear_schedule_with_warmup(optim, num_warmup_steps=100,
                                              num_training_steps=total_steps)

    alpha = args.alpha
    print(f"[train] {args.epochs} epochs over {len(train_ds)} records, "
          f"effective batch {args.batch_size}", file=sys.stderr)

    for epoch in range(args.epochs):
        student.train()
        running_loss = 0.0
        for step, batch in enumerate(train_loader):
            input_ids = batch["input_ids"].to(device)
            attn = batch["attention_mask"].to(device)
            hard = batch["hard_label"].to(device)
            soft = batch["soft_label"].to(device)

            logits = student(input_ids=input_ids, attention_mask=attn).logits
            student_log_softmax = F.log_softmax(logits, dim=-1)
            # Teacher gave us P(literal) only; reconstruct full distribution
            teacher_p_literal = soft
            teacher_p_referenced = 1.0 - teacher_p_literal
            teacher_dist = torch.stack([teacher_p_referenced, teacher_p_literal], dim=-1)

            kl_loss = F.kl_div(student_log_softmax, teacher_dist,
                               reduction="batchmean")
            bce_loss = F.cross_entropy(logits, hard)
            loss = alpha * kl_loss + (1 - alpha) * bce_loss

            optim.zero_grad()
            loss.backward()
            optim.step()
            sched.step()
            running_loss += loss.item()
            if (step + 1) % 50 == 0:
                print(f"  epoch={epoch} step={step+1}/{len(train_loader)} "
                      f"loss={running_loss/(step+1):.4f}", file=sys.stderr)

        # Validation
        student.eval()
        val_preds = []
        val_hards = []
        with torch.no_grad():
            for batch in val_loader:
                logits = student(
                    input_ids=batch["input_ids"].to(device),
                    attention_mask=batch["attention_mask"].to(device),
                ).logits
                probs = F.softmax(logits, dim=-1)[:, 1].cpu().tolist()
                val_preds.extend(probs)
                val_hards.extend(batch["hard_label"].tolist())
        from sklearn.metrics import roc_auc_score
        auc = roc_auc_score(val_hards, val_preds)
        print(f"  [val] epoch {epoch} AUC = {auc:.4f}", file=sys.stderr)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    student.save_pretrained(args.output_dir)
    student_tokenizer.save_pretrained(args.output_dir)
    print(f"\n[done] student saved to {args.output_dir}", file=sys.stderr)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--teacher", type=Path, default=DEFAULT_TEACHER)
    p.add_argument("--train", type=Path, default=DEFAULT_TRAIN)
    p.add_argument("--val", type=Path, default=DEFAULT_VAL)
    p.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    p.add_argument("--student-base", default=DEFAULT_STUDENT_BASE)
    p.add_argument("--batch-size", type=int, default=16)
    p.add_argument("--epochs", type=int, default=2)
    p.add_argument("--learning-rate", type=float, default=2e-5)
    p.add_argument("--alpha", type=float, default=0.7,
                   help="Weighting toward KL (soft labels)")
    p.add_argument("--max-train-records", type=int, default=None,
                   help="Cap training corpus for quick iterations")
    p.add_argument("--cached-teacher-labels", type=Path,
                   help="Skip teacher inference; reuse cached soft labels JSONL.")
    args = p.parse_args(argv)

    train_records = _load_jsonl(args.train)
    val_records = _load_jsonl(args.val)
    if args.max_train_records:
        train_records = train_records[: args.max_train_records]
    print(f"[load] train={len(train_records)} val={len(val_records)}",
          file=sys.stderr)

    if args.cached_teacher_labels and args.cached_teacher_labels.exists():
        cached = _load_jsonl(args.cached_teacher_labels)
        train_soft = [r["p_literal"] for r in cached
                      if r.get("split") == "train"][:len(train_records)]
        val_soft = [r["p_literal"] for r in cached
                    if r.get("split") == "val"][:len(val_records)]
        if len(train_soft) != len(train_records) or len(val_soft) != len(val_records):
            print("WARN: cached soft labels don't fully match; regenerating",
                  file=sys.stderr)
            train_soft = _generate_teacher_soft_labels(
                args.teacher, train_records, TEACHER_TEMP)
            val_soft = _generate_teacher_soft_labels(
                args.teacher, val_records, TEACHER_TEMP)
    else:
        train_soft = _generate_teacher_soft_labels(
            args.teacher, train_records, TEACHER_TEMP)
        val_soft = _generate_teacher_soft_labels(
            args.teacher, val_records, TEACHER_TEMP)
        # Cache
        if args.cached_teacher_labels:
            args.cached_teacher_labels.parent.mkdir(parents=True, exist_ok=True)
            with args.cached_teacher_labels.open("w") as fh:
                for r, s in zip(train_records, train_soft):
                    fh.write(json.dumps({
                        "split": "train", "path_marker": r.get("source_path", ""),
                        "p_literal": s,
                    }) + "\n")
                for r, s in zip(val_records, val_soft):
                    fh.write(json.dumps({
                        "split": "val", "path_marker": r.get("source_path", ""),
                        "p_literal": s,
                    }) + "\n")
            print(f"[cache] wrote {args.cached_teacher_labels}", file=sys.stderr)

    _train_student(args, train_records, train_soft, val_records, val_soft)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
