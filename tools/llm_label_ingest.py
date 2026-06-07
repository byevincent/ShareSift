"""Ingest manually-collected JSONL labels from the Claude.ai chat workflow.

Reads a JSONL file built up by Vincent pasting Sonnet's per-chunk
``jsonl`` code-block contents end-to-end, validates each line against
``EvalRecord`` (looking up pre_category from the source queue and
echoing ``negative_validator.check_path`` warnings), and appends
validated records to ``eval_set_claude_linux.jsonl``.

Companion to ``tools/llm_label_chunkify.py``. The two split the
labeling roundtrip: chunkify exports the paste-ready prompt + chunks;
ingest validates + merges Sonnet's structured-text replies.

Invalid records are reported with their reason; the user can either
fix the line and re-run or paste the offending chunk back into Sonnet
for a re-label.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from pydantic import ValidationError

from src.eval.negative_validator import check_path as negative_check
from src.eval.schema import EvalRecord

DEFAULT_INPUT = REPO_ROOT / "data" / "eval" / "eval_set_claude_linux_manual.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "eval" / "eval_set_claude_linux.jsonl"
DEFAULT_QUEUE = REPO_ROOT / "data" / "eval" / "linux_queue_v05_1500.jsonl"
TODAY = date(2026, 5, 31)
ADDED_BY = "claude_llm"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and report; do not append to output.",
    )
    args = parser.parse_args()

    if not args.input.exists():
        print(f"error: input not found at {args.input}", file=sys.stderr)
        return 1

    queue_by_path: dict[str, dict] = {}
    for line in args.queue.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        queue_by_path[rec["path"]] = rec

    already_labeled: set[str] = set()
    if args.output.exists():
        for line in args.output.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            already_labeled.add(json.loads(line)["path"])

    valid: list[EvalRecord] = []
    seen_paths: set[str] = set()
    n_lines = 0
    n_duplicate_in_input = 0
    n_already_labeled = 0
    n_unknown_path = 0
    n_validation_error = 0
    n_json_error = 0
    errors: list[str] = []

    for lineno, line in enumerate(args.input.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        n_lines += 1
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as e:
            n_json_error += 1
            errors.append(f"line {lineno}: JSON decode failed — {e}")
            continue

        path = payload.get("path", "")
        if not path:
            n_validation_error += 1
            errors.append(f"line {lineno}: missing 'path' field")
            continue

        if path in seen_paths:
            n_duplicate_in_input += 1
            continue
        seen_paths.add(path)

        if path in already_labeled:
            n_already_labeled += 1
            continue

        src = queue_by_path.get(path)
        if src is None:
            n_unknown_path += 1
            errors.append(f"line {lineno}: path {path!r} not in source queue")
            continue

        try:
            rec = EvalRecord(
                path=path,
                label=payload["label"],
                tier=payload.get("tier"),
                category=payload["category"],
                sub_type=payload.get("sub_type"),
                source=src.get("source", "github_search"),
                notes=payload["notes"],
                added_date=TODAY,
                added_by=ADDED_BY,
                pre_category=src.get("pre_category"),
                validator_warnings=list(negative_check(path)),
            )
        except (ValidationError, KeyError) as e:
            n_validation_error += 1
            errors.append(f"line {lineno} [{path}]: {e}")
            continue
        valid.append(rec)

    print(f"input lines:          {n_lines}")
    print(f"valid records:        {len(valid)}")
    print(f"duplicates in input:  {n_duplicate_in_input}")
    print(f"already labeled:      {n_already_labeled}")
    print(f"unknown paths:        {n_unknown_path}")
    print(f"validation errors:    {n_validation_error}")
    print(f"json errors:          {n_json_error}")

    if errors:
        print()
        print("ERRORS (first 20):")
        for err in errors[:20]:
            print(f"  {err}")
        if len(errors) > 20:
            print(f"  ... and {len(errors) - 20} more")

    if args.dry_run:
        print()
        print("dry-run: not appending to output.")
        return 0 if not errors else 2

    if valid:
        with args.output.open("a", encoding="utf-8") as f:
            for rec in valid:
                f.write(rec.model_dump_json() + "\n")
        print()
        print(f"appended {len(valid)} records to {args.output}")
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
