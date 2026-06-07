"""Independent-model audit of the Claude-labeled eval set via Codex CLI.

Runs ``codex exec`` non-interactively against a stratified sample of
``data/eval/eval_set_claude.jsonl``, with ``notes`` and
``validator_warnings`` stripped so Codex judges purely on
``(path, label, tier, category)`` against the labeling guidelines text.
Disagreements are surfaced for the operator to adjudicate; real bugs
land as edits to ``tools/claude_label.py``, calibration disagreements
stay as-is (captured in feedback memory per the post-2026-05-28
recalibration policy).

Background: Pass-1 of the prior 2,638-record queue ran a blind random
stratified Codex audit and surfaced 6 substantive rule fixes the
Claude self-review missed — different priors, different training data,
genuine independent check. This script ports that workflow to a
reusable form (was an ad-hoc one-shot the first time).

Sampling modes:
    random: rng.sample(records, --sample-size)
    category-stratified: rng.sample(records_in_cat, --per-category)
        for each category, then concatenated. Forces rare-category
        coverage that random sampling under-represents.

Usage:
    python3 tools/codex_audit.py --seed 2026 --sample-size 50
    python3 tools/codex_audit.py --seed 31337 --category-stratified \\
        --per-category 5
"""

from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LABELED_PATH = REPO_ROOT / "data" / "eval" / "eval_set_claude.jsonl"
GUIDELINES_PATH = REPO_ROOT / "docs" / "labeling_guidelines.md"


def load_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def strip_for_codex(rec: dict) -> dict:
    """Remove fields Codex must not see (notes, validator_warnings) so
    its judgment is independent of the rule that produced the label."""
    out = {k: rec[k] for k in ("path", "label", "tier", "category", "sub_type")}
    return out


def sample_random(records: list[dict], n: int, seed: int) -> list[dict]:
    rng = random.Random(seed)
    return rng.sample(records, min(n, len(records)))


def sample_category_stratified(
    records: list[dict], per_category: int, seed: int
) -> list[dict]:
    rng = random.Random(seed)
    by_cat: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        by_cat[r.get("category", "uncategorized")].append(r)
    out: list[dict] = []
    for cat in sorted(by_cat):
        out.extend(rng.sample(by_cat[cat], min(per_category, len(by_cat[cat]))))
    return out


def build_prompt(guidelines: str, sample: list[dict]) -> str:
    sample_json = json.dumps(
        [strip_for_codex(r) for r in sample], indent=2
    )
    return f"""You are an independent reviewer of an eval-set labeling exercise.

The labeling guidelines below define the rules. A sample of labeled records follows. For each record, decide if you AGREE or DISAGREE with the assigned (label, tier, category), based purely on the path and the guidelines. Be terse.

Output a JSON array, one object per record, in the same order as the input. Schema:

[
  {{
    "path": "<the path string verbatim>",
    "agree": true,
    "reason": "<one sentence>"
  }},
  {{
    "path": "<the path string verbatim>",
    "agree": false,
    "reason": "<one sentence>",
    "your_label": {{"label": "juicy"|"not_juicy", "tier": "Black"|"Red"|"Yellow"|null, "category": "<category slug>"}}
  }}
]

Output ONLY the JSON array. No preamble. No markdown fences. No commentary outside the JSON.

=== LABELING GUIDELINES ===
{guidelines}
=== END GUIDELINES ===

=== SAMPLE RECORDS ===
{sample_json}
=== END SAMPLE ===
"""


def run_codex(prompt: str) -> str:
    """Run ``codex exec`` non-interactively, capture the final message.

    Uses --output-last-message to a tempfile; codex's stdout includes
    session metadata we don't want to parse. The last-message file
    contains only the agent's final text.
    """
    with tempfile.NamedTemporaryFile(
        mode="w+", suffix=".txt", delete=False
    ) as tf:
        last_message_path = Path(tf.name)
    try:
        subprocess.run(
            [
                "codex",
                "exec",
                "--output-last-message",
                str(last_message_path),
                prompt,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return last_message_path.read_text(encoding="utf-8")
    finally:
        last_message_path.unlink(missing_ok=True)


def parse_codex_response(response: str) -> list[dict]:
    """Extract the JSON array from Codex's response. Tolerant of
    code-fence wrapping (Codex sometimes adds ```json ... ``` despite
    instructions). Raises ValueError if no valid JSON array found."""
    text = response.strip()
    if text.startswith("```"):
        # Strip leading fence (with optional language tag) and trailing fence.
        lines = text.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)
    # Find first '[' and last ']' to slice the array out.
    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1 or end < start:
        raise ValueError("No JSON array found in Codex response")
    return json.loads(text[start : end + 1])


def diff_labels(
    original: list[dict], codex_judgments: list[dict]
) -> tuple[list[dict], list[dict]]:
    """Return (agreements, disagreements). Matches by path."""
    by_path = {r["path"]: r for r in original}
    agreements: list[dict] = []
    disagreements: list[dict] = []
    for j in codex_judgments:
        path = j.get("path")
        orig = by_path.get(path)
        if orig is None:
            continue
        if j.get("agree"):
            agreements.append({"path": path, "reason": j.get("reason", "")})
        else:
            disagreements.append(
                {
                    "path": path,
                    "current": {
                        "label": orig.get("label"),
                        "tier": orig.get("tier"),
                        "category": orig.get("category"),
                    },
                    "codex_suggests": j.get("your_label", {}),
                    "reason": j.get("reason", ""),
                }
            )
    return agreements, disagreements


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--seed", type=int, required=True)
    p.add_argument(
        "--sample-size",
        type=int,
        default=50,
        help="Sample size for random mode (default 50).",
    )
    p.add_argument(
        "--category-stratified",
        action="store_true",
        help="Stratify by category instead of random sample.",
    )
    p.add_argument(
        "--per-category",
        type=int,
        default=5,
        help="Records per category in stratified mode (default 5).",
    )
    p.add_argument(
        "--input",
        type=Path,
        default=LABELED_PATH,
        help=f"Labeled JSONL (default {LABELED_PATH.relative_to(REPO_ROOT)}).",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=None,
        help="JSON file to write full audit result. Default: stdout summary only.",
    )
    args = p.parse_args(argv)

    records = load_jsonl(args.input)
    guidelines = GUIDELINES_PATH.read_text(encoding="utf-8")

    if args.category_stratified:
        sample = sample_category_stratified(records, args.per_category, args.seed)
        mode_desc = (
            f"category-stratified, {args.per_category}/cat, seed={args.seed}"
        )
    else:
        sample = sample_random(records, args.sample_size, args.seed)
        mode_desc = f"random, n={args.sample_size}, seed={args.seed}"

    print(f"Sampled {len(sample)} records ({mode_desc})", file=sys.stderr)
    print("Calling codex exec (this can take 1-2 minutes)...", file=sys.stderr)

    prompt = build_prompt(guidelines, sample)
    response = run_codex(prompt)

    try:
        judgments = parse_codex_response(response)
    except (ValueError, json.JSONDecodeError) as e:
        print(f"error: could not parse Codex response: {e}", file=sys.stderr)
        print("--- raw response ---", file=sys.stderr)
        print(response, file=sys.stderr)
        return 1

    agreements, disagreements = diff_labels(sample, judgments)
    total = len(agreements) + len(disagreements)

    print(f"\n=== Audit summary ({mode_desc}) ===")
    if total:
        print(
            f"Agreement: {len(agreements)}/{total} "
            f"({100 * len(agreements) / total:.0f}%)"
        )
    print(f"Disagreements: {len(disagreements)}\n")

    for i, d in enumerate(disagreements, 1):
        print(f"--- Disagreement {i}/{len(disagreements)} ---")
        print(f"  path:    {d['path']}")
        print(
            f"  current: {d['current']['label']} / "
            f"{d['current']['tier']} / {d['current']['category']}"
        )
        cs = d["codex_suggests"]
        if cs:
            print(
                f"  codex:   {cs.get('label')} / "
                f"{cs.get('tier')} / {cs.get('category')}"
            )
        print(f"  reason:  {d['reason']}")
        print()

    if args.output:
        args.output.write_text(
            json.dumps(
                {
                    "mode": mode_desc,
                    "total": total,
                    "agreements": agreements,
                    "disagreements": disagreements,
                    "raw_codex_response": response,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"Full audit result written to {args.output}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
