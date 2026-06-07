"""v0.14 — LLM cross-check labeling for Snaffler-hit ground truth.

Adapter that takes Snaffler-flagged records from
``build_msf3_ground_truth.py`` (or any equivalent share's ground truth
file) and produces per-record ``has_credential`` labels via LLM.

Two modes are supported, mirroring the v0.9 paste-pipeline pattern:

* ``--mode prep``: writes a paste-ready JSON chunked file you can run
  through Claude.ai or any other LLM interface, then ingest back via
  ``--mode ingest``. Zero API cost; survives credit issues.
* ``--mode anthropic-api``: calls the Anthropic Messages API directly.
  Requires ``ANTHROPIC_API_KEY`` env var. ~$0.003 per record on Sonnet.

Cross-check workflow (vs ``feedback_labeling_calibration.md`` pattern):

1. Run once with ``--mode anthropic-api --model claude-sonnet-4-6
   --output sonnet_labels.jsonl``
2. Run again with ``--mode anthropic-api --model claude-haiku-4-5
   --output haiku_labels.jsonl`` (or via codex/openai for true
   independent prior)
3. Run ``--mode diff --left sonnet_labels.jsonl --right haiku_labels.jsonl
   --output disagreements.jsonl`` to surface records where the two
   models disagree on has_credential — manual review queue
4. After Vincent reviews disagreements, merge final labels back to
   ground_truth.jsonl via ``build_msf3_ground_truth.py --supplement``

Expected agreement rate: 85-90% (higher than path-only labeling because
content snippets give both models more signal). Manual review burden:
~100-150 records per share.

Output schema per labeled record::

    {
        "path": "...",
        "model": "claude-sonnet-4-6",
        "has_credential": true | false | null,
        "credential_type": "plaintext_password" | "hash" | ... | null,
        "confidence": 0.0..1.0,
        "reasoning": "...short explanation...",
        "labeled_at": "..."
    }

Usage::

    # Prep paste file
    uv run python tools/label_snaffler_hits.py --mode prep \\
        --input data/external/metasploitable3/ground_truth.jsonl \\
        --output reports/labeling_kit_msf3.jsonl

    # Direct API
    export ANTHROPIC_API_KEY=...
    uv run python tools/label_snaffler_hits.py --mode anthropic-api \\
        --input data/external/metasploitable3/ground_truth.jsonl \\
        --output reports/sonnet_labels_msf3.jsonl \\
        --model claude-sonnet-4-6

    # Diff two runs
    uv run python tools/label_snaffler_hits.py --mode diff \\
        --left reports/sonnet_labels_msf3.jsonl \\
        --right reports/haiku_labels_msf3.jsonl \\
        --output reports/disagreements_msf3.jsonl
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

SYSTEM_PROMPT = (
    "You are a security analyst classifying credential-scanner hits. Each hit "
    "is a file path Snaffler flagged on a Windows SMB share. You'll see the "
    "path, the rule Snaffler used, the tier Snaffler assigned, and a short "
    "snippet of the matched content. Decide whether this file actually "
    "contains a real credential value (password, hash, key, token, secret).\n\n"
    "Common false-positive shapes to ignore:\n"
    "- PowerShell / CMD tutorial code that documents a -Password parameter\n"
    "- Variable references like $password, %SSLPassword%, ${VAR}\n"
    "- Function signatures and param() blocks declaring credential parameters\n"
    "- .EXAMPLE blocks and <#...#> comment regions\n"
    "- Regex patterns themselves (e.g. passw?o?r?d\\s*=)\n"
    "- Template placeholder values: CHANGE_ME, YOUR_PASSWORD, xxxxxxxx, *DELETED*\n\n"
    "Common true-positive shapes to flag:\n"
    "- Literal string values: password='Ok6/FqR5WtJY5UCLrnvjQQ=='\n"
    "- XML credential elements: <Password>actualvalue</Password>\n"
    "- SSH key files, .keytab, krb5cc_ ticket caches\n"
    "- Wp-config.php, config.inc.php, database.yml with real connection info\n"
    "- Unattend.xml with AdministratorPassword (even if scrubbed in snippet)\n"
    "- shell history, passwd / SAM hive files, FTP server XML\n\n"
    "Output strict JSON with keys: has_credential (bool), credential_type "
    "(string or null), confidence (float 0-1), reasoning (one-sentence rationale)."
)


def _build_user_prompt(record: dict) -> str:
    path = record.get("path", "")
    tier = record.get("snaffler_tier", "unknown")
    rule = record.get("snaffler_rule", "unknown")
    match = (record.get("snaffler_match") or "")[:600]
    return (
        f"Path: {path}\n"
        f"Snaffler tier: {tier}\n"
        f"Snaffler rule: {rule}\n"
        f"Snaffler match snippet (≤600 chars):\n"
        f"---\n"
        f"{match}\n"
        f"---\n"
        f"\nClassify this hit. Respond with strict JSON only."
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


def _filter_records_for_labeling(records: list[dict]) -> list[dict]:
    """Keep only Snaffler-flagged records lacking a verified has_credential."""
    out = []
    for r in records:
        if r.get("source") != "snaffler_flag":
            continue
        # Already labeled and verified — skip
        if r.get("verified") and r.get("has_credential") is not None:
            continue
        out.append(r)
    return out


# ---------------------------------------------------------------------------
# Mode: prep (write paste-ready prompts)
# ---------------------------------------------------------------------------

def _mode_prep(args) -> int:
    records = _load_jsonl(args.input)
    to_label = _filter_records_for_labeling(records)
    print(f"[prep] {len(records)} input records, {len(to_label)} to label",
          file=sys.stderr)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        for r in to_label:
            chunk = {
                "path": r["path"],
                "snaffler_tier": r.get("snaffler_tier"),
                "snaffler_rule": r.get("snaffler_rule"),
                "snaffler_match": (r.get("snaffler_match") or "")[:600],
                "system_prompt": SYSTEM_PROMPT,
                "user_prompt": _build_user_prompt(r),
            }
            fh.write(json.dumps(chunk) + "\n")
    print(f"[prep] wrote {len(to_label)} prompts → {args.output}", file=sys.stderr)
    print(f"\nPaste each user_prompt into Claude.ai (or your LLM of choice) "
          f"with the system_prompt as system message. Capture the JSON "
          f"response and run `--mode ingest --raw-responses <file>` to "
          f"merge labels back.", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# Mode: anthropic-api (call Sonnet/Haiku directly)
# ---------------------------------------------------------------------------

_ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"


def _call_anthropic(api_key: str, model: str, system: str, user: str,
                    max_tokens: int = 300) -> dict:
    import urllib.request
    import urllib.error
    body = json.dumps({
        "model": model,
        "max_tokens": max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": user}],
    }).encode("utf-8")
    req = urllib.request.Request(_ANTHROPIC_API_URL, data=body, headers={
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    })
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code in (429, 529):
                wait = 30 * (attempt + 1)
                print(f"  [rate] {e.code} sleeping {wait}s", file=sys.stderr)
                time.sleep(wait)
                continue
            raise
        except (urllib.error.URLError, TimeoutError) as e:
            print(f"  [net] {e} retry {attempt+1}", file=sys.stderr)
            time.sleep(5 * (attempt + 1))
    raise RuntimeError("anthropic API max retries exceeded")


def _parse_label_response(text: str) -> dict | None:
    """Extract the JSON object from the model's response. Tolerant to
    chat-style preamble or markdown fences."""
    m = re.search(r"\{[\s\S]*?\}", text)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None


def _mode_anthropic_api(args) -> int:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: set ANTHROPIC_API_KEY env var", file=sys.stderr)
        return 2
    records = _load_jsonl(args.input)
    to_label = _filter_records_for_labeling(records)
    # Resume support: skip records already labeled in output
    existing: set[str] = set()
    if args.output.exists() and not args.no_resume:
        for r in _load_jsonl(args.output):
            existing.add(r.get("path", ""))
        print(f"[resume] skipping {len(existing)} already-labeled paths",
              file=sys.stderr)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    out_fh = args.output.open("a", encoding="utf-8")
    n_ok = 0
    n_error = 0
    try:
        for i, r in enumerate(to_label, start=1):
            if r["path"] in existing:
                continue
            if args.max_records and n_ok >= args.max_records:
                break
            user = _build_user_prompt(r)
            try:
                response = _call_anthropic(api_key, args.model, SYSTEM_PROMPT, user)
                text = response["content"][0]["text"]
                parsed = _parse_label_response(text)
            except Exception as e:
                print(f"  [{i}/{len(to_label)}] error on {r['path']}: {e}",
                      file=sys.stderr)
                n_error += 1
                continue
            if parsed is None:
                print(f"  [{i}/{len(to_label)}] no JSON in response: {text[:200]}",
                      file=sys.stderr)
                n_error += 1
                continue
            out_rec = {
                "path": r["path"],
                "model": args.model,
                "has_credential": parsed.get("has_credential"),
                "credential_type": parsed.get("credential_type"),
                "confidence": parsed.get("confidence"),
                "reasoning": parsed.get("reasoning"),
                "labeled_at": datetime.now(timezone.utc).isoformat(),
            }
            out_fh.write(json.dumps(out_rec) + "\n")
            out_fh.flush()
            n_ok += 1
            if n_ok % 50 == 0:
                print(f"  [progress] {n_ok} labeled, {n_error} errors",
                      file=sys.stderr)
    finally:
        out_fh.close()
    print(f"\n[final] {n_ok} labeled, {n_error} errors → {args.output}",
          file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# Mode: diff (cross-check two label runs)
# ---------------------------------------------------------------------------

def _mode_diff(args) -> int:
    left = {r["path"]: r for r in _load_jsonl(args.left)}
    right = {r["path"]: r for r in _load_jsonl(args.right)}
    shared = set(left) & set(right)
    print(f"[diff] left={len(left)} right={len(right)} shared={len(shared)}",
          file=sys.stderr)
    disagreements = []
    agreements = 0
    for path in sorted(shared):
        l, r = left[path], right[path]
        if l.get("has_credential") == r.get("has_credential"):
            agreements += 1
        else:
            disagreements.append({
                "path": path,
                "left_model": l.get("model"),
                "left_has_credential": l.get("has_credential"),
                "left_confidence": l.get("confidence"),
                "left_reasoning": l.get("reasoning"),
                "right_model": r.get("model"),
                "right_has_credential": r.get("has_credential"),
                "right_confidence": r.get("confidence"),
                "right_reasoning": r.get("reasoning"),
            })
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        for d in disagreements:
            fh.write(json.dumps(d) + "\n")
    agreement_rate = agreements / max(1, len(shared))
    print(f"[diff] agreements: {agreements} ({agreement_rate:.1%}), "
          f"disagreements: {len(disagreements)} → {args.output}",
          file=sys.stderr)
    print(f"\nManual review queue: {len(disagreements)} records. After "
          f"resolving, write your decisions to a JSONL with has_credential "
          f"+ verified=true and feed to build_msf3_ground_truth.py "
          f"--supplement.", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# Mode: prep-kit (batched paste-ready markdown for Claude.ai)
# ---------------------------------------------------------------------------

_KIT_README = """\
# v0.14 Snaffler-hit Labeling Kit (Claude.ai paste workflow)

Cross-check labels for Metasploitable 3 Snaffler hits, mirroring the
v0.15 path-extraction kit pattern. Paste each batch into a FRESH
Claude.ai conversation; save responses as `responses/batch_NNN.json`;
ingest back via `--mode ingest-responses`.

## Workflow

1. Open Claude.ai in a fresh conversation (Sonnet 4.6 or Opus 4.x)
2. Open `batches/batch_NNN.md`, copy the entire contents
3. Paste into Claude.ai, submit
4. Claude returns JSON. Copy ONLY the JSON (drop any preamble text)
5. Save to `responses/batch_NNN.json`
6. Move to the next batch
7. When done: `--mode ingest-responses --kit-dir {kit_dir} --output sonnet_labels.jsonl`

## Batches

Total: {n_batches} batches, ~{records_per_batch} records each, covering
{n_records} Snaffler-flagged ground-truth records.
"""


def _mode_prep_kit(args) -> int:
    records = _load_jsonl(args.input)
    to_label = _filter_records_for_labeling(records)
    if args.max_records:
        to_label = to_label[: args.max_records]
    records_per_batch = args.records_per_batch
    kit_dir = args.kit_dir
    batches_dir = kit_dir / "batches"
    responses_dir = kit_dir / "responses"
    batches_dir.mkdir(parents=True, exist_ok=True)
    responses_dir.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, list[dict]] = {}
    n_batches = (len(to_label) + records_per_batch - 1) // records_per_batch
    for batch_idx in range(n_batches):
        start = batch_idx * records_per_batch
        end = min(start + records_per_batch, len(to_label))
        batch = to_label[start:end]
        batch_num = batch_idx + 1
        batch_id = f"batch_{batch_num:03d}"
        manifest[batch_id] = []

        lines = [
            "# SYSTEM PROMPT",
            "",
            SYSTEM_PROMPT,
            "",
            "# YOUR TASK",
            "",
            f"Classify each of the {len(batch)} Snaffler hits below. Return "
            f"strict JSON only — no prose preamble, no markdown fences — "
            f"with this exact shape:",
            "",
            "```",
            "{",
            "  \"results\": [",
            "    {\"hit_index\": 0, \"has_credential\": true,",
            "     \"credential_type\": \"plaintext_password\",",
            "     \"confidence\": 0.9, \"reasoning\": \"...\"},",
            "    {\"hit_index\": 1, ...},",
            "    ...",
            "  ]",
            "}",
            "```",
            "",
            "---",
            "",
            "# SNAFFLER HITS",
            "",
        ]
        for i, r in enumerate(batch):
            manifest[batch_id].append({"index": i, "path": r["path"]})
            match = (r.get("snaffler_match") or "")[:600]
            lines.append(f"## Hit {i}")
            lines.append("")
            lines.append(f"**Path:** `{r['path']}`")
            lines.append(f"**Snaffler tier:** {r.get('snaffler_tier', 'unknown')}")
            lines.append(f"**Snaffler rule:** {r.get('snaffler_rule', 'unknown')}")
            lines.append("")
            lines.append("**Match snippet:**")
            lines.append("```")
            lines.append(match)
            lines.append("```")
            lines.append("")
        (batches_dir / f"{batch_id}.md").write_text(
            "\n".join(lines), encoding="utf-8")

    (kit_dir / "manifest.json").write_text(json.dumps(manifest, indent=2),
                                            encoding="utf-8")
    (kit_dir / "README.md").write_text(
        _KIT_README.format(
            kit_dir=kit_dir, n_batches=n_batches,
            records_per_batch=records_per_batch, n_records=len(to_label)),
        encoding="utf-8",
    )
    print(f"[kit] {n_batches} batches, {len(to_label)} records → {kit_dir}",
          file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# Mode: ingest-responses (parse Claude.ai response JSONs)
# ---------------------------------------------------------------------------

def _mode_ingest_responses(args) -> int:
    kit_dir = args.kit_dir
    manifest_file = kit_dir / "manifest.json"
    responses_dir = kit_dir / "responses"
    if not manifest_file.exists():
        print(f"ERROR: {manifest_file} missing — run --mode prep-kit first",
              file=sys.stderr)
        return 2
    manifest: dict[str, list[dict]] = json.loads(manifest_file.read_text())

    args.output.parent.mkdir(parents=True, exist_ok=True)
    out_fh = args.output.open("w", encoding="utf-8")
    n_batches_seen = n_batches_missing = n_records = 0

    for batch_id, batch_records in manifest.items():
        response_file = responses_dir / f"{batch_id}.json"
        if not response_file.exists():
            n_batches_missing += 1
            continue
        raw = response_file.read_text(encoding="utf-8")
        m = re.search(r"\{[\s\S]*\}\s*$", raw)
        raw_json = m.group(0) if m else raw
        try:
            parsed = json.loads(raw_json)
        except json.JSONDecodeError as e:
            print(f"  [{batch_id}] JSON parse error: {e}", file=sys.stderr)
            n_batches_missing += 1
            continue
        results = parsed.get("results", [])
        if not isinstance(results, list):
            n_batches_missing += 1
            continue
        n_batches_seen += 1
        results_by_idx = {r.get("hit_index"): r for r in results if isinstance(r, dict)}
        for entry in batch_records:
            res = results_by_idx.get(entry["index"])
            if res is None:
                continue
            out_fh.write(json.dumps({
                "path": entry["path"],
                "model": "claude.ai-paste",
                "has_credential": res.get("has_credential"),
                "credential_type": res.get("credential_type"),
                "confidence": res.get("confidence"),
                "reasoning": res.get("reasoning"),
                "labeled_at": datetime.now(timezone.utc).isoformat(),
                "kit_batch": batch_id,
            }) + "\n")
            n_records += 1
    out_fh.close()
    print(f"[ingest] {n_batches_seen} batches, {n_records} labels → {args.output}",
          file=sys.stderr)
    if n_batches_missing:
        print(f"[ingest] {n_batches_missing} batches missing/unparseable",
              file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# Mode: codex-cli (shell out to `codex exec`)
# ---------------------------------------------------------------------------

def _mode_codex_cli(args) -> int:
    import subprocess, tempfile
    if subprocess.run(["which", "codex"], capture_output=True).returncode != 0:
        print("ERROR: `codex` CLI not on PATH.", file=sys.stderr)
        return 2

    records = _load_jsonl(args.input)
    to_label = _filter_records_for_labeling(records)
    if args.max_records:
        to_label = to_label[: args.max_records]

    existing: set[str] = set()
    if args.output.exists() and not args.no_resume:
        for r in _load_jsonl(args.output):
            existing.add(r.get("path", ""))
        print(f"[resume] skipping {len(existing)} already-labeled", file=sys.stderr)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    out_fh = args.output.open("a", encoding="utf-8")
    n_ok = n_error = 0

    def _run_codex(prompt: str) -> str:
        """Run codex exec; codex's stdout has session metadata so use
        --output-last-message and read that file (same pattern as
        tools/codex_audit.py)."""
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".txt", delete=False) as tf:
            last_message_path = tf.name
        try:
            subprocess.run(
                ["codex", "exec", "--output-last-message", last_message_path, prompt],
                check=True, capture_output=True, text=True, timeout=180,
            )
            with open(last_message_path, encoding="utf-8") as f:
                return f.read()
        finally:
            try:
                Path(last_message_path).unlink()
            except FileNotFoundError:
                pass

    try:
        for i, r in enumerate(to_label, start=1):
            if r["path"] in existing:
                continue
            if args.max_records and n_ok >= args.max_records:
                break
            prompt = (
                SYSTEM_PROMPT + "\n\n" +
                _build_user_prompt(r) + "\n\n"
                "Respond with a JSON object on a single line. Example: "
                '{"has_credential": true, "credential_type": "plaintext_password", '
                '"confidence": 0.9, "reasoning": "..."}'
            )
            try:
                text = _run_codex(prompt)
                m = re.search(r"\{[\s\S]*?\}", text)
                parsed = json.loads(m.group(0)) if m else None
            except Exception as e:
                print(f"  [{i}/{len(to_label)}] codex error on {r['path']}: {e}",
                      file=sys.stderr)
                n_error += 1
                continue
            if parsed is None:
                n_error += 1
                continue
            out_fh.write(json.dumps({
                "path": r["path"],
                "model": "codex-cli",
                "has_credential": parsed.get("has_credential"),
                "credential_type": parsed.get("credential_type"),
                "confidence": parsed.get("confidence"),
                "reasoning": parsed.get("reasoning"),
                "labeled_at": datetime.now(timezone.utc).isoformat(),
            }) + "\n")
            out_fh.flush()
            n_ok += 1
            if n_ok % 10 == 0:
                print(f"  [progress] {n_ok}/{len(to_label)} labeled, {n_error} errors",
                      file=sys.stderr)
    finally:
        out_fh.close()
    print(f"\n[final] {n_ok} labeled, {n_error} errors → {args.output}",
          file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--mode",
                   choices=["prep", "prep-kit", "anthropic-api",
                            "ingest-responses", "codex-cli", "diff"],
                   required=True)
    p.add_argument("--input", type=Path, help="ground_truth.jsonl for prep/api modes")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--kit-dir", type=Path,
                   default=Path("data/external/metasploitable3/labeling_kit"),
                   help="Kit directory for prep-kit / ingest-responses")
    p.add_argument("--records-per-batch", type=int, default=15,
                   help="Records per Claude.ai paste batch")
    p.add_argument("--model", default="claude-sonnet-4-6",
                   help="Anthropic model name for --mode anthropic-api")
    p.add_argument("--max-records", type=int, default=None,
                   help="Cap records (smoke testing)")
    p.add_argument("--no-resume", action="store_true",
                   help="Don't skip already-labeled paths in --output")
    p.add_argument("--left", type=Path, help="left labels JSONL (--mode diff)")
    p.add_argument("--right", type=Path, help="right labels JSONL (--mode diff)")
    args = p.parse_args(argv)

    if args.mode == "prep":
        if not args.input or not args.input.exists():
            print("ERROR: --input required", file=sys.stderr)
            return 2
        return _mode_prep(args)
    if args.mode == "prep-kit":
        if not args.input or not args.input.exists():
            print("ERROR: --input required", file=sys.stderr)
            return 2
        return _mode_prep_kit(args)
    if args.mode == "anthropic-api":
        if not args.input or not args.input.exists():
            print("ERROR: --input required", file=sys.stderr)
            return 2
        return _mode_anthropic_api(args)
    if args.mode == "ingest-responses":
        return _mode_ingest_responses(args)
    if args.mode == "codex-cli":
        if not args.input or not args.input.exists():
            print("ERROR: --input required", file=sys.stderr)
            return 2
        return _mode_codex_cli(args)
    if args.mode == "diff":
        if not args.left or not args.right:
            print("ERROR: --left and --right required for diff mode",
                  file=sys.stderr)
            return 2
        return _mode_diff(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
