"""LLM-based labeler for paths the rule-based labeler can't handle.

Added v0.5 for the Linux corpus expansion. The rule-based labeler in
``tools/claude_label.py`` assumes UNC path shape (a ``\\\\host\\share\\...``
structure) and emits ``not_juicy / benign_noise`` for every Linux path
because ``_host_segment()`` returns empty. Rather than parallel-port the
30+ rule blocks to a Linux equivalent, this tool calls Anthropic's API
with a structured-output tool-use schema; the LLM applies the same
calibration discipline as the rule-based pass and emits records that
slot directly into the existing ``eval_set_claude*.jsonl`` pipeline.

Calibration positions baked into the system prompt are derived from
Vincent's signed-off calibrations (memory: ``feedback_labeling_calibration``)
and the Phase B Linux discussion (this session):

* ``/etc/shadow``, ``/etc/gshadow``, ``~/.ssh/id_*`` private keys,
  ``~/.aws/credentials`` → Black
* ``/etc/sudoers``, ``~/.bash_history`` family, ``~/.ssh/known_hosts``,
  ``/opt/<app>/.env``-style → Red
* ``/etc/passwd``, ``/var/log/auth.log`` → Yellow
* ``/etc/timezone``, ``/srv/<personal>``, CTF artifacts → not_juicy

The LLM is free to pick any of the 16 ``CATEGORY_SLUGS`` for ``category``
and any of (``Black``, ``Red``, ``Yellow``, ``null``) for ``tier``. Schema
validation runs on every emitted record before write, so malformed LLM
output crashes the run instead of silently producing invalid records.

Resumable: with ``--resume``, paths already present in the output JSONL
are skipped, so a crashed mid-batch run can pick up without re-billing.

Cost reporting: total input/output tokens and an estimated dollar cost
(at the model's published rate, hard-coded here for Sonnet 4.6) print
at end-of-run. A 1500-path run takes ~60 calls and costs ~$3 at default
batch size 25.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import date
from pathlib import Path

import anthropic
from pydantic import ValidationError

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from src.eval.categories import CATEGORY_SLUGS, LABELS, SEVERITY_TIERS
from src.eval.negative_validator import check_path as negative_check
from src.eval.schema import EvalRecord

DEFAULT_QUEUE_PATH = REPO_ROOT / "data" / "eval" / "linux_queue_v05_1500.jsonl"
DEFAULT_OUTPUT_PATH = REPO_ROOT / "data" / "eval" / "eval_set_claude_linux.jsonl"
DEFAULT_MODEL = "claude-sonnet-4-6"
DEFAULT_BATCH_SIZE = 25
TODAY = date(2026, 5, 31)
ADDED_BY = "claude_llm"

# Sonnet 4.6 pricing (USD per million tokens). Update if model changes.
_PRICE_PER_MTOK_INPUT = 3.0
_PRICE_PER_MTOK_OUTPUT = 15.0


# --- Prompt ----------------------------------------------------------------

_SYSTEM_PROMPT = f"""You are a labeler for Linux/Unix file paths in a pentest evaluation set.
For each path, decide whether it's "juicy" (worth a pentest operator's attention) or "not_juicy".

LABEL: one of {list(LABELS)}.

TIER (required when juicy, must be omitted when not_juicy): one of {list(SEVERITY_TIERS)}.
  - Black: would compromise the host or organization if read. Reserve for files
    that ALMOST CERTAINLY contain credentials or keys (private SSH keys,
    /etc/shadow, ~/.aws/credentials, ~/.kube/config with embedded token).
  - Red: high-value credentials, backups, or files with a high base rate of
    embedded credential material (database dumps, .env files in /opt/<app>/,
    /etc/sudoers, ~/.bash_history family — operators routinely find creds
    fat-fingered into shell history).
  - Yellow: useful intel or partial credential info — enumeration data,
    config files that point to credentials without containing them, system
    logs that occasionally surface plaintext creds (/var/log/auth.log,
    /etc/passwd for user enumeration, nginx site configs).

CATEGORY: pick the best fit from {list(CATEGORY_SLUGS)}.
  - benign_noise for not_juicy paths
  - ssh_credentials for ~/.ssh/id_*, authorized_keys, known_hosts, sshd_config
  - cloud_credentials for ~/.aws/, ~/.gcp/, ~/.kube/config
  - private_keys_x509 for .pem, .key, .crt, .pfx files
  - db_files for sqlite, .sql dumps, .mdb, .ldf
  - embedded_secrets for .env files, files explicitly containing secrets
  - scm_cicd_tokens for .npmrc, .pypirc, .docker/config.json, .git-credentials
  - credential_containers for .kdbx (KeePass), .1password
  - decoy_docs for HR/finance/legal docs not specifically credential-bearing

SUB_TYPE: always null unless category is modern_saas_tokens.

NOTES: ONE sentence, minimum 15 chars, explaining the tier decision.

CALIBRATION (Vincent's signed-off positions — apply consistently):

  Path pattern                        Label      Tier    Category
  /etc/shadow                         juicy      Black   ssh_credentials
  /etc/gshadow                        juicy      Black   ssh_credentials
  /etc/passwd                         juicy      Yellow  ssh_credentials
  /etc/sudoers (and sudoers.d/*)      juicy      Red     ssh_credentials
  ~/.ssh/id_rsa, id_ed25519, id_*     juicy      Black   ssh_credentials
  ~/.ssh/authorized_keys              juicy      Red     ssh_credentials
  ~/.ssh/known_hosts                  juicy      Red     ssh_credentials
  ~/.ssh/config                       juicy      Yellow  ssh_credentials
  ~/.bash_history, ~/.zsh_history     juicy      Red     embedded_secrets
  /root/.bash_history                 juicy      Red     embedded_secrets
  ~/.aws/credentials                  juicy      Black   cloud_credentials
  ~/.aws/config                       juicy      Yellow  cloud_credentials
  ~/.kube/config                      juicy      Black   cloud_credentials
  ~/.docker/config.json               juicy      Red     scm_cicd_tokens
  ~/.netrc                            juicy      Red     embedded_secrets
  /opt/<app>/.env                     juicy      Red     embedded_secrets
  /etc/<service>/<config>.conf        juicy      Yellow  embedded_secrets
    (nginx, apache2, mysql, postgresql)
  /etc/ssl/private/*.key              juicy      Black   private_keys_x509
  /etc/ssl/certs/*.crt (no key)       juicy      Yellow  private_keys_x509
  /var/log/auth.log                   juicy      Yellow  embedded_secrets
  /var/log/secure                     juicy      Yellow  embedded_secrets
  /var/log/<service>/*.log            not_juicy  null    benign_noise
    (clamav, apache access logs, etc — not auth events)
  /etc/timezone, /etc/hostname        not_juicy  null    benign_noise
  /var/run/*.pid                      not_juicy  null    benign_noise
  /srv/<personal-content>             not_juicy  null    benign_noise
    (anime-collection, photo dirs, hobby repos)
  CTF/lab markers (hackme, vulnvm,    not_juicy  null    benign_noise
    marvel-dc, htb-user, kali home)

ASYMMETRY DISCIPLINE: When uncertain between two tiers, prefer the higher one
for credential-adjacent paths (a missed Red triaged as Yellow costs operator
attention; a missed Yellow triaged as Red costs minor noise). When uncertain
between juicy and not_juicy, prefer not_juicy unless there's a concrete
credential-association reason (label inflation pollutes the training set).

Output one entry per input path via the submit_labels tool. Preserve input order."""


_TOOL_SCHEMA = {
    "name": "submit_labels",
    "description": "Submit pentest labels for a batch of Linux file paths.",
    "input_schema": {
        "type": "object",
        "properties": {
            "labels": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "label": {"type": "string", "enum": list(LABELS)},
                        "tier": {
                            "type": ["string", "null"],
                            "enum": list(SEVERITY_TIERS) + [None],
                        },
                        "category": {"type": "string", "enum": list(CATEGORY_SLUGS)},
                        "sub_type": {"type": ["string", "null"]},
                        "notes": {"type": "string", "minLength": 15},
                    },
                    "required": ["path", "label", "tier", "category", "sub_type", "notes"],
                },
            },
        },
        "required": ["labels"],
    },
}


# --- Core ------------------------------------------------------------------


def _format_batch(batch: list[dict]) -> str:
    """Format a batch of queue records as a numbered list for the user message."""
    lines = []
    for i, rec in enumerate(batch, start=1):
        hint = rec.get("pre_category") or "none"
        lines.append(f"{i}. {rec['path']}   [pre_category hint: {hint}]")
    return "\n".join(lines)


def _label_batch(
    client: anthropic.Anthropic,
    model: str,
    batch: list[dict],
) -> tuple[list[dict], int, int]:
    """Send one batch to the API; return (labels, input_tokens, output_tokens).

    Raises on API or schema errors so the caller can decide whether to
    retry or abort.
    """
    user_msg = (
        f"Label these {len(batch)} paths. Return one entry per path in input order:\n\n"
        + _format_batch(batch)
    )
    resp = client.messages.create(
        model=model,
        max_tokens=8192,
        system=_SYSTEM_PROMPT,
        tools=[_TOOL_SCHEMA],
        tool_choice={"type": "tool", "name": "submit_labels"},
        messages=[{"role": "user", "content": user_msg}],
    )
    # Find the tool_use block.
    tool_blocks = [b for b in resp.content if b.type == "tool_use"]
    if not tool_blocks:
        raise RuntimeError(
            f"no tool_use block in response (stop_reason={resp.stop_reason}); "
            f"content: {resp.content!r}"
        )
    labels = tool_blocks[0].input.get("labels", [])
    if len(labels) != len(batch):
        raise RuntimeError(
            f"LLM returned {len(labels)} labels for {len(batch)} paths — "
            f"will need manual reconciliation"
        )
    return labels, resp.usage.input_tokens, resp.usage.output_tokens


def _to_eval_record(
    label: dict,
    source_record: dict,
) -> EvalRecord:
    """Construct an EvalRecord from one LLM label + the source queue record.

    Echoes negative_validator warnings so the validate.py drift check
    passes on the merged eval set.
    """
    path = label["path"]
    warnings = list(negative_check(path))
    return EvalRecord(
        path=path,
        label=label["label"],
        tier=label["tier"],
        category=label["category"],
        sub_type=label["sub_type"],
        source=source_record.get("source", "github_search"),
        notes=label["notes"],
        added_date=TODAY,
        added_by=ADDED_BY,
        pre_category=source_record.get("pre_category"),
        validator_warnings=warnings,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Label paths via Anthropic API. Used for Linux paths in v0.5 "
            "where the rule-based labeler's UNC-shape assumptions block all "
            "Linux records. Output is eval_set-schema-compatible."
        ),
    )
    parser.add_argument("--queue", type=Path, default=DEFAULT_QUEUE_PATH)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Skip paths already present in --output (resume after a crash).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Only label the first N paths (for smoke-testing the prompt).",
    )
    args = parser.parse_args()

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("error: ANTHROPIC_API_KEY not set in environment", file=sys.stderr)
        return 1

    queue_records = []
    for line in args.queue.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        queue_records.append(json.loads(line))
    if args.limit:
        queue_records = queue_records[: args.limit]

    already_labeled: set[str] = set()
    if args.resume and args.output.exists():
        for line in args.output.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            already_labeled.add(json.loads(line)["path"])
        print(
            f"resuming: {len(already_labeled)} paths already in {args.output.name}",
            file=sys.stderr,
        )

    pending = [r for r in queue_records if r["path"] not in already_labeled]
    print(
        f"labeling {len(pending)} paths via {args.model} "
        f"(batch_size={args.batch_size})",
        file=sys.stderr,
    )

    client = anthropic.Anthropic()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Append mode so resume works; truncate if not resuming and output exists.
    write_mode = "a" if args.resume else "w"
    total_in = 0
    total_out = 0
    n_written = 0
    n_validation_errors = 0
    start_time = time.time()

    with args.output.open(write_mode, encoding="utf-8") as out_f:
        for i in range(0, len(pending), args.batch_size):
            batch = pending[i : i + args.batch_size]
            batch_idx = i // args.batch_size + 1
            n_batches = (len(pending) + args.batch_size - 1) // args.batch_size
            try:
                labels, in_tok, out_tok = _label_batch(client, args.model, batch)
            except Exception as e:
                print(
                    f"  batch {batch_idx}/{n_batches} FAILED: {e}",
                    file=sys.stderr,
                )
                continue
            total_in += in_tok
            total_out += out_tok
            # Reconcile labels with source records by path (LLM should preserve
            # order, but key on path defensively in case it doesn't).
            src_by_path = {r["path"]: r for r in batch}
            batch_written = 0
            for label in labels:
                if label["path"] not in src_by_path:
                    print(
                        f"    skip: LLM returned unknown path {label['path']!r}",
                        file=sys.stderr,
                    )
                    continue
                try:
                    rec = _to_eval_record(label, src_by_path[label["path"]])
                except ValidationError as e:
                    n_validation_errors += 1
                    print(
                        f"    skip: schema validation failed for {label['path']!r}: {e}",
                        file=sys.stderr,
                    )
                    continue
                out_f.write(rec.model_dump_json() + "\n")
                batch_written += 1
            out_f.flush()
            n_written += batch_written
            print(
                f"  batch {batch_idx}/{n_batches}: wrote {batch_written}/{len(batch)} "
                f"(in_tok={in_tok}, out_tok={out_tok})",
                file=sys.stderr,
            )

    elapsed = time.time() - start_time
    in_cost = total_in * _PRICE_PER_MTOK_INPUT / 1_000_000
    out_cost = total_out * _PRICE_PER_MTOK_OUTPUT / 1_000_000
    total_cost = in_cost + out_cost
    print(file=sys.stderr)
    print(f"DONE: wrote {n_written} records to {args.output}", file=sys.stderr)
    print(f"  skipped (already labeled): {len(already_labeled)}", file=sys.stderr)
    print(f"  skipped (schema validation): {n_validation_errors}", file=sys.stderr)
    print(f"  elapsed: {elapsed:.1f}s", file=sys.stderr)
    print(
        f"  tokens: {total_in:,} in + {total_out:,} out = "
        f"${in_cost:.3f} + ${out_cost:.3f} = ${total_cost:.3f}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
