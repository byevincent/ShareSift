"""v0.9.2: LLM-label writeup-mined paths against Vincent's calibration.

Reads ``data/eval/writeups/raw_paths.jsonl`` (output of v0.9.1
scraper), sends each path + context to Claude with the calibration
positions Vincent has signed off on as the labeling oracle, writes
labeled records to ``data/eval/writeups/labeled_paths.jsonl``.

Why LLM not rule-based: the existing rule-based labeler
(``tools/claude_label.py``) is UNC-focused and flags Linux-shape paths
as regex artifacts. The 6,284 Linux paths from v0.9.1 need a labeling
oracle that knows Vincent's calibrated stance on
``/root/.bash_history``, ``/etc/sudoers``, scripts-on-shares, etc.
Encoding that into a fresh rule pack is multi-day work; LLM-labeling
costs ~$5 in Haiku-class tokens and applies the calibration directly.

Calibration positions (encoded in the system prompt):
* Scripts (.ps1/.bat/.vbs/.cmd/.sh) on shares (except vendor pkg mgrs)
  → juicy on prior. Pentester would always look.
* SSH known_hosts / authorized_keys / id_rsa → Red/ssh_credentials.
* Shell history (.bash_history etc) → Red/embedded_secrets.
* /etc/sudoers + /etc/sudoers.d → Red/ssh_credentials.
* SQL backup directories → Yellow; .bak/.mdf/.ldf files → Red.
* Custom .exe binaries → Yellow/embedded_secrets on prior;
  vendor binaries (Adobe/Sysmon/etc) → not_juicy.
* PDM "vault" with pdmworks token → not_juicy (engineering data).
* "password" with "dictionary"/"wordlist" → not_juicy.
* Default posture: permissive (aggressive juicy-on-prior).

The output JSONL is the input to v0.9.3 (Snaffler-blind filtering +
eval against existing path classifiers).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = REPO_ROOT / "data" / "eval" / "writeups" / "raw_paths.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "eval" / "writeups" / "labeled_paths.jsonl"
DEFAULT_MODEL = "claude-haiku-4-5"


_SYSTEM_PROMPT = """You are a penetration-tester triage assistant labeling
filesystem paths from HTB write-ups according to a specific calibrated
labeling posture. Your role is judgment, not creativity. Apply the
calibration positions below verbatim.

CALIBRATION POSITIONS (apply these directly, do not re-litigate):
1. SCRIPTS ON SHARES (.ps1/.bat/.vbs/.cmd/.sh) outside SYSVOL/NETLOGON
   → juicy on prior. Pentester would always look. EXCEPTION: scripts
   named for well-known public package management (Chocolatey, scoop,
   winget, oh-my-zsh, npm, pip) → not_juicy.
2. SSH known_hosts, authorized_keys, id_rsa, id_ed25519, *.pub →
   juicy / Red / ssh_credentials.
3. Shell history files (.bash_history, .zsh_history, .python_history,
   .mysql_history, .psql_history) → juicy / Red / embedded_secrets.
4. /etc/sudoers and /etc/sudoers.d/* → juicy / Red / ssh_credentials.
5. /etc/shadow, /etc/gshadow, /etc/passwd-backup → juicy / Red /
   embedded_secrets.
6. SQL backup *files* (.bak, .mdf, .ldf, .sql.gz, .dmp) → juicy / Red
   / db_files. SQL backup *directories* (no file artifact) → juicy /
   Yellow / db_files.
7. Custom-looking .exe binaries (not a known vendor name like Adobe,
   Microsoft, Sysmon) → juicy / Yellow / embedded_secrets on prior.
8. /etc/{ssh,ssl,letsencrypt,nginx,apache2,postgresql,mysql}/* config
   files → juicy / Yellow / iac when the path includes config tokens
   that suggest credentials (private keys, certificates, .conf files
   that take passwords).
9. /var/www, /opt/*, /home/*/.aws, /home/*/.kube, /home/*/.config
   → category depends on specific subpath; aws/kube config dirs ARE
   juicy / Red / cloud_credentials.
10. Engineering data vaults (PDM/SolidWorks context with pdm/pdmworks
    token in path) → not_juicy. Word "vault" alone is ambiguous.
11. Wordlists / password dictionaries (path contains both "password"
    AND "dictionary"/"wordlist"/"rockyou"/"SecLists") → not_juicy.
12. Common system paths (/usr/bin, /usr/lib, /var/log without auth
    context, /tmp, /opt/john/run/* tooling) → not_juicy.

POSTURE: Permissive prior. When uncertain on a juicy-vs-not call,
lean juicy. "Worth looking into" is the threshold, not "definitely
exploitable."

TIER GUIDANCE:
- Black: near-certain credential material (private keys, password
  files explicitly named, NTDS.dit, .kdbx, SAM hive, .gmsa keys)
- Red: high-confidence operational sensitivity (shell history,
  sudoers, ssh keys, .bak DB files, GPP cpassword, aws/kube creds)
- Yellow: moderate signal worth checking (config files, custom .exe,
  bare SYSVOL/Policies dirs, backup directories without file artifact)
- null: not juicy

OUTPUT: Always call the label_path tool. Never respond with prose."""


_TOOL_SCHEMA = {
    "name": "label_path",
    "description": "Record the labeling judgment for one path.",
    "input_schema": {
        "type": "object",
        "properties": {
            "is_juicy": {
                "type": "boolean",
                "description": "True if a pentester would investigate this path.",
            },
            "tier": {
                "type": "string",
                "enum": ["Black", "Red", "Yellow", "None"],
                "description": "Triage tier. Use 'None' when is_juicy is false.",
            },
            "category": {
                "type": "string",
                "description": "Short category tag (ssh_credentials, embedded_secrets, "
                "db_files, cloud_credentials, iac, high_value_software, benign_noise, etc.)",
            },
            "reason": {
                "type": "string",
                "description": "One-sentence justification keyed to a calibration rule "
                "number where applicable.",
            },
        },
        "required": ["is_juicy", "tier", "category", "reason"],
    },
}


def _label_one(client, model: str, rec: dict) -> dict:
    """Single API call. Returns the original record + 'label' field."""
    path = rec["path"]
    context = rec.get("context", "")[:500]  # cap context to keep tokens low
    user_msg = (
        f"Path: {path}\n\n"
        f"Source context (writeup snippet around the path):\n"
        f"```\n{context}\n```\n\n"
        f"Label this path per the calibration."
    )
    resp = client.messages.create(
        model=model,
        max_tokens=400,
        system=_SYSTEM_PROMPT,
        tools=[_TOOL_SCHEMA],
        tool_choice={"type": "tool", "name": "label_path"},
        messages=[{"role": "user", "content": user_msg}],
    )
    label = None
    for block in resp.content:
        if getattr(block, "type", None) == "tool_use" and block.name == "label_path":
            label = block.input
            break
    if label is None:
        return {**rec, "label": None, "error": "no tool_use response"}
    return {**rec, "label": label}


def _existing_labeled(path: Path) -> set[str]:
    """Resume support: paths already in the output."""
    if not path.exists():
        return set()
    out: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
            out.add(rec["path"])
        except (json.JSONDecodeError, KeyError):
            continue
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--parallel", type=int, default=8)
    p.add_argument(
        "--max-records",
        type=int,
        default=None,
        help="Cap on labeled records (for smoke tests).",
    )
    args = p.parse_args(argv)

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ERROR: ANTHROPIC_API_KEY not set", file=sys.stderr)
        return 2

    try:
        import anthropic  # type: ignore[import-not-found]
    except ImportError:
        print("ERROR: anthropic SDK not installed", file=sys.stderr)
        return 2
    client = anthropic.Anthropic()

    records = [json.loads(line) for line in args.input.read_text().splitlines() if line.strip()]
    # Deduplicate by path; keep first occurrence's context (one label per
    # unique path is enough — provenance can be re-joined later).
    seen: set[str] = set()
    deduped: list[dict] = []
    for r in records:
        if r["path"] in seen:
            continue
        seen.add(r["path"])
        deduped.append(r)
    print(f"Input: {len(records)} records → {len(deduped)} unique paths", file=sys.stderr)

    already = _existing_labeled(args.output)
    todo = [r for r in deduped if r["path"] not in already]
    if args.max_records:
        todo = todo[: args.max_records]
    print(
        f"  already labeled: {len(already)}, to label this run: {len(todo)}",
        file=sys.stderr,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("a", encoding="utf-8") as out:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as pool:
            futures = {
                pool.submit(_label_one, client, args.model, rec): rec
                for rec in todo
            }
            n_done = 0
            n_err = 0
            for fut in concurrent.futures.as_completed(futures):
                rec_in = futures[fut]
                try:
                    rec_out = fut.result()
                except Exception as e:
                    rec_out = {**rec_in, "label": None, "error": str(e)[:200]}
                    n_err += 1
                out.write(json.dumps(rec_out) + "\n")
                out.flush()
                n_done += 1
                if n_done % 50 == 0:
                    print(
                        f"  [{n_done}/{len(todo)}] errors={n_err}",
                        file=sys.stderr,
                    )

    print(f"\nWrote {len(todo)} new labels to {args.output.relative_to(REPO_ROOT)}", file=sys.stderr)
    print(f"  errors: {n_err}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
