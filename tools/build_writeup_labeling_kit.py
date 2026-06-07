"""v0.9.2 paste-workflow kit: writeup paths → Claude.ai chunks.

Reads ``data/eval/writeups/raw_paths.jsonl`` (v0.9.1 output),
deduplicates by path, stratified-samples to ~1500 records (capped to
keep paste burden tractable), and writes:

* ``labeling_kit_v0p9/PROMPT.md`` — system prompt with calibration
  positions (paste once into Claude.ai conversation start).
* ``labeling_kit_v0p9/chunk_NN.txt`` — chunked user messages, ~100
  paths each.
* ``labeling_kit_v0p9/INSTRUCTIONS.md`` — workflow steps.

Stratification: take all UNC + all Windows-drive paths (lower volume,
each useful), sample remaining Linux paths to fit target size.

Output format Sonnet returns per chunk: a single JSONL code block with
one record per input path, fields {idx, is_juicy, tier, category,
reason}. Ingest tool at ``tools/llm_label_writeup_ingest.py`` parses
the responses back into a labeled JSONL.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = REPO_ROOT / "data" / "eval" / "writeups" / "raw_paths.jsonl"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "labeling_kit_v0p9"


_PROMPT = """You are a labeler for filesystem paths extracted from
HackTheBox write-ups. For each path you receive, judge whether it's
"juicy" (worth a pentest operator's attention) per the calibration
positions below.

CALIBRATION POSITIONS (Vincent's signed-off; apply verbatim):

1. SCRIPTS ON SHARES (.ps1/.bat/.vbs/.cmd/.sh) outside SYSVOL/NETLOGON
   → juicy on prior. EXCEPTION: scripts named for known public
   package managers (Chocolatey, scoop, winget, oh-my-zsh, npm, pip,
   apt, dnf, brew) → not_juicy.
2. SSH known_hosts, authorized_keys, id_rsa, id_ed25519, id_dsa,
   *.pub keys, ~/.ssh/config → juicy / Red / ssh_credentials.
3. Shell history (.bash_history, .zsh_history, .python_history,
   .mysql_history, .psql_history, .lesshst) → juicy / Red /
   embedded_secrets.
4. /etc/sudoers and /etc/sudoers.d/* → juicy / Red / ssh_credentials.
5. /etc/shadow, /etc/gshadow, /etc/passwd-backup → juicy / Red /
   embedded_secrets. (Note: /etc/passwd alone is Yellow, not Red —
   it's world-readable in standard configs.)
6. SQL backup *files* (.bak, .mdf, .ldf, .sql.gz, .dmp) → juicy /
   Red / db_files. SQL backup *directories* (no file artifact in
   path) → juicy / Yellow / db_files.
7. Custom-looking .exe binaries (not a known vendor — Adobe, Microsoft,
   Sysmon, MariaDB, Apache, Nginx, etc) → juicy / Yellow /
   embedded_secrets on prior.
8. AWS/GCP/Azure credential dirs (~/.aws/credentials, ~/.config/gcloud,
   ~/.azure) → juicy / Red / cloud_credentials.
9. Kubernetes/Docker secrets (~/.kube/config, ~/.docker/config.json) →
   juicy / Red / cloud_credentials.
10. NTDS.dit, *.kdbx, SAM hive backups → juicy / Black /
    embedded_secrets.
11. /var/www/<app>/.env-style → juicy / Red / iac.
12. Engineering data vaults (path contains "pdm" or "pdmworks" tokens
    near "vault") → not_juicy.
13. Wordlists / password dictionaries (path contains "password" AND
    one of "dictionar", "wordlist", "rockyou", "SecLists") →
    not_juicy.
14. Standard system paths (/usr/bin, /usr/lib, /var/log without
    auth.log/syslog context, /tmp without specific artifact, tooling
    paths like /opt/john/run/*) → not_juicy.
15. /home/<user>/.cache, /home/<user>/.local/share/Trash → not_juicy.

POSTURE: Permissive prior. When uncertain on a juicy-vs-not call,
lean juicy. "Worth looking into" is the threshold, not "definitely
exploitable."

TIER GUIDANCE:
- Black: near-certain credential material (private keys, .kdbx files,
  password files explicitly named, NTDS.dit, SAM hive)
- Red: high-confidence operational sensitivity (shell history,
  sudoers, ssh keys, .bak DB files, GPP cpassword, aws/kube creds,
  .env files, .shadow)
- Yellow: moderate signal worth checking (config files, custom .exe,
  bare SYSVOL/Policies dirs, backup directories without file artifact,
  /etc/passwd)
- null: not juicy

CATEGORY: pick the best fit from:
- ssh_credentials, embedded_secrets, db_files, cloud_credentials,
  iac, high_value_software, browser_artifacts, kerberos_artifacts,
  windows_credentials, benign_noise

OUTPUT FORMAT (strict): Each chunk message I send contains N numbered
paths. Reply with a SINGLE jsonl code block, one JSON object per
input path, in input order. Schema:

  {"idx": <int>, "is_juicy": <bool>, "tier": "Black"|"Red"|"Yellow"|null,
   "category": <str>, "reason": <str ≤120 chars>}

Tier MUST be null when is_juicy is false. Don't write prose outside
the code block."""


_INSTRUCTIONS = """# v0.9.2 paste-labeling workflow

1. Open a fresh Claude.ai conversation (any Sonnet or Opus model).
2. Paste the entire contents of `PROMPT.md` as your first message.
   Claude should respond with something like "Understood. Send the
   first chunk." (If it asks questions instead, hit it with the
   first chunk anyway — the prompt is self-contained.)
3. For each `chunk_NN.txt` in numerical order:
   - Copy the entire file contents into the next user message.
   - Wait for Claude's jsonl response.
   - Save the jsonl code block content (just the code block contents,
     not the surrounding markdown) to a file
     `responses/chunk_NN.jsonl`.
4. When all chunks are done, run:
   ```
   uv run python tools/llm_label_writeup_ingest.py \\
       --responses-dir labeling_kit_v0p9/responses \\
       --chunks-dir labeling_kit_v0p9 \\
       --output data/eval/writeups/labeled_paths.jsonl
   ```
5. The ingest tool merges responses back to the writeup-paths shape
   for v0.9.3 (Snaffler-blind filter + classifier eval).

Context budget: Claude.ai conversations cap around 100K tokens of
chat history. Each chunk is ~5K tokens. You can fit ~20 chunks per
conversation before context fills; start a fresh one (paste PROMPT.md
again) for chunks past that.
"""


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    p.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    p.add_argument(
        "--target",
        type=int,
        default=1500,
        help="Approximate target sample size.",
    )
    p.add_argument(
        "--chunk-size",
        type=int,
        default=100,
        help="Paths per chunk file.",
    )
    p.add_argument("--seed", type=int, default=2026)
    args = p.parse_args(argv)

    rng = random.Random(args.seed)

    records = [json.loads(line) for line in args.input.read_text().splitlines() if line.strip()]
    # Dedup by path.
    seen: set[str] = set()
    deduped: list[dict] = []
    for r in records:
        if r["path"] in seen:
            continue
        seen.add(r["path"])
        deduped.append(r)
    print(f"Input: {len(records)} records → {len(deduped)} unique paths", file=sys.stderr)

    # Stratified sample.
    by_kind = {"unc": [], "win_drive": [], "linux_abs": []}
    for r in deduped:
        by_kind[r["kind"]].append(r)
    print(
        f"  by kind: unc={len(by_kind['unc'])}, "
        f"win_drive={len(by_kind['win_drive'])}, "
        f"linux_abs={len(by_kind['linux_abs'])}",
        file=sys.stderr,
    )

    # Take all UNC + all win_drive; sample linux to fill target.
    sampled = list(by_kind["unc"]) + list(by_kind["win_drive"])
    n_linux_target = max(0, args.target - len(sampled))
    rng.shuffle(by_kind["linux_abs"])
    sampled.extend(by_kind["linux_abs"][:n_linux_target])
    rng.shuffle(sampled)
    print(f"  sampled: {len(sampled)} paths", file=sys.stderr)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    # Clear stale chunks.
    for stale in args.output_dir.glob("chunk_*.txt"):
        stale.unlink()

    (args.output_dir / "PROMPT.md").write_text(_PROMPT, encoding="utf-8")
    (args.output_dir / "INSTRUCTIONS.md").write_text(_INSTRUCTIONS, encoding="utf-8")
    (args.output_dir / "responses").mkdir(exist_ok=True)

    # Write a manifest mapping idx → path so the ingest tool can recover
    # the (chunk_id, idx) → full record mapping.
    manifest = []
    n_chunks = (len(sampled) + args.chunk_size - 1) // args.chunk_size
    for i in range(n_chunks):
        chunk = sampled[i * args.chunk_size : (i + 1) * args.chunk_size]
        chunk_id = i + 1
        header = (
            f"Label these {len(chunk)} paths (chunk {chunk_id}/{n_chunks}).\n"
            f"Reply with one jsonl code block, one record per path, in input order.\n\n"
        )
        body_lines = []
        for j, rec in enumerate(chunk, start=1):
            context = rec.get("context", "").replace("\n", " ").strip()[:200]
            line = f"{j}. {rec['path']}"
            if context:
                line += f"\n   context: {context}"
            body_lines.append(line)
            manifest.append({
                "chunk_id": chunk_id,
                "idx": j,
                "path": rec["path"],
                "kind": rec["kind"],
                "source_url": rec.get("source_url"),
                "source_box": rec.get("source_box"),
            })
        out_path = args.output_dir / f"chunk_{chunk_id:02d}.txt"
        out_path.write_text(header + "\n".join(body_lines) + "\n", encoding="utf-8")

    (args.output_dir / "manifest.jsonl").write_text(
        "\n".join(json.dumps(r) for r in manifest) + "\n",
        encoding="utf-8",
    )

    print(
        f"\nWrote PROMPT.md, INSTRUCTIONS.md, manifest.jsonl, and "
        f"{n_chunks} chunk_NN.txt files to "
        f"{args.output_dir.relative_to(REPO_ROOT)}",
        file=sys.stderr,
    )
    print(f"  paths per chunk: {args.chunk_size}", file=sys.stderr)
    print(f"  total chunks to paste: {n_chunks}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
