"""Generate a manual-labeling kit for paste-into-Claude.ai workflow.

Produces a ``labeling_kit/`` directory containing:

* ``PROMPT.md`` — paste once at conversation start. Sets the labeler role,
  tier discipline, calibration table, and output format spec.
* ``chunk_NN.txt`` — paste each chunk in order as a user message.
  Sonnet responds with a JSONL code block for that chunk.
* ``INSTRUCTIONS.md`` — workflow steps.

Why this exists: the API path (``tools/llm_label.py``) requires Anthropic
API credits. The chat path lets Vincent use his Claude.ai Sonnet
subscription to do the remainder of the labeling at the cost of his
copy-paste time.

Reads the queue + existing labeled output, computes the unlabeled diff,
splits into chunks. Default chunk size 100 — balances scroll-burden
against round-trip count.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_QUEUE = REPO_ROOT / "data" / "eval" / "linux_queue_v05_1500.jsonl"
DEFAULT_EXISTING = REPO_ROOT / "data" / "eval" / "eval_set_claude_linux.jsonl"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "labeling_kit"
DEFAULT_CHUNK_SIZE = 100


_PROMPT = """You are a labeler for Linux/Unix file paths in a pentest evaluation set.
For each path I send, decide whether it's "juicy" (worth a pentest operator's attention) or "not_juicy".

LABEL: one of ["juicy", "not_juicy"].

TIER (required when juicy, must be null when not_juicy): one of ["Black", "Red", "Yellow"].
  - Black: would compromise the host or organization if read. Reserve for files
    that ALMOST CERTAINLY contain credentials or keys (private SSH keys,
    /etc/shadow, ~/.aws/credentials, ~/.kube/config with embedded token).
  - Red: high-value credentials, backups, or files with a high base rate of
    embedded credential material (database dumps, .env files in /opt/<app>/,
    /etc/sudoers, ~/.bash_history family — operators routinely find creds
    fat-fingered into shell history).
  - Yellow: useful intel or partial credential info — enumeration data,
    config files that point to credentials without containing them, system
    logs that occasionally surface plaintext creds.

CATEGORY: pick the best fit from EXACTLY one of:
  ["private_keys_x509", "ssh_credentials", "credential_containers",
   "browser_credentials", "cloud_credentials", "modern_saas_tokens",
   "scm_cicd_tokens", "comms_tokens", "db_files", "embedded_secrets",
   "iac", "network_device", "windows_credential_artifacts",
   "decoy_docs", "benign_noise", "high_value_software"]

  - benign_noise for all not_juicy paths
  - ssh_credentials for ~/.ssh/id_*, authorized_keys, known_hosts, sshd_config, /etc/shadow, /etc/passwd, /etc/sudoers
  - cloud_credentials for ~/.aws/, ~/.gcp/, ~/.kube/config
  - private_keys_x509 for .pem, .key, .crt, .pfx files
  - db_files for sqlite, .sql dumps, .mdb, .ldf
  - embedded_secrets for .env files, ~/.bash_history family, /var/log/auth.log
  - scm_cicd_tokens for .npmrc, .pypirc, .docker/config.json, .git-credentials
  - credential_containers for .kdbx (KeePass), .1password
  - decoy_docs for HR/finance/legal docs not specifically credential-bearing
  - modern_saas_tokens for SaaS-vendor token files (Okta, Stripe, OpenAI, Anthropic, etc.)
  - comms_tokens for Slack/Discord/Teams webhook files

SUB_TYPE: ALWAYS null EXCEPT when category is "modern_saas_tokens", in which case sub_type
MUST be exactly one of: ["ai_llm", "paas", "baas", "identity", "package_registry", "payments", "observability"].
  - Okta paths → sub_type: "identity"
  - Stripe paths → sub_type: "payments"
  - OpenAI/Anthropic paths → sub_type: "ai_llm"
  - Supabase paths → sub_type: "baas"
  - Datadog paths → sub_type: "observability"
  - npm/pypi paths → sub_type: "package_registry"
  - Vercel/Auth0 paths → sub_type: "identity" or "paas" depending on context

NOTES: ONE sentence, minimum 15 characters, explaining the tier decision.

CALIBRATION TABLE (Vincent's signed-off positions — apply consistently):

  Path pattern                              Label      Tier    Category
  /etc/shadow                               juicy      Black   ssh_credentials
  /etc/gshadow                              juicy      Black   ssh_credentials
  /etc/passwd                               juicy      Yellow  ssh_credentials
  /etc/sudoers, /etc/sudoers.d/*            juicy      Red     ssh_credentials
  ~/.ssh/id_rsa, id_ed25519, id_*           juicy      Black   ssh_credentials
  ~/.ssh/authorized_keys                    juicy      Red     ssh_credentials
  ~/.ssh/known_hosts                        juicy      Red     ssh_credentials
  ~/.ssh/config                             juicy      Yellow  ssh_credentials
  ~/.bash_history, ~/.zsh_history           juicy      Red     embedded_secrets
  /root/.bash_history                       juicy      Red     embedded_secrets
  ~/.aws/credentials                        juicy      Black   cloud_credentials
  ~/.aws/config                             juicy      Yellow  cloud_credentials
  ~/.kube/config                            juicy      Black   cloud_credentials
  ~/.docker/config.json                     juicy      Red     scm_cicd_tokens
  ~/.netrc                                  juicy      Red     embedded_secrets
  /opt/<app>/.env                           juicy      Red     embedded_secrets
  /etc/<service>/<config>.conf              juicy      Yellow  embedded_secrets
    (nginx, apache2, mysql, postgresql)
  /etc/ssl/private/*.key                    juicy      Black   private_keys_x509
  /etc/ssl/certs/*.crt (no key)             juicy      Yellow  private_keys_x509
  /var/log/auth.log, /var/log/secure        juicy      Yellow  embedded_secrets
  /var/log/<service>/*.log                  not_juicy  null    benign_noise
    (clamav, apache access logs, etc — not auth events)
  /etc/timezone, /etc/hostname              not_juicy  null    benign_noise
  /var/run/*.pid                            not_juicy  null    benign_noise
  /srv/<personal-content>                   not_juicy  null    benign_noise
    (anime-collection, photo dirs, hobby repos)
  CTF/lab markers (hackme, vulnvm,          not_juicy  null    benign_noise
    marvel-dc, htb-user)

ASYMMETRY DISCIPLINE: When uncertain between two tiers, prefer the higher one
for credential-adjacent paths (a missed Red triaged as Yellow costs operator
attention; a missed Yellow triaged as Red costs minor noise). When uncertain
between juicy and not_juicy, prefer not_juicy unless there's a concrete
credential-association reason (label inflation pollutes the training set).

OUTPUT FORMAT — STRICT:

For each batch of paths I send, respond with EXACTLY ONE fenced code block
tagged ```jsonl containing one JSON object per line, one line per path,
in input order. No prose before or after the code block. No extra fields.

EXAMPLE for two input paths:

```jsonl
{"path": "/etc/shadow", "label": "juicy", "tier": "Black", "category": "ssh_credentials", "sub_type": null, "notes": "Hashed local password file; readable shadow yields offline password cracking."}
{"path": "/srv/anime-collection", "label": "not_juicy", "tier": null, "category": "benign_noise", "sub_type": null, "notes": "User personal content directory with no credential association."}
```

Confirm you understand by replying "ready" — then I'll send the first batch."""


_INSTRUCTIONS = """# Manual labeling workflow

You'll paste the prompt into a fresh Claude.ai (Sonnet) conversation once,
then paste each chunk as a separate user message. Sonnet will respond with
a `jsonl` code block. Collect all those code blocks into one file.

## Steps

1. **Open a new Claude.ai conversation.** Default Sonnet model.

2. **Paste `PROMPT.md` as the first message.** Wait for Sonnet to reply
   "ready" (or equivalent).

3. **For each `chunk_NN.txt`:**
   - Paste the chunk file's contents as your next message.
   - Sonnet replies with a `jsonl` code block. Copy ONLY the contents
     between the ``` fence markers (not the markers themselves).
   - Append the copied JSONL lines to a single file:
     `data/eval/eval_set_claude_linux_manual.jsonl`
   - Repeat for the next chunk.

4. **When all chunks done:** run the ingester
   ```bash
   uv run python tools/llm_label_ingest.py \\
       --input data/eval/eval_set_claude_linux_manual.jsonl
   ```
   It validates each line against the schema, attaches pre_category +
   validator_warnings, and appends to `eval_set_claude_linux.jsonl`.

## If Sonnet drifts

- If output isn't a fenced ```jsonl block, ask: "Reformat your last reply
  as a single jsonl code block, no prose."
- If a tier seems wrong on a high-stakes path (e.g. /etc/shadow as Yellow),
  flag it and ask Sonnet to reconsider — or fix it manually before paste.
- If a category isn't in the allowed enum, ask Sonnet to map to the closest
  one or fall back to "embedded_secrets" for cred-adjacent unknowns.

## If you need to restart

`tools/llm_label_chunkify.py` is idempotent — re-running it recomputes the
unlabeled diff, so you can run it again after partial progress to get
fresh chunks of only-still-unlabeled paths.
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    parser.add_argument("--existing", type=Path, default=DEFAULT_EXISTING)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE)
    args = parser.parse_args()

    queue = []
    for line in args.queue.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        queue.append(json.loads(line))

    already_labeled: set[str] = set()
    if args.existing.exists():
        for line in args.existing.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            already_labeled.add(json.loads(line)["path"])

    pending = [r for r in queue if r["path"] not in already_labeled]
    print(f"queue: {len(queue)} records")
    print(f"already labeled: {len(already_labeled)}")
    print(f"pending: {len(pending)} records")
    if not pending:
        print("nothing to chunk.")
        return 0

    args.output_dir.mkdir(parents=True, exist_ok=True)
    # Clear any prior chunk files so re-runs don't leave stale chunks behind.
    for stale in args.output_dir.glob("chunk_*.txt"):
        stale.unlink()

    (args.output_dir / "PROMPT.md").write_text(_PROMPT, encoding="utf-8")
    (args.output_dir / "INSTRUCTIONS.md").write_text(_INSTRUCTIONS, encoding="utf-8")

    n_chunks = (len(pending) + args.chunk_size - 1) // args.chunk_size
    for i in range(n_chunks):
        chunk = pending[i * args.chunk_size : (i + 1) * args.chunk_size]
        header = (
            f"Label these {len(chunk)} paths "
            f"(chunk {i + 1}/{n_chunks}). Reply with one jsonl code block, "
            f"one JSON record per path, in input order.\n\n"
        )
        body_lines = []
        for j, rec in enumerate(chunk, start=1):
            hint = rec.get("pre_category") or "none"
            body_lines.append(f"{j}. {rec['path']}   [pre_category hint: {hint}]")
        out_path = args.output_dir / f"chunk_{i + 1:02d}.txt"
        out_path.write_text(header + "\n".join(body_lines) + "\n", encoding="utf-8")

    print(f"wrote PROMPT.md, INSTRUCTIONS.md, and {n_chunks} chunk files to {args.output_dir}")
    print(f"  paths per chunk: {args.chunk_size}")
    print(f"  total round-trips: {n_chunks}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
