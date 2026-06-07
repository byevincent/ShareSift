"""v0.15 Phase C — LLM extraction of file paths from scraped articles.

Reads scraped articles from
``data/external/engagement_corpus/articles.jsonl`` (Phase B output),
runs each through an LLM with a structured-output JSON schema, and
extracts file paths attackers found/created/discovered with
surrounding context. Output feeds the v0.15 path-classifier retrain.

Hallucination guard: every extracted ``verbatim_path`` must appear as
a substring in the source article text. LLMs occasionally invent
plausible-sounding paths that don't exist in the source — these are
rejected before reaching the output JSONL. Normalized matches
(case-insensitive after stripping whitespace) are flagged for review
but kept in a separate ``review`` queue.

Three modes mirror :mod:`tools.label_snaffler_hits`:

* ``--mode prep``: write paste-ready chunks for the Claude.ai workflow
* ``--mode anthropic-api``: direct Sonnet/Haiku calls with API key
* ``--mode diff``: cross-check two extraction runs (e.g., Sonnet vs
  Haiku/Codex) and surface disagreements

Output schema (one record per extracted path)::

    {
        "source_url": "https://thedfirreport.com/...",
        "source_title": "...",
        "verbatim_path": "C:\\\\Users\\\\admin\\\\AppData\\\\...",
        "context_excerpt": "...200 chars around the path mention...",
        "credential_type": "plaintext_password" | "hash" | "key_material"
            | "private_key" | "token" | "encrypted_credential"
            | "config_secret" | "ssh_credentials" | "embedded_secrets" | null,
        "share_context": "domain_controller" | "file_server"
            | "workstation" | "web_server" | "database_server"
            | "developer_workstation" | "unknown",
        "discovery_type": "found_by_attacker" | "navigated_through"
            | "created_by_attacker" | "mentioned_as_example"
            | "documented_in_writeup",
        "tier": "Black" | "Red" | "Yellow" | "None",
        "verbatim_match_quality": "exact" | "normalized",
        "model": "claude-sonnet-4-6",
        "extracted_at": "..."
    }

Usage::

    # Prep paste file
    uv run python tools/extract_paths_from_articles.py --mode prep \\
        --input data/external/engagement_corpus/articles.jsonl \\
        --output reports/extraction_kit_engagement.jsonl

    # Direct API
    export ANTHROPIC_API_KEY=...
    uv run python tools/extract_paths_from_articles.py \\
        --mode anthropic-api \\
        --input data/external/engagement_corpus/articles.jsonl \\
        --output data/external/engagement_corpus/extracted_paths_sonnet.jsonl \\
        --model claude-sonnet-4-6 \\
        --max-articles 50  # smoke first

    # Diff two extraction runs
    uv run python tools/extract_paths_from_articles.py --mode diff \\
        --left  data/external/engagement_corpus/extracted_paths_sonnet.jsonl \\
        --right data/external/engagement_corpus/extracted_paths_haiku.jsonl \\
        --output reports/extraction_disagreements.jsonl
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

DEFAULT_ARTICLES = REPO_ROOT / "data" / "external" / "engagement_corpus" / "articles.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "external" / "engagement_corpus" / "extracted_paths.jsonl"

# Cap article text per request to keep LLM input bounded. Most blog posts
# fit under 30k chars after our crude HTML strip; cap is conservative.
MAX_ARTICLE_CHARS = 30000
# Reserve LLM output budget for ~30 paths per article (most articles have
# fewer, but DFIR Report incidents can be path-rich).
MAX_RESPONSE_TOKENS = 4000

SYSTEM_PROMPT = """You are extracting file paths from a security writeup or incident report.

Your job: identify every file path (Windows or Unix) the article mentions as a
location where attackers found, created, navigated through, or documented
credentials, secrets, or sensitive configuration. Output strict JSON only.

INCLUDE paths that:
- Are described as containing credentials, keys, hashes, or auth material
- Are accessed/staged/dumped by the attacker for later credential extraction
- Are documented as part of attacker tradecraft for credential discovery
- Are example paths from the writeup demonstrating where to look

EXCLUDE paths that:
- Are URLs (http/https/ftp links)
- Are command outputs or binary file paths with no credential relevance
- Are author-provided cleanup/remediation paths
- Are documentation references unrelated to credentials

For each path, classify:

credential_type (null if not credential-related):
- plaintext_password: literal password in a file
- hash: NTLM, bcrypt, SHA, etc.
- key_material: private keys, certs, master keys
- private_key: SSH/PGP/RSA private keys specifically
- token: OAuth, API token, JWT, session token
- encrypted_credential: stored cred encrypted by another mechanism
- config_secret: config file containing credential info (wp-config.php)
- ssh_credentials: known_hosts, authorized_keys, .ssh/ contents
- embedded_secrets: scripts/code containing literal credentials

share_context (best guess from article context):
- domain_controller / file_server / workstation / web_server
- database_server / developer_workstation / unknown

discovery_type:
- found_by_attacker: attacker stumbled on it during enumeration
- navigated_through: path was traversed, no credential found there
- created_by_attacker: attacker dropped this file (staging, output dump)
- mentioned_as_example: writeup illustrates the path as a typical target
- documented_in_writeup: author notes this is a common artifact

tier (operator-value triage):
- Black: top-tier (SAM hive, ntds.dit, master keys, SSH private keys, plaintext creds)
- Red: high-value (DB configs with creds, AD service accounts, web app configs)
- Yellow: probable (config files that may contain creds, intermediate caches)
- None: navigated-through only, not credential-bearing

verbatim_path: EXACT substring from the article. Preserve case, separators,
trailing slash, environment-variable wrappers. If the article wraps a path
in backticks or quotes, do NOT include the wrappers but preserve everything
between them. The path must appear verbatim in the article source text.

context_excerpt: ~150 chars surrounding the path mention, helps the
downstream auditor verify the classification.

OUTPUT FORMAT — strict JSON object with a top-level "paths" array:

{
  "paths": [
    {
      "verbatim_path": "...",
      "context_excerpt": "...",
      "credential_type": "...",
      "share_context": "...",
      "discovery_type": "...",
      "tier": "...",
      "reasoning": "one-sentence why this tier"
    }
  ]
}

If the article mentions no credential-relevant paths, return {"paths": []}.
"""


def _build_user_prompt(article: dict) -> str:
    title = article.get("title", "")
    url = article.get("url", "")
    text = (article.get("text") or "")[:MAX_ARTICLE_CHARS]
    return (
        f"Article URL: {url}\n"
        f"Article title: {title}\n"
        f"\n---ARTICLE TEXT---\n"
        f"{text}\n"
        f"---END ARTICLE---\n"
        f"\nExtract all credential-relevant file paths per the schema."
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


# ---------------------------------------------------------------------------
# Hallucination guard
# ---------------------------------------------------------------------------

def _strip_path_wrappers(p: str) -> str:
    """Strip common path wrappers LLMs sometimes include despite instructions:
    backticks, surrounding quotes, leading/trailing whitespace."""
    p = p.strip()
    for q in ("`", '"', "'"):
        if p.startswith(q) and p.endswith(q) and len(p) > 1:
            p = p[1:-1]
    return p.strip()


def _verify_path_in_source(path: str, source_text: str) -> tuple[bool, str]:
    """Returns (kept, match_quality). match_quality is 'exact' if the path
    appears verbatim, 'normalized' if found after case-folding + whitespace
    normalization. (False, 'hallucination') if neither matches."""
    if not path or not source_text:
        return False, "hallucination"
    cleaned = _strip_path_wrappers(path)
    if cleaned in source_text:
        return True, "exact"
    # Some articles render Windows paths with escaped backslashes (e.g.,
    # `C:\\Users\\...`). Normalize both to test.
    src_norm = source_text.replace("\\\\", "\\").lower()
    path_norm = cleaned.replace("\\\\", "\\").lower()
    if path_norm in src_norm:
        return True, "normalized"
    # Sometimes the LLM strips a leading "C:\" because the article does
    # too in display. Try the path's tail half against the source.
    tail = cleaned[len(cleaned) // 2:]
    if len(tail) >= 12 and tail.lower() in src_norm:
        return True, "normalized"
    return False, "hallucination"


# ---------------------------------------------------------------------------
# Mode: prep
# ---------------------------------------------------------------------------

def _mode_prep(args) -> int:
    articles = _load_jsonl(args.input)
    if args.max_articles:
        articles = articles[: args.max_articles]
    print(f"[prep] {len(articles)} articles", file=sys.stderr)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        for a in articles:
            chunk = {
                "url": a.get("url"),
                "title": a.get("title"),
                "source": a.get("source"),
                "system_prompt": SYSTEM_PROMPT,
                "user_prompt": _build_user_prompt(a),
            }
            fh.write(json.dumps(chunk) + "\n")
    print(f"[prep] wrote {len(articles)} prompts → {args.output}", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# Mode: anthropic-api
# ---------------------------------------------------------------------------

_ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"


def _call_anthropic(api_key: str, model: str, system: str, user: str,
                    max_tokens: int) -> dict:
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
    backoff = 30
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code in (429, 529):
                print(f"  [rate] HTTP {e.code} sleeping {backoff}s", file=sys.stderr)
                time.sleep(backoff)
                backoff = min(backoff * 2, 300)
                continue
            if e.code in (500, 502, 503, 504):
                print(f"  [server] HTTP {e.code} retry", file=sys.stderr)
                time.sleep(10 * (attempt + 1))
                continue
            raise
        except (urllib.error.URLError, TimeoutError) as e:
            print(f"  [net] {e} retry {attempt+1}", file=sys.stderr)
            time.sleep(5 * (attempt + 1))
    raise RuntimeError("Anthropic API max retries exceeded")


def _parse_paths_response(text: str) -> list[dict]:
    """Extract the paths array from the model's response. Tolerant to chat
    preamble and markdown fences."""
    # Try to find the first JSON object with a 'paths' key
    m = re.search(r"\{[\s\S]*?\"paths\"\s*:\s*\[[\s\S]*?\][\s\S]*?\}", text)
    if not m:
        return []
    try:
        obj = json.loads(m.group(0))
    except json.JSONDecodeError:
        # Try after stripping markdown fences
        cleaned = re.sub(r"```(?:json)?\s*|\s*```", "", text)
        m2 = re.search(r"\{[\s\S]*\}", cleaned)
        if not m2:
            return []
        try:
            obj = json.loads(m2.group(0))
        except json.JSONDecodeError:
            return []
    return obj.get("paths", []) if isinstance(obj, dict) else []


def _mode_anthropic_api(args) -> int:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: set ANTHROPIC_API_KEY env var", file=sys.stderr)
        return 2
    articles = _load_jsonl(args.input)
    if args.max_articles:
        articles = articles[: args.max_articles]

    # Resume support
    seen_urls: set[str] = set()
    if args.output.exists() and not args.no_resume:
        for r in _load_jsonl(args.output):
            seen_urls.add(r.get("source_url", ""))
        # Also a parallel "no-paths" sidecar so we don't re-query empty articles
        no_paths_path = args.output.with_suffix(".no_paths.jsonl")
        if no_paths_path.exists():
            for r in _load_jsonl(no_paths_path):
                seen_urls.add(r.get("source_url", ""))
        print(f"[resume] skipping {len(seen_urls)} already-extracted URLs",
              file=sys.stderr)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    out_fh = args.output.open("a", encoding="utf-8")
    no_paths_path = args.output.with_suffix(".no_paths.jsonl")
    no_paths_fh = no_paths_path.open("a", encoding="utf-8")
    review_path = args.output.with_suffix(".review.jsonl")
    review_fh = review_path.open("a", encoding="utf-8")

    n_articles_ok = 0
    n_articles_error = 0
    n_paths_kept = 0
    n_paths_normalized = 0
    n_paths_hallucinated = 0

    try:
        for i, article in enumerate(articles, start=1):
            url = article.get("url", "")
            if url in seen_urls:
                continue
            user = _build_user_prompt(article)
            try:
                response = _call_anthropic(
                    api_key, args.model, SYSTEM_PROMPT, user, MAX_RESPONSE_TOKENS,
                )
                text = response["content"][0]["text"]
                paths = _parse_paths_response(text)
            except Exception as e:
                print(f"  [{i}/{len(articles)}] error on {url}: {e}",
                      file=sys.stderr)
                n_articles_error += 1
                continue

            if not paths:
                no_paths_fh.write(json.dumps({
                    "source_url": url,
                    "source_title": article.get("title"),
                    "source": article.get("source"),
                    "model": args.model,
                    "extracted_at": datetime.now(timezone.utc).isoformat(),
                }) + "\n")
                no_paths_fh.flush()
                n_articles_ok += 1
                continue

            for p in paths:
                vpath = p.get("verbatim_path", "")
                kept, quality = _verify_path_in_source(vpath, article.get("text", ""))
                base_rec = {
                    "source_url": url,
                    "source_title": article.get("title"),
                    "source": article.get("source"),
                    "verbatim_path": _strip_path_wrappers(vpath),
                    "context_excerpt": p.get("context_excerpt"),
                    "credential_type": p.get("credential_type"),
                    "share_context": p.get("share_context"),
                    "discovery_type": p.get("discovery_type"),
                    "tier": p.get("tier"),
                    "reasoning": p.get("reasoning"),
                    "verbatim_match_quality": quality,
                    "model": args.model,
                    "extracted_at": datetime.now(timezone.utc).isoformat(),
                }
                if not kept:
                    review_fh.write(json.dumps(base_rec) + "\n")
                    review_fh.flush()
                    n_paths_hallucinated += 1
                    continue
                if quality == "normalized":
                    n_paths_normalized += 1
                out_fh.write(json.dumps(base_rec) + "\n")
                out_fh.flush()
                n_paths_kept += 1
            n_articles_ok += 1
            if n_articles_ok % 10 == 0:
                print(f"  [progress] {n_articles_ok} articles, "
                      f"{n_paths_kept} paths kept ({n_paths_normalized} normalized), "
                      f"{n_paths_hallucinated} rejected", file=sys.stderr)
    finally:
        out_fh.close()
        no_paths_fh.close()
        review_fh.close()
    print(f"\n[final] {n_articles_ok} articles ok, {n_articles_error} errors",
          file=sys.stderr)
    print(f"        {n_paths_kept} paths kept ({n_paths_normalized} normalized matches)",
          file=sys.stderr)
    print(f"        {n_paths_hallucinated} hallucinated paths → {review_path}",
          file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# Mode: diff
# ---------------------------------------------------------------------------

def _mode_diff(args) -> int:
    left = _load_jsonl(args.left)
    right = _load_jsonl(args.right)

    def _bucket(records):
        # key by (url, verbatim_path) — same url+path between runs is a "match"
        b: dict[tuple[str, str], dict] = {}
        for r in records:
            key = (r.get("source_url", ""), r.get("verbatim_path", ""))
            b[key] = r
        return b

    L = _bucket(left)
    R = _bucket(right)
    keys_L = set(L)
    keys_R = set(R)
    only_left = sorted(keys_L - keys_R)
    only_right = sorted(keys_R - keys_L)
    shared = keys_L & keys_R

    classification_disagreements = []
    for k in shared:
        l, r = L[k], R[k]
        diff_fields = {}
        for field in ("credential_type", "share_context", "discovery_type", "tier"):
            if l.get(field) != r.get(field):
                diff_fields[field] = {"left": l.get(field), "right": r.get(field)}
        if diff_fields:
            classification_disagreements.append({
                "source_url": k[0],
                "verbatim_path": k[1],
                "diffs": diff_fields,
                "left_model": l.get("model"),
                "right_model": r.get("model"),
            })

    print(f"[diff] left: {len(left)} paths, right: {len(right)} paths",
          file=sys.stderr)
    print(f"  shared (url, path): {len(shared)}", file=sys.stderr)
    print(f"  only in left:  {len(only_left)} (paths {l.get('model','left')} found, "
          f"{r.get('model','right')} missed)", file=sys.stderr)
    print(f"  only in right: {len(only_right)}", file=sys.stderr)
    print(f"  classification disagreements (shared paths, different labels): "
          f"{len(classification_disagreements)}", file=sys.stderr)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        for k in only_left:
            fh.write(json.dumps({
                "kind": "only_in_left",
                "source_url": k[0],
                "verbatim_path": k[1],
                "record": L[k],
            }) + "\n")
        for k in only_right:
            fh.write(json.dumps({
                "kind": "only_in_right",
                "source_url": k[0],
                "verbatim_path": k[1],
                "record": R[k],
            }) + "\n")
        for d in classification_disagreements:
            d["kind"] = "classification_disagreement"
            fh.write(json.dumps(d) + "\n")

    print(f"\n[diff] wrote disagreements → {args.output}", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Mode: prep-kit (batched Markdown for Claude.ai paste workflow)
# ---------------------------------------------------------------------------

_KIT_README = """\
# v0.15 Path Extraction Kit (Claude.ai paste workflow)

Use this kit to extract credential-relevant paths from the engagement
article corpus using Claude.ai directly, without paying API costs.

## How to use

For each `batches/batch_NNN.md` file:

1. Open Claude.ai in a fresh conversation (Sonnet 4.6 or Opus 4.x recommended).
2. Open the batch file. Copy the entire contents (including the SYSTEM PROMPT
   block at the top — Claude treats the first message as setup context).
3. Paste into Claude.ai. Press Enter / submit.
4. Claude returns a JSON object. Copy the JSON only (drop any preamble text).
5. Save the JSON to `responses/batch_NNN.json` (matching the batch number).
6. Move to the next batch.

When you've done all the batches you want to process, run:

    uv run python tools/extract_paths_from_articles.py \\
        --mode ingest-responses \\
        --kit-dir {kit_dir} \\
        --output data/external/engagement_corpus/extracted_paths.jsonl

This applies the hallucination guard (every path Claude returns must appear
verbatim in the original article text) and writes the standard schema.

## Resuming

If you stop midway, just keep going from whichever `batch_NNN.md` you
haven't yet saved a response for. The ingest step reads every JSON in
`responses/` and skips missing ones silently.

## Batches

Total: {n_batches} batches covering {n_articles} articles. Each batch is
~{articles_per_batch} articles, designed to fit comfortably in one
Claude.ai message and stay under Sonnet's 8k output token limit.
"""


def _mode_prep_kit(args) -> int:
    articles = _load_jsonl(args.input)
    if args.max_articles:
        articles = articles[: args.max_articles]
    kit_dir = args.kit_dir
    batches_dir = kit_dir / "batches"
    responses_dir = kit_dir / "responses"
    batches_dir.mkdir(parents=True, exist_ok=True)
    responses_dir.mkdir(parents=True, exist_ok=True)
    articles_per_batch = args.articles_per_batch

    # Manifest maps batch_index → list of (article_index_in_batch, url) so
    # ingestion can rejoin Claude's response.results[i] to the original article.
    manifest: dict[str, list[dict]] = {}
    n_batches = (len(articles) + articles_per_batch - 1) // articles_per_batch
    for batch_idx in range(n_batches):
        start = batch_idx * articles_per_batch
        end = min(start + articles_per_batch, len(articles))
        batch = articles[start:end]
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
            f"Extract credential-relevant paths from each of the {len(batch)} "
            f"articles below. Return strict JSON only — no prose preamble, "
            f"no markdown fences — with this exact shape:",
            "",
            "```",
            "{",
            "  \"results\": [",
            "    {\"article_index\": 0, \"paths\": [ {<path object>}, ... ]},",
            "    {\"article_index\": 1, \"paths\": [ ... ]},",
            "    ...",
            "  ]",
            "}",
            "```",
            "",
            "Each `paths[*]` object follows the schema above (verbatim_path, "
            "context_excerpt, credential_type, share_context, discovery_type, "
            "tier, reasoning). If an article mentions no credential-relevant "
            "paths, return `{\"article_index\": <i>, \"paths\": []}`.",
            "",
            "---",
            "",
            "# ARTICLES",
            "",
        ]
        for i, a in enumerate(batch):
            manifest[batch_id].append({"index": i, "url": a.get("url", "")})
            text = (a.get("text") or "")[:MAX_ARTICLE_CHARS]
            lines.append(f"## Article {i}")
            lines.append("")
            lines.append(f"**URL:** {a.get('url', '')}")
            lines.append(f"**Title:** {a.get('title', '')}")
            lines.append("")
            lines.append("```")
            lines.append(text)
            lines.append("```")
            lines.append("")
        batch_file = batches_dir / f"{batch_id}.md"
        batch_file.write_text("\n".join(lines), encoding="utf-8")

    # Manifest file (used by ingest-responses)
    manifest_file = kit_dir / "manifest.json"
    manifest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    # README
    readme_file = kit_dir / "README.md"
    readme_file.write_text(
        _KIT_README.format(
            kit_dir=kit_dir,
            n_batches=n_batches,
            n_articles=len(articles),
            articles_per_batch=articles_per_batch,
        ),
        encoding="utf-8",
    )

    # Sample empty response template so the user sees the expected format
    template_file = kit_dir / "response_template.json"
    template_file.write_text(json.dumps({
        "results": [
            {"article_index": 0, "paths": []},
            {"article_index": 1, "paths": [
                {"verbatim_path": "C:\\Users\\admin\\Desktop\\creds.txt",
                 "context_excerpt": "...the attacker found credentials at...",
                 "credential_type": "plaintext_password",
                 "share_context": "workstation",
                 "discovery_type": "found_by_attacker",
                 "tier": "Black",
                 "reasoning": "literal cred file on admin desktop"},
            ]},
        ]
    }, indent=2), encoding="utf-8")

    print(f"[kit] wrote {n_batches} batches covering {len(articles)} articles → "
          f"{kit_dir}", file=sys.stderr)
    print(f"      manifest: {manifest_file.relative_to(kit_dir.parent)}",
          file=sys.stderr)
    print(f"      readme:   {readme_file.relative_to(kit_dir.parent)}",
          file=sys.stderr)
    print(f"      template: {template_file.relative_to(kit_dir.parent)}",
          file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# Mode: ingest-responses (parse Claude.ai response JSONs into extracted_paths.jsonl)
# ---------------------------------------------------------------------------

def _mode_ingest_responses(args) -> int:
    kit_dir = args.kit_dir
    manifest_file = kit_dir / "manifest.json"
    responses_dir = kit_dir / "responses"
    if not manifest_file.exists():
        print(f"ERROR: {manifest_file} missing — re-run --mode prep-kit first",
              file=sys.stderr)
        return 2
    manifest: dict[str, list[dict]] = json.loads(manifest_file.read_text())

    # Need original article text for hallucination guard
    articles = _load_jsonl(args.input) if args.input else []
    if args.max_articles:
        articles = articles[: args.max_articles]
    url_to_text = {a.get("url", ""): a.get("text", "") for a in articles}
    url_to_title = {a.get("url", ""): a.get("title", "") for a in articles}
    url_to_source = {a.get("url", ""): a.get("source", "") for a in articles}

    args.output.parent.mkdir(parents=True, exist_ok=True)
    review_path = args.output.with_suffix(".review.jsonl")
    no_paths_path = args.output.with_suffix(".no_paths.jsonl")
    out_fh = args.output.open("w", encoding="utf-8")
    no_fh = no_paths_path.open("w", encoding="utf-8")
    review_fh = review_path.open("w", encoding="utf-8")

    n_batches_seen = 0
    n_batches_missing = 0
    n_paths_kept = 0
    n_paths_normalized = 0
    n_paths_hallucinated = 0
    n_articles_no_paths = 0

    for batch_id, batch_articles in manifest.items():
        response_file = responses_dir / f"{batch_id}.json"
        if not response_file.exists():
            n_batches_missing += 1
            continue
        try:
            raw = response_file.read_text(encoding="utf-8")
        except Exception as e:
            print(f"  [{batch_id}] read error: {e}", file=sys.stderr)
            n_batches_missing += 1
            continue
        # Tolerate JSON wrapped in markdown fences or chat preamble
        m = re.search(r"\{[\s\S]*\}\s*$", raw)
        if m:
            raw_json = m.group(0)
        else:
            raw_json = raw
        try:
            parsed = json.loads(raw_json)
        except json.JSONDecodeError as e:
            print(f"  [{batch_id}] JSON parse error: {e}", file=sys.stderr)
            n_batches_missing += 1
            continue
        results = parsed.get("results", [])
        if not isinstance(results, list):
            print(f"  [{batch_id}] results not a list", file=sys.stderr)
            n_batches_missing += 1
            continue
        n_batches_seen += 1
        # Index results by article_index for fast lookup
        results_by_idx = {r.get("article_index"): r for r in results
                           if isinstance(r, dict)}
        for entry in batch_articles:
            idx = entry["index"]
            url = entry["url"]
            res = results_by_idx.get(idx)
            if res is None:
                continue
            paths = res.get("paths", []) or []
            if not paths:
                no_fh.write(json.dumps({"source_url": url,
                                        "source_title": url_to_title.get(url, ""),
                                        "source": url_to_source.get(url, "")}) + "\n")
                n_articles_no_paths += 1
                continue
            source_text = url_to_text.get(url, "")
            for p in paths:
                vpath = p.get("verbatim_path", "") if isinstance(p, dict) else ""
                kept, quality = _verify_path_in_source(vpath, source_text)
                rec = {
                    "source_url": url,
                    "source_title": url_to_title.get(url, ""),
                    "source": url_to_source.get(url, ""),
                    "verbatim_path": _strip_path_wrappers(vpath),
                    "context_excerpt": p.get("context_excerpt") if isinstance(p, dict) else None,
                    "credential_type": p.get("credential_type") if isinstance(p, dict) else None,
                    "share_context": p.get("share_context") if isinstance(p, dict) else None,
                    "discovery_type": p.get("discovery_type") if isinstance(p, dict) else None,
                    "tier": p.get("tier") if isinstance(p, dict) else None,
                    "reasoning": p.get("reasoning") if isinstance(p, dict) else None,
                    "verbatim_match_quality": quality,
                    "model": "claude.ai-paste",
                    "extracted_at": datetime.now(timezone.utc).isoformat(),
                    "kit_batch": batch_id,
                }
                if not kept:
                    review_fh.write(json.dumps(rec) + "\n")
                    n_paths_hallucinated += 1
                    continue
                if quality == "normalized":
                    n_paths_normalized += 1
                out_fh.write(json.dumps(rec) + "\n")
                n_paths_kept += 1

    out_fh.close()
    no_fh.close()
    review_fh.close()

    print(f"\n[ingest] {n_batches_seen} batches ingested, "
          f"{n_batches_missing} missing/unparseable", file=sys.stderr)
    print(f"         {n_paths_kept} paths kept ({n_paths_normalized} normalized)",
          file=sys.stderr)
    print(f"         {n_articles_no_paths} articles returned no paths",
          file=sys.stderr)
    print(f"         {n_paths_hallucinated} hallucinated → {review_path}",
          file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--mode",
                   choices=["prep", "prep-kit", "anthropic-api",
                            "ingest-responses", "diff"],
                   required=True)
    p.add_argument("--input", type=Path, default=DEFAULT_ARTICLES,
                   help="articles.jsonl (Phase B output)")
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    p.add_argument("--kit-dir", type=Path,
                   default=REPO_ROOT / "data" / "external" / "engagement_corpus" / "extraction_kit",
                   help="Kit directory for prep-kit / ingest-responses modes")
    p.add_argument("--articles-per-batch", type=int, default=15,
                   help="Articles per Claude.ai paste batch (default 15 — fits "
                        "within Sonnet's output token budget for path-rich corpora)")
    p.add_argument("--model", default="claude-sonnet-4-6",
                   help="Anthropic model name for anthropic-api mode")
    p.add_argument("--max-articles", type=int, default=None,
                   help="Cap articles (smoke testing)")
    p.add_argument("--no-resume", action="store_true",
                   help="Don't skip already-extracted URLs in --output")
    p.add_argument("--left", type=Path, help="left extraction JSONL (--mode diff)")
    p.add_argument("--right", type=Path, help="right extraction JSONL (--mode diff)")
    args = p.parse_args(argv)

    if args.mode == "prep":
        if not args.input.exists():
            print(f"ERROR: --input missing: {args.input}", file=sys.stderr)
            return 2
        return _mode_prep(args)
    if args.mode == "prep-kit":
        if not args.input.exists():
            print(f"ERROR: --input missing: {args.input}", file=sys.stderr)
            return 2
        return _mode_prep_kit(args)
    if args.mode == "anthropic-api":
        if not args.input.exists():
            print(f"ERROR: --input missing: {args.input}", file=sys.stderr)
            return 2
        return _mode_anthropic_api(args)
    if args.mode == "ingest-responses":
        return _mode_ingest_responses(args)
    if args.mode == "diff":
        if not args.left or not args.right:
            print("ERROR: --left and --right required for diff mode",
                  file=sys.stderr)
            return 2
        return _mode_diff(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
