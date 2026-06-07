#!/usr/bin/env python3
"""v0.13 Phase 2 — github scrape for literal-vs-referenced credential corpus.

Scrapes public github for PowerShell + CMD/BAT + XML files containing
password-related tokens, applies regex labelers to classify each match
as either a literal credential value (positive) or a referenced /
parameterized / templated / documented credential (negative), and
writes labeled snippets in Snaffler-match-window shape (500 chars
centered on the match).

Output schema (JSONL, one record per labeled match):
    {
        "snippet":         "...500 chars centered on regex match...",
        "label":           "literal" | "referenced",
        "subtype":         null                          # if label == "literal"
                            | "variable_reference"        # password=$var, %var%, ${var}
                            | "parameter_declaration"     # param([Password]$p)
                            | "documentation_example"     # .EXAMPLE, <#...#>, ```fences
                            | "regex_template",           # password={{var}}, passw?o?r?d
        "matched_pattern": "the regex that fired",
        "match_offset":    int,                          # match start within snippet
        "matched_text":    "the substring the regex matched",
        "literal_value":   "the extracted literal" | null,  # only when label == "literal"
        "source_repo":     "owner/name",
        "source_path":     "path/in/repo.ps1",
        "source_sha":      "...",
        "file_extension":  "ps1" | "psm1" | "bat" | "cmd" | "xml" | "sql",
        "scraped_at":      "2026-06-03T12:34:56Z"
    }

Usage:
    export GITHUB_TOKEN=ghp_xxx
    uv run python tools/build_literal_vs_referenced_corpus.py \\
        --output data/external/literal_vs_referenced/scraped.jsonl \\
        --target-snippets 80000 \\
        --max-per-repo 5 \\
        --resume

Resume semantics: re-reads the output file on startup, indexes by
(source_repo, source_path, match_offset), and skips queries that would
re-produce records already seen. Safe to kill and restart.

Rate limiting: GitHub code search API caps at 30 req/min for authenticated
clients. This script sleeps 2.1s between calls and backs off exponentially
on 403/429.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from urllib import error, parse, request


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO_ROOT / "data" / "external" / "literal_vs_referenced" / "scraped.jsonl"
DEFAULT_BANLIST = REPO_ROOT / "data" / "external" / "literal_vs_referenced" / "banlist_repos.txt"

GITHUB_API = "https://api.github.com"
GITHUB_RAW = "https://raw.githubusercontent.com"
USER_AGENT = "truffler-v0p13-scraper/1.0"

# Code-search rate limit is 30/min for authenticated clients. 2.1s = ~28/min,
# leaves headroom for occasional retries without hitting the cap.
MIN_INTERVAL_SECONDS = 2.1
# Per-file content fetches use the higher 5000/hr REST rate limit, so we
# don't need to throttle them as hard. 0.2s pads against burstiness.
CONTENT_FETCH_INTERVAL = 0.2

# Snippet window — matches Snaffler's match-context shape so the classifier
# trains on the same input distribution it will see at inference time.
SNIPPET_WINDOW = 500
SNIPPET_HALF = SNIPPET_WINDOW // 2

# Hard cap on per-file content fetches. Large files (binaries, minified bundles)
# rarely contain credential signal worth labeling.
MAX_FILE_BYTES = 200 * 1024


# ---------------------------------------------------------------------------
# Labeler regex patterns
#
# Two stages:
#   1. POSITIVE_PATTERNS extract a literal value if one is present. If the
#      value is non-empty, length >= 6, and not on the placeholder denylist,
#      the match is labeled "literal".
#   2. Otherwise NEGATIVE_SUBTYPE_PATTERNS run in order; first hit wins
#      and assigns the subtype. If none match but the regex still fired,
#      default subtype is "variable_reference".
#
# All patterns are applied to file content. The "matched_text" for the
# output record is the regex match itself (group 0); for positives we
# additionally extract group 1 as "literal_value".
# ---------------------------------------------------------------------------

@dataclass
class Pattern:
    name: str
    regex: re.Pattern
    extension: str | None = None  # None = applies to all

POSITIVE_PATTERNS = [
    Pattern(
        "ps_single_quote",
        re.compile(r"""\$?[Pp]asswo?r?d\s*=\s*'([^'$%`(){}\s][^']{4,})'"""),
        extension="ps1",
    ),
    Pattern(
        "ps_double_quote",
        re.compile(r'''\$?[Pp]asswo?r?d\s*=\s*"([^"$%`(){}\s<>][^"]{4,})"'''),
        extension="ps1",
    ),
    Pattern(
        "bat_set_password",
        re.compile(r"""set\s+\w*[Pp]asswo?r?d\w*=([^\s%$"<>][^\s%$"<>]{4,})""", re.IGNORECASE),
        extension="bat",
    ),
    Pattern(
        "xml_password_tag",
        re.compile(r"""<\w*[Pp]asswo?r?d\w*>([^<>${}%\s][^<>]{4,})</"""),
        extension="xml",
    ),
    Pattern(
        "sql_password_literal",
        re.compile(r"""PASSWORD\s*=\s*'([^'$%`{}][^']{4,})'"""),
    ),
    Pattern(
        "yaml_password_kv",
        re.compile(r"""(?:password|passwd|pwd)\s*:\s*['"]?([^\s'"$%`{}<>][^\s'"#]{5,})['"]?""", re.IGNORECASE),
    ),
]

# Placeholder denylist — case-insensitive substring match against extracted
# literal_value. If any token appears in the candidate literal, we treat it
# as a placeholder, not a real credential, and reject the positive label.
# Goal: prevent autogenerated templates and CI fixtures (which are common on
# github) from poisoning the literal class.
PLACEHOLDER_DENYLIST = [
    "change_me", "changeme", "change-me",
    "your_password", "yourpassword", "your-password",
    "password_here", "passwordhere",
    "password123", "password1234",
    "passw0rd", "p@ssw0rd",
    "xxxxxxxx", "xxxxxx", "xxxxx",
    "********", "******",
    "placeholder", "example", "default",
    "sample", "template", "demo",
    "secret_here", "secretvalue",
    "redacted", "deleted", "scrubbed", "sensitive",
    "data_deleted", "data-deleted",
    "your_secret", "your-secret",
    "fillmein", "fill_me_in",
    "todo", "fixme",
    "<password>", "<pass>", "<pwd>",
    "{{password", "{password}", "${password",
    "abc123", "12345678",
    "qwerty",
]

NEGATIVE_SUBTYPE_PATTERNS = [
    # documentation_example — match falls inside or directly references a
    # documentation construct. Heuristic: check the snippet window contains
    # any of these markers within ~150 chars of the match.
    Pattern(
        "doc_example_block",
        re.compile(r"\.EXAMPLE\b", re.IGNORECASE),
    ),
    Pattern(
        "doc_ps_comment_block",
        re.compile(r"<#[\s\S]{0,1500}?#>"),
    ),
    Pattern(
        "doc_md_code_fence",
        re.compile(r"```[\s\S]{0,1500}?```"),
    ),
    Pattern(
        "doc_synopsis",
        re.compile(r"\.SYNOPSIS\b|\.DESCRIPTION\b|\.NOTES\b", re.IGNORECASE),
    ),

    # parameter_declaration — match is inside a function signature or param
    # block. Look backward in the snippet for `param(` or `function ... [`
    # that hasn't been closed yet.
    Pattern(
        "param_block",
        re.compile(r"param\s*\([^)]{0,500}[Pp]assw", re.IGNORECASE),
    ),
    Pattern(
        "function_signature",
        re.compile(r"function\s+\w+[^{(]{0,200}[Pp]assw", re.IGNORECASE),
    ),
    Pattern(
        "type_annotated_param",
        re.compile(r"\[(?:SecureString|PSCredential|string|System\.String)\]\s*\$\w*[Pp]assw", re.IGNORECASE),
    ),

    # regex_template — the match itself contains regex metachars or template
    # syntax, indicating the file is itself a pattern definition, not an
    # actual credential.
    Pattern(
        "regex_metachars",
        re.compile(r"passw\?o\?r\?d|password\\s|password\.\*|\[Pp\]asswo\?r\?d"),
    ),
    Pattern(
        "template_braces",
        re.compile(r"password\s*[=:]\s*['\"]?\{\{|password\s*[=:]\s*['\"]?\$\{"),
    ),
]


# Heuristic: variable_reference is the catch-all when a password regex
# fires but no literal extraction succeeds and no subtype matches.
SIGIL_RE = re.compile(r'[\$%`]\w|\$\(|\$env:|\$\{|%[A-Z_]+%')


# ---------------------------------------------------------------------------
# Search queries
#
# Each query is a github code-search expression. We diversify across:
#   - Languages / extensions
#   - Positive-shape and negative-shape tokens
#   - Star count buckets (avoids the 1000-result-per-query cap and
#     prevents the result set from being dominated by a few mega-repos)
# ---------------------------------------------------------------------------

SEARCH_QUERIES: list[str] = [
    # PowerShell — likely-positive shapes
    '"Password = \'" extension:ps1',
    '"Password = \\"" extension:ps1',
    '"$Password = \'" extension:ps1',
    # PowerShell — likely-negative shapes (parameter / docs)
    '"-Password" extension:ps1',
    '".EXAMPLE" "password" extension:ps1',
    '"[SecureString]" "$Password" extension:ps1',
    '"param(" "Password" extension:ps1',
    '"<#" "password" extension:ps1',
    # PowerShell module variants
    '"password" extension:psm1',
    # CMD/BAT
    '"password=" extension:bat',
    '"set password=" extension:bat',
    '"password=" extension:cmd',
    '"net user" "password" extension:bat',
    '"schtasks" "/RP" extension:bat',
    # XML credential storage
    '"<Password>" extension:xml',
    '"<AdministratorPassword>" extension:xml',
    '"<DbPassword>" extension:xml',
    # SQL-style literal
    '"PASSWORD=\'" extension:sql',
    '"PASSWORD=\'" extension:xml',
    # YAML credential storage
    '"password:" extension:yml',
    '"password:" extension:yaml',
    '"db_password:" extension:yml',
    # ===== Top-up batch (2026-06-03) — distribution-gap targets =====
    # Windows enterprise XML configs — connection strings
    '"<ConnectionString>" extension:xml',
    '"<DbConnectionString>" extension:xml',
    '"providerConnectionString=" extension:xml',
    '"connectionString=" extension:config',
    '"<add" "password=" extension:config',
    # Java / .NET / Linux config formats
    '"password=" extension:properties',
    '"db.password=" extension:properties',
    '"password=" extension:ini',
    '"password=" extension:conf',
    '"password=" extension:cfg',
    # Secret / API key / token variants
    '"apiKey = \'" extension:ps1',
    '"secret = \'" extension:ps1',
    '"<APIKey>" extension:xml',
    '"<Secret>" extension:xml',
    '"<Token>" extension:xml',
    '"apiKey:" extension:yml',
    '"secret:" extension:yml',
    '"access_token:" extension:yml',
    # OAuth / cloud literals
    '"oauth_token = \'" extension:ps1',
    '"client_secret = \'" extension:ps1',
    '"aws_secret_access_key = \'" extension:ps1',
    # Python / Ruby / PHP literals
    '"password = \'" extension:py',
    '"PASSWORD = \'" extension:py',
    '"password: \'" extension:rb',
    # PHP define and array shapes
    '"define(\'DB_PASSWORD\'" extension:php',
    '"\'password\' => \'" extension:php',
    # Tomcat / Java app-server credential XML
    '"<user " "password=" extension:xml',
    # Memcache / Redis / generic key-value formats
    '"requirepass " extension:conf',
    # Shell scripts (added during scrape audit; KeepShellScriptCredentials.toml empty upstream)
    '"PASSWORD=\\"" extension:sh',
    '"export PASSWORD=" extension:sh',
]


# ---------------------------------------------------------------------------
# GitHub client
# ---------------------------------------------------------------------------

class GitHubClient:
    def __init__(self, token: str):
        self.token = token
        self._last_search_at = 0.0
        self._last_content_at = 0.0

    def _wait(self, last_at: float, min_interval: float) -> float:
        elapsed = time.time() - last_at
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        return time.time()

    def _request(self, url: str, *, max_retries: int = 5) -> dict | bytes:
        """GET a URL with auth header + retry + exponential backoff.

        Returns parsed JSON for application/json responses, raw bytes otherwise.
        """
        req = request.Request(url, headers={
            "User-Agent": USER_AGENT,
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        backoff = 30
        for attempt in range(max_retries):
            try:
                with request.urlopen(req, timeout=30) as resp:
                    body = resp.read()
                    ctype = resp.headers.get("Content-Type", "")
                    if "application/json" in ctype:
                        return json.loads(body)
                    return body
            except error.HTTPError as e:
                if e.code in (403, 429):
                    # rate-limit or abuse-detection — back off hard
                    reset = e.headers.get("X-RateLimit-Reset")
                    wait_s = backoff
                    if reset:
                        try:
                            wait_s = max(backoff, int(reset) - int(time.time()) + 5)
                        except ValueError:
                            pass
                    print(f"  [rate-limit] {e.code} — sleeping {wait_s}s", file=sys.stderr)
                    time.sleep(min(wait_s, 600))
                    backoff = min(backoff * 2, 300)
                    continue
                if e.code in (502, 503, 504):
                    print(f"  [server-error] {e.code} — retry {attempt+1}", file=sys.stderr)
                    time.sleep(5 * (attempt + 1))
                    continue
                if e.code == 404:
                    return {}
                raise
            except (error.URLError, TimeoutError) as e:
                print(f"  [network] {e} — retry {attempt+1}", file=sys.stderr)
                time.sleep(5 * (attempt + 1))
        raise RuntimeError(f"max retries exceeded for {url}")

    def search_code(self, query: str, page: int = 1) -> dict:
        self._last_search_at = self._wait(self._last_search_at, MIN_INTERVAL_SECONDS)
        url = (
            f"{GITHUB_API}/search/code"
            f"?q={parse.quote(query)}"
            f"&per_page=100"
            f"&page={page}"
        )
        result = self._request(url)
        return result if isinstance(result, dict) else {}

    def fetch_content(self, repo: str, path: str, ref: str) -> str | None:
        """Fetch file content via raw.githubusercontent.com (avoids the
        REST contents endpoint's 1MB limit). Returns decoded text or None
        on size/decode failure."""
        self._last_content_at = self._wait(self._last_content_at, CONTENT_FETCH_INTERVAL)
        encoded_path = "/".join(parse.quote(p) for p in path.split("/"))
        url = f"{GITHUB_RAW}/{repo}/{ref}/{encoded_path}"
        try:
            body = self._request(url)
        except Exception as e:
            print(f"  [content] {repo}/{path}: {e}", file=sys.stderr)
            return None
        if isinstance(body, dict):
            return None
        if len(body) > MAX_FILE_BYTES:
            return None
        try:
            return body.decode("utf-8", errors="replace")
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Labeler
# ---------------------------------------------------------------------------

@dataclass
class LabeledSnippet:
    snippet: str
    label: str
    subtype: str | None
    matched_pattern: str
    match_offset: int
    matched_text: str
    literal_value: str | None
    source_repo: str
    source_path: str
    source_sha: str
    file_extension: str
    scraped_at: str


def _extract_snippet(content: str, match_start: int, match_end: int) -> tuple[str, int]:
    """Return (snippet, match_offset_within_snippet)."""
    center = (match_start + match_end) // 2
    left = max(0, center - SNIPPET_HALF)
    right = min(len(content), left + SNIPPET_WINDOW)
    # Re-anchor left if right hit content end, to keep snippet at full width.
    left = max(0, right - SNIPPET_WINDOW)
    snippet = content[left:right]
    return snippet, match_start - left


def _looks_like_placeholder(literal: str) -> bool:
    low = literal.lower()
    for tok in PLACEHOLDER_DENYLIST:
        if tok in low:
            return True
    return False


def _detect_subtype(snippet: str) -> str:
    """Apply NEGATIVE_SUBTYPE_PATTERNS in order against the snippet window.

    Returns the first matching subtype name, or 'variable_reference' if
    none match (catch-all when a password pattern fires but no structural
    marker is detected)."""
    for pat in NEGATIVE_SUBTYPE_PATTERNS:
        if pat.regex.search(snippet):
            # Map pattern name → subtype category
            if pat.name.startswith("doc_"):
                return "documentation_example"
            if pat.name in ("param_block", "function_signature", "type_annotated_param"):
                return "parameter_declaration"
            if pat.name in ("regex_metachars", "template_braces"):
                return "regex_template"
    # No explicit subtype matched — if the snippet contains variable sigils
    # near the match, call it variable_reference. Otherwise still call it
    # variable_reference as the default negative (most common shape).
    return "variable_reference"


def label_file(
    content: str,
    extension: str,
    repo: str,
    path: str,
    sha: str,
) -> Iterator[LabeledSnippet]:
    now = datetime.now(timezone.utc).isoformat()
    seen_offsets: set[int] = set()

    # First pass: try positive patterns. Each match is a candidate literal.
    for pat in POSITIVE_PATTERNS:
        if pat.extension is not None and pat.extension != extension:
            continue
        for m in pat.regex.finditer(content):
            if m.start() in seen_offsets:
                continue
            seen_offsets.add(m.start())
            literal = m.group(1) if m.groups() else ""
            if not literal or len(literal) < 6:
                continue
            if _looks_like_placeholder(literal):
                # Same regex would have fired — but the value is a
                # placeholder. Re-label as referenced with documentation_example
                # subtype (templates ARE documentation, structurally).
                snippet, offset = _extract_snippet(content, m.start(), m.end())
                yield LabeledSnippet(
                    snippet=snippet,
                    label="referenced",
                    subtype="documentation_example",
                    matched_pattern=pat.name,
                    match_offset=offset,
                    matched_text=m.group(0)[:200],
                    literal_value=None,
                    source_repo=repo,
                    source_path=path,
                    source_sha=sha,
                    file_extension=extension,
                    scraped_at=now,
                )
                continue
            snippet, offset = _extract_snippet(content, m.start(), m.end())
            yield LabeledSnippet(
                snippet=snippet,
                label="literal",
                subtype=None,
                matched_pattern=pat.name,
                match_offset=offset,
                matched_text=m.group(0)[:200],
                literal_value=literal[:200],
                source_repo=repo,
                source_path=path,
                source_sha=sha,
                file_extension=extension,
                scraped_at=now,
            )

    # Second pass: find password-shaped tokens that POSITIVE_PATTERNS didn't
    # capture (compound forms, variable sigils, parameter flags). We deliberately
    # drop word boundaries: Snaffler fires on substrings like "SSLPassword" and
    # "BoxstarterPassword" inside compound identifiers, and the training corpus
    # needs to mirror that distribution.
    NEGATIVE_TRIGGER = re.compile(r"""[Pp]asswo?r?d|PASSWORD""")
    per_file_negative_cap = 3  # prevent verbose tutorial files dominating the corpus
    n_negatives_emitted = 0
    for m in NEGATIVE_TRIGGER.finditer(content):
        if n_negatives_emitted >= per_file_negative_cap:
            break
        # Skip if this match is within an existing literal-pattern offset window
        if any(abs(m.start() - o) < 50 for o in seen_offsets):
            continue
        seen_offsets.add(m.start())
        snippet, offset = _extract_snippet(content, m.start(), m.end())
        subtype = _detect_subtype(snippet)
        yield LabeledSnippet(
            snippet=snippet,
            label="referenced",
            subtype=subtype,
            matched_pattern="negative_trigger",
            match_offset=offset,
            matched_text=m.group(0)[:200],
            literal_value=None,
            source_repo=repo,
            source_path=path,
            source_sha=sha,
            file_extension=extension,
            scraped_at=now,
        )
        n_negatives_emitted += 1


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def load_existing_keys(output_path: Path) -> tuple[set[tuple[str, str, int]], dict[str, int], int, int, int]:
    """Re-read existing output to support --resume. Returns:
        * seen: set of (repo, path, match_offset) tuples already emitted
        * per_repo_counts: how many snippets per repo
        * n_literal, n_referenced, n_total
    """
    seen: set[tuple[str, str, int]] = set()
    per_repo: dict[str, int] = defaultdict(int)
    n_literal = n_referenced = n_total = 0
    if not output_path.exists():
        return seen, per_repo, 0, 0, 0
    with output_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            key = (rec["source_repo"], rec["source_path"], rec["match_offset"])
            seen.add(key)
            per_repo[rec["source_repo"]] += 1
            if rec["label"] == "literal":
                n_literal += 1
            else:
                n_referenced += 1
            n_total += 1
    return seen, per_repo, n_literal, n_referenced, n_total


def load_banlist(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {
        line.strip().lower()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }


# ---------------------------------------------------------------------------
# Main scrape loop
# ---------------------------------------------------------------------------

def scrape(
    client: GitHubClient,
    output_path: Path,
    queries: list[str],
    target_snippets: int,
    max_per_repo: int,
    banlist: set[str],
) -> None:
    seen, per_repo_counts, n_literal, n_referenced, n_total = load_existing_keys(output_path)
    print(
        f"[init] Resuming with {n_total} existing snippets "
        f"(literal={n_literal}, referenced={n_referenced})",
        file=sys.stderr,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    out_fh = output_path.open("a", encoding="utf-8")

    snippet_hashes: set[str] = set()  # global dedup against fork copies

    def _hash(rec: LabeledSnippet) -> str:
        h = hashlib.sha256()
        h.update(rec.snippet.encode("utf-8", errors="replace"))
        return h.hexdigest()[:16]

    try:
        for q_idx, query in enumerate(queries):
            print(f"\n[query {q_idx+1}/{len(queries)}] {query}", file=sys.stderr)
            for page in range(1, 11):  # github code search caps at 1000 results
                if n_total >= target_snippets:
                    print(f"[done] hit target {target_snippets}", file=sys.stderr)
                    return
                try:
                    result = client.search_code(query, page=page)
                except Exception as e:
                    print(f"  [search error] page {page}: {e}", file=sys.stderr)
                    break
                items = result.get("items", [])
                if not items:
                    break
                for item in items:
                    if n_total >= target_snippets:
                        return
                    repo = item.get("repository", {}).get("full_name", "")
                    if not repo or repo.lower() in banlist:
                        continue
                    if per_repo_counts[repo] >= max_per_repo:
                        continue
                    path = item.get("path", "")
                    sha = item.get("sha", "")
                    if not path or not sha:
                        continue
                    ext_match = re.search(r"\.([a-zA-Z0-9]+)$", path)
                    if not ext_match:
                        continue
                    extension = ext_match.group(1).lower()
                    ref = item.get("repository", {}).get("default_branch", "master")
                    content = client.fetch_content(repo, path, ref)
                    if content is None:
                        continue
                    # Run labeler over this file
                    for rec in label_file(content, extension, repo, path, sha):
                        if (rec.source_repo, rec.source_path, rec.match_offset) in seen:
                            continue
                        h = _hash(rec)
                        if h in snippet_hashes:
                            continue  # fork dedup
                        snippet_hashes.add(h)
                        seen.add((rec.source_repo, rec.source_path, rec.match_offset))
                        per_repo_counts[repo] += 1
                        if rec.label == "literal":
                            n_literal += 1
                        else:
                            n_referenced += 1
                        n_total += 1
                        out_fh.write(json.dumps(asdict(rec)) + "\n")
                        out_fh.flush()
                        if per_repo_counts[repo] >= max_per_repo:
                            break
                print(
                    f"  page {page}: cumulative {n_total} "
                    f"({n_literal} literal, {n_referenced} referenced)",
                    file=sys.stderr,
                )
    finally:
        out_fh.close()
        print(
            f"\n[final] {n_total} snippets "
            f"(literal={n_literal}, referenced={n_referenced})",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    p.add_argument(
        "--target-snippets", type=int, default=80000,
        help="Stop once this many labeled snippets have been written (default: 80000)",
    )
    p.add_argument(
        "--max-per-repo", type=int, default=5,
        help="Cap snippets per repo to prevent one big repo from dominating (default: 5)",
    )
    p.add_argument(
        "--banlist", type=Path, default=DEFAULT_BANLIST,
        help="Newline-delimited file of repos (owner/name) to skip",
    )
    p.add_argument(
        "--queries-file", type=Path, default=None,
        help="Optional newline-delimited file of additional search queries",
    )
    p.add_argument(
        "--resume", action="store_true", default=True,
        help="(default) Resume from existing output file",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("ERROR: set GITHUB_TOKEN env var (github PAT with public_repo scope)",
              file=sys.stderr)
        return 1
    queries = list(SEARCH_QUERIES)
    if args.queries_file and args.queries_file.exists():
        for line in args.queries_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                queries.append(line)
    banlist = load_banlist(args.banlist)
    if banlist:
        print(f"[init] {len(banlist)} repos on banlist", file=sys.stderr)
    client = GitHubClient(token)
    scrape(
        client=client,
        output_path=args.output,
        queries=queries,
        target_snippets=args.target_snippets,
        max_per_repo=args.max_per_repo,
        banlist=banlist,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
