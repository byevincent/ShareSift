"""GitHub Code Search → real-Windows-path candidates for the eval set.

Collects real enterprise UNC/Windows paths from publicly-committed code
on GitHub via the documented REST code-search API, normalizes and
dedups them, drops obvious placeholders, and writes a CSV that
``build_queue.py`` can consume directly.

The tool PROPOSES candidates. It is not authoritative — pre-categorization
and the labeler's review-while-labeling are what turn a candidate into a
labeled eval record. This module deliberately does NOT pre-judge juiciness
or category; that's the labeler's job.

Auth
----
Requires a classic personal access token in env var ``TRUFFLER_GITHUB_TOKEN``.
Scope: ``public_repo`` only. Fine-grained PATs are NOT supported by GitHub's
code-search endpoint at the time of writing; classic PAT only. Fail-fast at
startup if the env var is missing.

Rate-limit handling
-------------------
The code-search API has a custom limit: 10 requests/minute, authenticated.
Pagination counts as separate requests against the same budget.
Implementation uses a **sliding-window deque** that tracks all recent
request timestamps and waits for the oldest in-window entry to age out
before exceeding ``_BUDGET_PER_WINDOW`` (9 per 60s; one under the hard
cap for clock-skew safety). Cached pages bypass the pacer — only actual
API calls register.

The server's ``X-RateLimit-Remaining`` header is the **authoritative
override**: read after every successful response, and if the server says
0–1 remaining, sleep until ``X-RateLimit-Reset`` + buffer regardless of
what the local deque thinks. This is what makes 9-per-60s safe vs
needing 8.

On 429 or 403-with-zero-remaining: sleep per ``X-RateLimit-Reset`` (primary
signal) or ``Retry-After`` (fallback), then retry. Up to
``_MAX_RATE_LIMIT_RETRIES`` (3) retries per page, then raise with the
query string and page number in the message. The caller in
``_search_one_query`` converts to ``_QueryFailedError``, which
``collect()`` catches at the per-query boundary and records in
``CollectResult.failed_queries`` — the run continues to the next query
rather than crashing. End-of-run summary lists every failed query so the
operator can see what didn't complete (never silently skipped). On
transient 5xx: exponential backoff with jitter, max 3 retries.

The original 6.5-seconds-fixed-spacing pacer + 1-retry budget was buggy:
pagination requests blew the per-minute cap because the pacer only
knew about the most recent single request, and exhausted retries
silently produced zero results because a 1-retry budget was too tight
against the actual reset window. Both surfaced on the first live run
and are fixed here with unit coverage.

Caching
-------
Raw API responses cache to ``data/eval/sources/github_cache/<query-hash>/page_N.json``
so extraction-logic iteration doesn't re-hit the API. Cache invalidates
on ``--refresh`` (wipes the affected query's cache and re-fetches).
Cache dir is gitignored. A human-readable ``manifest.json`` records
which queries were run when, with their total-count and page counts.

Query templates
---------------
Two design-intent tiers, organized in the constants below:

* **Idiom-based core** (high signal-to-noise): queries anchored on
  share-mapping operations (New-PSDrive, net use, robocopy, logon
  scripts, MapNetworkDrive, AD folder redirection, etc.). Paths surface
  in actual using-context.
* **Long-tail supplement** (lower S/N): share-purpose keywords
  (fileserver/nas/backup/scripts/common) co-occurring with UNC literal.
  Keep them — they do find paths the idiom queries miss — but expect
  more noise.

Industry-specific keywords are deliberately excluded: domain-specific
shares live in INTERNAL repos not on public GitHub, so generic
automation idioms out-yield them. That domain realism is what
Mandiant-provided engagement data will add later; it's not something
GitHub Code Search can give.

Extraction
----------
Regex extracts UNC paths from each result's text-match fragment,
filters out variable-interpolation candidates (``$server``,
``%COMPUTERNAME%``, ``{server}``), drops obviously-placeholder
hostnames (``\\\\server\\share``, ``\\\\SERVERNAME\\...``, RFC1918 IPs,
etc.), and dedups via the shared ``normalize_for_dedup`` so this
module can't disagree with ``build_queue`` or ``validate`` about path
identity.

Drive-path extraction was DROPPED in a post-first-live-run filter pass
— spot-check showed drive paths from public GitHub were dominantly
noise (``C:\\Windows``, ``C:\\Program Files``, registry exports
written with leading drive letter like ``M:\\Software\\Microsoft\\
Windows\\CurrentVersion``). The eval set targets enterprise SMB share
content, not local-machine filesystem content; UNC is the right
extraction target. Pinned by ``test_drive_paths_not_extracted`` so a
future revert is loud. Cascading benefit: dropping drive extraction
also eliminated the registry-shape-noise problem by construction
(registry paths formatted with leading drive letter no longer match
any extraction regex; UNC paths shaped like
``\\\\backup\\share\\registry-exports\\HKLM.reg`` ARE still extracted
because the share IS real-share-content signal).

Security/CTF repo filter (default ON)
-------------------------------------
After the existing filter chain, candidates are dropped if their
provenance URL or path matches known offensive-security/CTF
patterns. The "ironic-leak" problem: public GitHub was meant to escape
synthetic-lab bias, but the labs themselves are on GitHub. Filtering:

* **URL substring match** against ``_OFFENSIVE_SECURITY_URL_PATTERNS``
  — known repo-name patterns (poshc2, metasploit, meterpreter,
  meterpeter, mishky/mishkys, cobaltstrike, bloodhound, goad, sliver,
  havoc, etc.).
* **Path substring match** against ``_LAB_PATH_MARKERS`` — known
  unambiguous lab share/server names (marvel-dc, hackme, dreadgoad,
  vulnvm, etc.). Deliberately short and high-confidence to avoid
  over-filtering on generic enterprise terms (``titan`` and bare
  ``goad`` are NOT in the path-marker list — both are common enough
  in real names that filtering on them would kill real candidates).

End-of-run summary prints the drop count for visible auditing.
Override with ``--no-filter-security-repos`` if you want to inspect
the unfiltered output.

Note on backslash escaping: most code on GitHub written in PowerShell,
batch, cmd, ini, and config files uses LITERAL backslashes (no
escaping). The queries target those file types, and the extraction
regex assumes literal backslashes in fragments. C#/Java/JS files with
``"\\\\\\\\server\\\\share"``-style escaping would be missed —
acceptable for v0 since the query set targets the literal-backslash
languages.

CLI
---
**Strongly recommended:** run ``--dry-run`` first to preview the
query plan and estimated runtime before paying the rate-limit cost.

    python -m src.eval.source_github --dry-run --query-set v0
    python -m src.eval.source_github --query-set v0
    python -m src.eval.build_queue \\
        --input data/eval/sources/github_search_<timestamp>.csv \\
        --output data/eval/queue.jsonl \\
        --source-default github_search
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from src.eval._path_filters import (
    extract_linux_paths,
    extract_unc_paths,
    has_variable_interpolation,
    is_linux_too_short,
    is_offensive_security_provenance,
    is_placeholder_server,
    is_too_short,
)
from src.eval._paths import normalize_for_dedup

# ============================================================================
# Module constants
# ============================================================================

_PAT_ENV_VAR = "TRUFFLER_GITHUB_TOKEN"
_GITHUB_API_BASE = "https://api.github.com"
_SEARCH_CODE_PATH = "/search/code"

# Sliding-window rate-limit budget. Code search is hard-capped at 10
# requests/minute; we allow 9 to leave headroom for clock skew between
# our wall clock and GitHub's window boundary. The X-RateLimit-Remaining
# header read after each successful response is the authoritative
# override — if the server says 0, we wait until Reset regardless of
# what the local deque says.
_BUDGET_PER_WINDOW = 9
_WINDOW_SECONDS = 60.0

# When X-RateLimit-Remaining drops to this or below, proactively sleep
# until Reset+buffer before the next request. 1 (not 0) so we always
# have a safety margin even on tight-budget responses.
_LOW_REMAINING_THRESHOLD = 1
# Buffer added to every Reset-based sleep — absorbs clock skew between
# our wall clock and GitHub's reset timer. 5s is generous but cheap.
_RATE_LIMIT_BUFFER_SECONDS = 5

# Per-page rate-limit retry budget. The previous one-retry budget was
# too tight: if the retry also hit the limit (which happens when our
# wait was under-estimated against actual reset window), the query
# failed. Three retries × ~60s = ~3 min worst case per query.
_MAX_RATE_LIMIT_RETRIES = 3

_MAX_RETRIES_5XX = 3
_MAX_PAGES_PER_QUERY = 5  # was 10; first few pages carry highest-quality results
_PER_PAGE = 100

_DEFAULT_CACHE_DIR = Path("data/eval/sources/github_cache")
_DEFAULT_OUTPUT_DIR = Path("data/eval/sources")


# ============================================================================
# Query templates — V0
#
# Each entry is a literal GitHub code-search query as the API receives it.
# Raw strings (``r"..."``) used so backslashes in path literals stay raw —
# ``r'"\\"'`` is the 4-char Python string ``"\\"`` (3 chars after the
# opening quote: ``\``, ``\``, ``"``), which GitHub parses as the
# phrase-search for the two-backslash UNC prefix.
# ============================================================================

# Idiom-based high-signal core: paths surface in actual using-context
# (share-mapping operations, file-copy operations, AD-aware idioms). Each
# query is anchored on something a script DOES with a share, not just on
# share-name keyword co-occurrence. This is where the labeler gets the
# best yield-per-query.
_QUERY_TEMPLATES_V0_CORE: tuple[str, ...] = (
    # PowerShell share-mapping + file-ops
    r'"\\" "New-PSDrive" language:powershell',
    r'"\\" "Copy-Item" language:powershell',
    # File-copy idioms
    r'"\\" "robocopy"',
    r'"\\" "xcopy"',
    # Batch / cmd share-mapping
    r'"\\" "net use" extension:bat',
    r'"\\" "net use" extension:cmd',
    # Logon scripts — peak enterprise share-mapping locus
    r'"\\" "netlogon"',
    r'"\\" "logon" extension:bat',
    # Legacy enterprise scripting idioms
    r'"\\" "MapNetworkDrive"',
    r'"\\" "pushd"',
    # AD folder redirection → \\server\users$ paths
    r'"\\" "HomeDirectory"',
    r'"\\" "FolderRedirection"',
)

# Long-tail share-purpose keyword supplement: noisier (matches don't
# necessarily mean share-mapping context, just keyword co-occurrence)
# but does surface paths the idiom queries miss. Lower yield per query;
# kept for coverage breadth.
_QUERY_TEMPLATES_V0_LONG_TAIL: tuple[str, ...] = (
    r'"\\" "fileserver" extension:ps1',
    r'"\\" "fileserver" extension:bat',
    r'"\\" "fileshare" language:powershell',
    r'"\\" "nas" extension:ps1',
    r'"\\" "backup" extension:ps1',
    r'"\\" "scripts" extension:ps1',
    r'"\\" "common" extension:ps1',
)

# Config-file queries: UNC paths inside .config / .ini files land
# high-quality candidates. The connectionString variant is a high-value
# overlap region (UNC adjacent to credentials in the same file).
_QUERY_TEMPLATES_V0_CONFIG: tuple[str, ...] = (
    r'"\\" extension:config',
    r'"\\" extension:ini',
    r'"\\" extension:config "connectionString"',
)

# AD-adjacent contexts: explicitly-AD-aware code that mentions UNC.
_QUERY_TEMPLATES_V0_AD: tuple[str, ...] = (
    r'"\\" "SYSVOL"',
    r'"\\" "domain controller" extension:ps1',
)

_QUERY_TEMPLATES_V0: tuple[str, ...] = (
    _QUERY_TEMPLATES_V0_CORE
    + _QUERY_TEMPLATES_V0_LONG_TAIL
    + _QUERY_TEMPLATES_V0_CONFIG
    + _QUERY_TEMPLATES_V0_AD
)


# ============================================================================
# Linux query templates (added v0.5 for Linux corpus expansion)
#
# Mirrors the UNC sets' structure: high-signal idiom queries first, then
# broader keyword/config-context queries. Each query is anchored on a
# concrete Linux path likely to appear in actual scripts/configs (not
# documentation prose). Path-search filters (``path:*.sh``,
# ``extension:env``) bias toward executable/config content where pen-
# test-relevant paths actually surface.
#
# Coverage spans: SSH keys/configs, cloud credentials, shell histories,
# /etc service configs, app secrets in /opt and /srv, and /var/log
# state files. Excluded: package-manager state, kernel pseudo-fs paths
# (caught at extraction time by LINUX_PATH_RE's root allowlist).
# ============================================================================

# Credential/key files — highest yield-per-query bucket.
_QUERY_TEMPLATES_V0_LINUX_CREDENTIALS: tuple[str, ...] = (
    r'"/etc/shadow" extension:sh',
    r'"/etc/sudoers" extension:conf',
    r'"~/.ssh/id_rsa"',
    r'"~/.ssh/id_ed25519"',
    r'"~/.ssh/authorized_keys" extension:sh',
    r'"~/.aws/credentials"',
    r'"~/.aws/config" extension:sh',
    r'"~/.kube/config" extension:yaml',
    r'"~/.docker/config.json"',
    r'"~/.netrc"',
)

# Service / app configs — UNC's _QUERY_TEMPLATES_V0_CONFIG analogue.
_QUERY_TEMPLATES_V0_LINUX_CONFIG: tuple[str, ...] = (
    r'"/etc/mysql/" "password" extension:cnf',
    r'"/etc/postgresql/" "password"',
    r'"/etc/nginx/" extension:conf',
    r'"/etc/apache2/" extension:conf',
    r'"/opt/" "secret" extension:env',
    r'"/opt/" "api_key" extension:yml',
    r'"/srv/" "password" extension:yaml',
    r'"/var/www/" extension:env',
)

# Logs and shell state — distinct context where Linux paths appear.
_QUERY_TEMPLATES_V0_LINUX_STATE: tuple[str, ...] = (
    r'"/var/log/auth.log"',
    r'"/var/log/secure"',
    r'"/root/.bash_history"',
    r'"~/.bash_history"',
    r'"~/.zsh_history"',
)

# Broader secret-hunt patterns — noisier but catch idioms the targeted
# queries miss (e.g. inline `export PASSWORD=` in /etc scripts).
_QUERY_TEMPLATES_V0_LINUX_BROAD: tuple[str, ...] = (
    r'"export PASSWORD=" "/etc/"',
    r'"BEGIN OPENSSH PRIVATE KEY" "~/.ssh/"',
)

_QUERY_TEMPLATES_V0_LINUX: tuple[str, ...] = (
    _QUERY_TEMPLATES_V0_LINUX_CREDENTIALS
    + _QUERY_TEMPLATES_V0_LINUX_CONFIG
    + _QUERY_TEMPLATES_V0_LINUX_STATE
    + _QUERY_TEMPLATES_V0_LINUX_BROAD
)


_QUERY_SETS: dict[str, tuple[str, ...]] = {
    "v0": _QUERY_TEMPLATES_V0,
    "linux": _QUERY_TEMPLATES_V0_LINUX,
}


# ============================================================================
# Path extraction and filter primitives are imported from
# ``_path_filters`` so this module and ``source_stackexchange`` share a
# single source of truth for the UNC regex, placeholder denylist, and
# security/CTF filter. See ``_path_filters`` for the constants and
# functions used below in ``collect()``.
# ============================================================================


# ============================================================================
# Candidate dataclass — the unit yielded by `collect()`
# ============================================================================


@dataclass(frozen=True)
class Candidate:
    """One extracted-and-filtered UNC path with its GitHub provenance URL.

    ``path`` is the raw extracted UNC path, pre-normalization — the CSV
    writes the path as found so the labeler sees the actual casing/form
    from the source file. Dedup uses ``normalize_for_dedup`` internally
    so case-variants collapse to one Candidate without losing the
    original form.

    ``provenance_url`` is the file's GitHub HTML URL (not line-anchored,
    since text_matches doesn't give a stable line URL). Useful for
    labeler review-while-labeling: click through, ctrl-F the path to
    see the surrounding code.
    """

    path: str
    provenance_url: str


@dataclass(frozen=True)
class FailedQuery:
    """One query that exhausted its rate-limit retry budget. Recorded by
    ``collect()`` and surfaced in the end-of-run summary so the operator
    can see which queries didn't complete and re-run them later.

    Never silent — this is the load-bearing fix from the first live run,
    where rate-limit exhaustion was silently dropping queries to zero
    results. Failure is reported, not swallowed.
    """

    query: str
    failed_at_page: int
    reason: str


@dataclass
class CollectResult:
    """Per-run output: deduped candidates + the list of any queries
    that failed after retries + the count of candidates dropped by the
    security/CTF filter. ``main()`` writes the CSV from ``candidates``
    and prints a stderr summary listing ``failed_queries`` and the
    drop count (so the filter isn't silent — operator can audit
    over-filtering)."""

    candidates: list[Candidate] = field(default_factory=list)
    failed_queries: list[FailedQuery] = field(default_factory=list)
    dropped_security_count: int = 0


class _QueryFailedError(Exception):
    """Raised by ``_search_one_query`` when ``_fetch_search_page``
    exhausts its rate-limit retry budget. Caught only at the per-query
    boundary in ``collect()`` so a single bad query doesn't crash the
    whole run."""

    def __init__(self, page: int, reason: str):
        super().__init__(f"failed at page {page}: {reason}")
        self.page = page
        self.reason = reason


# ============================================================================
# Auth — PAT read from env, fail-fast on absence
# ============================================================================


def _read_pat() -> str:
    """Read the PAT from ``TRUFFLER_GITHUB_TOKEN``; raise if missing.

    Project-specific env var name to avoid clashing with the ``gh`` CLI
    or other tools that read ``GITHUB_TOKEN`` / ``GH_TOKEN``. Fails
    fast so the operator gets a clear setup message rather than a
    cryptic 401 mid-run.
    """
    pat = os.environ.get(_PAT_ENV_VAR)
    if not pat:
        raise RuntimeError(
            f"Environment variable {_PAT_ENV_VAR} not set. Create a classic "
            f"personal access token at github.com/settings/tokens with the "
            f"'public_repo' scope and export it: "
            f"export {_PAT_ENV_VAR}=ghp_..."
        )
    return pat


# ============================================================================
# Cache layer — disk-backed raw response storage
# ============================================================================


def _query_hash(query: str) -> str:
    """12-char hex prefix of SHA-256(query) — short enough for dir names,
    long enough to avoid practical collisions across the small query
    counts we'll have."""
    return hashlib.sha256(query.encode("utf-8")).hexdigest()[:12]


def _cache_path_for(query: str, page: int, cache_dir: Path) -> Path:
    return cache_dir / _query_hash(query) / f"page_{page}.json"


def _load_cached(query: str, page: int, cache_dir: Path) -> dict | None:
    path = _cache_path_for(query, page, cache_dir)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        # Cache corruption: treat as miss; next fetch will overwrite.
        return None


def _save_cached(query: str, page: int, body: dict, cache_dir: Path) -> None:
    path = _cache_path_for(query, page, cache_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body, indent=2), encoding="utf-8")


def _wipe_query_cache(query: str, cache_dir: Path) -> None:
    """Remove all cached pages for a query (used by --refresh)."""
    qdir = cache_dir / _query_hash(query)
    if qdir.exists():
        for f in qdir.iterdir():
            f.unlink()
        qdir.rmdir()


def _update_manifest(
    query: str,
    pages_fetched: int,
    total_count: int,
    cache_dir: Path,
    *,
    status: str = "completed",
    error: str | None = None,
) -> None:
    """Atomic manifest update — humans grep this to see what was queried
    when, how many results each query returned, and which queries
    failed after retries.

    ``status`` is ``"completed"`` for normal success or
    ``"failed_after_retries"`` when ``_fetch_search_page`` exhausts
    rate-limit retries. ``error`` carries the failure reason for the
    failed case (page number + retry-exhausted message) so the operator
    can grep ``manifest.json`` for which queries to re-run.
    """
    manifest_path = cache_dir / "manifest.json"
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            manifest = {"queries": {}}
    else:
        manifest = {"queries": {}}
    manifest.setdefault("queries", {})
    entry = {
        "query": query,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "pages_fetched": pages_fetched,
        "total_count": total_count,
        "status": status,
    }
    if error:
        entry["error"] = error
    manifest["queries"][_query_hash(query)] = entry
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = manifest_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, manifest_path)


# ============================================================================
# Rate-limit-aware HTTP — sliding-window pacing + Reset-honoring backoff
#
# The original 6.5s-fixed-spacing pacer assumed 1 request per query, but
# pagination means a single query fires multiple requests in close
# succession. Worse, the API's per-minute window doesn't align with our
# run start — a run that starts mid-window has less budget than the
# steady-state math predicts. The sliding-window deque below tracks
# actual request density and waits for the oldest in-window entry to
# age out before exceeding budget.
#
# The X-RateLimit-Remaining header read from each successful response
# is the AUTHORITATIVE override — the server's view of the budget is
# what matters. If it drops to _LOW_REMAINING_THRESHOLD or below, we
# proactively sleep until Reset+buffer before the next request,
# regardless of what the local deque thinks.
# ============================================================================

# Timestamps of recent API requests, used by the sliding-window pacer.
# Module-global because the rate limit applies process-wide.
_REQUEST_TIMESTAMPS: deque[float] = deque()


def _evict_aged_request_timestamps(now: float) -> None:
    """Drop entries older than _WINDOW_SECONDS from the front."""
    while _REQUEST_TIMESTAMPS and now - _REQUEST_TIMESTAMPS[0] > _WINDOW_SECONDS:
        _REQUEST_TIMESTAMPS.popleft()


def _wait_for_rate_limit() -> None:
    """Sliding-window rate limiter: ensure no more than
    ``_BUDGET_PER_WINDOW`` requests in any ``_WINDOW_SECONDS`` interval.

    Cached pages bypass this — only callers that hit the actual API
    call this function. Module-global ``_REQUEST_TIMESTAMPS`` deque
    tracks actual request density across the whole run, so pagination
    requests count against the same budget as new-query requests
    (the fix for bug 1).
    """
    now = time.time()
    _evict_aged_request_timestamps(now)
    if len(_REQUEST_TIMESTAMPS) >= _BUDGET_PER_WINDOW:
        oldest = _REQUEST_TIMESTAMPS[0]
        sleep_for = (oldest + _WINDOW_SECONDS) - now + 1.0
        if sleep_for > 0:
            print(
                f"  rate budget reached ({_BUDGET_PER_WINDOW}/"
                f"{_WINDOW_SECONDS:.0f}s); sleeping {sleep_for:.1f}s",
                file=sys.stderr,
            )
            time.sleep(sleep_for)
            now = time.time()
            _evict_aged_request_timestamps(now)
    _REQUEST_TIMESTAMPS.append(time.time())


def _honor_remaining_header(headers) -> None:
    """If the response's ``X-RateLimit-Remaining`` is at or below
    ``_LOW_REMAINING_THRESHOLD``, proactively sleep until
    ``X-RateLimit-Reset`` + buffer.

    The server's view of budget is authoritative and is what makes
    9-per-60s safe (vs needing 8): even if our deque thinks we have
    budget, if the server says 0 we respect that. No-op if either
    header is absent or unparseable.
    """
    remaining_str = headers.get("X-RateLimit-Remaining") if headers else None
    reset_str = headers.get("X-RateLimit-Reset") if headers else None
    if not remaining_str or not reset_str:
        return
    try:
        remaining = int(remaining_str)
        reset = int(reset_str)
    except (TypeError, ValueError):
        return
    if remaining > _LOW_REMAINING_THRESHOLD:
        return
    sleep_for = max(0, reset - int(time.time())) + _RATE_LIMIT_BUFFER_SECONDS
    if sleep_for > 0:
        print(
            f"  X-RateLimit-Remaining={remaining}; sleeping {sleep_for}s "
            f"until reset (server's view of budget is authoritative)",
            file=sys.stderr,
        )
        time.sleep(sleep_for)


def _fetch_search_page(query: str, page: int, pat: str) -> dict:
    """One API call. Handles rate-limit responses (429 / 403-with-zero-
    remaining) with ``_MAX_RATE_LIMIT_RETRIES`` retries honoring
    ``X-RateLimit-Reset`` + buffer, and transient 5xx with exponential
    backoff.

    Raises ``RuntimeError`` after all rate-limit retries exhaust, with
    the query and page in the message. Caller (``_search_one_query``)
    converts to ``_QueryFailedError`` for per-query graceful failure
    handling — the run continues to the next query rather than
    crashing.
    """
    params = urllib.parse.urlencode({"q": query, "per_page": _PER_PAGE, "page": page})
    url = f"{_GITHUB_API_BASE}{_SEARCH_CODE_PATH}?{params}"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {pat}",
            "Accept": "application/vnd.github.text-match+json",
            "User-Agent": "sharesift-source-github/0.0",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )

    rate_limit_retries = 0
    fivexx_attempt = 0
    while True:
        _wait_for_rate_limit()
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = json.loads(resp.read())
                _honor_remaining_header(resp.headers)
                return body
        except urllib.error.HTTPError as e:
            sleep_for = _rate_limit_sleep_seconds(e)
            if sleep_for is not None:
                if rate_limit_retries >= _MAX_RATE_LIMIT_RETRIES:
                    raise RuntimeError(
                        f"rate-limit exhausted after {_MAX_RATE_LIMIT_RETRIES} "
                        f"retries for query {query!r} page {page}"
                    ) from e
                rate_limit_retries += 1
                print(
                    f"  rate-limit hit (retry {rate_limit_retries}/"
                    f"{_MAX_RATE_LIMIT_RETRIES}); sleeping {sleep_for}s",
                    file=sys.stderr,
                )
                time.sleep(sleep_for)
                continue
            if 500 <= e.code < 600:
                if fivexx_attempt < _MAX_RETRIES_5XX:
                    backoff = (4**fivexx_attempt) + random.uniform(0, 1)
                    print(
                        f"  HTTP {e.code} on attempt {fivexx_attempt + 1}; sleeping {backoff:.1f}s",
                        file=sys.stderr,
                    )
                    time.sleep(backoff)
                    fivexx_attempt += 1
                    continue
            raise


def _rate_limit_sleep_seconds(e: urllib.error.HTTPError) -> int | None:
    """Return seconds to sleep if ``e`` indicates rate-limiting,
    else None. Primary signal is ``X-RateLimit-Reset`` (the actual
    reset time, what code-search uses reliably). ``Retry-After`` is
    a fallback for abuse-rate-limits which we shouldn't hit at this
    volume. Flat 60s as final fallback. Buffer is
    ``_RATE_LIMIT_BUFFER_SECONDS`` (5s) to absorb clock skew."""
    is_429 = e.code == 429
    is_403_zero = e.code == 403 and e.headers.get("X-RateLimit-Remaining") == "0"
    if not (is_429 or is_403_zero):
        return None
    reset = e.headers.get("X-RateLimit-Reset")
    if reset:
        try:
            return max(0, int(reset) - int(time.time())) + _RATE_LIMIT_BUFFER_SECONDS
        except (TypeError, ValueError):
            pass
    retry_after = e.headers.get("Retry-After")
    if retry_after:
        try:
            return int(retry_after) + _RATE_LIMIT_BUFFER_SECONDS
        except (TypeError, ValueError):
            pass
    return 60


# ============================================================================
# Per-query orchestration — paginate, cache, yield bodies
# ============================================================================


def _search_one_query(
    query: str,
    cache_dir: Path,
    pat: str,
    *,
    refresh: bool,
    max_pages: int,
) -> Iterator[dict]:
    """Yield one response body per page, fetching from API or cache.

    Pagination terminates at the first of: ``max_pages`` reached,
    page returns no items, page returns fewer than ``_PER_PAGE`` items
    (last page). Updates the cache manifest with the final page count,
    total_count, and ``status`` field (``"completed"`` or
    ``"failed_after_retries"``).

    Raises ``_QueryFailedError`` if ``_fetch_search_page`` exhausts its
    rate-limit retry budget mid-pagination. Caller in ``collect()``
    catches this and continues to the next query (per-query graceful
    failure — the load-bearing never-silently-skip behavior).
    """
    if refresh:
        _wipe_query_cache(query, cache_dir)

    page = 1
    total_count = 0
    pages_fetched = 0
    while page <= max_pages:
        body = _load_cached(query, page, cache_dir)
        if body is None:
            try:
                body = _fetch_search_page(query, page, pat)
            except RuntimeError as e:
                _update_manifest(
                    query,
                    pages_fetched,
                    total_count,
                    cache_dir,
                    status="failed_after_retries",
                    error=f"page {page}: {e}",
                )
                raise _QueryFailedError(page=page, reason=str(e)) from e
            _save_cached(query, page, body, cache_dir)
        pages_fetched += 1
        if page == 1:
            total_count = body.get("total_count", 0)
        yield body
        items = body.get("items", [])
        if not items or len(items) < _PER_PAGE:
            break
        page += 1
    _update_manifest(query, pages_fetched, total_count, cache_dir, status="completed")


# ============================================================================
# collect() — top-level generator that yields filtered, deduped Candidates
# ============================================================================


def collect(
    query_set: str,
    cache_dir: Path,
    pat: str,
    *,
    refresh: bool = False,
    max_pages_per_query: int = _MAX_PAGES_PER_QUERY,
    filter_security_repos: bool = True,
) -> CollectResult:
    """Run every query in ``query_set``, return deduped candidates and
    any per-query failures.

    Per-query graceful failure: if one query exhausts its rate-limit
    retry budget, ``_search_one_query`` raises ``_QueryFailedError``,
    which is caught here and recorded in ``CollectResult.failed_queries``.
    The run continues to the next query — never silently skips, never
    crashes the whole run on a single bad query.

    Security/CTF filter is applied after the standard filter chain
    (interpolation / too-short / placeholder), BEFORE dedup. Dropped
    candidates are counted in ``CollectResult.dropped_security_count``
    so the end-of-run summary can surface the count for auditing.
    Disable with ``filter_security_repos=False`` (CLI:
    ``--no-filter-security-repos``).

    Dedup is across-queries within one run: a path matched by multiple
    queries surfaces once, with the first-encountered provenance_url.
    Uses ``normalize_for_dedup`` (the same callable build_queue and
    validate use), so dedup decisions can't disagree with downstream
    pipeline stages.
    """
    if query_set not in _QUERY_SETS:
        raise ValueError(f"unknown query set {query_set!r}; available: {sorted(_QUERY_SETS)}")
    queries = _QUERY_SETS[query_set]
    seen_norm: set[str] = set()
    result = CollectResult()

    for q_idx, query in enumerate(queries, start=1):
        print(f"[{q_idx}/{len(queries)}] {query}", file=sys.stderr)
        try:
            for body in _search_one_query(
                query, cache_dir, pat, refresh=refresh, max_pages=max_pages_per_query
            ):
                for item in body.get("items", []):
                    provenance_url = item.get("html_url", "")
                    for tm in item.get("text_matches", []):
                        fragment = tm.get("fragment", "")
                        for raw_path in extract_unc_paths(fragment):
                            if has_variable_interpolation(raw_path):
                                continue
                            if is_too_short(raw_path):
                                continue
                            if is_placeholder_server(raw_path):
                                continue
                            if filter_security_repos and is_offensive_security_provenance(
                                provenance_url, raw_path
                            ):
                                result.dropped_security_count += 1
                                continue
                            norm = normalize_for_dedup(raw_path)
                            if norm in seen_norm:
                                continue
                            seen_norm.add(norm)
                            result.candidates.append(
                                Candidate(path=raw_path, provenance_url=provenance_url)
                            )
                        # Extract Linux paths from the same fragment regardless
                        # of which query set we're running — a UNC-targeted
                        # query may surface a script that also contains
                        # ``~/.aws/credentials`` and vice versa. Filter chain
                        # mirrors UNC's but skips ``is_placeholder_server``
                        # (server-portion concept doesn't apply) and uses the
                        # Linux-specific length threshold.
                        for raw_path in extract_linux_paths(fragment):
                            if has_variable_interpolation(raw_path):
                                continue
                            if is_linux_too_short(raw_path):
                                continue
                            if filter_security_repos and is_offensive_security_provenance(
                                provenance_url, raw_path
                            ):
                                result.dropped_security_count += 1
                                continue
                            norm = normalize_for_dedup(raw_path)
                            if norm in seen_norm:
                                continue
                            seen_norm.add(norm)
                            result.candidates.append(
                                Candidate(path=raw_path, provenance_url=provenance_url)
                            )
        except _QueryFailedError as e:
            result.failed_queries.append(
                FailedQuery(query=query, failed_at_page=e.page, reason=e.reason)
            )
            print(
                f"  query failed (page {e.page}): {e.reason} — continuing to next query",
                file=sys.stderr,
            )
    return result


# ============================================================================
# CSV writer — atomic write to a build_queue-compatible CSV
# ============================================================================


def _write_csv(output_path: Path, candidates: list[Candidate]) -> None:
    """Atomic write: tempfile + os.replace. Output schema:
    ``path,source,provenance_url``. ``build_queue._read_csv`` reads
    path + source and silently ignores provenance_url, which is there
    purely for the labeler's review-while-labeling click-through."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = output_path.with_suffix(output_path.suffix + ".tmp")
    try:
        with tmp.open("w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["path", "source", "provenance_url"])
            for c in candidates:
                writer.writerow([c.path, "github_search", c.provenance_url])
        os.replace(tmp, output_path)
    except Exception:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
        raise


# ============================================================================
# CLI
# ============================================================================


def _print_dry_run(query_set: str, cache_dir: Path, max_pages: int) -> None:
    queries = _QUERY_SETS[query_set]
    print(f"Query set: {query_set}", file=sys.stderr)
    print(f"Cache dir: {cache_dir}", file=sys.stderr)
    print(f"Max pages per query: {max_pages}", file=sys.stderr)
    print(f"Queries that would run ({len(queries)}):", file=sys.stderr)
    for i, q in enumerate(queries, 1):
        print(f"  [{i:>2}] {q}", file=sys.stderr)
    # Runtime estimate based on the actual budget math:
    # N queries × M pages = total requests; at _BUDGET_PER_WINDOW / _WINDOW_SECONDS
    # req/s steady-state, that's (N*M * _WINDOW_SECONDS / _BUDGET_PER_WINDOW) seconds.
    # Plus retry-wait overhead which can add minutes when the cap is hit; rough
    # estimate adds ~25% to upper bound to reflect realistic retry frequency.
    secs_per_req = _WINDOW_SECONDS / _BUDGET_PER_WINDOW  # ~6.67s
    lo_min = len(queries) * 3 * secs_per_req / 60
    hi_min = len(queries) * max_pages * secs_per_req / 60 * 1.25
    print(
        f"\nEstimated runtime: ~{lo_min:.0f}–{hi_min:.0f} minutes "
        f"({len(queries)} queries × ~3–{max_pages} pages, paced under the "
        f"{_BUDGET_PER_WINDOW}-per-{_WINDOW_SECONDS:.0f}s code-search budget, "
        f"plus retry-wait overhead when the cap is hit).",
        file=sys.stderr,
    )
    print("Re-run without --dry-run to execute.", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="source_github",
        description=(
            "Collect real Windows/UNC paths from public GitHub code via the "
            "code-search API. STRONGLY RECOMMENDED: run --dry-run first to "
            "preview the query plan and estimated runtime before paying the "
            "rate-limit cost (~6–20 minutes for a full v0 run)."
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output CSV path (default: data/eval/sources/github_search_<timestamp>.csv)",
    )
    parser.add_argument(
        "--query-set",
        default="v0",
        choices=sorted(_QUERY_SETS),
        help="Named query template profile (default: v0)",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Wipe cache for the selected query set and re-fetch from API",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "STRONGLY RECOMMENDED FIRST. Print the query plan and estimated "
            "runtime; do not call the API or write any output."
        ),
    )
    parser.add_argument(
        "--max-pages-per-query",
        type=int,
        default=_MAX_PAGES_PER_QUERY,
        help=(
            f"Pagination cap (default: {_MAX_PAGES_PER_QUERY}). First few "
            f"pages carry the highest-relevance results; bump to 10 (the "
            f"API hard cap) for full pagination at ~1.5x runtime and "
            f"proportionally more rate-limit retries."
        ),
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=_DEFAULT_CACHE_DIR,
        help=f"Cache directory (default: {_DEFAULT_CACHE_DIR})",
    )
    parser.add_argument(
        "--no-filter-security-repos",
        action="store_true",
        help=(
            "Disable the default-on filter that drops candidates from known "
            "offensive-security / CTF repos (poshc2, metasploit, goad, etc.) "
            "and unambiguous lab share names (marvel-dc, hackme, etc.). Use "
            "to inspect the unfiltered output for comparison; end-of-run "
            "summary always prints the drop count whether the filter is on "
            "or off."
        ),
    )
    args = parser.parse_args(argv)

    if args.dry_run:
        _print_dry_run(args.query_set, args.cache_dir, args.max_pages_per_query)
        return 0

    try:
        pat = _read_pat()
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if args.output is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        args.output = _DEFAULT_OUTPUT_DIR / f"github_search_{ts}.csv"

    args.cache_dir.mkdir(parents=True, exist_ok=True)

    result = collect(
        query_set=args.query_set,
        cache_dir=args.cache_dir,
        pat=pat,
        refresh=args.refresh,
        max_pages_per_query=args.max_pages_per_query,
        filter_security_repos=not args.no_filter_security_repos,
    )

    _write_csv(args.output, result.candidates)

    # End-of-run summary: queries attempted vs completed vs failed.
    # Failure surfacing is the load-bearing never-silently-skip behavior —
    # the operator must see WHICH queries didn't complete so they can
    # re-run with --refresh (v0.1 will add a --retry-failed flag that
    # targets only the failed subset).
    total = len(_QUERY_SETS[args.query_set])
    failed = len(result.failed_queries)
    completed = total - failed
    print(
        f"\nsummary: {total} queries attempted; {completed} completed; "
        f"{failed} failed after retries",
        file=sys.stderr,
    )
    if result.failed_queries:
        for fq in result.failed_queries:
            print(
                f"  - failed: {fq.query!r} at page {fq.failed_at_page} ({fq.reason})",
                file=sys.stderr,
            )
        print(
            "re-run with --refresh to retry the full set, OR wait for the "
            "v0.1 --retry-failed flag that targets only the failed queries.",
            file=sys.stderr,
        )
    # Drop-count line is always printed (even at 0) when the filter is
    # active, so the operator has a stable signal to read. When the
    # filter is disabled, surface that fact explicitly.
    if args.no_filter_security_repos:
        print(
            "  security/CTF filter: DISABLED (--no-filter-security-repos)",
            file=sys.stderr,
        )
    else:
        print(
            f"  dropped {result.dropped_security_count} candidates from "
            f"security/CTF repos (--no-filter-security-repos to disable)",
            file=sys.stderr,
        )
    print(
        f"wrote {len(result.candidates)} unique candidate paths to {args.output}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
