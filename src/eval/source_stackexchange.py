"""Stack Exchange data-dump → real-Windows-path candidates for the eval set.

Streams the Posts.xml file from a Stack Exchange site's quarterly data
dump, extracts UNC path candidates from question and answer bodies,
applies the shared filter pipeline from ``_path_filters``, and writes a
CSV that ``build_queue.py`` can consume directly.

ServerFault is the primary target for v0 (sysadmin Q&A, highest path
density of any public source). Stack Overflow / Super User work the
same way — just point ``--input`` at their Posts.xml and pass
``--site stackoverflow.com`` (or whichever host).

The tool PROPOSES candidates. It is not authoritative — pre-categorization
and the labeler's review-while-labeling are what turn a candidate into
a labeled eval record. This module deliberately does NOT pre-judge
juiciness or category; that's the labeler's job.

Data dump procurement
---------------------
Stack Exchange publishes quarterly data dumps on Internet Archive:
``https://archive.org/details/stackexchange``. Each site's dump is a
.7z archive containing several XML files (Posts.xml, Comments.xml,
Users.xml, etc.). This tool reads Posts.xml only.

Operator workflow:

  1. Download the desired site's archive from archive.org (e.g.,
     ``serverfault.com.7z``).
  2. Decompress with ``7z x serverfault.com.7z`` (or similar). No
     in-process decompression — keeps this module stdlib-only and
     the unpack step auditable.
  3. Point ``--input`` at the resulting ``Posts.xml``.

No PAT, no rate limits, no cache layer — the .xml IS the snapshot.
A different quarterly dump = re-run with the new file.

Streaming parse
---------------
Posts.xml is multi-GB (ServerFault ~3GB, StackOverflow ~80GB).
``xml.etree.ElementTree.iterparse`` streams over the file with
``elem.clear()`` after each row, plus root.clear() periodically, to
keep memory flat. No ``lxml`` dep.

Body-substring pre-filter
-------------------------
~99% of posts don't contain ``\\`` literally. Cheap string-substring
pre-filter (``"\\\\" in body``) runs before HTML unescape and regex
extraction, pruning the vast majority of rows at the cost of a single
string scan. Real cost is HTML unescape + regex on the survivors.

HTML entity unescape
--------------------
Post bodies are HTML with code blocks formatted as ``<pre><code>...</code></pre>``.
Inside code blocks, ``<`` / ``>`` / ``&`` are HTML-encoded as
``&lt;`` / ``&gt;`` / ``&amp;``. We call ``html.unescape`` on the body
before regex extraction so that ``&lt;server&gt;`` placeholders
correctly fail the placeholder filter (the regex's server class
rejects ``<``/``>`` anyway, but defense in depth is cheap).

Body-wide vs code-block-only extraction
---------------------------------------
v0 extracts from the entire post body, not just code blocks. Real-world
posts mention paths in prose too ("we mount ``\\\\fileserv\\backup``
via..."). The shared filter pipeline already handles placeholder /
interpolation rejection, so the extra recall is essentially free.
A future ``--code-blocks-only`` flag is a precision knob if the
signal-to-noise from prose extraction turns out poor.

Provenance URL
--------------
``https://{site}/q/{post_id}`` for questions, ``/a/{post_id}`` for
answers (the latter URL redirects to the parent question with the
answer anchor). Useful for the labeler's review-while-labeling
click-through: see the path in context.

Site identifier is the host string (default ``serverfault.com``).
Operator passes it via ``--site``.

CLI
---
``--dry-run`` previews row counts without extraction.

    python -m src.eval.source_stackexchange --input PATH/Posts.xml --dry-run
    python -m src.eval.source_stackexchange --input PATH/Posts.xml
    python -m src.eval.build_queue \\
        --input data/eval/sources/stackexchange_<timestamp>.csv \\
        --output data/eval/queue.jsonl \\
        --source-default stackexchange
"""

from __future__ import annotations

import argparse
import csv
import html
import os
import sys
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from src.eval._path_filters import (
    extract_unc_paths,
    has_variable_interpolation,
    is_offensive_security_provenance,
    is_placeholder_server,
    is_too_short,
)
from src.eval._paths import normalize_for_dedup

# ============================================================================
# Module constants
# ============================================================================

_DEFAULT_SITE = "serverfault.com"
_DEFAULT_OUTPUT_DIR = Path("data/eval/sources")

# Tag values that identify a row in Posts.xml. PostTypeId=1 is a
# question, PostTypeId=2 is an answer. We extract from both; the
# provenance URL prefix differs (``/q/`` vs ``/a/``).
_POST_TYPE_QUESTION = "1"
_POST_TYPE_ANSWER = "2"

# Default inclusion tags for Stack Overflow runs. ServerFault/SuperUser
# are sysadmin-only sites where every backslash-containing post is
# potentially relevant; SO is ~58M posts of mostly programming Q&A, so
# even after the ``\\`` body pre-filter the corpus is dominated by
# tutorial code referencing C:\Users\ paths rather than real-share
# discussion. This set restricts to questions tagged with sysadmin /
# Windows-infra topics; answers inherit their parent question's
# filter result. CLI flag ``--no-tag-filter`` disables when needed.
_DEFAULT_SO_INCLUDE_TAGS: frozenset[str] = frozenset(
    {
        "windows",
        "powershell",
        "windows-server",
        "smb",
        "cifs",
        "samba",
        "unc",
        "active-directory",
        "dfs",
        "iis",
        "network-share",
        "network-drive",
        "mapped-drive",
        "windows-services",
    }
)

# Periodic root.clear() interval — clears accumulated processed
# elements every N rows to keep memory flat over multi-GB streams.
# Pure iterparse without this leaks O(file_size) memory.
_ROOT_CLEAR_EVERY = 10_000

# Body-substring pre-filter: ``"\\\\"`` (two backslashes) literally
# present in the body. ~99% of posts won't have this; the cheap
# substring check prunes them before HTML unescape + regex.
_BACKSLASH_PREFIX = "\\\\"


# ============================================================================
# Output dataclass
# ============================================================================


@dataclass(frozen=True)
class Candidate:
    """One extracted-and-filtered UNC path with its Stack Exchange
    provenance URL. Shape-identical to source_github.Candidate but
    deliberately a separate type — each source module owns its output
    record so the modules don't couple to each other for output
    semantics.

    ``path`` is the raw extracted UNC path. Dedup uses
    ``normalize_for_dedup`` internally so case-variants collapse
    without losing the original form for the labeler.

    ``provenance_url`` is the post's web URL (question or answer-
    specific). Click-through during labeling shows the surrounding
    discussion.
    """

    path: str
    provenance_url: str


@dataclass
class CollectResult:
    """Per-run output: deduped candidates + dropped-security count.

    No failed_queries field (unlike source_github) — there's no
    transient-failure mode on local-file processing. Either the file
    is parseable (we process every row) or it isn't (we fail-fast at
    startup with a clear error).
    """

    candidates: list[Candidate] = field(default_factory=list)
    posts_seen: int = 0
    posts_with_backslash: int = 0
    dropped_security_count: int = 0


# ============================================================================
# Provenance URL construction
# ============================================================================


def build_provenance_url(site: str, post_type_id: str, post_id: str) -> str:
    """Return the post's web URL. ``/q/`` for questions, ``/a/`` for
    answers (latter redirects to parent question with answer anchor).

    Unknown ``post_type_id`` (Stack Exchange has additional types for
    wiki, tag wiki, etc.) defaults to ``/posts/`` which is the
    site-internal redirect endpoint and always resolves.
    """
    if post_type_id == _POST_TYPE_QUESTION:
        prefix = "q"
    elif post_type_id == _POST_TYPE_ANSWER:
        prefix = "a"
    else:
        prefix = "posts"
    return f"https://{site}/{prefix}/{post_id}"


# ============================================================================
# Row processing
# ============================================================================


def _body_might_contain_unc(body: str) -> bool:
    """Cheap pre-filter: does the body literally contain ``\\\\``?

    Two backslashes is the start-of-UNC marker; bodies without this
    can't possibly yield a UNC candidate. Substring scan is O(n) but
    constant-factor cheap compared to HTML unescape + regex on the
    same body.
    """
    return _BACKSLASH_PREFIX in body


def extract_candidates_from_row(
    body: str,
    *,
    site: str,
    post_type_id: str,
    post_id: str,
    filter_security_repos: bool,
) -> Iterator[tuple[Candidate, bool]]:
    """Yield ``(candidate, dropped_by_security_filter)`` for each
    extracted-and-filtered UNC path in ``body``.

    ``dropped_by_security_filter`` is True for candidates the caller
    should count toward ``dropped_security_count`` rather than emit;
    surfacing the count in the end-of-run summary is the visibility
    discipline (filter not silent — auditable).

    Returns nothing if the body has no UNC-shaped content. Caller
    drives dedup via ``normalize_for_dedup``.
    """
    unescaped = html.unescape(body)
    provenance_url = build_provenance_url(site, post_type_id, post_id)
    for raw_path in extract_unc_paths(unescaped):
        if has_variable_interpolation(raw_path):
            continue
        if is_too_short(raw_path):
            continue
        if is_placeholder_server(raw_path):
            continue
        if filter_security_repos and is_offensive_security_provenance(
            provenance_url, raw_path
        ):
            yield Candidate(path=raw_path, provenance_url=provenance_url), True
            continue
        yield Candidate(path=raw_path, provenance_url=provenance_url), False


# ============================================================================
# Streaming XML parse
# ============================================================================


def parse_tags(tags_str: str) -> frozenset[str]:
    """Parse a Posts.xml ``Tags`` attribute value into a tag set.

    Stack Exchange data dumps use two different tag formats:

    * **Angle-bracket**: ``<windows><powershell>`` — older / smaller
      sites including ServerFault and SuperUser. iterparse delivers
      the already-entity-unescaped value, so we see angle brackets
      directly, not ``&lt;``.
    * **Pipe-delimited**: ``|windows|powershell|`` — Stack Overflow
      (observed in the April 2024 dump). Leading and trailing pipes
      are present even on single-tag questions.

    The first character disambiguates. Discovered the hard way on a
    full-SO run that returned 0 hits because the angle-bracket parser
    saw 60M ``|c#|asp.net|...|``-style tag strings.

    Tag-name false-substring risk (``<windows>`` vs ``<windows-server>``,
    ``|c#|`` vs ``|c#-7.0|``) is avoided by splitting on the format's
    delimiter and exact-matching tokens rather than substring search.
    """
    if not tags_str:
        return frozenset()
    first = tags_str[0]
    if first == "<":
        inner = tags_str.strip("<>")
        if not inner:
            return frozenset()
        return frozenset(t for t in inner.split("><") if t)
    if first == "|":
        return frozenset(t for t in tags_str.split("|") if t)
    return frozenset()


def _iter_post_rows(
    xml_path: Path,
) -> Iterator[tuple[str, str, str, str, str, str]]:
    """Yield ``(post_id, post_type_id, body, title, tags, parent_id)`` for
    each Posts.xml row.

    Streams via ``ET.iterparse`` with periodic root.clear() to keep
    memory flat over multi-GB files. Rows without a ``Body`` attribute
    are skipped silently (some PostTypeId values like tag wiki excerpts
    can have empty bodies).

    ``tags`` is the raw ``Tags`` attribute string (questions only;
    answers carry empty tags but inherit their parent question's tag
    set via ``parent_id`` lookup at the caller level).

    Bare-stdlib parse — no ``lxml`` dep. iterparse handles malformed
    XML by raising ``ET.ParseError`` which propagates to the caller.
    """
    context = iter(ET.iterparse(xml_path, events=("start", "end")))
    _, root = next(context)  # capture root for periodic clear()
    rows_since_root_clear = 0
    for event, elem in context:
        if event != "end" or elem.tag != "row":
            continue
        post_id = elem.get("Id", "")
        post_type_id = elem.get("PostTypeId", "")
        body = elem.get("Body", "")
        title = elem.get("Title", "")
        tags = elem.get("Tags", "")
        parent_id = elem.get("ParentId", "")
        if post_id and body:
            yield post_id, post_type_id, body, title, tags, parent_id
        elem.clear()
        rows_since_root_clear += 1
        if rows_since_root_clear >= _ROOT_CLEAR_EVERY:
            root.clear()
            rows_since_root_clear = 0


# ============================================================================
# collect() — top-level processing
# ============================================================================


def collect(
    xml_path: Path,
    *,
    site: str = _DEFAULT_SITE,
    filter_security_repos: bool = True,
    max_posts: int | None = None,
    include_tags: frozenset[str] | None = None,
) -> CollectResult:
    """Stream Posts.xml, extract UNC candidates, return deduped result.

    Dedup is via ``normalize_for_dedup`` (same callable as build_queue,
    validate, and source_github), so dedup decisions can't disagree
    with downstream pipeline stages or with another source module.

    Within-source dedup only — paths already in eval_set.jsonl or
    queue.jsonl are dropped by ``build_queue`` at queue-build time,
    not here. This is the same posture as source_github.

    ``max_posts`` (debug knob) stops processing after N rows so the
    operator can sanity-check on a small slice before the full pass.

    ``include_tags`` restricts processing to questions whose ``Tags``
    overlap with the set, plus answers whose parent question matched.
    Used on Stack Overflow to filter out programming-tutorial noise
    (~58M posts dominated by code samples referencing C:\\Users\\ paths
    rather than real-share discussion). ``None`` (default) processes
    all post types — the right posture for ServerFault/SuperUser where
    the entire site is sysadmin Q&A.
    """
    seen_norm: set[str] = set()
    result = CollectResult()
    # Track question IDs whose tags pass the filter; answers inherit
    # their parent question's result by ParentId lookup. Memory is
    # bounded by the number of matching questions (~500k on SO with the
    # default tag set ≈ ~5MB of string IDs — trivial).
    matching_question_ids: set[str] = set()

    for (
        post_id,
        post_type_id,
        body,
        _title,
        tags,
        parent_id,
    ) in _iter_post_rows(xml_path):
        result.posts_seen += 1
        if max_posts is not None and result.posts_seen > max_posts:
            break
        if include_tags is not None:
            if post_type_id == _POST_TYPE_QUESTION:
                if not (parse_tags(tags) & include_tags):
                    continue
                matching_question_ids.add(post_id)
            elif post_type_id == _POST_TYPE_ANSWER:
                if parent_id not in matching_question_ids:
                    continue
            else:
                # Non-Q/A post types (tag wikis, etc.) skipped under
                # tag-filter mode — no parent linkage to resolve.
                continue
        if not _body_might_contain_unc(body):
            continue
        result.posts_with_backslash += 1
        for candidate, dropped in extract_candidates_from_row(
            body,
            site=site,
            post_type_id=post_type_id,
            post_id=post_id,
            filter_security_repos=filter_security_repos,
        ):
            if dropped:
                result.dropped_security_count += 1
                continue
            norm = normalize_for_dedup(candidate.path)
            if norm in seen_norm:
                continue
            seen_norm.add(norm)
            result.candidates.append(candidate)

    return result


# ============================================================================
# CSV writer — atomic write, build_queue-compatible
# ============================================================================


def _write_csv(output_path: Path, candidates: list[Candidate]) -> None:
    """Atomic write: tempfile + os.replace. Output schema:
    ``path,source,provenance_url``. Identical schema to source_github's
    output so ``build_queue._read_csv`` can read either source's CSV
    without distinguishing them."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = output_path.with_suffix(output_path.suffix + ".tmp")
    try:
        with tmp.open("w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["path", "source", "provenance_url"])
            for c in candidates:
                writer.writerow([c.path, "stackexchange", c.provenance_url])
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


def _print_dry_run(xml_path: Path, site: str, max_posts: int | None) -> None:
    """Print what would happen without touching the filesystem (beyond
    stat-ing the input). No XML parse — just confirm the file exists
    and surface the parameters."""
    print(f"Input: {xml_path}", file=sys.stderr)
    print(f"Site: {site}", file=sys.stderr)
    print(
        f"Max posts: {'all' if max_posts is None else max_posts}",
        file=sys.stderr,
    )
    if not xml_path.exists():
        print(
            f"\nWARNING: {xml_path} does not exist. Real run will fail.",
            file=sys.stderr,
        )
    else:
        size_mb = xml_path.stat().st_size / (1024 * 1024)
        print(f"File size: {size_mb:.0f} MB", file=sys.stderr)
        # Rough runtime estimate: streaming parse + filter is I/O bound,
        # ~30-100 MB/s depending on disk. Use 50 MB/s as midpoint.
        est_seconds = size_mb / 50
        if est_seconds < 60:
            print(
                f"Estimated runtime: ~{est_seconds:.0f}s (I/O-bound stream parse)",
                file=sys.stderr,
            )
        else:
            print(
                f"Estimated runtime: ~{est_seconds / 60:.1f} min "
                f"(I/O-bound stream parse)",
                file=sys.stderr,
            )
    print("\nRe-run without --dry-run to execute.", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="source_stackexchange",
        description=(
            "Extract UNC candidate paths from a Stack Exchange data-dump "
            "Posts.xml file. No PAT, no rate limits — the .xml IS the "
            "snapshot. Download the .7z from archive.org/details/stackexchange "
            "and decompress before running."
        ),
    )
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Path to the Posts.xml file from a decompressed dump",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help=(
            "Output CSV path (default: "
            "data/eval/sources/stackexchange_<timestamp>.csv)"
        ),
    )
    parser.add_argument(
        "--site",
        default=_DEFAULT_SITE,
        help=(
            f"Site URL host for provenance URLs (default: {_DEFAULT_SITE}). "
            f"Examples: stackoverflow.com, superuser.com, "
            f"sharepoint.stackexchange.com"
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Print the run plan and estimated runtime; do not parse the "
            "file or write any output."
        ),
    )
    parser.add_argument(
        "--max-posts",
        type=int,
        default=None,
        help=(
            "Stop after processing N rows (debug knob for sanity-checking "
            "extraction on a slice before the full pass)."
        ),
    )
    parser.add_argument(
        "--no-filter-security-repos",
        action="store_true",
        help=(
            "Disable the default-on filter that drops candidates from known "
            "offensive-security / CTF sources and unambiguous lab share "
            "names. End-of-run summary always prints the drop count whether "
            "the filter is on or off."
        ),
    )
    parser.add_argument(
        "--include-tags",
        default=None,
        help=(
            "Comma-separated tag list; only process questions whose Tags "
            "overlap with the list (and answers to those questions). "
            "Auto-defaults to a sysadmin-tag set for --site stackoverflow.com; "
            "no filter for other sites. Pass an explicit list to override "
            "the auto-default, or use --no-tag-filter to disable entirely."
        ),
    )
    parser.add_argument(
        "--no-tag-filter",
        action="store_true",
        help=(
            "Disable the tag filter even when --site is stackoverflow.com. "
            "Without this, SO runs auto-default to the sysadmin-tag set."
        ),
    )
    args = parser.parse_args(argv)

    if args.dry_run:
        _print_dry_run(args.input, args.site, args.max_posts)
        return 0

    if not args.input.exists():
        print(f"error: input file {args.input} does not exist", file=sys.stderr)
        return 1

    if args.output is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        args.output = _DEFAULT_OUTPUT_DIR / f"stackexchange_{ts}.csv"

    # Resolve the effective tag filter: explicit --include-tags wins,
    # then --no-tag-filter, then site-based auto-default (SO only).
    if args.no_tag_filter:
        include_tags: frozenset[str] | None = None
    elif args.include_tags is not None:
        include_tags = frozenset(
            t.strip() for t in args.include_tags.split(",") if t.strip()
        )
    elif "stackoverflow.com" in args.site:
        include_tags = _DEFAULT_SO_INCLUDE_TAGS
    else:
        include_tags = None

    try:
        result = collect(
            args.input,
            site=args.site,
            filter_security_repos=not args.no_filter_security_repos,
            max_posts=args.max_posts,
            include_tags=include_tags,
        )
    except ET.ParseError as e:
        print(f"error: malformed XML in {args.input}: {e}", file=sys.stderr)
        return 1

    _write_csv(args.output, result.candidates)

    # End-of-run summary
    print(
        f"\nsummary: {result.posts_seen} posts seen; "
        f"{result.posts_with_backslash} contained '\\\\'; "
        f"{len(result.candidates)} unique candidate paths emitted",
        file=sys.stderr,
    )
    if include_tags is not None:
        print(
            f"  tag filter: ON ({len(include_tags)} tags: "
            f"{', '.join(sorted(include_tags))})",
            file=sys.stderr,
        )
    else:
        print("  tag filter: OFF", file=sys.stderr)
    if args.no_filter_security_repos:
        print(
            "  security/CTF filter: DISABLED (--no-filter-security-repos)",
            file=sys.stderr,
        )
    else:
        print(
            f"  dropped {result.dropped_security_count} candidates from "
            f"security/CTF sources (--no-filter-security-repos to disable)",
            file=sys.stderr,
        )
    print(f"wrote {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
