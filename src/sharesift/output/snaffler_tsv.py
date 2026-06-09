"""Snaffler-compatible TSV output (v0.36 step 4).

Snaffler emits an 11-column tab-separated line per file result when
run with ``-y``. The format is consumed by SnafflerParser, Efflanrs,
Parsler, snafflepy, and most operator-rolled grep / awk pipelines.

Line shape (per ``SnaffleRunner.cs::FileResultLogFromMessage``):

    <ts>[File]\\t<triage>\\t<rule>\\t<R>\\t<W>\\t<M>\\t<matched>\\t<size>\\t<modified>\\t<path>\\t<altname>\\t<context>

Where:

  * <ts>       — line timestamp, ``yyyy-MM-dd HH:mm:ssZ`` UTC
  * <triage>   — Black / Red / Yellow / Green
  * <rule>     — matched rule name
  * <R>/<W>/<M> — "R" / "W" / "M" or empty (read / write / modify)
  * <matched>  — first regex hit
  * <size>     — file size in bytes (string, empty if unknown)
  * <modified> — file mtime UTC, same format as <ts>, empty if unknown
  * <path>     — full file path (UNC or filesystem)
  * <altname>  — alt name prefixed with "#_as_#" (SCCM content-lib);
                 empty when not applicable
  * <context>  — match-context snippet, newlines escaped to ``\\n``

ShareSift fills the columns from a ``hits.jsonl`` record. R is "R"
because we read the file to score it. W/M stay empty until v0.36
step 3 ships share-writability probing. Size and mtime come from
``os.stat()`` for local paths; UNC paths emit empty (we don't
re-open SMB connections at format time).
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
from pathlib import Path
from typing import Iterable, Iterator

_SEP = "\t"

# Strip ANSI / control bytes that would break TSV parsing downstream
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _utc_now() -> str:
    return _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%d %H:%M:%SZ")


def _utc_format(timestamp: float | None) -> str:
    if timestamp is None:
        return ""
    return _dt.datetime.fromtimestamp(timestamp, _dt.UTC).strftime(
        "%Y-%m-%d %H:%M:%SZ"
    )


def _is_unc(path: str) -> bool:
    return path.startswith("\\\\") or path.startswith("//")


def _stat_local(path: str) -> tuple[str, str]:
    """Return ``(size, modified)`` from filesystem; empty pair on failure
    or UNC. Lookups happen at format time, after the scan, so UNCs
    (whose SMB session is closed) emit empty."""
    if _is_unc(path):
        return "", ""
    try:
        st = os.stat(path)
    except OSError:
        return "", ""
    return str(st.st_size), _utc_format(st.st_mtime)


def _escape_context(text: str | None) -> str:
    """Strip newlines + control chars from a match-context snippet.

    Matches Snaffler's behavior in FileResultLogFromMessage:
    ``Regex.Replace(matchcontext, @"\\r\\n?|\\n", "\\n")``.
    """
    if not text:
        return ""
    # Replace CR/LF with literal "\n" (two chars), then strip controls
    text = text.replace("\r\n", "\\n").replace("\r", "\\n").replace("\n", "\\n")
    text = _CONTROL_CHARS.sub("", text)
    return text


def _extract_triage_and_rule(record: dict) -> tuple[str, str, str]:
    """Pull the most-specific tier + rule from a record.

    Returns ``(triage, rule_name, matched_string)``. Preference order:
    content_matches first (a rule actually fired on content) →
    extracted_fields (parser-derived) → path_tier (Stage 1 only).
    """
    content_matches = record.get("content_matches") or []
    if content_matches:
        first = content_matches[0]
        triage = (
            first.get("tier")
            or first.get("triage")
            or record.get("content_tier")
            or record.get("path_tier")
            or "Yellow"
        )
        rule = first.get("rule_name") or first.get("rule") or "ContentRule"
        matched = first.get("matched_text") or first.get("matched") or ""
        return str(triage), str(rule), str(matched)

    extracted = record.get("extracted_fields") or []
    if extracted:
        first = extracted[0]
        triage = (
            record.get("content_tier")
            or record.get("path_tier")
            or "Yellow"
        )
        rule = "Parser:" + str(first.get("parser") or "unknown")
        matched = str(first.get("value") or "")[:80]
        return triage, rule, matched

    # Path-only triage signal
    triage = record.get("path_tier") or "Green"
    return str(triage), "PathClassifier", ""


def record_to_snaffler_tsv(
    record: dict, *, line_timestamp: str | None = None
) -> str:
    """Convert one ShareSift ``hits.jsonl`` record to a Snaffler TSV line.

    ``line_timestamp`` defaults to "now in UTC" (matches Snaffler's
    log-line timestamp behavior). Tests pass a fixed timestamp for
    determinism.
    """
    ts = line_timestamp or _utc_now()
    triage, rule, matched = _extract_triage_and_rule(record)

    path = str(record.get("path") or "")
    size, modified = _stat_local(path)

    # R is always set — we read the file to score it.
    # W/M stay empty until v0.36 step 3 (share writability).
    can_read = "R"
    can_write = ""
    can_modify = ""

    # First content_match's snippet → match context (newlines escaped)
    context = ""
    content_matches = record.get("content_matches") or []
    if content_matches:
        snippet = (
            content_matches[0].get("match_context")
            or content_matches[0].get("snippet")
            or record.get("content_excerpt")
            or ""
        )
        context = _escape_context(snippet)

    altname = ""  # ShareSift doesn't track SCCM-style alt names

    fields = [
        f"{ts}[File]",
        triage,
        rule,
        can_read, can_write, can_modify,
        matched,
        size,
        modified,
        path,
        altname,
        context,
    ]
    # Defensive: scrub any embedded tabs in field values so the TSV
    # stays well-formed for downstream parsers.
    fields = [str(f).replace("\t", " ") for f in fields]
    return _SEP.join(fields)


def iter_snaffler_tsv_lines(
    records: Iterable[dict], *, line_timestamp: str | None = None
) -> Iterator[str]:
    """Stream Snaffler-TSV lines from a record iterable. Useful for
    converting hits.jsonl on the fly without loading it all."""
    for r in records:
        yield record_to_snaffler_tsv(r, line_timestamp=line_timestamp)
