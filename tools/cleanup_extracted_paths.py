"""v0.15 — clean placeholder hosts + trailing context fragments from
extracted_paths.jsonl before feeding to the synthetic generator / training.

Two failure modes from ``regex_extract_paths_from_articles.py``:

1. **Placeholder hostnames.** Articles use literal placeholders like
   ``\\\\REDACTED\\share`` or ``\\\\your.webdavserver.net`` as stand-ins.
   These leak into the share-root pool and produce unrealistic synthetic
   paths (``\\\\REDACTED\\C$\\users\\fmc\\Desktop\\sam.save``).

2. **Trailing context fragments.** The regex captures sentence-tail
   words when an article doesn't terminate the path cleanly. E.g.,
   ``NTDS.dit C`` (trailing " C" from a content word) or
   ``\\path\\scaner.zip. Shortly after`` (trailing prose).

Cleanup strategy:
- Drop records whose share root matches a known-placeholder denylist
- Trim trailing fragment patterns (`` <1-2 chars>$``, common stop words)
- Drop records whose final filename component looks malformed
  (too long, contains prose-like word boundaries)

Idempotent — re-running over a cleaned file produces no further changes.

Usage::

    uv run python tools/cleanup_extracted_paths.py \\
        --input data/external/engagement_corpus/extracted_paths.jsonl \\
        --output data/external/engagement_corpus/extracted_paths_clean.jsonl
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = REPO_ROOT / "data" / "external" / "engagement_corpus" / "extracted_paths.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "external" / "engagement_corpus" / "extracted_paths_clean.jsonl"

# Hostnames that appear as placeholders in writeups. Case-insensitive
# substring match against the share-root segment.
_PLACEHOLDER_HOSTS = {
    "redacted", "redact", "anonymous",
    "your.webdavserver.net", "your.server.com", "yourcompany",
    "yourdomain", "yourorganization", "yourdc", "yourhost",
    "example.com", "example.org", "example.net",
    "myhost", "mycompany", "mydomain",
    "<host>", "<server>", "<dc>", "<computer>",
    "[host]", "[server]",
    "computername", "hostname", "domain.com",
    "victim.local", "victim.com", "victim",
    "target.local", "test.local",
    "internal.lan", "corp.local",
    "domaincontroller",  # generic literal; real DCs have actual names
}

# Sentence-tail words that get captured at the end of a path when the
# article wraps without a clean terminator.
_TRAILING_FRAGMENTS = re.compile(
    r"\s+(?:to|and|for|with|from|in|on|or|the|a|an|but|so|as|by|then|"
    r"after|before|while|where|when|which|that|will|would|could|should|"
    r"shortly|likely|usually|finally|eventually|etc|\.\.\.)"
    r"\b.*$",
    re.IGNORECASE,
)

# Trailing single/double-character noise (e.g., "NTDS.dit C", "creds.txt a")
_TRAILING_SHORT_WORD = re.compile(r"\s[A-Za-z]{1,2}\.?$")

# Punctuation/whitespace to strip from the right edge
_RIGHT_STRIP = re.compile(r"[\s.,;:'\"()<>]+$")

# Final filename validity: must be at most 255 chars (NTFS max) and not
# contain prose-shaped whitespace runs
_VALID_BASENAME = re.compile(r"^[^\\/]{1,255}$")


def _share_root_of(path: str) -> str:
    """Extract the share-root segment for placeholder-host check."""
    if path.startswith("\\\\"):
        # \\host\share\...
        parts = path.split("\\")
        # parts[0] = "", parts[1] = "", parts[2] = "host", parts[3] = "share"
        if len(parts) >= 3:
            return parts[2].lower()
    if len(path) >= 2 and path[1] == ":":
        return path[:2].lower()
    return ""


def _has_placeholder_host(path: str) -> bool:
    host = _share_root_of(path)
    if not host:
        return False
    if host in _PLACEHOLDER_HOSTS:
        return True
    # Substring match too — catches "your.webdavserver.net" variations
    for placeholder in _PLACEHOLDER_HOSTS:
        if "." in placeholder or "<" in placeholder or "[" in placeholder:
            if placeholder in host:
                return True
    return False


def _trim_trailing_fragment(path: str) -> str:
    cleaned = path
    while True:
        before = cleaned
        cleaned = _TRAILING_FRAGMENTS.sub("", cleaned)
        cleaned = _TRAILING_SHORT_WORD.sub("", cleaned)
        cleaned = _RIGHT_STRIP.sub("", cleaned)
        if cleaned == before:
            break
    return cleaned


def _basename(path: str) -> str:
    return path.replace("/", "\\").rsplit("\\", 1)[-1]


def _basename_valid(path: str) -> bool:
    base = _basename(path)
    if not base:
        return False
    if not _VALID_BASENAME.match(base):
        return False
    # If the basename has 3+ space-separated words it's almost certainly prose
    if base.count(" ") >= 3:
        return False
    return True


def _looks_too_short(path: str) -> bool:
    # Single-segment paths after share root (e.g., \\host\share alone)
    # are not useful training signal.
    if path.startswith("\\\\"):
        parts = [p for p in path.split("\\") if p]
        return len(parts) < 3
    if len(path) <= 4:
        return True
    return False


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = p.parse_args(argv)

    if not args.input.exists():
        print(f"ERROR: --input missing: {args.input}", file=sys.stderr)
        return 2

    n_in = 0
    n_kept = 0
    n_dropped_placeholder = 0
    n_dropped_basename = 0
    n_dropped_too_short = 0
    n_trimmed = 0
    drop_examples_placeholder: list[str] = []
    trim_examples: list[tuple[str, str]] = []

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.input.open(encoding="utf-8") as fh_in, \
         args.output.open("w", encoding="utf-8") as fh_out:
        for line in fh_in:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            n_in += 1
            original = rec.get("verbatim_path", "")
            if not original:
                continue
            # Step 1: trim trailing fragment
            trimmed = _trim_trailing_fragment(original)
            if trimmed != original:
                n_trimmed += 1
                if len(trim_examples) < 5:
                    trim_examples.append((original, trimmed))
            # Step 2: placeholder host check
            if _has_placeholder_host(trimmed):
                n_dropped_placeholder += 1
                if len(drop_examples_placeholder) < 5:
                    drop_examples_placeholder.append(trimmed)
                continue
            # Step 3: basename validity
            if not _basename_valid(trimmed):
                n_dropped_basename += 1
                continue
            # Step 4: minimum length
            if _looks_too_short(trimmed):
                n_dropped_too_short += 1
                continue
            rec["verbatim_path"] = trimmed
            rec["cleaned"] = (trimmed != original)
            fh_out.write(json.dumps(rec) + "\n")
            n_kept += 1

    print(f"[cleanup] input: {n_in} records", file=sys.stderr)
    print(f"[cleanup] kept:  {n_kept}", file=sys.stderr)
    print(f"[cleanup]   trimmed trailing fragments: {n_trimmed}", file=sys.stderr)
    print(f"[cleanup] dropped placeholder host: {n_dropped_placeholder}",
          file=sys.stderr)
    print(f"[cleanup] dropped invalid basename: {n_dropped_basename}", file=sys.stderr)
    print(f"[cleanup] dropped too short: {n_dropped_too_short}", file=sys.stderr)
    print(f"[cleanup] → {args.output}", file=sys.stderr)
    if trim_examples:
        print(f"\n  Trim examples:", file=sys.stderr)
        for orig, new in trim_examples:
            print(f"    {orig!r} → {new!r}", file=sys.stderr)
    if drop_examples_placeholder:
        print(f"\n  Placeholder examples dropped:", file=sys.stderr)
        for p in drop_examples_placeholder:
            print(f"    {p!r}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
