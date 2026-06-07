"""Shared path-extraction and filter primitives for path-source modules.

``source_github.py`` and ``source_stackexchange.py`` both extract UNC
candidate paths from text fragments (GitHub code snippets, Stack Exchange
post bodies) and apply the same filter pipeline before emitting CSV
records. This module is the single source of truth for those primitives —
without it, a future divergence between the two sources' placeholder
lists is just waiting to happen.

Single discipline (load-bearing): any new source module MUST import its
extraction regex and filter functions from here, never duplicate them.
Adding a new placeholder, lab marker, or interpolation token happens
once, here.

Drive-path extraction was dropped (was in source_github before the first-
live-run filter pass). Reasoning preserved in source_github's module
docstring; pinned by ``test_drive_paths_not_extracted``.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

# ============================================================================
# UNC path-extraction regex
#
# Matches ``\\server\share[\sub...]``. Server allows alphanumeric +
# dot/hyphen/underscore (covers FQDN-style names). Share allows the
# above plus ``$`` for admin shares. Spaces deliberately excluded from
# share class — including them lets the share segment greedily swallow
# whitespace between adjacent UNC literals in a fragment, breaking
# multi-path extraction. Subpath components reject whitespace/quotes/
# control chars.
#
# Assumes LITERAL backslashes in the input fragment, matching the
# PowerShell/batch/cmd/ini/config languages targeted by source_github's
# query templates and the analogous fragments in Stack Exchange answers.
# C#/Java/JS escaped-backslash sources would not match (acceptable
# limitation for v0).
# ============================================================================

UNC_PATH_RE = re.compile(r"\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9._\-$]+(?:\\[^\\\s\"'<>|*?\x00-\x1f]+)*")


# ============================================================================
# Linux path-extraction regex (added v0.5 for Linux corpus expansion)
#
# Matches absolute Unix paths starting with a known-sensitive root
# (``/etc``, ``/root``, ``/home``, ``/var``, ``/opt``, ``/srv``,
# ``/tmp``, ``/mnt``, ``/media``, ``/data``, ``/usr/local``) and
# tilde-expanded paths (``~/...`` and ``~user/...``). The allowlist of
# roots is the extraction-time analogue of the path classifier's job:
# kernel pseudo-filesystems (``/proc``, ``/sys``, ``/dev``) and read-only
# system trees (``/bin``, ``/usr/bin``, ``/lib``, ``/boot``) are
# deliberately excluded — they never hold secrets and would drown the
# corpus in noise.
#
# Body class is conservative: ASCII alphanumerics + ``._/-``. Linux
# filenames technically allow almost any byte, but config-snippet
# fragments overwhelmingly stick to this subset. Spaces, quotes, and
# shell metachars stop the match so multi-path fragments extract cleanly.
# ============================================================================

_LINUX_ABSOLUTE_ROOT_RE = r"/(?:etc|root|home|var|opt|srv|tmp|mnt|media|data|usr/local)/"
_LINUX_TILDE_ROOT_RE = r"~(?:[A-Za-z_][A-Za-z0-9_-]*)?/"

LINUX_PATH_RE = re.compile(
    f"(?:{_LINUX_ABSOLUTE_ROOT_RE}|{_LINUX_TILDE_ROOT_RE})"
    r"[A-Za-z0-9._-][A-Za-z0-9._/-]*"
)


# ============================================================================
# Filter denylists
#
# Variable-interpolation chars: any of these in a path means it's a
# template, not a concrete path. Conservative — drop the whole candidate.
#
# Placeholder server names: case-insensitive exact-match set of common
# stand-ins (``server``, ``SERVERNAME``, ``yourserver``, etc.), plus
# substring patterns (``your-``, ``your_``), plus RFC1918 private IP
# ranges and loopback. Real server names like ``fs01``, ``fileserver01``,
# ``dc01.corp.local`` are unaffected.
# ============================================================================

VARIABLE_INTERPOLATION_CHARS = frozenset("${}%")

PLACEHOLDER_SERVERS = frozenset(
    {
        "server",
        "servername",
        "hostname",
        "host",
        "mycomputer",
        "pc-name",
        "computername",
        "your-server",
        "your_server",
        "yourserver",
        "example",
        "example.com",
        "domain.com",
        "domain.local",
        "placeholder",
        "name",
        "foo",
        "bar",
        "baz",
        "test",
        "localhost",
    }
)

PLACEHOLDER_SERVER_SUBSTRINGS = ("your-", "your_")

PRIVATE_OR_LOOPBACK_IP_RE = re.compile(
    r"^(?:"
    r"127\.\d+\.\d+\.\d+"
    r"|10\.\d+\.\d+\.\d+"
    r"|192\.168\.\d+\.\d+"
    r"|172\.(?:1[6-9]|2[0-9]|3[01])\.\d+\.\d+"
    r")$"
)

# Minimum UNC path length. ``\\srv\sh`` is 8 chars; ``\\srv\share`` is
# 10. Threshold at 10 drops obvious noise like ``\\a\b`` without
# excluding short-but-plausible real shares.
MIN_UNC_PATH_LEN = 10

# Minimum Linux path length. ``/etc/x`` is 6 chars; ``~/.x`` is 4. Set
# to 6 so the shortest sensible absolute path (``/tmp/x``, ``/etc/x``)
# passes but tilde nubs like ``~/.x`` are dropped as noise.
MIN_LINUX_PATH_LEN = 6


# ============================================================================
# Security/CTF source filter
#
# Drops candidates from public offensive-security/CTF sources and known
# unambiguous lab share/server names. Both source modules default this
# filter ON.
#
# Deliberately SHORT and HIGH-CONFIDENCE. Vincent's framing: the labeler
# is the final filter; an exhaustive denylist is a long tail not worth
# chasing. Entries here must be unambiguous as security/CTF markers —
# generic enterprise terms (``titan``, bare ``goad`` as a share name)
# are intentionally excluded to avoid killing real candidates.
#
# Asymmetry to note: ``goad`` is in the URL list (repo named goad IS the
# lab) but NOT the path list (a share named goad is ambiguous). Same
# logic applies to any future addition.
# ============================================================================

# Case-insensitive substring match against the provenance URL.
OFFENSIVE_SECURITY_URL_PATTERNS: tuple[str, ...] = (
    "poshc2",
    "metasploit",
    "meterpreter",
    "meterpeter",  # specific tool, deliberately distinct spelling
    "mishky",  # Mishkys-AD-Range repo (produced \\Marvel-DC\\HackMe in the first run)
    "mishkys",
    "cobaltstrike",
    "bloodhound",
    "goad",  # repo name only; not in path-marker list (share name ambiguous)
    "peass-ng",
    "covenant-c2",
    "sliver",
    "havoc",
    "crowdstrike-rtr",
    "redteamoperations",
    "offensive-",
    "red-team-",
    "pentestmonkey",
    "ired-team",
)

# Case-insensitive substring match against the extracted path.
# DELIBERATELY SHORT — only unambiguous lab markers. Common enterprise
# terms (``titan``, bare ``goad``) excluded; the URL list catches their
# repos.
LAB_PATH_MARKERS: tuple[str, ...] = (
    "marvel-dc",  # GOAD's Marvel-themed AD
    "hackme",
    "dreadgoad",
    "dreadgoat",
    "vulnvm",
    "vulnerablevm",
)


# ============================================================================
# Pure functions — path extraction and filtering
# ============================================================================


def extract_unc_paths(fragment: str) -> Iterator[str]:
    """Yield raw UNC paths from a single text fragment.

    No filtering applied here — caller is responsible for placeholder /
    interpolation / length / security-source checks. This function
    exists as its own pure primitive so the extraction regex is
    independently testable across all source modules that share it.
    """
    for m in UNC_PATH_RE.finditer(fragment):
        yield m.group(0)


def extract_linux_paths(fragment: str) -> Iterator[str]:
    """Yield raw Linux paths from a single text fragment.

    Strips trailing ``/`` and ``.`` from each match so end-of-sentence
    punctuation (``...see /etc/passwd.``) and trailing directory
    separators don't leak into the candidate. No other filtering
    applied — caller is responsible for placeholder / interpolation /
    length / security-source checks, mirroring ``extract_unc_paths``.
    """
    for m in LINUX_PATH_RE.finditer(fragment):
        yield m.group(0).rstrip("./")


def is_linux_too_short(path: str) -> bool:
    """True if the Linux path is shorter than ``MIN_LINUX_PATH_LEN``."""
    return len(path) < MIN_LINUX_PATH_LEN


def has_variable_interpolation(path: str) -> bool:
    """True if the path contains any of ``$``, ``{``, ``}``, ``%``.

    Covers PowerShell (``$server``), batch (``%COMPUTERNAME%``), .NET
    format strings (``{0}``), and similar. Conservative — drops the
    whole candidate; a path-with-a-variable resolves to nothing useful
    for the eval set.
    """
    return any(c in VARIABLE_INTERPOLATION_CHARS for c in path)


def is_too_short(path: str) -> bool:
    """True if the path is shorter than ``MIN_UNC_PATH_LEN``."""
    return len(path) < MIN_UNC_PATH_LEN


def is_placeholder_server(path: str) -> bool:
    """True if the UNC's server portion is a known placeholder, RFC1918
    IP, or contains template markers like ``<`` / ``>``."""
    rest = path[2:]  # strip leading \\
    server, _, _ = rest.partition("\\")
    server_lower = server.lower()
    if server_lower in PLACEHOLDER_SERVERS:
        return True
    if any(p in server_lower for p in PLACEHOLDER_SERVER_SUBSTRINGS):
        return True
    if "<" in server or ">" in server:
        return True
    if PRIVATE_OR_LOOPBACK_IP_RE.match(server):
        return True
    return False


def is_offensive_security_provenance(provenance_url: str, path: str) -> bool:
    """True if the candidate looks like it came from an offensive-
    security / CTF source — either the provenance URL matches a known
    repo/site pattern (``OFFENSIVE_SECURITY_URL_PATTERNS``) OR the path
    contains an unambiguous lab marker (``LAB_PATH_MARKERS``).

    Both lists are deliberately short and high-confidence; the labeler
    is the final filter for anything that slips through. Each source
    module's end-of-run summary prints the drop count for visible
    auditing.
    """
    url_lower = provenance_url.lower()
    if any(p in url_lower for p in OFFENSIVE_SECURITY_URL_PATTERNS):
        return True
    path_lower = path.lower()
    if any(m in path_lower for m in LAB_PATH_MARKERS):
        return True
    return False
