"""Recursive base64/url decode for hidden credential blobs.

Admins routinely store credentials base64-encoded inside ``.config``,
``.xml``, ``.ps1``, ``.json`` files — either as obfuscation (Windows
``ConvertFrom-SecureString``) or as legitimate envelope encoding (DPAPI
exports, signed tokens, certificate PEMs). Content rules running over
raw bytes miss these.

This preprocessor walks the file content, identifies "suspicious"
base64-shaped strings (long enough, valid alphabet, decodes to
printable text), decodes them, and appends the decoded text to the
content blob that downstream content rules scan. Recurses up to a
fixed depth.

Inspired by Gitleaks v8.20+ ``--max-decode-depth`` (Gitleaks 2026,
MIT).

Tunable knobs:

- ``min_blob_len`` — only decode strings at least this long (filters
  short coincidental matches)
- ``max_depth`` — recursion cap (default 3)
- ``max_total_bytes`` — overall expansion cap (default 1 MB)
"""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from dataclasses import dataclass

# Conservative base64-shape: at least 32 chars of standard alphabet
# plus optional padding. Tighter than ``[A-Za-z0-9+/=]+`` because we want
# to avoid matching ordinary identifiers (long variable names look
# base64-ish too).
_BASE64_BLOB = re.compile(
    r"(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2,3}={1,2})?"
)
# URL-safe base64 variant (used in JWT, modern token formats).
_BASE64_URL = re.compile(
    r"(?:[A-Za-z0-9_-]{4}){8,}(?:[A-Za-z0-9_-]{2,3}={0,2})?"
)
# Percent-encoded URL data (cred-bearing URL params). Match any
# substring containing at least one percent-escape; the decoder will
# unquote the whole thing. Length floor is enforced below.
_URL_ENCODED = re.compile(r"[A-Za-z0-9._~/:?&=+\-]*(?:%[0-9A-Fa-f]{2}[A-Za-z0-9._~/:?&=+\-]*)+")


@dataclass
class _Decode:
    method: str          # "base64", "base64url", "url"
    source_span: tuple[int, int]  # offset in original content
    decoded_text: str
    depth: int


def _try_decode_base64(blob: str, urlsafe: bool = False) -> str | None:
    """Return decoded text if decoding succeeds and the result is mostly
    printable; else None."""
    if len(blob) < 16:
        return None
    blob_padded = blob + "=" * (-len(blob) % 4)
    try:
        if urlsafe:
            decoded = base64.urlsafe_b64decode(blob_padded)
        else:
            decoded = base64.b64decode(blob_padded, validate=False)
    except (binascii.Error, ValueError):
        return None
    if not decoded:
        return None
    # Heuristic: result must be predominantly printable ASCII / UTF-8
    # to be useful for content scanning. Random binary won't trigger
    # password regexes anyway, but skipping it cuts noise.
    try:
        text = decoded.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        try:
            text = decoded.decode("latin-1", errors="replace")
        except Exception:
            return None
    printable = sum(1 for c in text if 32 <= ord(c) < 127 or c in "\r\n\t")
    if printable / max(1, len(text)) < 0.75:
        return None
    return text


def _try_decode_url(blob: str) -> str | None:
    try:
        decoded = urllib.parse.unquote(blob)
    except Exception:
        return None
    if decoded == blob:
        return None
    return decoded


def recursive_base64_decode(
    content: str,
    *,
    max_depth: int = 3,
    min_blob_len: int = 32,
    max_total_bytes: int = 1_000_000,
) -> tuple[str, list[_Decode]]:
    """Expand ``content`` by appending the decoded form of every
    base64-/url-encoded blob found, recursively up to ``max_depth``.

    Returns ``(expanded_content, decode_log)``. ``expanded_content`` is
    the original text plus a delimiter and the concatenation of each
    decoded blob (so downstream content rules see both forms). The
    decode log records what was decoded for diagnostics.
    """
    expanded_parts: list[str] = [content]
    log: list[_Decode] = []
    total_appended = 0
    queue: list[tuple[str, int]] = [(content, 0)]

    while queue and total_appended < max_total_bytes:
        text, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        for rex, method, urlsafe in (
            (_BASE64_BLOB, "base64", False),
            (_BASE64_URL, "base64url", True),
        ):
            for m in rex.finditer(text):
                blob = m.group(0)
                if len(blob) < min_blob_len:
                    continue
                decoded = _try_decode_base64(blob, urlsafe=urlsafe)
                if not decoded:
                    continue
                log.append(_Decode(method=method,
                                    source_span=(m.start(), m.end()),
                                    decoded_text=decoded[:5000],
                                    depth=depth))
                expanded_parts.append(decoded)
                total_appended += len(decoded)
                if total_appended >= max_total_bytes:
                    break
                if depth + 1 < max_depth:
                    queue.append((decoded, depth + 1))
            if total_appended >= max_total_bytes:
                break
        for m in _URL_ENCODED.finditer(text):
            blob = m.group(0)
            if len(blob) < 12:
                continue
            decoded = _try_decode_url(blob)
            if not decoded:
                continue
            log.append(_Decode(method="url",
                                source_span=(m.start(), m.end()),
                                decoded_text=decoded[:5000],
                                depth=depth))
            expanded_parts.append(decoded)
            total_appended += len(decoded)
            if total_appended >= max_total_bytes:
                break

    if len(expanded_parts) == 1:
        return content, log
    delim = "\n\n<<<TRUFFLER_DECODED>>>\n\n"
    return delim.join(expanded_parts), log


__all__ = ["recursive_base64_decode"]
