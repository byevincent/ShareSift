"""``.netrc`` — machine/login/password tokens used by curl/wget/git CLI.

The format is whitespace-separated tokens with no per-machine
delimiter — entries chain until the next ``machine`` token. A
``default`` block matches anything not explicitly listed.

    machine api.example.com
        login alice
        password secret123
    machine other.example.com login bob password hunter2

Single-line and multi-line forms are both valid. Tokens may be
quoted but commonly aren't.
"""

from __future__ import annotations

import re
from typing import Iterable

from sharesift.parsers.dispatch import ExtractedField

_TOKEN = re.compile(r"\S+")


def register(reg) -> None:
    reg(r"^\.netrc$", parse_netrc)
    reg(r"^_netrc$", parse_netrc)  # Windows variant
    reg(r"^netrc$", parse_netrc)


def parse_netrc(content: str) -> Iterable[ExtractedField]:
    tokens = _TOKEN.findall(content)
    i = 0
    current_machine = None
    while i < len(tokens):
        tok = tokens[i].lower()
        if tok == "machine":
            i += 1
            if i < len(tokens):
                current_machine = tokens[i]
            i += 1
            continue
        if tok == "default":
            current_machine = "default"
            i += 1
            continue
        if tok in ("login", "user", "password", "account", "macdef"):
            field = tok
            i += 1
            if i >= len(tokens):
                break
            value = tokens[i].strip('"').strip("'")
            i += 1
            if field == "macdef":
                # macros — skip until empty line / next directive
                continue
            if field in ("login", "user"):
                yield ExtractedField(
                    field_name=f"{current_machine or 'unknown'}.username",
                    value=value,
                    confidence=0.7,
                    parser="netrc",
                    context=field,
                )
            elif field == "password":
                yield ExtractedField(
                    field_name=f"{current_machine or 'unknown'}.password",
                    value=value,
                    confidence=0.95,
                    parser="netrc",
                )
            elif field == "account":
                yield ExtractedField(
                    field_name=f"{current_machine or 'unknown'}.account_password",
                    value=value,
                    confidence=0.85,
                    parser="netrc",
                )
            continue
        # Unknown token — skip
        i += 1
