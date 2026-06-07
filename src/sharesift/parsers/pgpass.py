"""PostgreSQL .pgpass — colon-separated host:port:db:user:password."""
from __future__ import annotations
from typing import Iterable
from sharesift.parsers.dispatch import ExtractedField


def register(reg):
    reg(r"^\.pgpass$", parse_pgpass)
    reg(r"^pgpass\.conf$", parse_pgpass)


def parse_pgpass(content: str) -> Iterable[ExtractedField]:
    for line_no, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # host:port:database:user:password (colons inside fields escaped with backslash)
        parts: list[str] = []
        current = ""
        i = 0
        while i < len(line):
            c = line[i]
            if c == "\\" and i + 1 < len(line):
                current += line[i + 1]
                i += 2
                continue
            if c == ":":
                parts.append(current)
                current = ""
                i += 1
                continue
            current += c
            i += 1
        parts.append(current)
        if len(parts) != 5:
            continue
        host, port, db, user, password = parts
        if password and password != "*":
            yield ExtractedField(
                field_name=f"{user}@{host}:{port}/{db}",
                value=password,
                confidence=0.99,
                parser="pgpass",
                context=f"line {line_no}",
            )
