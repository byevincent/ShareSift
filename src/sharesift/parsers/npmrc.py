"""npm .npmrc — auth tokens (npm + GitHub package registry)."""
from __future__ import annotations
import re
from typing import Iterable
from sharesift.parsers.dispatch import ExtractedField


def register(reg):
    reg(r"^\.npmrc$", parse_npmrc)


_AUTH_LINE = re.compile(
    r"(?im)^//(?P<registry>[^:]+):_authToken=(?P<token>\S+)$"
)
_PASSWORD_LINE = re.compile(
    r"(?im)^//(?P<registry>[^:]+):_password=(?P<password>\S+)$"
)


def parse_npmrc(content: str) -> Iterable[ExtractedField]:
    for m in _AUTH_LINE.finditer(content):
        yield ExtractedField(
            field_name=f"{m.group('registry')}._authToken",
            value=m.group("token"),
            confidence=0.95,
            parser="npmrc",
        )
    for m in _PASSWORD_LINE.finditer(content):
        yield ExtractedField(
            field_name=f"{m.group('registry')}._password",
            value=m.group("password"),
            confidence=0.95,
            parser="npmrc",
        )
