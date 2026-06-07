"""WinSCP.ini — saved session credentials (Password field is custom-obfuscated)."""
from __future__ import annotations
import configparser
import io
import re
from typing import Iterable
from sharesift.parsers.dispatch import ExtractedField


def register(reg):
    reg(r"^winscp\.ini$", parse_winscp)


def parse_winscp(content: str) -> Iterable[ExtractedField]:
    parser = configparser.ConfigParser(
        delimiters=("=",), strict=False, interpolation=None,
    )
    try:
        parser.read_string(content)
    except configparser.Error:
        # Fallback regex
        for m in re.finditer(r"Password\s*=\s*([^\r\n]+)", content):
            yield ExtractedField(
                field_name="Password",
                value=m.group(1).strip(),
                confidence=0.85,
                parser="winscp_fallback",
                context="(WinSCP obfuscated)",
            )
        return
    for section in parser.sections():
        if not section.lower().startswith("sessions"):
            continue
        host = parser.get(section, "HostName", fallback="")
        user = parser.get(section, "UserName", fallback="")
        if parser.has_option(section, "Password"):
            yield ExtractedField(
                field_name=f"[{section}].Password",
                value=parser.get(section, "Password"),
                confidence=0.95,
                parser="winscp_ini",
                context=f"HostName={host} UserName={user}",
            )
