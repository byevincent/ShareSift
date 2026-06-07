"""MySQL .my.cnf / my.ini — client password in [client] / [mysql] sections."""
from __future__ import annotations
import configparser
import re
from typing import Iterable
from sharesift.parsers.dispatch import ExtractedField


def register(reg):
    reg(r"^\.my\.cnf$", parse_my_cnf)
    reg(r"^my\.cnf$", parse_my_cnf)
    reg(r"^client\.cnf$", parse_my_cnf)


def parse_my_cnf(content: str) -> Iterable[ExtractedField]:
    parser = configparser.ConfigParser(
        delimiters=("=",), strict=False, interpolation=None,
        allow_no_value=True,
    )
    try:
        parser.read_string(content)
    except configparser.Error:
        for m in re.finditer(r"(?im)^\s*password\s*=\s*([^\r\n#]+)", content):
            yield ExtractedField(
                field_name="password",
                value=m.group(1).strip().strip('"').strip("'"),
                confidence=0.9,
                parser="my_cnf_fallback",
            )
        return
    for section in parser.sections():
        for option in parser.options(section):
            if option.lower() in ("password", "pass", "passwd"):
                val = (parser.get(section, option) or "").strip().strip('"').strip("'")
                if val:
                    yield ExtractedField(
                        field_name=f"[{section}].{option}",
                        value=val,
                        confidence=0.95,
                        parser="my_cnf",
                    )
