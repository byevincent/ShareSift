"""``.pypirc`` — PyPI upload tokens.

The ``.pypirc`` file lives at ``~/.pypirc`` and carries credentials
for ``twine upload``. Format is INI:

    [distutils]
    index-servers = pypi testpypi

    [pypi]
    username = __token__
    password = pypi-AgEIcHlwaS5vcmcCJDxxxxxxxxxxxxxxxx...

    [testpypi]
    repository = https://test.pypi.org/legacy/
    username = __token__
    password = pypi-AgENdGVzdC5weXBpLm9yZwIk...

The PyPI token format (``pypi-``-prefixed base64) is publicly
documented and used by both PyPI and TestPyPI.
"""

from __future__ import annotations

import configparser
import re
from typing import Iterable

from sharesift.parsers.dispatch import ExtractedField


def register(reg) -> None:
    reg(r"^\.pypirc$", parse_pypirc)
    reg(r"^pypirc$", parse_pypirc)


def parse_pypirc(content: str) -> Iterable[ExtractedField]:
    parser = configparser.ConfigParser(
        delimiters=("=",), strict=False, interpolation=None,
        allow_no_value=True,
    )
    try:
        parser.read_string(content)
    except configparser.Error:
        # Fallback: regex over password lines.
        for m in re.finditer(
            r"(?im)^\s*password\s*=\s*([^\r\n#]+)", content
        ):
            val = m.group(1).strip().strip('"').strip("'")
            if val:
                yield ExtractedField(
                    field_name="password",
                    value=val,
                    confidence=0.95,
                    parser="pypirc_fallback",
                )
        return

    for section in parser.sections():
        if section.lower() == "distutils":
            # Index list, not a credential block.
            continue
        for option in parser.options(section):
            lower = option.lower()
            if lower in ("password", "passwd"):
                val = (parser.get(section, option) or "").strip().strip('"').strip("'")
                if not val:
                    continue
                yield ExtractedField(
                    field_name=f"[{section}].password",
                    value=val,
                    confidence=0.95,
                    parser="pypirc",
                )
            elif lower == "username":
                val = (parser.get(section, option) or "").strip().strip('"').strip("'")
                if not val:
                    continue
                yield ExtractedField(
                    field_name=f"[{section}].username",
                    value=val,
                    confidence=0.5,  # may just be "__token__"
                    parser="pypirc",
                )
