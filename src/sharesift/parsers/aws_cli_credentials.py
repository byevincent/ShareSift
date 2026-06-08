"""AWS CLI credentials file — INI sections with access key + secret pairs.

The AWS CLI stores credentials in ``~/.aws/credentials`` as INI
format:

    [default]
    aws_access_key_id = AKIAIOSFODNN7EXAMPLE
    aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

    [production]
    aws_access_key_id = AKIAI44QH8DHBEXAMPLE
    aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
    aws_session_token = AQoDYXdzEJr...<remainder>

Per-profile credentials are independent. The file is high-frequency
on engineering shares and pickup of even one section is engagement-
level value.
"""

from __future__ import annotations

import configparser
import re
from typing import Iterable

from sharesift.parsers.dispatch import ExtractedField

_CRED_KEYS = {
    "aws_access_key_id": 0.85,
    "aws_secret_access_key": 0.95,
    "aws_session_token": 0.90,
}


def register(reg) -> None:
    # Match the canonical filename (no extension) and common backups.
    reg(r"^credentials$", parse_aws_credentials)
    reg(r"^aws_credentials$", parse_aws_credentials)
    reg(r"^credentials\.bak$", parse_aws_credentials)


def parse_aws_credentials(content: str) -> Iterable[ExtractedField]:
    parser = configparser.ConfigParser(
        delimiters=("=",), strict=False, interpolation=None,
        allow_no_value=True,
    )
    try:
        parser.read_string(content)
    except configparser.Error:
        # Fallback: regex over key = value lines.
        for key, conf in _CRED_KEYS.items():
            for m in re.finditer(
                rf"(?im)^\s*{re.escape(key)}\s*=\s*([^\r\n#]+)", content
            ):
                val = m.group(1).strip().strip('"').strip("'")
                if val and val.lower() != "none":
                    yield ExtractedField(
                        field_name=key,
                        value=val,
                        confidence=conf,
                        parser="aws_cli_credentials_fallback",
                    )
        return

    for section in parser.sections():
        for key, conf in _CRED_KEYS.items():
            if parser.has_option(section, key):
                val = (parser.get(section, key) or "").strip().strip('"').strip("'")
                if val and val.lower() != "none":
                    yield ExtractedField(
                        field_name=f"[{section}].{key}",
                        value=val,
                        confidence=conf,
                        parser="aws_cli_credentials",
                    )
