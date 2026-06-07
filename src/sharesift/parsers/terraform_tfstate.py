"""Terraform state file — extracts provider secrets + sensitive outputs.

State files (``terraform.tfstate`` / ``*.tfstate``) embed provider
credentials and resource attributes in plain JSON. Common cred-bearing
shapes::

    resources[].instances[].attributes.{secret, password, *_key,
    credentials, ...}
    outputs.{...}.value when outputs.{...}.sensitive == true

The parser only emits fields whose name contains a credential token
(password, secret, key, token, etc.) to avoid drowning the operator
in non-credential resource attributes.
"""

from __future__ import annotations

import json
import re
from typing import Iterable

from sharesift.parsers.dispatch import ExtractedField


def register(reg):
    reg(r"\.tfstate(?:\.backup)?$", parse_tfstate)
    reg(r"^terraform\.tfstate$", parse_tfstate)


_CRED_TOKEN = re.compile(
    r"password|secret|token|access_key|api_key|client_secret|"
    r"private_key|credentials|connection_string",
    re.IGNORECASE,
)


def _is_cred_field(name: str) -> bool:
    return bool(_CRED_TOKEN.search(name or ""))


def _walk(node, path: str) -> Iterable[tuple[str, str]]:
    if isinstance(node, dict):
        for k, v in node.items():
            child_path = f"{path}.{k}" if path else k
            if isinstance(v, (str, int, float)) and _is_cred_field(k) and v:
                yield child_path, str(v)
            else:
                yield from _walk(v, child_path)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            yield from _walk(item, f"{path}[{i}]")


def parse_tfstate(content: str) -> Iterable[ExtractedField]:
    try:
        state = json.loads(content)
    except (ValueError, TypeError):
        return
    if not isinstance(state, dict):
        return
    for field_path, value in _walk(state, ""):
        yield ExtractedField(
            field_name=field_path,
            value=value,
            confidence=0.9,
            parser="terraform_tfstate",
            context=f"tfstate@{field_path}",
        )
    # Sensitive outputs — flagged explicitly even if field name doesn't match
    for out_name, out_data in (state.get("outputs") or {}).items():
        if isinstance(out_data, dict) and out_data.get("sensitive"):
            v = out_data.get("value")
            if v is None:
                continue
            yield ExtractedField(
                field_name=f"outputs.{out_name}.value",
                value=str(v),
                confidence=0.95,
                parser="terraform_tfstate",
                context="sensitive=true",
            )
