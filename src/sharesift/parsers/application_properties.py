"""Java application.properties / spring boot application.yml — db.password etc."""
from __future__ import annotations
import re
from typing import Iterable
from sharesift.parsers.dispatch import ExtractedField


def register(reg):
    reg(r"^application(?:-[\w]+)?\.properties$", parse_properties)
    reg(r"^(application|bootstrap)(?:-[\w]+)?\.ya?ml$", parse_spring_yaml)
    reg(r"\.properties$", parse_properties)


_CRED_KEYS = re.compile(
    r"^(?P<key>[\w.]*?(?:password|pwd|secret|token|apikey|api[_.]key|"
    r"private[_.]key|access[_.]key|client[_.]secret|auth[_.]token)[\w.]*?)"
    r"\s*=\s*(?P<val>.+)$",
    re.IGNORECASE | re.MULTILINE,
)


def parse_properties(content: str) -> Iterable[ExtractedField]:
    for m in _CRED_KEYS.finditer(content):
        key = m.group("key").strip()
        val = m.group("val").strip().strip('"').strip("'")
        if not val or val.startswith("${"):
            # Spring placeholder ${ENV_VAR} — not a literal
            continue
        # Skip variable references and obvious placeholders
        if val.upper() in ("CHANGEME", "CHANGE_ME", "YOUR_PASSWORD", "TODO", "XXX", ""):
            continue
        yield ExtractedField(
            field_name=key,
            value=val,
            confidence=0.9 if "password" in key.lower() else 0.75,
            parser="application_properties",
            context=f"line: {key}=...",
        )


_YAML_CRED = re.compile(
    r"(?im)^\s*(?P<key>[\w.-]*?(?:password|pwd|secret|token|apikey|api[_.]key|"
    r"private[_.]key|access[_.]key|client[_.]secret|auth[_.]token)[\w.-]*?)"
    r"\s*:\s*['\"]?(?P<val>[^\s'\"#][^\r\n'\"#]*)['\"]?",
)


def parse_spring_yaml(content: str) -> Iterable[ExtractedField]:
    for m in _YAML_CRED.finditer(content):
        key = m.group("key").strip()
        val = m.group("val").strip()
        if not val or val.startswith("${"):
            continue
        if val.upper() in ("CHANGEME", "CHANGE_ME", "YOUR_PASSWORD", "TODO", "XXX"):
            continue
        yield ExtractedField(
            field_name=key,
            value=val,
            confidence=0.85,
            parser="spring_yaml",
            context=f"yaml: {key}:",
        )
