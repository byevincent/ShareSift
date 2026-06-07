"""ASP.NET / IIS web.config + app.config — connection strings, appSettings."""
from __future__ import annotations
import re
import xml.etree.ElementTree as ET
from typing import Iterable
from sharesift.parsers.dispatch import ExtractedField


def register(reg):
    reg(r"^(web|app|appsettings)\.config$", parse_web_config)
    reg(r"^applicationhost\.config$", parse_web_config)
    reg(r"^machine\.config$", parse_web_config)


_CRED_HINTS = ("password", "pwd", "secret", "key", "token", "apikey", "auth")


def _has_cred_hint(s: str) -> bool:
    s_low = s.lower()
    return any(h in s_low for h in _CRED_HINTS)


def parse_web_config(content: str) -> Iterable[ExtractedField]:
    # XML parsing is robust against the format. Fall back to regex
    # if parsing fails (mis-formed configs are common).
    try:
        # Strip BOM and any leading garbage so ElementTree accepts it
        cleaned = content.lstrip("﻿").strip()
        root = ET.fromstring(cleaned)
    except ET.ParseError:
        yield from _parse_via_regex(content)
        return

    # connectionStrings/add[@connectionString]
    for el in root.iter():
        tag = el.tag.split("}", 1)[-1].lower()
        if tag == "add" and "connectionString" in el.attrib:
            cs = el.attrib["connectionString"]
            if _has_cred_hint(cs):
                yield ExtractedField(
                    field_name="connectionString",
                    value=cs,
                    confidence=0.9,
                    parser="web_config",
                    context=f'<add name="{el.attrib.get("name", "")}" providerName="{el.attrib.get("providerName", "")}">',
                )
        # appSettings entries with password-ish keys
        if tag == "add" and "key" in el.attrib and "value" in el.attrib:
            key = el.attrib["key"]
            if _has_cred_hint(key):
                yield ExtractedField(
                    field_name=key,
                    value=el.attrib["value"],
                    confidence=0.7,
                    parser="web_config",
                    context=f'<appSettings/add key="{key}">',
                )
        # identityRef / impersonate / aspnet sessionState
        if tag == "sessionstate" and "stateConnectionString" in el.attrib:
            yield ExtractedField(
                field_name="stateConnectionString",
                value=el.attrib["stateConnectionString"],
                confidence=0.85,
                parser="web_config",
                context="<sessionState>",
            )
        if tag == "identity" and "password" in el.attrib:
            yield ExtractedField(
                field_name="identity.password",
                value=el.attrib["password"],
                confidence=0.95,
                parser="web_config",
                context=f'<identity userName="{el.attrib.get("userName", "")}">',
            )


def _parse_via_regex(content: str) -> Iterable[ExtractedField]:
    # Best-effort fallback for mis-formed XML
    for m in re.finditer(r'connectionString\s*=\s*"([^"]+)"', content, re.IGNORECASE):
        if _has_cred_hint(m.group(1)):
            yield ExtractedField(
                field_name="connectionString",
                value=m.group(1),
                confidence=0.7,
                parser="web_config_fallback",
                context="(malformed XML)",
            )
    for m in re.finditer(r'<identity[^>]*password\s*=\s*"([^"]+)"', content, re.IGNORECASE):
        yield ExtractedField(
            field_name="identity.password",
            value=m.group(1),
            confidence=0.85,
            parser="web_config_fallback",
            context="(malformed XML)",
        )
