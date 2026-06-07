"""Maven settings.xml — repository server credentials."""
from __future__ import annotations
import re
import xml.etree.ElementTree as ET
from typing import Iterable
from sharesift.parsers.dispatch import ExtractedField


def register(reg):
    reg(r"^settings\.xml$", parse_settings_xml)


def parse_settings_xml(content: str) -> Iterable[ExtractedField]:
    # Strip Maven default namespace so plain ET works
    cleaned = re.sub(r'xmlns(?::\w+)?="[^"]*"', '', content)
    try:
        root = ET.fromstring(cleaned.lstrip("﻿").strip())
    except ET.ParseError:
        for m in re.finditer(
            r"<server>[\s\S]*?<id>([^<]+)</id>[\s\S]*?<username>([^<]+)</username>"
            r"[\s\S]*?<password>([^<]+)</password>",
            content,
        ):
            yield ExtractedField(
                field_name=f"server[{m.group(1).strip()}].password",
                value=m.group(3).strip(),
                confidence=0.95,
                parser="maven_settings_fallback",
                context=f"username={m.group(2).strip()}",
            )
        return
    for el in root.iter():
        if el.tag.split("}", 1)[-1].lower() != "server":
            continue
        sid = el.findtext("id", "") or el.findtext("Id", "")
        user = el.findtext("username", "") or el.findtext("Username", "")
        pw = el.findtext("password", "") or el.findtext("Password", "")
        if pw and pw.strip():
            yield ExtractedField(
                field_name=f"server[{sid}].password",
                value=pw.strip(),
                confidence=0.95,
                parser="maven_settings",
                context=f"username={user}",
            )
