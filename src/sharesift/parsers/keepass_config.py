"""KeePass.config.xml — DB location + key file paths (gives operator the
target to attack offline; the actual master password isn't in the config)."""
from __future__ import annotations
import re
import xml.etree.ElementTree as ET
from typing import Iterable
from sharesift.parsers.dispatch import ExtractedField


def register(reg):
    reg(r"^keepass(?:\.config)?\.xml$", parse_keepass_config)


def parse_keepass_config(content: str) -> Iterable[ExtractedField]:
    try:
        root = ET.fromstring(content.lstrip("﻿").strip())
    except ET.ParseError:
        for m in re.finditer(r"<KeySource[^>]*>([^<]+)</KeySource>", content):
            yield ExtractedField(
                field_name="KeySource",
                value=m.group(1).strip(),
                confidence=0.7,
                parser="keepass_fallback",
            )
        return
    for el in root.iter():
        tag = el.tag.split("}", 1)[-1].lower()
        if tag in ("databasepath", "keysource", "lastusedfile", "lastopenedfile"):
            txt = (el.text or "").strip()
            if txt:
                yield ExtractedField(
                    field_name=tag,
                    value=txt,
                    confidence=0.75,
                    parser="keepass_config",
                    context="KeePass DB target (decrypt offline)",
                )
