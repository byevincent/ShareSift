"""GPP Preferences XMLs — Groups.xml / Services.xml / ScheduledTasks.xml etc.

Each carries a ``cpassword`` attribute on a ``<Properties>`` element, AES-256
encrypted with a publicly published key (MS14-025). We extract the raw
encrypted blob; downstream tooling (or operator) can decrypt offline.
"""
from __future__ import annotations
import re
import xml.etree.ElementTree as ET
from typing import Iterable
from sharesift.parsers.dispatch import ExtractedField


def register(reg):
    reg(r"^(groups|services|scheduledtasks|printers|drives|datasources)\.xml$",
        parse_gpp_xml)


def parse_gpp_xml(content: str) -> Iterable[ExtractedField]:
    try:
        root = ET.fromstring(content.lstrip("﻿").strip())
    except ET.ParseError:
        for m in re.finditer(r'cpassword\s*=\s*"([^"]+)"', content, re.IGNORECASE):
            if m.group(1).strip():
                yield ExtractedField(
                    field_name="cpassword",
                    value=m.group(1).strip(),
                    confidence=0.99,
                    parser="gpp_xml_fallback",
                    context="(malformed XML)",
                )
        return
    for el in root.iter():
        # Properties element has cpassword as attribute
        if "cpassword" in el.attrib:
            cp = el.attrib["cpassword"].strip()
            if cp:
                user = el.attrib.get("userName", "") or el.attrib.get("newName", "")
                action = el.attrib.get("action", "")
                yield ExtractedField(
                    field_name=f"cpassword[{user or 'unknown'}]",
                    value=cp,
                    confidence=0.99,
                    parser="gpp_xml",
                    context=f'<Properties action="{action}" userName="{user}">',
                )
