"""Veeam Backup config XML — extracts account references + encrypted creds.

Veeam config files (``Config.xml``, ``VeeamBackup*.xml``, ``*.veeam.*``)
contain credential references that route through Veeam's internal
crypto. We extract::

  - account names / DNs from <Account>...</Account>
  - encrypted password blobs (operator can crack offline / use
    Veeam's decrypt tooling)
  - any element whose tag ends with "Password" or "Secret"
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Iterable

from sharesift.parsers.dispatch import ExtractedField


def register(reg):
    reg(r"^veeam[\w-]*\.config$", parse_veeam)
    reg(r"^veeam[\w-]*\.xml$", parse_veeam)
    reg(r"^veeambackup[\w-]*\.(config|xml)$", parse_veeam)


_PASSWORD_TAG = re.compile(r"password|secret|encrypted", re.IGNORECASE)
_ACCOUNT_TAG = re.compile(r"account|username|user|login", re.IGNORECASE)


def parse_veeam(content: str) -> Iterable[ExtractedField]:
    cleaned = content.lstrip("﻿").strip()
    try:
        root = ET.fromstring(cleaned)
    except ET.ParseError:
        yield from _parse_via_regex(content)
        return

    for el in root.iter():
        tag = el.tag.split("}", 1)[-1]
        text = (el.text or "").strip()
        if not text:
            continue
        if _PASSWORD_TAG.search(tag):
            yield ExtractedField(
                field_name=tag,
                value=text,
                confidence=0.9,
                parser="veeam_config_xml",
                context=f"<{tag}> (likely encrypted)",
            )
        elif _ACCOUNT_TAG.search(tag):
            yield ExtractedField(
                field_name="username",
                value=text,
                confidence=0.85,
                parser="veeam_config_xml",
                context=f"<{tag}>",
            )


def _parse_via_regex(content: str) -> Iterable[ExtractedField]:
    for m in re.finditer(
        r"<(\w*(?:[Pp]assword|[Ss]ecret|[Ee]ncrypted)\w*)>([^<]+)</\1>", content
    ):
        yield ExtractedField(
            field_name=m.group(1),
            value=m.group(2).strip(),
            confidence=0.85,
            parser="veeam_config_xml",
            context="(malformed XML fallback)",
        )
