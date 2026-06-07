"""FileZilla SiteManager.xml — saved FTP/SFTP credentials (base64 password)."""
from __future__ import annotations
import base64
import re
import xml.etree.ElementTree as ET
from typing import Iterable
from sharesift.parsers.dispatch import ExtractedField


def register(reg):
    reg(r"^sitemanager\.xml$", parse_filezilla)
    reg(r"^recentservers\.xml$", parse_filezilla)


def parse_filezilla(content: str) -> Iterable[ExtractedField]:
    try:
        root = ET.fromstring(content.lstrip("﻿").strip())
    except ET.ParseError:
        # Regex fallback
        for m in re.finditer(r"<Pass\b[^>]*>([^<]+)</Pass>", content):
            val = m.group(1).strip()
            try:
                decoded = base64.b64decode(val + "==").decode("utf-8", errors="replace")
            except Exception:
                decoded = val
            yield ExtractedField(
                field_name="Pass",
                value=decoded,
                confidence=0.9,
                parser="filezilla_fallback",
            )
        return
    for server in root.iter():
        tag = server.tag.split("}", 1)[-1]
        if tag != "Server":
            continue
        host = server.findtext("Host", "")
        user = server.findtext("User", "")
        pw_el = server.find("Pass")
        if pw_el is not None and (pw_el.text or "").strip():
            raw = (pw_el.text or "").strip()
            encoding = pw_el.attrib.get("encoding", "")
            if encoding == "base64":
                try:
                    raw = base64.b64decode(raw + "==").decode("utf-8", errors="replace")
                except Exception:
                    pass
            yield ExtractedField(
                field_name=f"server[{host}].Pass",
                value=raw,
                confidence=0.95,
                parser="filezilla_sitemanager",
                context=f"Host={host} User={user}",
            )
