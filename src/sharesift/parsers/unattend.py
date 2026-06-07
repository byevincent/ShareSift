"""Windows unattend.xml — AdministratorPassword + AutoLogon."""
from __future__ import annotations
import base64
import re
import xml.etree.ElementTree as ET
from typing import Iterable
from sharesift.parsers.dispatch import ExtractedField


def register(reg):
    reg(r"^(auto)?unattend\.xml$", parse_unattend)
    reg(r"^sysprep\.inf$", parse_unattend)


def parse_unattend(content: str) -> Iterable[ExtractedField]:
    # Drop namespace prefixes to make ElementTree happy with mixed XML
    # styles (Win7/Win10 unattend formats share schema modulo namespace).
    cleaned = re.sub(r'xmlns(?::\w+)?="[^"]*"', '', content)
    try:
        root = ET.fromstring(cleaned.lstrip("﻿").strip())
    except ET.ParseError:
        yield from _parse_via_regex(content)
        return
    for el in root.iter():
        tag = el.tag.split("}", 1)[-1]
        if tag in ("AdministratorPassword", "DomainPassword", "Password"):
            value_el = el.find(".//Value") or el.find("./Value")
            plain = (value_el.text if value_el is not None else el.text) or ""
            plain_text = (plain or "").strip()
            if not plain_text:
                continue
            # PlainText flag indicates b64 encoded
            plaintext_flag_el = el.find(".//PlainText") or el.find("./PlainText")
            is_b64 = (plaintext_flag_el is not None and
                      (plaintext_flag_el.text or "").strip().lower() == "false")
            value = plain_text
            decoded = None
            if is_b64:
                try:
                    decoded_raw = base64.b64decode(plain_text)
                    decoded = decoded_raw.decode("utf-16-le", errors="ignore")
                    # Microsoft appends the field-name literal AFTER the
                    # actual password (e.g. value="Password123" + "Administrator-
                    # Password" → "Password123AdministratorPassword"). Only
                    # strip these suffixes at the end of the decoded string.
                    for suffix in (tag, "AdministratorPassword", "Password"):
                        if decoded.endswith(suffix):
                            decoded = decoded[: -len(suffix)]
                            break
                    decoded = decoded.strip("\x00").strip()
                except Exception:
                    decoded = None
            yield ExtractedField(
                field_name=tag,
                value=decoded or value,
                confidence=0.95,
                parser="unattend",
                context=f"<{tag}>{'(b64-decoded)' if decoded else ''}",
            )
        if tag == "AutoLogon":
            user_el = el.find(".//Username") or el.find(".//UserName")
            pw_el = el.find(".//Password/Value") or el.find(".//Password")
            if user_el is not None and pw_el is not None:
                yield ExtractedField(
                    field_name="AutoLogon.Password",
                    value=(pw_el.text or "").strip(),
                    confidence=0.95,
                    parser="unattend",
                    context=f"AutoLogon for {(user_el.text or '').strip()}",
                )


def _parse_via_regex(content: str) -> Iterable[ExtractedField]:
    for m in re.finditer(
        r"<AdministratorPassword>\s*<Value>([^<]+)</Value>",
        content, re.IGNORECASE,
    ):
        yield ExtractedField(
            field_name="AdministratorPassword",
            value=m.group(1).strip(),
            confidence=0.9,
            parser="unattend_fallback",
            context="(regex fallback)",
        )
