"""Apache Tomcat tomcat-users.xml — user/password tuples."""
from __future__ import annotations
import re
import xml.etree.ElementTree as ET
from typing import Iterable
from sharesift.parsers.dispatch import ExtractedField


def register(reg):
    reg(r"^tomcat-users\.xml$", parse_tomcat_users)


def parse_tomcat_users(content: str) -> Iterable[ExtractedField]:
    cleaned = re.sub(r'xmlns(?::\w+)?="[^"]*"', '', content)
    try:
        root = ET.fromstring(cleaned.lstrip("﻿").strip())
    except ET.ParseError:
        # Fallback regex
        for m in re.finditer(
            r'<user[^>]*username\s*=\s*"([^"]+)"[^>]*password\s*=\s*"([^"]+)"',
            content, re.IGNORECASE,
        ):
            yield ExtractedField(
                field_name=f"user[{m.group(1)}].password",
                value=m.group(2),
                confidence=0.85,
                parser="tomcat_users_fallback",
            )
        return
    for el in root.iter():
        if el.tag.split("}", 1)[-1].lower() != "user":
            continue
        username = el.attrib.get("username") or el.attrib.get("name")
        password = el.attrib.get("password")
        if username and password:
            yield ExtractedField(
                field_name=f"user[{username}].password",
                value=password,
                confidence=0.95,
                parser="tomcat_users",
                context=f"<user roles=\"{el.attrib.get('roles', '')}\">",
            )
