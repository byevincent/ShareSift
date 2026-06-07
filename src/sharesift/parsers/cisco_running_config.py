"""Cisco IOS running-config — enable secrets, local users, SNMP community.

Common lines we extract::

    enable secret 5 $1$...               # type 5 MD5 hash (offline crack)
    enable secret 9 $9$...               # type 9 scrypt hash (slow crack)
    enable secret 0 plaintext            # type 0 literal
    enable password 7 <reversible>       # type 7 reversible XOR
    username admin password 7 ...
    username admin secret 5 ...
    snmp-server community public RO
    crypto isakmp key 0 cisco123 address ...
"""

from __future__ import annotations

import re
from typing import Iterable

from sharesift.parsers.dispatch import ExtractedField


def register(reg):
    reg(r"^running-config$", parse_cisco_running_config)
    reg(r"^startup-config$", parse_cisco_running_config)
    reg(r"\.cfg$", parse_cisco_running_config_maybe)
    reg(r"\.ios$", parse_cisco_running_config)


def _looks_cisco(content: str) -> bool:
    """Sniff for Cisco IOS-shape configs before extracting from generic .cfg files."""
    markers = ("enable secret", "ip access-list", "interface FastEthernet",
               "interface GigabitEthernet", "line vty", "snmp-server community",
               "ip route", "router ospf", "router eigrp", "version 1",
               "no service password-encryption", "service password-encryption")
    return sum(m in content for m in markers) >= 2


def parse_cisco_running_config_maybe(content: str) -> Iterable[ExtractedField]:
    """Generic .cfg dispatcher — sniff for Cisco shape first."""
    if _looks_cisco(content):
        yield from parse_cisco_running_config(content)


_ENABLE_SECRET = re.compile(r"^enable (secret|password)\s+(\d+)\s+(\S+)", re.MULTILINE)
_USERNAME = re.compile(
    r"^username\s+(\S+)\s+(?:privilege\s+\d+\s+)?(password|secret)\s+(\d+)\s+(\S+)",
    re.MULTILINE,
)
_SNMP_COMMUNITY = re.compile(
    r"^snmp-server community\s+(\S+)\s+(RO|RW|view\s+\S+)?", re.MULTILINE
)
_CRYPTO_KEY = re.compile(
    r"^crypto isakmp key\s+(?:\d+\s+)?(\S+)\s+address\s+(\S+)", re.MULTILINE
)


def parse_cisco_running_config(content: str) -> Iterable[ExtractedField]:
    for m in _ENABLE_SECRET.finditer(content):
        kind, type_num, value = m.group(1), m.group(2), m.group(3)
        confidence = 0.95 if kind == "secret" else 0.9
        yield ExtractedField(
            field_name=f"enable_{kind}_type{type_num}",
            value=value,
            confidence=confidence,
            parser="cisco_running_config",
            context=f"enable {kind} {type_num} ...",
        )
    for m in _USERNAME.finditer(content):
        user, kind, type_num, value = m.group(1), m.group(2), m.group(3), m.group(4)
        yield ExtractedField(
            field_name="username",
            value=user,
            confidence=0.85,
            parser="cisco_running_config",
            context=f"username {user} ...",
        )
        yield ExtractedField(
            field_name=f"password_type{type_num}",
            value=value,
            confidence=0.95,
            parser="cisco_running_config",
            context=f"username {user} {kind} {type_num} ...",
        )
    for m in _SNMP_COMMUNITY.finditer(content):
        yield ExtractedField(
            field_name="snmp_community",
            value=m.group(1),
            confidence=0.95,
            parser="cisco_running_config",
            context=f"snmp-server community ({m.group(2) or 'RO'})",
        )
    for m in _CRYPTO_KEY.finditer(content):
        yield ExtractedField(
            field_name="crypto_isakmp_key",
            value=m.group(1),
            confidence=0.95,
            parser="cisco_running_config",
            context=f"crypto isakmp key ... address {m.group(2)}",
        )
