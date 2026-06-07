"""OpenVPN .ovpn / .conf — inline credentials + auth-user-pass path."""
from __future__ import annotations
import re
from typing import Iterable
from sharesift.parsers.dispatch import ExtractedField


def register(reg):
    reg(r"\.ovpn$", parse_openvpn)
    reg(r"^openvpn\.conf$", parse_openvpn)


_AUTH_USER_PASS = re.compile(r"(?m)^auth-user-pass\s+(\S+)")
_INLINE_AUTH = re.compile(
    r"(?ms)<auth-user-pass>\s*(.*?)\s*</auth-user-pass>"
)
_INLINE_KEY = re.compile(r"(?ms)<key>\s*(.*?)\s*</key>")
_INLINE_TLS_AUTH = re.compile(r"(?ms)<tls-auth>\s*(.*?)\s*</tls-auth>")
_INLINE_TLS_CRYPT = re.compile(r"(?ms)<tls-crypt>\s*(.*?)\s*</tls-crypt>")


def parse_openvpn(content: str) -> Iterable[ExtractedField]:
    m = _INLINE_AUTH.search(content)
    if m:
        lines = m.group(1).strip().splitlines()
        if len(lines) >= 2:
            yield ExtractedField(
                field_name=f"auth-user-pass[{lines[0]}]",
                value=lines[1],
                confidence=0.99,
                parser="openvpn",
                context="<auth-user-pass> inline block",
            )
    m = _INLINE_KEY.search(content)
    if m:
        body = m.group(1)
        if body.startswith("-----BEGIN") or "PRIVATE KEY" in body:
            yield ExtractedField(
                field_name="inline_private_key",
                value=body[:200] + ("...[truncated]" if len(body) > 200 else ""),
                confidence=0.98,
                parser="openvpn",
                context="<key> inline private key block",
            )
    for name, rex in (("tls-auth", _INLINE_TLS_AUTH), ("tls-crypt", _INLINE_TLS_CRYPT)):
        m = rex.search(content)
        if m:
            yield ExtractedField(
                field_name=f"inline_{name}",
                value=m.group(1)[:200],
                confidence=0.9,
                parser="openvpn",
                context=f"<{name}> inline key block",
            )
    m = _AUTH_USER_PASS.search(content)
    if m:
        yield ExtractedField(
            field_name="auth_user_pass_file",
            value=m.group(1),
            confidence=0.85,
            parser="openvpn",
            context="auth-user-pass FILE_PATH directive (creds in referenced file)",
        )
