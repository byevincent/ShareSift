"""PuTTY ``.ppk`` key files — used by PuTTY / WinSCP on Windows.

Format (well-documented):

    PuTTY-User-Key-File-2: ssh-rsa
    Encryption: none
    Comment: my-server-key
    Public-Lines: 6
    AAAAB3NzaC1yc2EAAAADAQAB...
    Private-Lines: 14
    AAABABCD...
    Private-MAC: a1b2c3d4...

``Encryption: none`` → the private body is base64-encoded plaintext.
``Encryption: aes256-cbc`` (or aes256-gcm in v3) → the body is
ciphertext, decryptable offline with the user's PPK passphrase.

We don't try to decrypt — we surface:

* The PPK version (v2 / v3) and key algorithm
* The encryption status
* The comment (typically a hostname or user identification)
* The public-key body (useful for matching against an authorized_keys
  file once the operator has access)

Encrypted PPK private bodies stay opaque; flagging the file as
"present + encrypted" is the operational signal.
"""

from __future__ import annotations

import re
from typing import Iterable

from sharesift.parsers.dispatch import ExtractedField

_HEADER = re.compile(
    r"^PuTTY-User-Key-File-(?P<version>\d+):\s*(?P<algo>[\w\-]+)\s*$",
    re.MULTILINE,
)
_FIELD = re.compile(
    r"^(?P<key>Encryption|Comment|Public-Lines|Private-Lines|Private-MAC|Key-Derivation|Argon2-Memory|Argon2-Passes|Argon2-Parallelism|Argon2-Salt):\s*(?P<value>.+)$",
    re.MULTILINE,
)


def register(reg) -> None:
    reg(r"\.ppk$", parse_ppk)


def parse_ppk(content: str) -> Iterable[ExtractedField]:
    header = _HEADER.search(content)
    if not header:
        return
    version = header.group("version")
    algo = header.group("algo")

    fields = {m.group("key"): m.group("value").strip() for m in _FIELD.finditer(content)}
    encryption = fields.get("Encryption", "unknown")
    comment = fields.get("Comment", "")

    # File presence is the headline.
    yield ExtractedField(
        field_name=f"ppk_v{version}_{algo}",
        value=f"encryption={encryption}; comment={comment}",
        # Encrypted PPK = lower confidence as a credential (passphrase
        # required), but the file's existence is still a high signal.
        confidence=0.6 if encryption.lower() != "none" else 0.9,
        parser="putty_ppk",
        context=encryption,
    )

    if encryption.lower() == "none":
        # Plaintext private key body is encoded after "Private-Lines:".
        # Extract the base64 chunk for downstream operator triage; the
        # SSH-key extractor in verify/extractor.py won't catch it
        # because PPK isn't PEM-shaped.
        m = re.search(
            r"^Private-Lines:\s*\d+\s*$\n(?P<body>(?:[A-Za-z0-9+/=]+\s*\n)+)",
            content,
            re.MULTILINE,
        )
        if m:
            body = m.group("body").strip()
            yield ExtractedField(
                field_name="private_key_body",
                value=body[:200] + ("..." if len(body) > 200 else ""),
                confidence=0.95,
                parser="putty_ppk",
                context="base64; reassemble lines for full key material",
            )
