"""Python ``keyring`` cleartext / file-backend storage.

Most ``keyring`` deployments use OS-native backends (Windows Cred
Manager, macOS Keychain, libsecret), but the ``keyrings.alt`` package
adds plaintext / encrypted-file fallback backends commonly seen on
CI runners and Linux servers without dbus:

* ``~/.local/share/python_keyring/keyring_pass.cfg`` — base64-
  encoded passwords under per-service INI sections
* ``~/.local/share/python_keyring/keyring_cryptfile_pass.cfg`` —
  AES-encrypted blobs (we surface the presence; decryption is
  offline operator work)
* ``keyringrc.cfg`` — backend config that may name a non-OS backend

Schema (keyring_pass.cfg, INI):

    [service-name]
    user_a = base64encodedpassword==
    user_b = base64encodedpassword==

The base64-encoded passwords are de-facto plaintext for any
attacker holding the file.
"""

from __future__ import annotations

import configparser
import re
from typing import Iterable

from sharesift.parsers.dispatch import ExtractedField


def register(reg) -> None:
    reg(r"^keyring_pass\.cfg$", parse_keyring_pass)
    reg(r"^keyring_cryptfile_pass\.cfg$", parse_keyring_cryptfile)
    reg(r"^keyringrc\.cfg$", parse_keyringrc)


def parse_keyring_pass(content: str) -> Iterable[ExtractedField]:
    parser = configparser.ConfigParser(
        delimiters=("=",), strict=False, interpolation=None,
        allow_no_value=True,
    )
    try:
        parser.read_string(content)
    except configparser.Error:
        return
    for section in parser.sections():
        for user in parser.options(section):
            val = (parser.get(section, user) or "").strip()
            if not val:
                continue
            yield ExtractedField(
                field_name=f"[{section}].{user}",
                value=val,
                confidence=0.90,  # base64 of cleartext password
                parser="keyring_pass",
            )


def parse_keyring_cryptfile(content: str) -> Iterable[ExtractedField]:
    """Encrypted file backend — surface presence + structure.

    The crypt file holds AES-encrypted blobs. We can't decrypt them
    without the master password, but flagging the file's existence
    + listing the (service, user) tuples it covers is operationally
    useful.
    """
    parser = configparser.ConfigParser(
        delimiters=("=",), strict=False, interpolation=None,
        allow_no_value=True,
    )
    try:
        parser.read_string(content)
    except configparser.Error:
        return
    for section in parser.sections():
        for user in parser.options(section):
            yield ExtractedField(
                field_name=f"[{section}].{user}",
                value="(encrypted blob present)",
                confidence=0.6,
                parser="keyring_cryptfile",
                context="encrypted; decryption requires offline crypto",
            )


def parse_keyringrc(content: str) -> Iterable[ExtractedField]:
    """Backend config — surfaces which storage backend is configured.

    Operational signal: if ``default-keyring`` names ``PlaintextKeyring``
    or ``EncryptedKeyring``, there's a cleartext / encrypted file
    nearby. Otherwise (e.g. native OS Keychain backend) this is just
    config metadata.
    """
    for m in re.finditer(
        r"(?im)^\s*default-keyring\s*=\s*([^\r\n#]+)", content
    ):
        val = m.group(1).strip().strip('"').strip("'")
        if not val:
            continue
        risky = any(token in val.lower() for token in (
            "plaintext", "encryptedkeyring", "file_base"
        ))
        if not risky:
            continue
        yield ExtractedField(
            field_name="default-keyring",
            value=val,
            confidence=0.5,
            parser="keyringrc",
            context="non-OS backend; sibling credential file likely",
        )
