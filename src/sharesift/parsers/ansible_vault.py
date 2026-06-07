"""Ansible vault file detection — vault header + cipher metadata.

Ansible-vault files begin with::

    $ANSIBLE_VAULT;1.1;AES256
    61626364...                # hex-encoded ciphertext

or for vault-id'd files::

    $ANSIBLE_VAULT;1.2;AES256;prod

We can't recover the plaintext (offline crack needed), but flagging
the file as containing encrypted secrets plus extracting the vault id
gives operators useful intel: knowing the vault id tells them which
vault password to try.

Also handles inline vault blocks inside group_vars / host_vars YAML
files (encrypted strings tagged with ``!vault``).
"""

from __future__ import annotations

import re
from typing import Iterable

from sharesift.parsers.dispatch import ExtractedField


def register(reg):
    reg(r"\.vault$", parse_ansible_vault)
    reg(r"^(group_vars|host_vars)/.+\.ya?ml$", parse_ansible_vault_maybe)
    reg(r"\.ya?ml$", parse_ansible_vault_maybe)


_HEADER = re.compile(
    r"^\$ANSIBLE_VAULT;(?P<version>[\d.]+);(?P<cipher>[A-Z0-9]+)(?:;(?P<vault_id>[\w\-]+))?",
    re.MULTILINE,
)
_INLINE = re.compile(
    r"!vault\s*\|\s*\n((?:\s+\$ANSIBLE_VAULT;[\d.]+;[A-Z0-9]+(?:;[\w\-]+)?\s*\n(?:\s+[A-Fa-f0-9]+\s*\n?)+))"
)


def parse_ansible_vault(content: str) -> Iterable[ExtractedField]:
    """Top-level vault file (entire content is one encrypted blob)."""
    m = _HEADER.search(content)
    if not m:
        return
    yield ExtractedField(
        field_name="vault_header",
        value=m.group(0),
        confidence=0.95,
        parser="ansible_vault",
        context=(
            f"vault_id={m.group('vault_id') or '(default)'} "
            f"cipher={m.group('cipher')} version={m.group('version')}"
        ),
    )
    cipher_start = m.end()
    cipher_blob = "".join(content[cipher_start:].split())
    if cipher_blob:
        yield ExtractedField(
            field_name="vault_ciphertext",
            value=cipher_blob[:200] + ("..." if len(cipher_blob) > 200 else ""),
            confidence=0.95,
            parser="ansible_vault",
            context=f"{len(cipher_blob)} bytes ciphertext",
        )


def parse_ansible_vault_maybe(content: str) -> Iterable[ExtractedField]:
    """YAML files — flag any inline ``!vault`` blocks but skip plain YAML."""
    if "$ANSIBLE_VAULT" not in content:
        return
    if _HEADER.match(content):
        yield from parse_ansible_vault(content)
        return
    for m in _INLINE.finditer(content):
        block = m.group(1)
        header_m = _HEADER.search(block)
        vault_id = header_m.group("vault_id") if header_m else "(default)"
        yield ExtractedField(
            field_name="inline_vault_block",
            value=block.strip()[:200] + ("..." if len(block) > 200 else ""),
            confidence=0.9,
            parser="ansible_vault",
            context=f"inline !vault, id={vault_id}",
        )
