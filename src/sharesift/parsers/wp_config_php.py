"""WordPress wp-config.php — extracts DB credentials + the 8 auth keys.

A WordPress wp-config.php declares values via PHP ``define()`` calls.
The four DB constants and the eight auth/nonce keys / salts are
always present in real installations and are the most credentials
an attacker can lift from a single file.

DB constants:
    DB_NAME, DB_USER, DB_PASSWORD, DB_HOST

Auth keys + salts (rotated by Wordpress on install; valuable for
session forgery if leaked):
    AUTH_KEY, SECURE_AUTH_KEY, LOGGED_IN_KEY, NONCE_KEY,
    AUTH_SALT, SECURE_AUTH_SALT, LOGGED_IN_SALT, NONCE_SALT

We parse with a regex over ``define()`` calls — PHP syntax is
flexible enough that a real PHP parser would be overkill for this
specific file. Quoted values are stripped of quotes and trailing
whitespace.
"""

from __future__ import annotations

import re
from typing import Iterable

from sharesift.parsers.dispatch import ExtractedField

_DB_KEYS = ("DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST")
_AUTH_KEYS = (
    "AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY",
    "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT",
)

_DEFINE_PATTERN = re.compile(
    r"""
    define\s*\(\s*
    ['"](?P<name>[A-Z_]+)['"]\s*,\s*
    ['"](?P<value>[^'"]*)['"]\s*
    \)
    """,
    re.VERBOSE,
)


def register(reg) -> None:
    reg(r"^wp-config\.php$", parse_wp_config)
    reg(r"^wp-config\.php\.bak$", parse_wp_config)
    reg(r"^wp-config\.php\.old$", parse_wp_config)


def parse_wp_config(content: str) -> Iterable[ExtractedField]:
    for m in _DEFINE_PATTERN.finditer(content):
        name = m.group("name")
        value = m.group("value").strip()
        if not value or value.startswith("put your") or "phrase here" in value.lower():
            # Boilerplate values from the install template — skip.
            continue
        if name in _DB_KEYS:
            yield ExtractedField(
                field_name=name,
                value=value,
                # DB_PASSWORD is the only one that's strictly a credential;
                # the others are useful context.
                confidence=0.95 if name == "DB_PASSWORD" else 0.6,
                parser="wp_config_php",
            )
        elif name in _AUTH_KEYS:
            yield ExtractedField(
                field_name=name,
                value=value,
                confidence=0.85,
                parser="wp_config_php",
            )
