"""GitHub CLI auth config — ``hosts.yml`` under ``~/.config/gh/``.

The ``gh`` CLI stores its OAuth tokens in a YAML file:

    github.com:
        oauth_token: gho_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789
        git_protocol: https
        user: alice
    github.enterprise.example.com:
        oauth_token: gho_OtherTokenHere
        user: alice

Each top-level mapping key is a hostname; ``oauth_token`` under it is
the credential. ``user`` is high-context-low-credential.
"""

from __future__ import annotations

import re
from typing import Iterable

from sharesift.parsers.dispatch import ExtractedField


def register(reg) -> None:
    # The filename `hosts.yml` is the canonical one. We don't match
    # bare `hosts.yml` because it could be e.g. Ansible inventory; we
    # parse-and-yield-nothing if no GitHub-shaped fields are present.
    reg(r"^hosts\.yml$", parse_gh_hosts)
    reg(r"^hosts\.yaml$", parse_gh_hosts)


def parse_gh_hosts(content: str) -> Iterable[ExtractedField]:
    # Lightweight parse — we don't want a yaml dep (it's optional in
    # the install matrix). Regex scan for hostname blocks and the
    # tokens within. Indentation-aware: we track the current top-level
    # host as the parent of subsequent indented oauth_token / user lines.
    current_host: str | None = None
    saw_github_field = False
    for raw_line in content.splitlines():
        line = raw_line.rstrip()
        if not line or line.startswith("#"):
            continue
        # Top-level: hostname followed by colon, no leading whitespace.
        if not line.startswith((" ", "\t")):
            m = re.match(r"^([A-Za-z0-9.\-_]+):\s*$", line)
            if m:
                current_host = m.group(1)
                continue
            current_host = None
            continue
        # Indented field under the current host.
        if current_host is None:
            continue
        stripped = line.strip()
        # oauth_token / user / git_protocol — only emit the credential ones.
        m = re.match(r"^(oauth_token|user)\s*:\s*(.+)$", stripped)
        if not m:
            continue
        field = m.group(1)
        value = m.group(2).strip().strip('"').strip("'")
        if not value:
            continue
        saw_github_field = True
        if field == "oauth_token":
            yield ExtractedField(
                field_name=f"{current_host}.oauth_token",
                value=value,
                confidence=0.95,
                parser="gh_cli_config",
            )
        elif field == "user":
            yield ExtractedField(
                field_name=f"{current_host}.user",
                value=value,
                confidence=0.4,
                parser="gh_cli_config",
            )

    # If we never saw an oauth_token under any host, this might be
    # Ansible inventory or another hosts.yml — the yielded fields
    # (if any) are still real, but we've already filtered at field level.
    _ = saw_github_field  # explicit no-op; documentation
