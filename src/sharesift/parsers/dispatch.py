"""Filename-based dispatch for structured credential parsers.

Each parser is a function ``(content: str) -> Iterable[ExtractedField]``.
The dispatch map keys filename patterns (case-insensitive substrings)
to parser functions. Multiple patterns may match a single file — every
matching parser runs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable


@dataclass(frozen=True)
class ExtractedField:
    """One credential field extracted from a structured file."""
    field_name: str          # e.g. "password", "cpassword", "ConnectionString"
    value: str               # the literal value (may be encrypted)
    confidence: float        # 0..1 — how sure the parser is this is a credential
    parser: str              # parser name (for provenance / logging)
    context: str = ""        # short surrounding context for the operator


_Parser = Callable[[str], Iterable[ExtractedField]]
_PATTERN_TO_PARSER: list[tuple[re.Pattern, _Parser]] = []


def _register(pattern: str, parser: _Parser) -> None:
    """Register a parser for filenames matching the (case-insensitive) pattern."""
    rex = re.compile(pattern, re.IGNORECASE)
    _PATTERN_TO_PARSER.append((rex, parser))


def parsers() -> list[tuple[str, str]]:
    """Return ``[(pattern, parser_name), ...]`` for diagnostics."""
    return [(p.pattern, fn.__name__) for p, fn in _PATTERN_TO_PARSER]


def parse_file(filename: str, content: str) -> list[ExtractedField]:
    """Dispatch ``content`` to every registered parser whose filename
    pattern matches ``filename``. Each parser runs at most once even if
    multiple patterns route to the same function (so .properties files
    don't get parsed twice by the application-properties parser, for
    example)."""
    name = filename.replace("\\", "/").rsplit("/", 1)[-1]
    out: list[ExtractedField] = []
    seen_parsers: set = set()
    for rex, parser in _PATTERN_TO_PARSER:
        if parser in seen_parsers:
            continue
        if rex.search(name):
            seen_parsers.add(parser)
            try:
                out.extend(list(parser(content)))
            except Exception:
                continue
    return out


# ---------------------------------------------------------------------------
# Import parsers and register them. Each parser module's _register_with()
# function is called below.
# ---------------------------------------------------------------------------

from sharesift.parsers import (  # noqa: E402
    web_config,
    unattend,
    tomcat_users,
    application_properties,
    filezilla_sitemanager,
    winscp_ini,
    pgpass,
    my_cnf,
    npmrc,
    groups_xml,
    settings_xml,
    keepass_config,
    openvpn_config,
    # v0.17 additions
    terraform_tfstate,
    docker_config_json,
    kube_config,
    cisco_running_config,
    veeam_config_xml,
    ansible_vault,
    # v0.24 additions
    wp_config_php,
    aws_cli_credentials,
    netrc,
    maven_settings_xml,
    # v0.25 additions
    pypirc,
    gcloud_credentials,
    gh_cli_config,
    keyring_credentials,
    # v0.26 additions
    putty_ppk,
)


for mod in (
    web_config, unattend, tomcat_users, application_properties,
    filezilla_sitemanager, winscp_ini, pgpass, my_cnf, npmrc,
    groups_xml, settings_xml, keepass_config, openvpn_config,
    terraform_tfstate, docker_config_json, kube_config,
    cisco_running_config, veeam_config_xml, ansible_vault,
    # v0.24
    wp_config_php, aws_cli_credentials, netrc, maven_settings_xml,
    # v0.25
    pypirc, gcloud_credentials, gh_cli_config, keyring_credentials,
    # v0.26
    putty_ppk,
):
    mod.register(_register)
