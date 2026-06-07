"""Docker config.json — extracts ``auths.*.auth`` base64-decoded creds.

The ``~/.docker/config.json`` file stores per-registry authentication
as ``{"auths": {"registry.example.com": {"auth": "base64(user:pass)"}}}``.
Operators routinely leave this on shared hosts.

We decode the base64 blob, split on the first colon, and emit username
and password as two ExtractedField records (parser-grouped so the pair
extractor in ``verify._pairs`` finds them).
"""

from __future__ import annotations

import base64
import json
from typing import Iterable

from sharesift.parsers.dispatch import ExtractedField


def register(reg):
    reg(r"^config\.json$", parse_docker_config)
    reg(r"^\.dockercfg$", parse_docker_config)


def parse_docker_config(content: str) -> Iterable[ExtractedField]:
    try:
        cfg = json.loads(content)
    except (ValueError, TypeError):
        return
    if not isinstance(cfg, dict):
        return

    auths = cfg.get("auths", {}) if isinstance(cfg.get("auths"), dict) else cfg
    for registry, entry in auths.items():
        if not isinstance(entry, dict):
            continue
        encoded = entry.get("auth")
        if isinstance(encoded, str) and encoded:
            try:
                decoded = base64.b64decode(encoded + "=" * (-len(encoded) % 4)).decode(
                    "utf-8", errors="replace"
                )
            except Exception:
                decoded = None
            if decoded and ":" in decoded:
                user, _, pw = decoded.partition(":")
                if user:
                    yield ExtractedField(
                        field_name="username",
                        value=user,
                        confidence=0.95,
                        parser="docker_config_json",
                        context=f"registry={registry}",
                    )
                if pw:
                    yield ExtractedField(
                        field_name="password",
                        value=pw,
                        confidence=0.95,
                        parser="docker_config_json",
                        context=f"registry={registry}",
                    )
        # identitytoken (OAuth refresh token)
        if isinstance(entry.get("identitytoken"), str) and entry["identitytoken"]:
            yield ExtractedField(
                field_name="identitytoken",
                value=entry["identitytoken"],
                confidence=0.9,
                parser="docker_config_json",
                context=f"registry={registry}",
            )

    # Top-level credHelpers and credsStore are pointers (binary names), not creds
    # — skip to keep noise low.
