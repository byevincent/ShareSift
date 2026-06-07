"""Kubernetes kubeconfig — extracts bearer tokens + client certs.

``~/.kube/config`` files yield::

    users:
      - name: admin
        user:
          token: eyJhbGc...           # bearer token
          client-certificate-data: ... # base64 PEM
          client-key-data: ...         # base64 PEM
          username: admin              # basic-auth pair
          password: ...

We extract each form with separate ExtractedField entries; the
``username``/``password`` pair routes through the pair extractor for
SMB/LDAP-style verification (though it'd target the k8s API server,
which we don't have a verifier for yet — operator handles).
"""

from __future__ import annotations

import re
from typing import Iterable

from sharesift.parsers.dispatch import ExtractedField


def register(reg):
    reg(r"^kubeconfig$", parse_kube_config)
    reg(r"^config$", parse_kube_config)  # ~/.kube/config — filename is just "config"


_USERS_BLOCK = re.compile(
    r"^(?P<indent>\s*)- name:\s*(?P<name>[^\n]+)\n(?P<body>(?:(?P=indent)\s+[^\n]*\n)+)",
    re.MULTILINE,
)
_FIELD = re.compile(r"^[ \t]+([\w-]+):[ \t]*(?P<value>[^\n]+)", re.MULTILINE)


def _looks_like_kube_config(content: str) -> bool:
    return (
        "apiVersion:" in content
        and "kind:" in content
        and ("Config" in content or "kind: Config" in content)
        and ("clusters:" in content or "users:" in content)
    )


def parse_kube_config(content: str) -> Iterable[ExtractedField]:
    if not _looks_like_kube_config(content):
        return
    users_section_match = re.search(r"^users:\s*\n", content, re.MULTILINE)
    if not users_section_match:
        return
    users_text = content[users_section_match.end():]
    end = re.search(r"^\S", users_text, re.MULTILINE)
    if end:
        users_text = users_text[: end.start()]

    for block in _USERS_BLOCK.finditer(users_text):
        name = block.group("name").strip()
        body = block.group("body")
        for fm in _FIELD.finditer(body):
            field_name = fm.group(1).strip()
            value = fm.group("value").strip()
            value = value.strip('"').strip("'")
            if field_name == "token":
                yield ExtractedField(
                    field_name="token",
                    value=value,
                    confidence=0.95,
                    parser="kube_config",
                    context=f"users[{name}].user.token",
                )
            elif field_name == "client-certificate-data":
                yield ExtractedField(
                    field_name="client_certificate_data",
                    value=value,
                    confidence=0.85,
                    parser="kube_config",
                    context=f"users[{name}].user (base64 PEM)",
                )
            elif field_name == "client-key-data":
                yield ExtractedField(
                    field_name="client_key_data",
                    value=value,
                    confidence=0.95,
                    parser="kube_config",
                    context=f"users[{name}].user (base64 PEM)",
                )
            elif field_name == "username":
                yield ExtractedField(
                    field_name="username",
                    value=value,
                    confidence=0.9,
                    parser="kube_config",
                    context=f"users[{name}]",
                )
            elif field_name == "password":
                yield ExtractedField(
                    field_name="password",
                    value=value,
                    confidence=0.95,
                    parser="kube_config",
                    context=f"users[{name}]",
                )
