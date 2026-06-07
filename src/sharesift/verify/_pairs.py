"""Find username/password pairs in a list of ExtractedField dicts.

Each structured parser emits one or more ``ExtractedField`` records
per source file. SMB / LDAP verification needs both halves of a
credential pair — username AND password — from the same parser run
on the same file. This module walks the per-record field list and
returns the pairs.

Heuristic shape: within one record's ``extracted_fields`` list, group
by ``parser`` (same parser within one source file → almost certainly
the same credential context), then pair any field whose ``field_name``
looks like a username with any field whose name looks like a password.
When there's exactly one of each, that's the pair; when there are
multiple of either, we pair them by order of appearance.
"""

from __future__ import annotations

from dataclasses import dataclass

_USERNAME_NAMES = {
    "username",
    "user",
    "user_name",
    "username_local",
    "login",
    "account",
    "principal",
    "uid",
    "sam_account_name",
}

_PASSWORD_NAMES = {
    "password",
    "pass",
    "pwd",
    "secret",
    "passphrase",
    "administratorpassword",
}


def _is_username_field(field_name: str) -> bool:
    n = field_name.lower()
    if n in _USERNAME_NAMES:
        return True
    return n.endswith(".user") or n.endswith(".username") or n.endswith(".login")


def _is_password_field(field_name: str) -> bool:
    n = field_name.lower()
    if n in _PASSWORD_NAMES:
        return True
    return n.endswith(".password") or n.endswith(".pass") or n.endswith(".secret")


@dataclass(frozen=True)
class CredentialPair:
    username: str
    password: str
    parser: str
    source_field_username: str
    source_field_password: str


def extract_user_password_pairs(
    extracted_fields: list[dict],
) -> list[CredentialPair]:
    """Pair username + password fields from the same parser.

    Returns a list of ``CredentialPair`` records — one per pairing.
    Multiple pairs are possible (e.g. tomcat-users.xml with several
    accounts). Records lacking either half of a pair contribute nothing.
    """
    by_parser: dict[str, list[dict]] = {}
    for f in extracted_fields or []:
        parser = f.get("parser") or "unknown"
        by_parser.setdefault(parser, []).append(f)

    out: list[CredentialPair] = []
    for parser, fields in by_parser.items():
        users = [f for f in fields if _is_username_field(f.get("field_name", ""))]
        passwords = [f for f in fields if _is_password_field(f.get("field_name", ""))]
        if not users or not passwords:
            continue
        # Pair by position: u[i] ↔ p[i]; if counts differ, pair shorter
        # list against the longer one's prefix (covers tomcat-users with
        # N users + N passwords as well as the common single-account case).
        for u, p in zip(users, passwords):
            uval = u.get("value")
            pval = p.get("value")
            if not uval or not pval:
                continue
            out.append(
                CredentialPair(
                    username=str(uval),
                    password=str(pval),
                    parser=parser,
                    source_field_username=u.get("field_name", ""),
                    source_field_password=p.get("field_name", ""),
                )
            )
    return out
