"""Re-extract credential strings from ScanResult content_excerpts.

Today's ScanResult schema doesn't carry the matched_text or matched
rule names — content classification is yes/no and the excerpt is the
full classified snippet. To know what to verify, we re-run a set of
targeted credential regexes against the excerpt.

Patterns mirror the ShareSift SaaS detectors in
``src/sharesift/rules/extra_rules.py`` plus a handful of formats that
the Snaffler default ruleset matches but doesn't extract structurally
(AWS access keys, GitHub PATs).

Drift note: when a vendor changes their key format (the AWS
``AKIA`` → ``ASIA`` switch, OpenAI's `sk-proj-` extension), update both
this module AND ``extra_rules.py``. Two-source-of-truth is deliberate
— ``extra_rules`` is the pysnaffler matcher, this module is the
verifier dispatcher.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ExtractedCredential:
    """One credential candidate pulled from a content excerpt.

    ``credential_type`` is the registry key (``"anthropic_api_key"``,
    ``"aws_access_key"``, etc.). ``value`` is the literal credential
    string the verifier will authenticate with. ``span`` is the start/
    end offsets within the excerpt — useful for UI highlighting later.
    """

    credential_type: str
    value: str
    span: tuple[int, int]


# Each pattern compiles once at module load. Order matters only for
# logging; multiple verifiers can fire on the same excerpt and that's
# fine — they're independent verifications.
_PATTERNS: list[tuple[str, re.Pattern]] = [
    # ---- AI / LLM providers (the 2026 leak hot zone) -------------------
    ("anthropic_api_key", re.compile(r"sk-ant-api03-[A-Za-z0-9_\-]{93}AA")),
    ("anthropic_admin_key", re.compile(r"sk-ant-admin01-[A-Za-z0-9_\-]{93}AA")),
    (
        "openai_api_key",
        re.compile(
            r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}"
        ),
    ),
    ("openai_api_key", re.compile(r"sk-[A-Za-z0-9]{48}")),  # legacy format
    ("huggingface_token", re.compile(r"hf_[A-Za-z]{34}")),
    ("huggingface_org_token", re.compile(r"api_org_[A-Za-z]{34}")),
    ("perplexity_api_key", re.compile(r"pplx-[a-zA-Z0-9]{48}")),
    # ---- AWS ----------------------------------------------------------
    ("aws_access_key", re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}")),
    ("aws_bedrock_long_lived", re.compile(r"ABSK[A-Za-z0-9+/]{109,269}=?")),
    (
        "aws_bedrock_short_lived",
        re.compile(r"bedrock-api-key-YmVkcm9jay5[A-Za-z0-9+/=_\-]{30,}"),
    ),
    # ---- SaaS / dev tools ---------------------------------------------
    ("databricks_pat", re.compile(r"dapi[a-f0-9]{32}(?:-\d)?")),
    ("clickhouse_cloud_key", re.compile(r"4b1d[A-Za-z0-9]{38}")),
    ("gitlab_pat", re.compile(r"glpat-[0-9a-zA-Z_\-]{20,}")),
    ("render_api_token", re.compile(r"rnd_[a-zA-Z0-9]{14}")),
    # ---- GitHub (Snaffler default catches the file; we add the cred) --
    ("github_pat_classic", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("github_pat_fine_grained", re.compile(r"github_pat_[A-Za-z0-9_]{82}")),
    ("github_oauth_token", re.compile(r"gho_[A-Za-z0-9]{36}")),
    ("github_app_user_token", re.compile(r"ghu_[A-Za-z0-9]{36}")),
    ("github_app_token", re.compile(r"ghs_[A-Za-z0-9]{36}")),
    # ---- Slack / messaging --------------------------------------------
    ("slack_bot_token", re.compile(r"xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+")),
    ("slack_user_token", re.compile(r"xoxp-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]+")),
    ("slack_workspace_token", re.compile(r"xoxa-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]+")),
]


_SSH_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:OPENSSH|RSA|DSA|EC|ED25519|PGP) PRIVATE KEY(?: BLOCK)?-----"
    r"[\s\S]+?"
    r"-----END (?:OPENSSH|RSA|DSA|EC|ED25519|PGP) PRIVATE KEY(?: BLOCK)?-----",
    re.MULTILINE,
)


def extract_credentials(excerpt: str) -> list[ExtractedCredential]:
    """Find all known credential formats in ``excerpt``.

    Returns one ``ExtractedCredential`` per regex match. The same byte
    range may match multiple patterns (e.g., a generic
    ``sk-[A-Za-z0-9]{48}`` and a specific OpenAI signature) — that's
    intentional; the verifier registry deduplicates by
    ``(credential_type, value)``.
    """
    if not excerpt:
        return []
    out: list[ExtractedCredential] = []
    seen: set[tuple[str, str]] = set()
    for cred_type, pat in _PATTERNS:
        for m in pat.finditer(excerpt):
            value = m.group(0)
            key = (cred_type, value)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                ExtractedCredential(
                    credential_type=cred_type,
                    value=value,
                    span=(m.start(), m.end()),
                )
            )
    # SSH private keys handled separately — multi-line, distinct shape.
    for m in _SSH_KEY_PATTERN.finditer(excerpt):
        value = m.group(0)
        key = ("ssh_private_key", value)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            ExtractedCredential(
                credential_type="ssh_private_key",
                value=value,
                span=(m.start(), m.end()),
            )
        )
    return out
