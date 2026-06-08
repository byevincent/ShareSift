"""Credential-type → verifier-class dispatch.

Imports are deferred inside ``get_verifier`` so the base verify
package doesn't require optional dependencies (``boto3``, ``paramiko``,
``ldap3``) until a verifier that needs them is actually instantiated.

Convention: every credential_type string here matches a string
produced by ``sharesift.verify.extractor`` or by the parser dispatcher
in ``sharesift.parsers.dispatch``.
"""

from __future__ import annotations

from typing import Callable

from sharesift.verify.base import BaseVerifier


def _load_anthropic() -> type[BaseVerifier]:
    from sharesift.verify.anthropic import AnthropicVerifier
    return AnthropicVerifier


def _load_openai() -> type[BaseVerifier]:
    from sharesift.verify.openai import OpenAIVerifier
    return OpenAIVerifier


def _load_huggingface() -> type[BaseVerifier]:
    from sharesift.verify.huggingface import HuggingFaceVerifier
    return HuggingFaceVerifier


def _load_github() -> type[BaseVerifier]:
    from sharesift.verify.github import GitHubVerifier
    return GitHubVerifier


def _load_slack() -> type[BaseVerifier]:
    from sharesift.verify.slack import SlackVerifier
    return SlackVerifier


def _load_databricks() -> type[BaseVerifier]:
    from sharesift.verify.databricks import DatabricksVerifier
    return DatabricksVerifier


def _load_aws() -> type[BaseVerifier]:
    from sharesift.verify.aws import AWSVerifier
    return AWSVerifier


def _load_ssh() -> type[BaseVerifier]:
    from sharesift.verify.ssh import SSHVerifier
    return SSHVerifier


def _load_smb() -> type[BaseVerifier]:
    from sharesift.verify.smb import SMBVerifier
    return SMBVerifier


def _load_ldap() -> type[BaseVerifier]:
    from sharesift.verify.ldap import LDAPVerifier
    return LDAPVerifier


# v0.26: read-only verifiers for the v0.23 extractor credential types.
def _load_stripe() -> type[BaseVerifier]:
    from sharesift.verify.stripe import StripeVerifier
    return StripeVerifier


def _load_sendgrid() -> type[BaseVerifier]:
    from sharesift.verify.sendgrid import SendGridVerifier
    return SendGridVerifier


def _load_mailgun() -> type[BaseVerifier]:
    from sharesift.verify.mailgun import MailgunVerifier
    return MailgunVerifier


def _load_twilio() -> type[BaseVerifier]:
    from sharesift.verify.twilio import TwilioVerifier
    return TwilioVerifier


def _load_azure_storage() -> type[BaseVerifier]:
    from sharesift.verify.azure_storage import AzureStorageVerifier
    return AzureStorageVerifier


# Each loader returns the verifier class on first access; cached by
# Python's import system thereafter.
_REGISTRY: dict[str, Callable[[], type[BaseVerifier]]] = {
    # Anthropic
    "anthropic_api_key": _load_anthropic,
    "anthropic_admin_key": _load_anthropic,
    # OpenAI
    "openai_api_key": _load_openai,
    # HuggingFace
    "huggingface_token": _load_huggingface,
    "huggingface_org_token": _load_huggingface,
    # GitHub (all PAT variants share one verifier — /user accepts them all)
    "github_pat_classic": _load_github,
    "github_pat_fine_grained": _load_github,
    "github_oauth_token": _load_github,
    "github_app_user_token": _load_github,
    "github_app_token": _load_github,
    # Slack
    "slack_bot_token": _load_slack,
    "slack_user_token": _load_slack,
    "slack_workspace_token": _load_slack,
    # Databricks (needs workspace URL via VerifyConfig.targets)
    "databricks_pat": _load_databricks,
    # AWS (boto3 STS)
    "aws_access_key": _load_aws,
    # Bedrock keys are AWS-issued but route to a separate Bedrock control
    # plane; deferred to v0.17. Fall back to skipped status.
    # SSH (paramiko bind to operator-supplied targets)
    "ssh_private_key": _load_ssh,
    # SMB / LDAP — scaffolded; need context['username'] + context['password']
    # supplied programmatically until v0.17 wires ExtractedField records
    # from the parser dispatcher through to the verify runner.
    "smb_credential": _load_smb,
    "ldap_credential": _load_ldap,
    # v0.26 read-only verifiers for the v0.23 extractor types.
    "stripe_live_secret": _load_stripe,
    "stripe_live_restricted": _load_stripe,
    "sendgrid_api_key": _load_sendgrid,
    "mailgun_api_key": _load_mailgun,
    "twilio_account_sid": _load_twilio,
    "twilio_api_key_sid": _load_twilio,
    # v0.31 — Azure storage connection-string verifier (Shared Key auth).
    "azure_storage_connection_string": _load_azure_storage,
}


def supported_credential_types() -> list[str]:
    return sorted(_REGISTRY.keys())


def get_verifier(credential_type: str) -> BaseVerifier | None:
    """Return a verifier instance for ``credential_type``, or None.

    Raises ``ImportError`` from the underlying loader if the verifier's
    optional dependency isn't installed — that surfaces a clear error
    rather than silently skipping verification.
    """
    loader = _REGISTRY.get(credential_type)
    if loader is None:
        return None
    cls = loader()
    return cls()
