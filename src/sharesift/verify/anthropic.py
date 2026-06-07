"""Anthropic API key verifier.

GET https://api.anthropic.com/v1/models with ``x-api-key`` header.
Valid keys return 200 + a JSON model list; invalid keys return 401.
Cheap and idempotent — no message generation, no token cost.
"""

from __future__ import annotations

from sharesift.verify._http import http_verify
from sharesift.verify.base import BaseVerifier, VerifyConfig, VerifyResult


class AnthropicVerifier(BaseVerifier):
    service = "anthropic"
    credential_type = "anthropic_api_key"

    def _verify_inner(
        self,
        credential: str,
        config: VerifyConfig,
        context: dict,
    ) -> VerifyResult:
        cred_type = context.get("credential_type", self.credential_type)
        return http_verify(
            credential_type=cred_type,
            service=self.service,
            method="GET",
            url="https://api.anthropic.com/v1/models",
            headers={
                "x-api-key": credential,
                "anthropic-version": "2023-06-01",
            },
            config=config,
            extract_metadata=lambda body: {
                "model_count": len(body.get("data", [])),
            },
        )
