"""OpenAI API key verifier.

GET https://api.openai.com/v1/models with ``Authorization: Bearer``.
200 = valid, 401 = invalid. Models list is paged but cheap; we don't
read past the first page.
"""

from __future__ import annotations

from sharesift.verify._http import http_verify
from sharesift.verify.base import BaseVerifier, VerifyConfig, VerifyResult


class OpenAIVerifier(BaseVerifier):
    service = "openai"
    credential_type = "openai_api_key"

    def _verify_inner(
        self,
        credential: str,
        config: VerifyConfig,
        context: dict,
    ) -> VerifyResult:
        return http_verify(
            credential_type=context.get("credential_type", self.credential_type),
            service=self.service,
            method="GET",
            url="https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {credential}"},
            config=config,
            extract_metadata=lambda body: {
                "model_count": len(body.get("data", [])),
            },
        )
