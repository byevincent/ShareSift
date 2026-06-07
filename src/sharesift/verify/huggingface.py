"""HuggingFace token verifier.

GET https://huggingface.co/api/whoami-v2 with ``Authorization: Bearer``.
On success returns user/org identity; on failure returns 401.
"""

from __future__ import annotations

from sharesift.verify._http import http_verify
from sharesift.verify.base import BaseVerifier, VerifyConfig, VerifyResult


class HuggingFaceVerifier(BaseVerifier):
    service = "huggingface"
    credential_type = "huggingface_token"

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
            url="https://huggingface.co/api/whoami-v2",
            headers={"Authorization": f"Bearer {credential}"},
            config=config,
            extract_metadata=lambda body: {
                "name": body.get("name"),
                "type": body.get("type"),
                "email_verified": body.get("emailVerified"),
            },
        )
