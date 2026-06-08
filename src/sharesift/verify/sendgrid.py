"""SendGrid API key verifier.

GET https://api.sendgrid.com/v3/user/profile with Bearer auth.
Valid keys return 200 + profile data; invalid keys return 401.

Read-only — confirms key liveness without sending mail.
"""

from __future__ import annotations

from sharesift.verify._http import http_verify
from sharesift.verify.base import BaseVerifier, VerifyConfig, VerifyResult


class SendGridVerifier(BaseVerifier):
    service = "sendgrid"
    credential_type = "sendgrid_api_key"

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
            url="https://api.sendgrid.com/v3/user/profile",
            headers={"Authorization": f"Bearer {credential}"},
            config=config,
            extract_metadata=lambda body: {
                "username": body.get("username"),
                "first_name": body.get("first_name"),
                "last_name": body.get("last_name"),
                "company": body.get("company"),
            },
        )
