"""Mailgun API key verifier.

GET https://api.mailgun.net/v3/domains with HTTP Basic auth
(``api`` as username, the key as password).

Valid keys return 200 + the list of domains owned by the account;
invalid keys return 401.

Read-only — confirms liveness + surfaces the account's sending
domain inventory (operationally useful for an engagement to know
what email infrastructure is exposed).
"""

from __future__ import annotations

import base64

from sharesift.verify._http import http_verify
from sharesift.verify.base import BaseVerifier, VerifyConfig, VerifyResult


class MailgunVerifier(BaseVerifier):
    service = "mailgun"
    credential_type = "mailgun_api_key"

    def _verify_inner(
        self,
        credential: str,
        config: VerifyConfig,
        context: dict,
    ) -> VerifyResult:
        cred_type = context.get("credential_type", self.credential_type)
        basic = base64.b64encode(f"api:{credential}".encode()).decode()
        return http_verify(
            credential_type=cred_type,
            service=self.service,
            method="GET",
            url="https://api.mailgun.net/v3/domains",
            headers={"Authorization": f"Basic {basic}"},
            config=config,
            extract_metadata=lambda body: {
                "domain_count": len(body.get("items", [])),
                "total_count": body.get("total_count"),
            },
        )
