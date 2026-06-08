"""Stripe API key verifier.

GET https://api.stripe.com/v1/account with Bearer auth.
Valid keys return 200 + an account JSON (id, country, business name);
invalid keys return 401.

Read-only — confirms liveness without touching balance, charges,
customers, or any other write-capable resource.
"""

from __future__ import annotations

from sharesift.verify._http import http_verify
from sharesift.verify.base import BaseVerifier, VerifyConfig, VerifyResult


class StripeVerifier(BaseVerifier):
    service = "stripe"
    credential_type = "stripe_live_secret"

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
            url="https://api.stripe.com/v1/account",
            headers={"Authorization": f"Bearer {credential}"},
            config=config,
            extract_metadata=lambda body: {
                "account_id": body.get("id"),
                "country": body.get("country"),
                "business_name": body.get("business_profile", {}).get("name"),
                "livemode": body.get("livemode"),
            },
        )
