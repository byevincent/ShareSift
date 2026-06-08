"""Twilio account SID + auth-token verifier.

The Twilio API uses HTTP Basic auth with the Account SID as the
username and the Auth Token (or an API Key SID) as the password.

GET https://api.twilio.com/2010-04-01/Accounts/<SID>.json

Valid creds return 200 + account JSON; invalid return 401.

Read-only — confirms liveness without sending SMS / placing calls.

This verifier handles both:
* ``twilio_account_sid`` — extracted ``AC...`` string, paired with
  an extracted Auth Token at runtime by the verify dispatcher
* ``twilio_api_key_sid`` — extracted ``SK...`` string

Both flavours hit the same endpoint with the same Basic-auth shape;
the Account SID is required as the URL component, so this verifier
requires ``context['username']`` (the Account SID) to be present.
"""

from __future__ import annotations

import base64

from sharesift.verify._http import http_verify
from sharesift.verify.base import BaseVerifier, VerifyConfig, VerifyResult


class TwilioVerifier(BaseVerifier):
    service = "twilio"
    credential_type = "twilio_account_sid"  # default; SK variant uses same path

    def _verify_inner(
        self,
        credential: str,
        config: VerifyConfig,
        context: dict,
    ) -> VerifyResult:
        cred_type = context.get("credential_type", self.credential_type)
        account_sid = context.get("username") or context.get("account_sid")
        if not account_sid:
            return VerifyResult(
                status="skipped",
                credential_type=cred_type,
                service=self.service,
                metadata={"reason": "no_account_sid_in_context"},
            )
        basic = base64.b64encode(
            f"{account_sid}:{credential}".encode()
        ).decode()
        return http_verify(
            credential_type=cred_type,
            service=self.service,
            method="GET",
            url=f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}.json",
            headers={"Authorization": f"Basic {basic}"},
            config=config,
            extract_metadata=lambda body: {
                "friendly_name": body.get("friendly_name"),
                "status": body.get("status"),
                "type": body.get("type"),
            },
        )
