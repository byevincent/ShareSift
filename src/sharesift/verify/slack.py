"""Slack token verifier.

POST https://slack.com/api/auth.test with ``Authorization: Bearer``.
Slack always returns 200; the JSON body's ``ok`` field is the actual
indicator. ``ok: false`` + ``error: invalid_auth`` means failed.
"""

from __future__ import annotations

import time

from sharesift.verify.base import BaseVerifier, VerifyConfig, VerifyResult


class SlackVerifier(BaseVerifier):
    service = "slack"
    credential_type = "slack_token"

    def _verify_inner(
        self,
        credential: str,
        config: VerifyConfig,
        context: dict,
    ) -> VerifyResult:
        import requests

        cred_type = context.get("credential_type", self.credential_type)
        t0 = time.perf_counter()
        try:
            resp = requests.post(
                "https://slack.com/api/auth.test",
                headers={"Authorization": f"Bearer {credential}"},
                timeout=config.timeout_sec,
            )
        except requests.exceptions.RequestException as exc:
            return VerifyResult(
                status="inconclusive",
                credential_type=cred_type,
                service=self.service,
                latency_ms=(time.perf_counter() - t0) * 1000,
                error=f"{type(exc).__name__}: {exc}",
            )
        latency_ms = (time.perf_counter() - t0) * 1000

        try:
            body = resp.json()
        except ValueError:
            return VerifyResult(
                status="inconclusive",
                credential_type=cred_type,
                service=self.service,
                latency_ms=latency_ms,
                error="non_json_response",
            )

        if body.get("ok"):
            return VerifyResult(
                status="passed",
                credential_type=cred_type,
                service=self.service,
                latency_ms=latency_ms,
                metadata={
                    "team": body.get("team"),
                    "team_id": body.get("team_id"),
                    "user": body.get("user"),
                    "user_id": body.get("user_id"),
                    "url": body.get("url"),
                },
            )
        return VerifyResult(
            status="failed",
            credential_type=cred_type,
            service=self.service,
            latency_ms=latency_ms,
            metadata={"slack_error": body.get("error")},
            error=body.get("error", "auth_test_not_ok"),
        )
