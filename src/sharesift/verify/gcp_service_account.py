"""GCP service-account JSON verifier — v0.32 structural validation.

The v0.31 release findings noted that a real GCP SA verifier needs:

1. The full SA JSON (private_key + client_email + token_uri) — closed
   by the v0.32 extractor expansion that captures the whole JSON object
   instead of just the email match.
2. PyJWT (or equivalent) to sign an RS256 JWT and exchange it for an
   OAuth access token, then call a benign API endpoint to confirm
   liveness — **NOT closed** by v0.32. Would add an optional dep.

v0.32 ships **structural verification**: parse the captured JSON,
confirm it has the required fields, confirm the private_key is
PEM-shaped. Returns ``passed`` when the structure is intact (i.e.,
"this is a well-formed SA JSON"), ``failed`` when it isn't, and
``skipped`` when there's nothing to check.

Operator note: structural ``passed`` means the credential is
syntactically valid and ready for live verification (``gcloud auth
activate-service-account``). It does NOT confirm the key hasn't been
revoked. Live OAuth verification is queued for v0.33+ when an
operator workflow requests it.
"""

from __future__ import annotations

import json
import re
import time

from sharesift.verify.base import BaseVerifier, VerifyConfig, VerifyResult

_REQUIRED_FIELDS = (
    "type",
    "project_id",
    "private_key",
    "client_email",
    "token_uri",
)
_PEM_HEADER = "-----BEGIN PRIVATE KEY-----"
_PEM_FOOTER = "-----END PRIVATE KEY-----"
_EMAIL_PATTERN = re.compile(
    r"^[a-z0-9\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com$"
)


class GcpServiceAccountVerifier(BaseVerifier):
    service = "gcp_service_account"
    credential_type = "gcp_service_account_json"

    def _verify_inner(
        self,
        credential: str,
        config: VerifyConfig,
        context: dict,
    ) -> VerifyResult:
        cred_type = context.get("credential_type", self.credential_type)
        t0 = time.perf_counter()

        try:
            data = json.loads(credential)
        except json.JSONDecodeError as exc:
            return VerifyResult(
                status="failed",
                credential_type=cred_type,
                service=self.service,
                latency_ms=(time.perf_counter() - t0) * 1000,
                error=f"not_valid_json: {exc}",
            )

        if not isinstance(data, dict):
            return VerifyResult(
                status="failed",
                credential_type=cred_type,
                service=self.service,
                latency_ms=(time.perf_counter() - t0) * 1000,
                error="not_a_json_object",
            )

        missing = [f for f in _REQUIRED_FIELDS if f not in data]
        if missing:
            return VerifyResult(
                status="failed",
                credential_type=cred_type,
                service=self.service,
                latency_ms=(time.perf_counter() - t0) * 1000,
                error=f"missing_fields: {','.join(missing)}",
            )

        if data["type"] != "service_account":
            return VerifyResult(
                status="failed",
                credential_type=cred_type,
                service=self.service,
                latency_ms=(time.perf_counter() - t0) * 1000,
                error=f"wrong_type: {data['type']}",
            )

        if not _EMAIL_PATTERN.match(data["client_email"] or ""):
            return VerifyResult(
                status="failed",
                credential_type=cred_type,
                service=self.service,
                latency_ms=(time.perf_counter() - t0) * 1000,
                error="malformed_client_email",
            )

        pk = data["private_key"] or ""
        if _PEM_HEADER not in pk or _PEM_FOOTER not in pk:
            return VerifyResult(
                status="failed",
                credential_type=cred_type,
                service=self.service,
                latency_ms=(time.perf_counter() - t0) * 1000,
                error="private_key_not_pem_shaped",
            )

        # Structural validation passed. Live OAuth verification (sign a
        # JWT, exchange for access token) is v0.33+ — would add PyJWT
        # as an optional dep.
        return VerifyResult(
            status="passed",
            credential_type=cred_type,
            service=self.service,
            latency_ms=(time.perf_counter() - t0) * 1000,
            metadata={
                "client_email": data["client_email"],
                "project_id": data.get("project_id"),
                "private_key_id": data.get("private_key_id"),
                "validation_mode": "structural",
                "note": "live OAuth verification queued for v0.33+",
            },
        )
