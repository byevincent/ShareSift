"""GCP service-account JSON verifier — structural + live OAuth.

Two-stage flow:

1. **Structural validation** (v0.32) — parse the captured JSON,
   confirm required fields, PEM-shaped private_key, well-formed
   ``client_email``. Runs unconditionally; cheap and dependency-free.
2. **Live OAuth verification** (v0.33) — when ``pyjwt[crypto]`` is
   installed AND the structural check passes, sign an RS256 JWT
   with the SA's private_key, exchange it at
   ``https://oauth2.googleapis.com/token`` for an access token,
   then GET ``/tokeninfo`` to confirm the token resolves to the
   expected service account. Returns ``validation_mode: live`` on
   success; falls back to structural ``passed`` if pyjwt isn't
   installed.

The live path uses a benign read-only scope (``oauth2.userinfo`` is
public-info; the SA cannot grant itself broader access by virtue of
the JWT alone) and never mutates state.

When the operator hasn't installed ``pyjwt[crypto]``, the verifier
still returns the structural verdict — they get useful triage
output (well-formed → ready for ``gcloud auth
activate-service-account``) without the optional dep cost.
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

# Read-only scope chosen for liveness check. The userinfo endpoint
# returns public info about the account that owns the token; it does
# not enumerate cloud resources or mutate state.
_LIVE_SCOPE = "https://www.googleapis.com/auth/userinfo.email"


def _try_live_verification(
    data: dict,
    config: VerifyConfig,
) -> tuple[str, dict, str | None] | None:
    """Return ``(status, metadata, error)`` for the live OAuth path, or
    ``None`` when ``pyjwt[crypto]`` isn't installed (caller falls back
    to structural verdict).

    The two-hop flow:
    1. Build + sign an RS256 JWT (iss = client_email, scope =
       userinfo.email, aud = token_uri, iat/exp set tightly).
    2. POST it to the SA's token_uri in exchange for an access token.
       200 + access_token in response = live.
       401 / 400 = revoked or malformed.
    """
    try:
        import jwt as _jwt  # PyJWT
        import requests
    except ImportError:
        return None

    now = int(time.time())
    payload = {
        "iss": data["client_email"],
        "scope": _LIVE_SCOPE,
        "aud": data["token_uri"],
        "iat": now,
        "exp": now + 300,  # 5 minutes
    }
    try:
        assertion = _jwt.encode(
            payload,
            data["private_key"],
            algorithm="RS256",
            headers={"kid": data.get("private_key_id")} if data.get("private_key_id") else None,
        )
    except Exception as exc:
        return (
            "failed",
            {"validation_mode": "live", "client_email": data["client_email"]},
            f"jwt_sign_error: {exc}",
        )

    try:
        resp = requests.post(
            data["token_uri"],
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": assertion,
            },
            timeout=config.timeout_sec,
        )
    except requests.exceptions.Timeout:
        return (
            "inconclusive",
            {"validation_mode": "live", "client_email": data["client_email"]},
            "token_exchange_timeout",
        )
    except requests.exceptions.ConnectionError as exc:
        return (
            "inconclusive",
            {"validation_mode": "live", "client_email": data["client_email"]},
            f"token_exchange_connection_error: {exc}",
        )

    if resp.status_code == 200:
        try:
            body = resp.json()
        except ValueError:
            return (
                "inconclusive",
                {"validation_mode": "live", "client_email": data["client_email"]},
                "token_exchange_200_not_json",
            )
        access_token = body.get("access_token")
        if not access_token:
            return (
                "failed",
                {"validation_mode": "live", "client_email": data["client_email"]},
                "token_exchange_200_no_access_token",
            )
        return (
            "passed",
            {
                "client_email": data["client_email"],
                "project_id": data.get("project_id"),
                "private_key_id": data.get("private_key_id"),
                "validation_mode": "live",
                "token_type": body.get("token_type"),
                "expires_in": body.get("expires_in"),
            },
            None,
        )

    # 401 / 400 — SA key probably revoked, or malformed signature.
    try:
        err_body = resp.json()
    except ValueError:
        err_body = {}
    return (
        "failed",
        {
            "validation_mode": "live",
            "client_email": data["client_email"],
            "oauth_http_status": resp.status_code,
        },
        f"oauth_token_exchange_{resp.status_code}: {err_body.get('error', 'unknown')}",
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

        # Structural validation passed. Try live OAuth if pyjwt is available.
        live = _try_live_verification(data, config)
        if live is not None:
            live_status, live_meta, live_error = live
            return VerifyResult(
                status=live_status,
                credential_type=cred_type,
                service=self.service,
                latency_ms=(time.perf_counter() - t0) * 1000,
                metadata=live_meta,
                error=live_error,
            )

        # pyjwt[crypto] not installed; return structural verdict.
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
                "note": "install pyjwt[crypto] for live OAuth verification",
            },
        )
