"""AWS access key verifier.

Calls STS ``GetCallerIdentity`` — the cheapest, most universally
available AWS call. Returns Account ID + ARN + UserId on success;
``InvalidClientTokenId`` / ``SignatureDoesNotMatch`` on failure.

AWS access keys are always paired with a secret. The verifier looks
for the secret either in the same content excerpt (via
``context["paired_secret"]``) or in the same record's neighborhood —
in practice, both keys sit on adjacent lines in ``.aws/credentials``
or ``.env`` files. If no secret is paired, returns ``inconclusive``.

Boto3 is an optional dependency (group ``verify-cloud``); the import
error surfaces with the install hint.
"""

from __future__ import annotations

import re
import time

from sharesift.verify.base import BaseVerifier, VerifyConfig, VerifyResult

_SECRET_PATTERN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40}(?![A-Za-z0-9+/])")


def _find_paired_secret(excerpt: str | None, access_key: str) -> str | None:
    """Look for a 40-char AWS secret near the access key in the excerpt.

    Heuristic: the secret usually appears on the line below the access
    key in credentials/env files. We allow up to 200 chars of
    intervening text to handle indented YAML/JSON / wrapped lines.
    """
    if not excerpt:
        return None
    idx = excerpt.find(access_key)
    if idx < 0:
        return None
    window = excerpt[idx : idx + len(access_key) + 400]
    for m in _SECRET_PATTERN.finditer(window):
        if m.group(0) != access_key:
            return m.group(0)
    return None


class AWSVerifier(BaseVerifier):
    service = "aws"
    credential_type = "aws_access_key"

    def _verify_inner(
        self,
        credential: str,
        config: VerifyConfig,
        context: dict,
    ) -> VerifyResult:
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
        except ImportError as exc:
            return VerifyResult(
                status="inconclusive",
                credential_type=self.credential_type,
                service=self.service,
                error=f"boto3_not_installed: {exc}. Install with `uv sync --group verify-cloud`.",
            )

        secret = context.get("paired_secret") or _find_paired_secret(
            context.get("excerpt"), credential
        )
        if not secret:
            return VerifyResult(
                status="inconclusive",
                credential_type=self.credential_type,
                service=self.service,
                metadata={"reason": "no_paired_secret_found"},
            )

        t0 = time.perf_counter()
        try:
            client = boto3.client(
                "sts",
                aws_access_key_id=credential,
                aws_secret_access_key=secret,
                region_name="us-east-1",
            )
            ident = client.get_caller_identity()
        except (NoCredentialsError,) as exc:
            return VerifyResult(
                status="failed",
                credential_type=self.credential_type,
                service=self.service,
                latency_ms=(time.perf_counter() - t0) * 1000,
                error=f"NoCredentials: {exc}",
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in {"InvalidClientTokenId", "SignatureDoesNotMatch", "AuthFailure"}:
                return VerifyResult(
                    status="failed",
                    credential_type=self.credential_type,
                    service=self.service,
                    latency_ms=(time.perf_counter() - t0) * 1000,
                    metadata={"aws_error_code": code},
                    error=code,
                )
            return VerifyResult(
                status="inconclusive",
                credential_type=self.credential_type,
                service=self.service,
                latency_ms=(time.perf_counter() - t0) * 1000,
                metadata={"aws_error_code": code},
                error=f"ClientError: {code}",
            )

        return VerifyResult(
            status="passed",
            credential_type=self.credential_type,
            service=self.service,
            latency_ms=(time.perf_counter() - t0) * 1000,
            metadata={
                "account_id": ident.get("Account"),
                "arn": ident.get("Arn"),
                "user_id": ident.get("UserId"),
            },
        )
