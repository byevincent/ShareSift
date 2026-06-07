"""Shared HTTP helper for the SaaS verifiers.

All seven SaaS verifiers follow the same shape: send one authenticated
request to a known-cheap endpoint (``/v1/models``, ``/user``,
``auth.test``), translate the HTTP response into a ``VerifyResult``.
This module is the shared transport so each verifier file is ~15
lines of service-specific configuration rather than ~60 lines of
duplicated request-and-error handling.
"""

from __future__ import annotations

import time
from typing import Any

from sharesift.verify.base import VerifyConfig, VerifyResult


def http_verify(
    *,
    credential_type: str,
    service: str,
    method: str,
    url: str,
    headers: dict[str, str],
    config: VerifyConfig,
    success_status: tuple[int, ...] = (200,),
    fail_status: tuple[int, ...] = (401, 403),
    extract_metadata: Any = None,
    body: dict | None = None,
) -> VerifyResult:
    """Run one HTTP request and map the response to a VerifyResult.

    ``extract_metadata`` is an optional ``(response_json) -> dict``
    callable that pulls per-service identifying fields (account id,
    user login, team name) into ``VerifyResult.metadata`` on success.

    Imports ``requests`` lazily so the verify subsystem doesn't add
    ``requests`` to the base install.
    """
    import requests

    t0 = time.perf_counter()
    try:
        resp = requests.request(
            method,
            url,
            headers=headers,
            json=body,
            timeout=config.timeout_sec,
        )
    except requests.exceptions.Timeout:
        return VerifyResult(
            status="inconclusive",
            credential_type=credential_type,
            service=service,
            latency_ms=(time.perf_counter() - t0) * 1000,
            error="timeout",
        )
    except requests.exceptions.ConnectionError as exc:
        return VerifyResult(
            status="inconclusive",
            credential_type=credential_type,
            service=service,
            latency_ms=(time.perf_counter() - t0) * 1000,
            error=f"connection_error: {exc}",
        )

    latency_ms = (time.perf_counter() - t0) * 1000
    if resp.status_code in success_status:
        metadata: dict = {"http_status": resp.status_code}
        if extract_metadata is not None:
            try:
                metadata.update(extract_metadata(resp.json()))
            except (ValueError, KeyError, TypeError):
                pass
        return VerifyResult(
            status="passed",
            credential_type=credential_type,
            service=service,
            latency_ms=latency_ms,
            metadata=metadata,
        )
    if resp.status_code in fail_status:
        return VerifyResult(
            status="failed",
            credential_type=credential_type,
            service=service,
            latency_ms=latency_ms,
            metadata={"http_status": resp.status_code},
            error=f"http_{resp.status_code}",
        )
    return VerifyResult(
        status="inconclusive",
        credential_type=credential_type,
        service=service,
        latency_ms=latency_ms,
        metadata={"http_status": resp.status_code, "body_excerpt": resp.text[:200]},
        error=f"unexpected_http_{resp.status_code}",
    )
