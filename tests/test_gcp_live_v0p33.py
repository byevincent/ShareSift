"""v0.33: GCP service-account live OAuth verification.

When ``pyjwt[crypto]`` is installed (it's in the ``verify`` group),
the verifier signs an RS256 JWT with the SA's private_key and
exchanges it for an access token at the SA's ``token_uri``. We
generate a real synthetic RSA key in the test fixtures so the JWT
actually signs; the OAuth HTTP call itself is mocked.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from sharesift.verify.base import VerifyConfig


def _generate_real_rsa_pem() -> str:
    """Generate a synthetic 2048-bit RSA key as a PEM string. Used so
    PyJWT can actually sign; the resulting signature is rejected by
    the (mocked) OAuth endpoint anyway."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem.decode("utf-8")


@pytest.fixture(scope="module")
def synthetic_sa_with_real_key() -> dict:
    """A SA JSON whose private_key is a valid RSA PEM — so PyJWT can
    sign it — but obviously synthetic (key generated at test time)."""
    return {
        "type": "service_account",
        "project_id": "test-project-v0p33",
        "private_key_id": "fakeb0fakeb0fakeb0fakeb0fakeb0fakeb0fakeb",
        "private_key": _generate_real_rsa_pem(),
        "client_email": "synthetic-sa@test-project-v0p33.iam.gserviceaccount.com",
        "token_uri": "https://oauth2.googleapis.com/token",
        "client_id": "111111111111111111111",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    }


def _mock_oauth_response(status_code: int, body: dict | None = None) -> MagicMock:
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = body or {}
    r.text = ""
    return r


# --- Happy path -----------------------------------------------------


def test_live_verification_passes_on_oauth_200(synthetic_sa_with_real_key):
    """When the SA signs a valid JWT and the OAuth endpoint returns
    200 + access_token, return validation_mode=live."""
    from sharesift.verify.gcp_service_account import GcpServiceAccountVerifier
    with patch("requests.post") as mock_post:
        mock_post.return_value = _mock_oauth_response(200, {
            "access_token": "ya29.synthetic-access-token",
            "token_type": "Bearer",
            "expires_in": 3599,
        })
        result = GcpServiceAccountVerifier().verify(
            credential=json.dumps(synthetic_sa_with_real_key),
            config=VerifyConfig(),
            context={"credential_type": "gcp_service_account_json"},
        )
        assert result.status == "passed"
        assert result.metadata["validation_mode"] == "live"
        assert result.metadata["token_type"] == "Bearer"
        assert result.metadata["expires_in"] == 3599
        assert result.metadata["client_email"] == synthetic_sa_with_real_key["client_email"]
        # Confirm we POSTed to the right endpoint.
        call = mock_post.call_args
        assert call.args[0] == "https://oauth2.googleapis.com/token"
        # JWT grant.
        data = call.kwargs.get("data", {})
        assert data["grant_type"] == "urn:ietf:params:oauth:grant-type:jwt-bearer"
        assert "assertion" in data
        assert len(data["assertion"]) > 100  # JWT is non-trivial


def test_live_verification_returns_live_meta_when_oauth_succeeds(synthetic_sa_with_real_key):
    from sharesift.verify.gcp_service_account import GcpServiceAccountVerifier
    with patch("requests.post") as mock_post:
        mock_post.return_value = _mock_oauth_response(200, {
            "access_token": "ya29.ok",
            "token_type": "Bearer",
            "expires_in": 60,
        })
        result = GcpServiceAccountVerifier().verify(
            credential=json.dumps(synthetic_sa_with_real_key),
            config=VerifyConfig(),
            context={"credential_type": "gcp_service_account_json"},
        )
        # The metadata should distinguish live mode + carry liveness signals.
        assert "validation_mode" in result.metadata
        assert result.metadata["validation_mode"] == "live"
        assert result.metadata["project_id"] == "test-project-v0p33"


# --- Failure paths --------------------------------------------------


def test_live_verification_fails_on_oauth_401_revoked_key(synthetic_sa_with_real_key):
    """A revoked / disabled SA key produces 401 + invalid_grant. The
    verifier surfaces that as failed (live mode), with the HTTP status
    in metadata."""
    from sharesift.verify.gcp_service_account import GcpServiceAccountVerifier
    with patch("requests.post") as mock_post:
        mock_post.return_value = _mock_oauth_response(401, {
            "error": "invalid_grant",
            "error_description": "Invalid JWT signature",
        })
        result = GcpServiceAccountVerifier().verify(
            credential=json.dumps(synthetic_sa_with_real_key),
            config=VerifyConfig(),
            context={"credential_type": "gcp_service_account_json"},
        )
        assert result.status == "failed"
        assert result.metadata["validation_mode"] == "live"
        assert result.metadata["oauth_http_status"] == 401
        assert "invalid_grant" in (result.error or "")


def test_live_verification_fails_on_oauth_400(synthetic_sa_with_real_key):
    """A malformed JWT (the OAuth endpoint says so) produces 400."""
    from sharesift.verify.gcp_service_account import GcpServiceAccountVerifier
    with patch("requests.post") as mock_post:
        mock_post.return_value = _mock_oauth_response(400, {
            "error": "invalid_request",
        })
        result = GcpServiceAccountVerifier().verify(
            credential=json.dumps(synthetic_sa_with_real_key),
            config=VerifyConfig(),
            context={"credential_type": "gcp_service_account_json"},
        )
        assert result.status == "failed"
        assert result.metadata["oauth_http_status"] == 400


def test_live_verification_inconclusive_on_oauth_timeout(synthetic_sa_with_real_key):
    """Network timeout → inconclusive, not failed (don't blame the SA
    for the operator's connectivity)."""
    from sharesift.verify.gcp_service_account import GcpServiceAccountVerifier
    import requests as _requests
    with patch("requests.post") as mock_post:
        mock_post.side_effect = _requests.exceptions.Timeout("timed out")
        result = GcpServiceAccountVerifier().verify(
            credential=json.dumps(synthetic_sa_with_real_key),
            config=VerifyConfig(timeout_sec=1),
            context={"credential_type": "gcp_service_account_json"},
        )
        assert result.status == "inconclusive"
        assert "token_exchange_timeout" in (result.error or "")


def test_live_verification_inconclusive_on_connection_error(synthetic_sa_with_real_key):
    from sharesift.verify.gcp_service_account import GcpServiceAccountVerifier
    import requests as _requests
    with patch("requests.post") as mock_post:
        mock_post.side_effect = _requests.exceptions.ConnectionError("dns failure")
        result = GcpServiceAccountVerifier().verify(
            credential=json.dumps(synthetic_sa_with_real_key),
            config=VerifyConfig(),
            context={"credential_type": "gcp_service_account_json"},
        )
        assert result.status == "inconclusive"
        assert "connection_error" in (result.error or "")


# --- JWT payload contents -------------------------------------------


def test_jwt_payload_includes_correct_oauth_claims(synthetic_sa_with_real_key):
    """The signed JWT must have iss, scope, aud, iat, exp — that's
    what Google's token exchange requires."""
    import jwt as _jwt
    from sharesift.verify.gcp_service_account import GcpServiceAccountVerifier
    with patch("requests.post") as mock_post:
        mock_post.return_value = _mock_oauth_response(200, {"access_token": "ya29.x"})
        GcpServiceAccountVerifier().verify(
            credential=json.dumps(synthetic_sa_with_real_key),
            config=VerifyConfig(),
            context={"credential_type": "gcp_service_account_json"},
        )
        # Decode the JWT we sent without verifying signature.
        assertion = mock_post.call_args.kwargs["data"]["assertion"]
        decoded = _jwt.decode(assertion, options={"verify_signature": False})
        assert decoded["iss"] == synthetic_sa_with_real_key["client_email"]
        assert decoded["aud"] == synthetic_sa_with_real_key["token_uri"]
        assert "scope" in decoded
        assert "userinfo.email" in decoded["scope"]
        assert "iat" in decoded and "exp" in decoded
        assert decoded["exp"] > decoded["iat"]


# --- Fallback to structural -----------------------------------------


def test_falls_back_to_structural_when_pyjwt_import_fails(synthetic_sa_with_real_key, monkeypatch):
    """If ``import jwt`` fails inside ``_try_live_verification``, the
    verifier returns structural 'passed' — same v0.32 behavior."""
    from sharesift.verify import gcp_service_account as gcp_sa

    # Patch the helper to simulate ImportError → returns None.
    monkeypatch.setattr(gcp_sa, "_try_live_verification", lambda data, config: None)
    result = gcp_sa.GcpServiceAccountVerifier().verify(
        credential=json.dumps(synthetic_sa_with_real_key),
        config=VerifyConfig(),
        context={"credential_type": "gcp_service_account_json"},
    )
    assert result.status == "passed"
    assert result.metadata["validation_mode"] == "structural"
